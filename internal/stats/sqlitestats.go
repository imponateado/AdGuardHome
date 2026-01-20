package stats

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghalg"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// sqliteStats implements the Interface using direct SQL queries on QueryLog DB.
type sqliteStats struct {
	queryLog          QueryLogReader
	configModifier    agh.ConfigModifier
	httpReg           aghhttp.Registrar
	logger            *slog.Logger
	confMu            *sync.RWMutex
	ignored           *aghnet.IgnoreEngine
	shouldCountClient func([]string) bool
	limit             time.Duration
	enabled           bool
}

// newSqliteStats creates a new sqliteStats instance.
func newSqliteStats(conf Config) Interface {
	s := &sqliteStats{
		logger:            conf.Logger,
		queryLog:          conf.QueryLog, // Store the interface
		limit:             conf.Limit,
		confMu:            &sync.RWMutex{},
		ignored:           conf.Ignored,
		shouldCountClient: conf.ShouldCountClient,
		enabled:           conf.Enabled,
		configModifier:    conf.ConfigModifier,
		httpReg:           conf.HTTPReg,
	}

	return s
}

func (s *sqliteStats) Start() {
	s.initWeb()
}

func (s *sqliteStats) Close() error {
	return nil
}

func (s *sqliteStats) Update(e *Entry) {
	// No-op: Data is inserted by QueryLog module directly.
}

func (s *sqliteStats) WriteDiskConfig(dc *Config) {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	dc.Ignored = s.ignored
	dc.Limit = s.limit
	dc.Enabled = s.enabled
}

func (s *sqliteStats) ShouldCount(host string, _, _ uint16, ids []string) bool {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	if !s.shouldCountClient(ids) {
		return false
	}
	return !s.ignored.Has(host)
}

func (s *sqliteStats) TopClientsIP(limit uint) []netip.Addr {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	if !s.enabled || s.limit == 0 {
		return nil
	}

	olderThan := time.Now().Add(-s.limit).UnixNano()
	query := `
		SELECT client_ip, COUNT(*) as cnt 
		FROM query_log 
		WHERE timestamp > ? AND client_ip != ''
		GROUP BY client_ip 
		ORDER BY cnt DESC 
		LIMIT ?`

	// Get DB from interface
	db := s.queryLog.GetSQLDB()
	rows, err := db.Query(query, olderThan, limit)
	if err != nil {
		s.logger.Error("querying top clients", slogutil.KeyError, err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var ips []netip.Addr
	for rows.Next() {
		var ipStr string
		var count int
		if scanErr := rows.Scan(&ipStr, &count); scanErr == nil {
			if ip, parseErr := netip.ParseAddr(ipStr); parseErr == nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// HTTP Handlers Replication

func (s *sqliteStats) initWeb() {
	s.httpReg.Register(http.MethodGet, "/control/stats", s.handleStats)
	s.httpReg.Register(http.MethodPost, "/control/stats_reset", s.handleStatsReset)
	s.httpReg.Register(http.MethodGet, "/control/stats/config", s.handleGetStatsConfig)
	s.httpReg.Register(http.MethodPut, "/control/stats/config/update", s.handlePutStatsConfig)
}

func (s *sqliteStats) handleStats(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	var resp *StatsResp

	func() {
		s.confMu.RLock()
		defer s.confMu.RUnlock()
		resp = s.getStatsData(ctx, s.limit) // Pass context for Flush
	}()

	s.logger.DebugContext(ctx, "prepared sqlite data", "elapsed", time.Since(start))

	aghhttp.WriteJSONResponseOK(ctx, s.logger, w, r, resp)
}

func (s *sqliteStats) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	db := s.queryLog.GetSQLDB()
	_, err := db.Exec("DELETE FROM query_log")
	if err != nil {
		aghhttp.ErrorAndLog(
			r.Context(),
			s.logger,
			r,
			w,
			http.StatusInternalServerError,
			"clearing stats: %s",
			err,
		)
	}
}

func (s *sqliteStats) handleGetStatsConfig(w http.ResponseWriter, r *http.Request) {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	resp := &getConfigResp{
		Ignored:        s.ignored.Values(),
		IgnoredEnabled: aghalg.BoolToNullBool(s.ignored.IsEnabled()),
		Interval:       float64(s.limit.Milliseconds()),
		Enabled:        aghalg.BoolToNullBool(s.enabled),
	}
	aghhttp.WriteJSONResponseOK(r.Context(), s.logger, w, r, resp)
}

func (s *sqliteStats) handlePutStatsConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqData := getConfigResp{}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusBadRequest, "json decode: %s", err)
		return
	}

	var ignoredEnabled bool
	if reqData.IgnoredEnabled == aghalg.NBNull {
		ignoredEnabled = len(reqData.Ignored) > 0
	} else {
		ignoredEnabled = reqData.IgnoredEnabled == aghalg.NBTrue
	}

	engine, err := aghnet.NewIgnoreEngine(reqData.Ignored, ignoredEnabled)
	if err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			s.logger,
			r,
			w,
			http.StatusUnprocessableEntity,
			"ignored: %s",
			err,
		)
		return
	}

	ivl := time.Duration(reqData.Interval) * time.Millisecond
	if err = validateIvl(ivl); err != nil {
		aghhttp.ErrorAndLog(
			ctx,
			s.logger,
			r,
			w,
			http.StatusUnprocessableEntity,
			"unsupported interval: %s",
			err,
		)
		return
	}

	defer s.configModifier.Apply(ctx)

	s.confMu.Lock()
	defer s.confMu.Unlock()
	s.ignored = engine
	s.limit = ivl
	s.enabled = reqData.Enabled == aghalg.NBTrue
}

// Data Retrieval Logic

func (s *sqliteStats) getStatsData(ctx context.Context, limit time.Duration) *StatsResp {
	resp := &StatsResp{
		TimeUnits: "hours",

		TopQueried:            []topAddrs{},
		TopBlocked:            []topAddrs{},
		TopClients:            []topAddrs{},
		TopUpstreamsResponses: []topAddrs{},
		TopUpstreamsAvgTime:   []topAddrsFloat{},

		DNSQueries:           []uint64{},
		BlockedFiltering:     []uint64{},
		ReplacedSafebrowsing: []uint64{},
		ReplacedParental:     []uint64{},
	}

	if !s.enabled || limit == 0 {
		return resp
	}

	// Force flush before querying.
	if err := s.queryLog.Flush(ctx); err != nil {
		s.logger.ErrorContext(ctx, "flushing query log for stats", slogutil.KeyError, err)
	}

	olderThan := time.Now().Add(-limit).UnixNano()

	db := s.queryLog.GetSQLDB()

	// 1. Totals
	queryTimeSeriesFixed := `
		SELECT 
			COUNT(*) as total,
			SUM(CASE WHEN is_filtered = 1 THEN 1 ELSE 0 END) as blocked,
			SUM(CASE WHEN reason = 4 THEN 1 ELSE 0 END) as safe_browsing, 
			SUM(CASE WHEN reason = 5 THEN 1 ELSE 0 END) as parental
		FROM query_log
		WHERE timestamp > ?
	`

	row := db.QueryRow(queryTimeSeriesFixed, olderThan)
	var total, blocked, sb, parental sql.NullInt64
	if err := row.Scan(&total, &blocked, &sb, &parental); err == nil {
		resp.NumDNSQueries = uint64(total.Int64)
		resp.NumBlockedFiltering = uint64(blocked.Int64)
		resp.NumReplacedSafebrowsing = uint64(sb.Int64)
		resp.NumReplacedParental = uint64(parental.Int64)
	}

	// 2. Top Queried Domains
	resp.TopQueried = s.getTopMap(
		db,
		`SELECT q_host, COUNT(*) FROM query_log WHERE timestamp > ? GROUP BY q_host ORDER BY 2 DESC LIMIT ?`,
		olderThan,
	)

	// 3. Top Blocked Domains (Corrected IsFiltered check)
	resp.TopBlocked = s.getTopMap(db, `
		SELECT q_host, COUNT(*) 
		FROM query_log 
		WHERE timestamp > ? AND is_filtered = 1
		GROUP BY q_host 
		ORDER BY 2 DESC 
		LIMIT ?`, olderThan)

	// 4. Top Clients (ID/IP)
	resp.TopClients = s.getTopMap(db, `
		SELECT 
			t.identifier, 
			SUM(t.cnt) 
		FROM (
			SELECT 
				CASE
					WHEN MAX(client_id) IS NOT NULL AND MAX(client_id) != '' THEN MAX(client_id)
					ELSE client_ip
				END as identifier, 
				COUNT(*) as cnt
			FROM query_log 
			WHERE timestamp > ? AND (client_ip != '' OR client_id != '')
			GROUP BY client_ip 
		) as t
		GROUP BY t.identifier 
		ORDER BY 2 DESC 
		LIMIT ?`, olderThan)

	// 5. Top Upstreams Responses
	resp.TopUpstreamsResponses = s.getTopMap(db, `
		SELECT upstream, COUNT(*)
		FROM query_log
		WHERE timestamp > ? AND upstream != ''
		GROUP BY upstream
		ORDER BY 2 DESC
		LIMIT ?`, olderThan)

	// 6. Top Upstreams Avg Time
	resp.TopUpstreamsAvgTime = s.getTopMapFloat(db, `
		SELECT upstream, AVG(elapsed_ns) / 1000000000.0
		FROM query_log
		WHERE timestamp > ? AND upstream != ''
		GROUP BY upstream
		ORDER BY 2 ASC
		LIMIT ?`, olderThan)

	return resp
}

func (s *sqliteStats) getTopMap(db *sql.DB, query string, olderThan int64) []map[string]uint64 {
	res := []map[string]uint64{}

	rows, err := db.Query(query, olderThan, 100) // Limit 100
	if err != nil {
		s.logger.Error("querying top", slogutil.KeyError, err)
		return res
	}
	defer func() { _ = rows.Close() }()

	count := 0
	for rows.Next() {
		count++
		var name string
		var count uint64
		if scanErr := rows.Scan(&name, &count); scanErr == nil {
			res = append(res, map[string]uint64{name: count})
		}
	}
	return res
}

func (s *sqliteStats) getTopMapFloat(db *sql.DB, query string, olderThan int64) []map[string]float64 {
	res := []map[string]float64{}

	rows, err := db.Query(query, olderThan, 100) // Limit 100
	if err != nil {
		s.logger.Error("querying top float", slogutil.KeyError, err)
		return res
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var name string
		var val float64
		if scanErr := rows.Scan(&name, &val); scanErr == nil {
			res = append(res, map[string]float64{name: val})
		}
	}
	return res
}
