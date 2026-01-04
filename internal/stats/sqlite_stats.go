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
	logger *slog.Logger
	
	// Changed from *sql.DB to QueryLogReader to allow Flush
	queryLog QueryLogReader

	confMu            *sync.RWMutex
	ignored           *aghnet.IgnoreEngine
	shouldCountClient func([]string) bool
	limit             time.Duration
	enabled           bool

	configModifier agh.ConfigModifier
	httpReg        aghhttp.Registrar
}

// newSqliteStats creates a new sqliteStats instance.
func newSqliteStats(conf Config) (Interface, error) {
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

	return s, nil
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
	defer rows.Close()

	var ips []netip.Addr
	for rows.Next() {
		var ipStr string
		var count int
		if err := rows.Scan(&ipStr, &count); err == nil {
			if ip, err := netip.ParseAddr(ipStr); err == nil {
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
	var err error

	func() {
		s.confMu.RLock()
		defer s.confMu.RUnlock()
		resp, err = s.getStatsData(ctx, s.limit) // Pass context for Flush
	}()

	s.logger.DebugContext(ctx, "prepared sqlite data", "elapsed", time.Since(start))

	if err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusInternalServerError, "getting stats: %s", err)
		return
	}

	aghhttp.WriteJSONResponseOK(ctx, s.logger, w, r, resp)
}

func (s *sqliteStats) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	db := s.queryLog.GetSQLDB()
	_, err := db.Exec("DELETE FROM query_log")
	if err != nil {
		aghhttp.ErrorAndLog(r.Context(), s.logger, r, w, http.StatusInternalServerError, "clearing stats: %s", err)
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
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusUnprocessableEntity, "ignored: %s", err)
		return
	}

	ivl := time.Duration(reqData.Interval) * time.Millisecond
	if err = validateIvl(ivl); err != nil {
		aghhttp.ErrorAndLog(ctx, s.logger, r, w, http.StatusUnprocessableEntity, "unsupported interval: %s", err)
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

func (s *sqliteStats) getStatsData(ctx context.Context, limit time.Duration) (*StatsResp, error) {
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
		return resp, nil
	}

	// FORCE FLUSH BEFORE QUERYING
	if err := s.queryLog.Flush(ctx); err != nil {
		s.logger.ErrorContext(ctx, "flushing query log for stats", slogutil.KeyError, err)
		// Continue anyway, maybe partially stale data is better than nothing
	}

	olderThan := time.Now().Add(-limit).UnixNano()
	db := s.queryLog.GetSQLDB()

	queryTimeSeriesFixed := `
		SELECT 
			COUNT(*) as total,
			SUM(CASE WHEN json_extract(filtering_result, '$.IsFiltered') = true THEN 1 ELSE 0 END) as blocked,
			SUM(CASE WHEN json_extract(filtering_result, '$.Reason') = 4 THEN 1 ELSE 0 END) as safe_browsing, 
			SUM(CASE WHEN json_extract(filtering_result, '$.Reason') = 5 THEN 1 ELSE 0 END) as parental
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

	resp.TopQueried = s.getTopMap(db, `SELECT q_host, COUNT(*) FROM query_log WHERE timestamp > ? GROUP BY q_host ORDER BY 2 DESC LIMIT ?`, olderThan)
	resp.TopBlocked = s.getTopMap(db, `SELECT q_host, COUNT(*) FROM query_log WHERE timestamp > ? AND json_extract(filtering_result, '$.IsFiltered') = true GROUP BY q_host ORDER BY 2 DESC LIMIT ?`, olderThan)
	resp.TopClients = s.getTopMap(db, `SELECT client_ip, COUNT(*) FROM query_log WHERE timestamp > ? AND client_ip != '' GROUP BY client_ip ORDER BY 2 DESC LIMIT ?`, olderThan)

	return resp, nil
}

func (s *sqliteStats) getTopMap(db *sql.DB, query string, olderThan int64) []map[string]uint64 {
	res := []map[string]uint64{}
	
	rows, err := db.Query(query, olderThan, 100)
	if err != nil {
		s.logger.Error("querying top", slogutil.KeyError, err)
		return res
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var count uint64
		if err := rows.Scan(&name, &count); err == nil {
			res = append(res, map[string]uint64{name: count})
		}
	}
	return res
}