package querylog

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/pbnjay/memory"
	_ "modernc.org/sqlite"
)

func initDB(path string) (*sql.DB, error) {
	dsn := getSQLiteDSN(path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	query := `
	CREATE TABLE IF NOT EXISTS query_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER,
		q_host TEXT,
		q_type TEXT,
		client_id TEXT,
		client_ip TEXT,
		upstream TEXT,
		elapsed_ns INTEGER,
		response_code TEXT,
		filtering_result TEXT,
		
		-- Generated Columns for Performance
		is_filtered INTEGER GENERATED ALWAYS AS (json_extract(filtering_result, '$.IsFiltered')) VIRTUAL,
		reason INTEGER GENERATED ALWAYS AS (json_extract(filtering_result, '$.Reason')) VIRTUAL
	);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON query_log (timestamp);
	
	-- Composite Indices for GROUP BY optimization
	CREATE INDEX IF NOT EXISTS idx_is_filtered_host ON query_log(is_filtered, q_host) WHERE is_filtered = 1;
	CREATE INDEX IF NOT EXISTS idx_timestamp_host ON query_log(timestamp, q_host);
	`

	_, err = db.Exec(query)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating table: %w", err)
	}

	_, _ = db.Exec("ALTER TABLE query_log ADD COLUMN filtering_result TEXT")

	// Migration for existing databases: Add generated columns and indices
	// Ignored errors are expected if columns/indices already exist.
	_, _ = db.Exec("ALTER TABLE query_log ADD COLUMN is_filtered INTEGER GENERATED ALWAYS AS (json_extract(filtering_result, '$.IsFiltered')) VIRTUAL")
	_, _ = db.Exec("ALTER TABLE query_log ADD COLUMN reason INTEGER GENERATED ALWAYS AS (json_extract(filtering_result, '$.Reason')) VIRTUAL")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_is_filtered ON query_log(is_filtered) WHERE is_filtered = 1")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_reason ON query_log(reason)")
	
	// Composite Indices Migration
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_is_filtered_host ON query_log(is_filtered, q_host) WHERE is_filtered = 1")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_timestamp_host ON query_log(timestamp, q_host)")

	return db, nil
}

func (l *queryLog) flushToSQLite(ctx context.Context) error {
	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	if l.buffer.Len() == 0 {
		return nil
	}

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		`
			INSERT INTO query_log(
				timestamp, q_host, q_type, client_id, client_ip, upstream, elapsed_ns, response_code, filtering_result
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
	if err != nil {
		return fmt.Errorf("preparing statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	var execErr error
	l.buffer.Range(func(entry *logEntry) bool {
		clientIP := ""
		if entry.IP != nil {
			clientIP = entry.IP.String()
		}

		responseCode := ""
		if len(entry.Answer) > 0 {
			msg := &dns.Msg{}
			if unpackErr := msg.Unpack(entry.Answer); unpackErr == nil {
				responseCode = dns.RcodeToString[msg.Rcode]
			}
		}

		resBytes, marshalErr := json.Marshal(entry.Result)
		if marshalErr != nil {
			l.logger.ErrorContext(ctx, "marshaling filtering result", slogutil.KeyError, marshalErr)
			resBytes = []byte("{}")
		}

		_, execErr = stmt.ExecContext(ctx,
			entry.Time.UnixNano(),
			entry.QHost,
			entry.QType,
			entry.ClientID,
			clientIP,
			entry.Upstream,
			entry.Elapsed.Nanoseconds(),
			responseCode,
			string(resBytes),
		)
		return execErr == nil
	})

	if execErr != nil {
		return fmt.Errorf("inserting entry: %w", execErr)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	l.buffer.Clear()
	l.flushPending = false

	return nil
}

func (l *queryLog) searchSQLite(ctx context.Context, params *searchParams) ([]*logEntry, error) {
	query := "SELECT timestamp, q_host, q_type, client_id, client_ip, upstream, elapsed_ns, response_code, filtering_result FROM query_log WHERE 1=1"
	var args []interface{}

	if !params.olderThan.IsZero() {
		query += " AND timestamp < ?"
		args = append(args, params.olderThan.UnixNano())
	}

	for _, c := range params.searchCriteria {
		if c.criterionType == ctTerm {
			query += " AND (q_host LIKE ? OR client_ip LIKE ? OR client_id LIKE ?)"
			pattern := "%" + c.value + "%"
			args = append(args, pattern, pattern, pattern)
		} else if c.criterionType == ctFilteringStatus {
			query += filteringStatusConditions[c.value]
		}
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	limit := params.limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit)

	if params.offset > 0 {
		query += " OFFSET ?"
		args = append(args, params.offset)
	}

	rows, err := l.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying sqlite: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*logEntry
	for rows.Next() {
		entry, scanErr := scanLogEntry(rows)
		if scanErr != nil {
			l.logger.ErrorContext(ctx, "scanning sqlite row", slogutil.KeyError, scanErr)
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func scanLogEntry(rows *sql.Rows) (*logEntry, error) {
	var ts int64
	var qHost, qType, clientID, clientIPStr, upstream, respCode string
	var elapsedNs int64
	var filteringResultJSON sql.NullString

	err := rows.Scan(&ts, &qHost, &qType, &clientID, &clientIPStr, &upstream, &elapsedNs, &respCode, &filteringResultJSON)
	if err != nil {
		return nil, err
	}

	entry := &logEntry{
		Time:     time.Unix(0, ts),
		QHost:    qHost,
		QType:    qType,
		ClientID: clientID,
		IP:       net.ParseIP(clientIPStr),
		Upstream: upstream,
		Elapsed:  time.Duration(elapsedNs),
	}

	if filteringResultJSON.Valid && filteringResultJSON.String != "" {
		_ = json.Unmarshal([]byte(filteringResultJSON.String), &entry.Result)
	}

	return entry, nil
}

var filteringStatusConditions = map[string]string{
	filteringStatusFiltered:            " AND (is_filtered = 1 OR reason IN (1, 9, 10, 11))",
	filteringStatusBlocked:             " AND is_filtered = 1 AND reason IN (3, 8)",
	filteringStatusBlockedService:      " AND is_filtered = 1 AND reason = 8",
	filteringStatusBlockedSafebrowsing: " AND is_filtered = 1 AND reason = 4",
	filteringStatusBlockedParental:     " AND is_filtered = 1 AND reason = 5",
	filteringStatusWhitelisted:         " AND reason = 1",
	filteringStatusRewritten:           " AND reason IN (9, 10, 11)",
	filteringStatusSafeSearch:          " AND is_filtered = 1 AND reason = 7",
	filteringStatusProcessed:           " AND reason NOT IN (3, 8, 1)",
}

func (l *queryLog) deleteOld(ctx context.Context, olderThan time.Time) error {
	l.logger.DebugContext(ctx, "deleting old sqlite entries", "older_than", olderThan)

	res, err := l.db.ExecContext(ctx, "DELETE FROM query_log WHERE timestamp < ?", olderThan.UnixNano())
	if err != nil {
		return fmt.Errorf("deleting old entries: %w", err)
	}

	rowsAffected, _ := res.RowsAffected()

	l.logger.DebugContext(ctx, "deleted old sqlite entries", "count", rowsAffected)

	return nil
}

func getSQLiteDSN(path string) (dsn string) {
	totalMem := memory.TotalMemory()

	const cachePercentage = 0.03
	cacheSizeKB := int(float64(totalMem) * cachePercentage / 1024)

	if cacheSizeKB < 2000 {
		cacheSizeKB = 2000
	}

	dsn = fmt.Sprintf(
		"file:%s?_pragma=journal_mode=WAL&_pragma=synchronous=NORMAL&_pragma=cache_size=-%d",
		path,
		cacheSizeKB,
	)

	if totalMem > 1024*1024*1024 {
		dsn += "&_pragma=temp_store=MEMORY"
	}

	return dsn
}
