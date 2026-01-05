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
	_ "modernc.org/sqlite"
)

func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
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
		filtering_result TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON query_log (timestamp);
	`

	_, err = db.Exec(query)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("creating table: %w", err)
	}

	db.Exec("ALTER TABLE query_log ADD COLUMN filtering_result TEXT")

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

	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`
			INSERT INTO query_log(
				timestamp, q_host, q_type, client_id, client_ip, upstream, elapsed_ns, response_code, filtering_result
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
	if err != nil {
		return fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	var execErr error
	l.buffer.Range(func(entry *logEntry) bool {
		clientIP := ""
		if entry.IP != nil {
			clientIP = entry.IP.String()
		}

		responseCode := ""
		if len(entry.Answer) > 0 {
			msg := &dns.Msg{}
			if err := msg.Unpack(entry.Answer); err == nil {
				responseCode = dns.RcodeToString[msg.Rcode]
			}
		}

		resBytes, err := json.Marshal(entry.Result)
		if err != nil {
			l.logger.ErrorContext(ctx, "marshaling filtering result", slogutil.KeyError, err)
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
			// Mapping based on internal/querylog/searchcriterion.go
			switch c.value {
			case filteringStatusAll:
				// No-op
			case filteringStatusFiltered:
				// IsFiltered OR Reason in (AllowList, Rewritten, RewrittenAutoHosts, RewrittenRule)
				query += " AND (json_extract(filtering_result, '$.IsFiltered') IN (1, 'true', true) OR json_extract(filtering_result, '$.Reason') IN (1, 9, 10, 11))"
			case filteringStatusBlocked:
				// IsFiltered AND Reason in (BlockList, BlockedService)
				query += " AND json_extract(filtering_result, '$.IsFiltered') IN (1, 'true', true) AND json_extract(filtering_result, '$.Reason') IN (3, 8)"
			case filteringStatusBlockedService:
				query += " AND json_extract(filtering_result, '$.IsFiltered') IN (1, 'true', true) AND json_extract(filtering_result, '$.Reason') = 8"
			case filteringStatusBlockedSafebrowsing:
				query += " AND json_extract(filtering_result, '$.IsFiltered') IN (1, 'true', true) AND json_extract(filtering_result, '$.Reason') = 4"
			case filteringStatusBlockedParental:
				query += " AND json_extract(filtering_result, '$.IsFiltered') IN (1, 'true', true) AND json_extract(filtering_result, '$.Reason') = 5"
			case filteringStatusWhitelisted:
				query += " AND json_extract(filtering_result, '$.Reason') = 1"
			case filteringStatusRewritten:
				query += " AND json_extract(filtering_result, '$.Reason') IN (9, 10, 11)"
			case filteringStatusSafeSearch:
				query += " AND json_extract(filtering_result, '$.IsFiltered') IN (1, 'true', true) AND json_extract(filtering_result, '$.Reason') = 7"
			case filteringStatusProcessed:
				// NOT IN (BlockList, BlockedService, AllowList)
				query += " AND json_extract(filtering_result, '$.Reason') NOT IN (3, 8, 1)"
			}
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
	defer rows.Close()

	var entries []*logEntry
	for rows.Next() {
		var ts int64
		var qHost, qType, clientID, clientIPStr, upstream, respCode string
		var elapsedNs int64
		var filteringResultJSON sql.NullString

		err := rows.Scan(&ts, &qHost, &qType, &clientID, &clientIPStr, &upstream, &elapsedNs, &respCode, &filteringResultJSON)
		if err != nil {
			fmt.Errorf("error: %w", err)
			continue
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

		entries = append(entries, entry)
	}

	return entries, nil
}