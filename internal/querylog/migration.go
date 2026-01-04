package querylog

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// CheckAndMigrate checks if migration between storage types is needed and performs it.
// It should be called during initialization.
func (l *queryLog) CheckAndMigrate(ctx context.Context) {
	l.confMu.RLock()
	storageType := l.conf.StorageType
	baseDir := l.conf.BaseDir
	l.confMu.RUnlock()

	jsonPath := filepath.Join(baseDir, queryLogFileName)
	sqlitePath := filepath.Join(baseDir, "querylog.sqlite")

	if storageType == "sqlite" {
		// Target is SQLite. Check if JSON exists to migrate FROM.
		if _, err := os.Stat(jsonPath); err == nil {
			l.logger.InfoContext(ctx, "migrating query log from json to sqlite")
			if err := l.migrateToSQLite(ctx, jsonPath, sqlitePath); err != nil {
				l.logger.ErrorContext(ctx, "migration failed", slogutil.KeyError, err)
			} else {
				l.logger.InfoContext(ctx, "migration to sqlite completed successfully")
				_ = os.Rename(jsonPath, jsonPath+".bak")
			}
		}
	} else {
		// Target is JSON. Check if SQLite exists to migrate FROM.
		if _, err := os.Stat(sqlitePath); err == nil {
			l.logger.InfoContext(ctx, "migrating query log from sqlite to json")
			if err := l.migrateToJSON(ctx, sqlitePath, jsonPath); err != nil {
				l.logger.ErrorContext(ctx, "migration failed", slogutil.KeyError, err)
			} else {
				l.logger.InfoContext(ctx, "migration to json completed successfully")
				_ = os.Rename(sqlitePath, sqlitePath+".bak")
			}
		}
	}
}

func (l *queryLog) migrateToSQLite(ctx context.Context, jsonPath, sqlitePath string) error {
	// We use l.db which is already open if we are in sqlite mode
	if l.db == nil {
		return errors.Error("sqlite db is not open")
	}

	f, err := os.Open(jsonPath)
	if err != nil {
		return fmt.Errorf("opening json log: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	
	// Begin transaction for speed
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO query_log(
			timestamp, q_host, q_type, client_id, client_ip, upstream, elapsed_ns, response_code, filtering_result
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing stmt: %w", err)
	}
	defer stmt.Close()

	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry := &logEntry{}
		if err := json.Unmarshal([]byte(line), entry); err != nil {
			// Skip malformed lines
			continue
		}

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

		resBytes, _ := json.Marshal(entry.Result)

		_, err = stmt.ExecContext(ctx,
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
		if err != nil {
			return fmt.Errorf("inserting row: %w", err)
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	l.logger.InfoContext(ctx, "migrated entries", "count", count)
	return nil
}

func (l *queryLog) migrateToJSON(ctx context.Context, sqlitePath, jsonPath string) error {
	// If we are in JSON mode, l.db is nil. We need to open SQLite explicitly just for migration.
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return fmt.Errorf("opening sqlite: %w", err)
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `SELECT timestamp, q_host, q_type, client_id, client_ip, upstream, elapsed_ns, response_code, filtering_result FROM query_log ORDER BY timestamp ASC`)
	if err != nil {
		return fmt.Errorf("querying sqlite: %w", err)
	}
	defer rows.Close()

	// Open JSON file for writing (append or create)
	// We should probably create a NEW file to be safe, then rename.
	tempJsonPath := jsonPath + ".tmp"
	f, err := os.Create(tempJsonPath)
	if err != nil {
		return fmt.Errorf("creating temp json: %w", err)
	}
	defer f.Close()
	defer os.Remove(tempJsonPath) // Clean up on error

	encoder := json.NewEncoder(f)
	count := 0

	for rows.Next() {
		var ts int64
		var qHost, qType, clientID, clientIPStr, upstream, respCode string
		var elapsedNs int64
		var filteringResultJSON sql.NullString

		err := rows.Scan(&ts, &qHost, &qType, &clientID, &clientIPStr, &upstream, &elapsedNs, &respCode, &filteringResultJSON)
		if err != nil {
			return err
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
		
		// Note: Answer/OrigAnswer binaries are lost in SQLite currently if we didn't save them.
		// So JSON will have missing DNS packet details, but stats/history will work.

		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("encoding json: %w", err)
		}
		count++
	}

	f.Close() // Explicit close to flush

	// Move temp to final
	if err := os.Rename(tempJsonPath, jsonPath); err != nil {
		return fmt.Errorf("renaming final json: %w", err)
	}

	l.logger.InfoContext(ctx, "migrated entries", "count", count)
	return nil
}
