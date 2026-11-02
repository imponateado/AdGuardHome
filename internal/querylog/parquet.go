package querylog

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/AdGuardHome/internal/aghrenameio"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/zstd"
)

// queryLogDirName is the name of the directory with the Parquet files.  Each
// flush of the memory buffer writes one file named by the Unix time in
// nanoseconds of its newest entry, so sorting the names sorts the files by
// time.
const queryLogDirName = "querylog"

// parquetExt is the extension of the query log files.
const parquetExt = ".parquet"

// parquetRow is a [logEntry] as stored in a Parquet file.
type parquetRow struct {
	Time        int64  `parquet:"t,delta"`
	QHost       string `parquet:"qh,dict"`
	QType       string `parquet:"qt,dict"`
	QClass      string `parquet:"qc,dict"`
	ReqECS      string `parquet:"ecs,dict"`
	ClientID    string `parquet:"cid,dict"`
	ClientProto string `parquet:"cp,dict"`
	Upstream    string `parquet:"up,dict"`
	IP          string `parquet:"ip,dict"`
	Answer      []byte `parquet:"ans"`
	OrigAnswer  []byte `parquet:"oans"`

	// Result is the JSON of [filtering.Result], exactly as the old JSON log
	// stored it, so that [queryLog.decodeLogEntry] decodes it.  It's empty for
	// the zero result.
	Result []byte `parquet:"res"`

	Elapsed           int64 `parquet:"el"`
	Cached            bool  `parquet:"cached"`
	AuthenticatedData bool  `parquet:"ad"`
}

// zeroResultJSON is the JSON of an empty [filtering.Result], which isn't stored.
var zeroResultJSON = errors.Must(json.Marshal(filtering.Result{}))

// newParquetRow converts e into a row.  e must not be nil.
func newParquetRow(e *logEntry) (r parquetRow, err error) {
	res, err := json.Marshal(e.Result)
	if err != nil {
		return r, fmt.Errorf("encoding result for %q: %w", e.QHost, err)
	} else if bytes.Equal(res, zeroResultJSON) {
		res = nil
	}

	r = parquetRow{
		Time:              e.Time.UnixNano(),
		QHost:             e.QHost,
		QType:             e.QType,
		QClass:            e.QClass,
		ReqECS:            e.ReqECS,
		ClientID:          e.ClientID,
		ClientProto:       string(e.ClientProto),
		Upstream:          e.Upstream,
		Answer:            e.Answer,
		OrigAnswer:        e.OrigAnswer,
		Result:            res,
		Elapsed:           int64(e.Elapsed),
		Cached:            e.Cached,
		AuthenticatedData: e.AuthenticatedData,
	}

	if e.IP != nil {
		r.IP = e.IP.String()
	}

	return r, nil
}

// toEntry converts r back into a log entry.  r must not be nil.
func (l *queryLog) toEntry(ctx context.Context, r *parquetRow) (e *logEntry) {
	e = &logEntry{
		Time:              time.Unix(0, r.Time),
		QHost:             r.QHost,
		QType:             r.QType,
		QClass:            r.QClass,
		ReqECS:            r.ReqECS,
		ClientID:          r.ClientID,
		ClientProto:       ClientProto(r.ClientProto),
		Upstream:          r.Upstream,
		IP:                net.ParseIP(r.IP),
		Answer:            nilIfEmpty(r.Answer),
		OrigAnswer:        nilIfEmpty(r.OrigAnswer),
		Elapsed:           time.Duration(r.Elapsed),
		Cached:            r.Cached,
		AuthenticatedData: r.AuthenticatedData,
	}

	if len(r.Result) > 0 {
		// Reuse the decoder of the old JSON log, which also fixes up legacy
		// result fields.
		l.decodeLogEntry(ctx, e, `{"Result":`+string(r.Result)+`}`)
	}

	return e
}

// nilIfEmpty returns nil for an empty b, since Parquet reads absent byte
// arrays as empty ones.
func nilIfEmpty(b []byte) (res []byte) {
	if len(b) == 0 {
		return nil
	}

	return b
}

// writeParquet writes entries into a new file in the log directory.  entries
// must be sorted by time and not empty.
func (l *queryLog) writeParquet(ctx context.Context, entries []*logEntry) (err error) {
	rows := make([]parquetRow, 0, len(entries))
	for _, e := range entries {
		var r parquetRow
		r, err = newParquetRow(e)
		if err != nil {
			l.logger.ErrorContext(ctx, "skipping entry", slogutil.KeyError, err)

			continue
		}

		rows = append(rows, r)
	}

	newest := entries[len(entries)-1].Time.UnixNano()
	name := filepath.Join(l.logDir, strconv.FormatInt(newest, 10)+parquetExt)

	f, err := aghrenameio.NewPendingFile(name, aghos.DefaultPermFile)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer func() { err = aghrenameio.WithDeferredCleanup(err, f) }()

	w := parquet.NewGenericWriter[parquetRow](f, parquet.Compression(&zstd.Codec{}))
	_, err = w.Write(rows)
	if err != nil {
		return fmt.Errorf("writing rows: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("closing writer: %w", err)
	}

	l.logger.DebugContext(ctx, "flushed to file", "file", name, "count", len(rows))

	return nil
}

// logFile is a query log file with the time of its newest entry.
type logFile struct {
	path   string
	newest int64
}

// listFiles returns the log files sorted from the newest to the oldest.
func (l *queryLog) listFiles() (files []logFile, err error) {
	ents, err := os.ReadDir(l.logDir)
	if err != nil {
		return nil, fmt.Errorf("reading log dir: %w", err)
	}

	for _, ent := range ents {
		name, ok := strings.CutSuffix(ent.Name(), parquetExt)
		if !ok {
			continue
		}

		newest, parseErr := strconv.ParseInt(name, 10, 64)
		if parseErr != nil {
			continue
		}

		files = append(files, logFile{path: filepath.Join(l.logDir, ent.Name()), newest: newest})
	}

	slices.SortFunc(files, func(a, b logFile) (res int) { return cmp.Compare(b.newest, a.newest) })

	return files, nil
}

// deleteOld removes the files with all entries older than olderThan.
func (l *queryLog) deleteOld(ctx context.Context, olderThan time.Time) {
	files, err := l.listFiles()
	if err != nil {
		l.logger.ErrorContext(ctx, "listing log files", slogutil.KeyError, err)

		return
	}

	deleted := 0
	for _, f := range files {
		if f.newest >= olderThan.UnixNano() {
			continue
		}

		// On Windows, a file being searched can't be removed; the next check
		// retries it.
		err = os.Remove(f.path)
		if err != nil {
			l.logger.ErrorContext(ctx, "removing old log file", slogutil.KeyError, err)

			continue
		}

		deleted++
	}

	l.logger.DebugContext(ctx, "deleted old log files", "count", deleted)
}

// searchFiles looks up log records from all log files.  It optionally uses the
// client cache, if provided.  searchFiles does not scan more than
// maxFileScanEntries so callers may need to call it several times to get all
// the results.  oldest and total are the time of the oldest processed entry
// and the total number of processed entries, including discarded ones,
// correspondingly.
func (l *queryLog) searchFiles(
	ctx context.Context,
	params *searchParams,
	cache clientCache,
) (entries []*logEntry, oldest time.Time, total int) {
	files, err := l.listFiles()
	if err != nil {
		l.logger.ErrorContext(ctx, "searching files", slogutil.KeyError, err)

		return nil, time.Time{}, 0
	}

	olderThan := int64(0)
	if !params.olderThan.IsZero() {
		olderThan = params.olderThan.UnixNano()
	}

	totalLimit := params.offset + params.limit
	maxScan := params.maxFileScanEntries
	for i, f := range files {
		// Entries of a file are newer than the newest entry of the next one,
		// so skip the file if even those are too new.
		if olderThan != 0 && i+1 < len(files) && files[i+1].newest >= olderThan {
			continue
		}

		var rows []parquetRow
		rows, err = parquet.ReadFile[parquetRow](f.path)
		if err != nil {
			l.logger.ErrorContext(ctx, "reading log file", "file", f.path, slogutil.KeyError, err)

			continue
		}

		for j := len(rows) - 1; j >= 0; j-- {
			r := &rows[j]
			if olderThan != 0 && r.Time >= olderThan {
				continue
			}

			total++
			oldest = time.Unix(0, r.Time)

			e := l.matchRow(ctx, r, params, cache)
			if e != nil {
				entries = append(entries, e)
			}

			if len(entries) == totalLimit || (maxScan > 0 && total >= maxScan) {
				return entries, oldest, total
			}
		}
	}

	// All the files are read, so there is nothing older.
	return entries, time.Time{}, total
}

// matchRow returns the entry of r if it matches params, or nil otherwise.  It
// optionally uses the client cache, if provided.
func (l *queryLog) matchRow(
	ctx context.Context,
	r *parquetRow,
	params *searchParams,
	cache clientCache,
) (e *logEntry) {
	if l.isIgnored(r.QHost) {
		return nil
	}

	e = l.toEntry(ctx, r)

	var err error
	e.client, err = l.client(e.ClientID, e.IP.String(), cache)
	if err != nil {
		l.logger.ErrorContext(
			ctx,
			"enriching file record",
			"at", e.Time,
			"client_ip", e.IP,
			"client_id", e.ClientID,
			slogutil.KeyError, err,
		)

		// Go on and try to match anyway.
	}

	if e.client != nil && e.client.IgnoreQueryLog {
		return nil
	}

	if !params.match(e) {
		return nil
	}

	return e
}
