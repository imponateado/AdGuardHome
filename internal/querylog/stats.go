package querylog

import (
	"context"
	"encoding/json"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/stats"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/parquet-go/parquet-go"
)

// statsRow is the part of a [parquetRow] that statistics need, so that the
// other columns aren't decoded.
type statsRow struct {
	QHost    string `parquet:"qh"`
	ClientID string `parquet:"cid"`
	IP       string `parquet:"ip"`
	Upstream string `parquet:"up"`
	Result   []byte `parquet:"res"`
	Time     int64  `parquet:"t"`
	Elapsed  int64  `parquet:"el"`
	Cached   bool   `parquet:"cached"`
}

// type check
var _ stats.QueryLogReader = (*queryLog)(nil)

// RangeEntries implements the [stats.QueryLogReader] interface for *queryLog.
func (l *queryLog) RangeEntries(
	ctx context.Context,
	since time.Time,
	f func(t time.Time, ids []string, e *stats.Entry),
) {
	// Take the file list and the buffer together, so that a concurrent flush
	// can neither hide nor duplicate entries.
	files, buffered := l.snapshot(ctx)

	sinceNano := since.UnixNano()
	n := slices.IndexFunc(files, func(file logFile) (ok bool) { return file.newest < sinceNano })
	if n >= 0 {
		files = files[:n]
	}

	// Decoding is the slow part, so decode a batch of files in parallel while
	// keeping the memory bounded, and call f from this goroutine only.
	batchLen := runtime.GOMAXPROCS(0)
	for len(files) > 0 {
		batch := files[:min(batchLen, len(files))]
		files = files[len(batch):]

		for _, rows := range l.decodeStatsFiles(ctx, batch) {
			rangeStatsRows(rows, sinceNano, f)
		}
	}

	rangeBuffered(buffered, since, f)
}

// decodeStatsFiles decodes the statistics rows of files in parallel.  Files
// that can't be read have no rows.
func (l *queryLog) decodeStatsFiles(ctx context.Context, files []logFile) (decoded [][]statsRow) {
	decoded = make([][]statsRow, len(files))
	wg := &sync.WaitGroup{}
	for i, file := range files {
		wg.Go(func() {
			var err error
			decoded[i], err = parquet.ReadFile[statsRow](file.path)
			if err != nil {
				l.logger.ErrorContext(ctx, "reading log file", "file", file.path, slogutil.KeyError, err)
			}
		})
	}

	wg.Wait()

	return decoded
}

// rangeBuffered calls f for each of the buffered entries not older than since.
func rangeBuffered(
	buffered []*logEntry,
	since time.Time,
	f func(t time.Time, ids []string, e *stats.Entry),
) {
	for _, le := range buffered {
		if le.Time.Before(since) {
			continue
		}

		ip := ""
		if le.IP != nil {
			ip = le.IP.String()
		}

		e, ids := newStatsEntry(
			le.QHost,
			le.ClientID,
			ip,
			le.Upstream,
			int64(le.Elapsed),
			le.Cached,
			le.Result.Reason,
		)
		f(le.Time, ids, e)
	}
}

// rangeStatsRows calls f for each of rows not older than sinceNano.
func rangeStatsRows(rows []statsRow, sinceNano int64, f func(t time.Time, ids []string, e *stats.Entry)) {
	for i := range rows {
		r := &rows[i]
		if r.Time < sinceNano {
			continue
		}

		var res struct{ Reason filtering.Reason }
		if len(r.Result) > 0 {
			_ = json.Unmarshal(r.Result, &res)
		}

		e, ids := newStatsEntry(r.QHost, r.ClientID, r.IP, r.Upstream, r.Elapsed, r.Cached, res.Reason)
		f(time.Unix(0, r.Time), ids, e)
	}
}

// snapshot returns the log files and a copy of the buffered entries.
func (l *queryLog) snapshot(ctx context.Context) (files []logFile, buffered []*logEntry) {
	l.fileFlushLock.Lock()
	defer l.fileFlushLock.Unlock()

	files, err := l.listFiles()
	if err != nil {
		l.logger.ErrorContext(ctx, "listing log files", slogutil.KeyError, err)
	}

	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	l.buffer.Range(func(e *logEntry) (cont bool) {
		buffered = append(buffered, e)

		return true
	})

	return files, buffered
}

// newStatsEntry returns the statistics entry for a logged query and the client
// identifiers to check whether it's counted.  It mirrors the conversion in
// dnsforward's updateStats, except that the log only keeps the main upstream
// and the total processing time.
func newStatsEntry(
	host string,
	clientID string,
	ip string,
	upstream string,
	elapsed int64,
	cached bool,
	reason filtering.Reason,
) (e *stats.Entry, ids []string) {
	e = &stats.Entry{
		Domain:         host,
		Client:         ip,
		Result:         stats.RNotFiltered,
		ProcessingTime: time.Duration(elapsed),
	}

	ids = []string{ip}
	if clientID != "" {
		e.Client = clientID
		ids = []string{clientID, ip}
	}

	if upstream != "" {
		e.UpstreamStats = []*proxy.UpstreamStatistics{{
			Address:       upstream,
			QueryDuration: time.Duration(elapsed),
			IsCached:      cached,
		}}
	}

	switch reason {
	case filtering.FilteredSafeBrowsing:
		e.Result = stats.RSafeBrowsing
	case filtering.FilteredParental:
		e.Result = stats.RParental
	case filtering.FilteredSafeSearch:
		e.Result = stats.RSafeSearch
	case
		filtering.FilteredBlockList,
		filtering.FilteredInvalid,
		filtering.FilteredBlockedService:
		e.Result = stats.RFiltered
	}

	return e, ids
}
