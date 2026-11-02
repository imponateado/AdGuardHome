package querylog

import (
	"context"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// flushLogBuffer flushes the current buffer to a new file and resets the
// current buffer.
func (l *queryLog) flushLogBuffer(ctx context.Context) (err error) {
	defer func() { err = errors.Annotate(err, "flushing log buffer: %w") }()

	l.fileFlushLock.Lock()
	defer l.fileFlushLock.Unlock()

	entries := l.takeEntries()
	if len(entries) == 0 {
		return nil
	}

	// Write outside of bufferLock so that adding entries isn't blocked.
	return l.writeParquet(ctx, entries)
}

// takeEntries returns the entries from the buffer, oldest first, and clears
// it.
func (l *queryLog) takeEntries() (entries []*logEntry) {
	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	entries = make([]*logEntry, 0, l.buffer.Len())
	l.buffer.Range(func(e *logEntry) (cont bool) {
		entries = append(entries, e)

		return true
	})

	l.buffer.Clear()
	l.flushPending = false

	return entries
}

func (l *queryLog) periodicRotate(ctx context.Context) {
	defer slogutil.RecoverAndLog(ctx, l.logger)

	l.checkAndRotate(ctx)

	// rotationCheckIvl is the period of time between checking the need for
	// rotating log files.  It's smaller of any available rotation interval to
	// increase time accuracy.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/3823.
	const rotationCheckIvl = 1 * time.Hour

	rotations := time.NewTicker(rotationCheckIvl)
	defer rotations.Stop()

	for range rotations.C {
		l.checkAndRotate(ctx)
	}
}

// checkAndRotate removes the log files with entries older than the rotation
// interval.
func (l *queryLog) checkAndRotate(ctx context.Context) {
	l.confMu.RLock()
	rotationIvl := l.conf.RotationIvl
	l.confMu.RUnlock()

	l.deleteOld(ctx, time.Now().Add(-rotationIvl))
}
