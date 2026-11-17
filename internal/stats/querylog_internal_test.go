package stats

import (
	"context"
	"sync"
	"time"
)

// TestQueryLog is a [QueryLogReader] for tests, which keeps the entries in
// memory.
type TestQueryLog struct {
	entries []testLogEntry
	mu      sync.Mutex
}

// testLogEntry is an entry of [TestQueryLog].
type testLogEntry struct {
	t time.Time
	e *Entry
}

// type check
var _ QueryLogReader = (*TestQueryLog)(nil)

// Add logs e at the start of the hour of the unit with id.
func (l *TestQueryLog) Add(id uint32, e *Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, testLogEntry{t: time.Unix(int64(id)*secsInHour, 0), e: e})
}

// RangeEntries implements the [QueryLogReader] interface for *TestQueryLog.
func (l *TestQueryLog) RangeEntries(
	_ context.Context,
	since time.Time,
	f func(t time.Time, ids []string, e *Entry),
) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, le := range l.entries {
		if !le.t.Before(since) {
			f(le.t, []string{le.e.Client}, le.e)
		}
	}
}
