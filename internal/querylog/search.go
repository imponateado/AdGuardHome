package querylog

import (
	"context"
	"slices"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// client finds the client info, if any, by its ClientID and IP address,
// optionally checking the provided cache.  It will use the IP address
// regardless of if the IP anonymization is enabled now, because the
// anonymization could have been disabled in the past, and client will try to
// find those records as well.
func (l *queryLog) client(clientID, ip string, cache clientCache) (c *Client, err error) {
	cck := clientCacheKey{clientID: clientID, ip: ip}

	var ok bool
	if c, ok = cache[cck]; ok {
		return c, nil
	}

	var ids []string
	if clientID != "" {
		ids = append(ids, clientID)
	}

	if ip != "" {
		ids = append(ids, ip)
	}

	c, err = l.findClient(ids)
	if err != nil {
		return nil, err
	}

	// Cache all results, including negative ones, to prevent excessive and
	// expensive client searching.
	cache[cck] = c

	return c, nil
}

// searchMemory looks up log records which are currently in the in-memory
// buffer.  It optionally uses the client cache, if provided.  It also returns
// the total amount of records in the buffer at the moment of searching.
// l.confMu is expected to be locked.
func (l *queryLog) searchMemory(
	ctx context.Context,
	params *searchParams,
	cache clientCache,
) (entries []*logEntry, total int) {
	// Check memory size, as the buffer can contain a single log record.  See
	// [newQueryLog].
	if l.conf.MemSize == 0 {
		return nil, 0
	}

	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	l.buffer.ReverseRange(func(entry *logEntry) (cont bool) {
		// A shallow clone is enough, since the only thing that this loop
		// modifies is the client field.
		e := entry.shallowClone()

		var err error
		e.client, err = l.client(e.ClientID, e.IP.String(), cache)
		if err != nil {
			l.logger.ErrorContext(
				ctx,
				"enriching memory record",
				"at", e.Time,
				"client_ip", e.IP,
				"client_id", e.ClientID,
				slogutil.KeyError, err,
			)

			// Go on and try to match anyway.
		}

		if params.match(e) {
			entries = append(entries, e)
		}

		return true
	})

	return entries, int(l.buffer.Len())
}

// search searches log entries in memory buffer and log file using specified
// parameters and returns the list of entries found and the time of the oldest
// entry.  l.confMu is expected to be locked.
func (l *queryLog) search(
	ctx context.Context,
	params *searchParams,
) (entries []*logEntry, oldest time.Time) {
	start := time.Now()

	if params.limit == 0 {
		return []*logEntry{}, time.Time{}
	}

	cache := clientCache{}

	memoryEntries, bufLen := l.searchMemory(ctx, params, cache)
	l.logger.DebugContext(ctx, "got entries from memory", "count", len(memoryEntries))

	fileEntries, oldest, total := l.searchFiles(ctx, params, cache)
	l.logger.DebugContext(ctx, "got entries from files", "count", len(fileEntries))

	total += bufLen

	totalLimit := params.offset + params.limit

	// now let's get a unified collection
	entries = append(memoryEntries, fileEntries...)
	if len(entries) > totalLimit {
		// remove extra records
		entries = entries[:totalLimit]
	}

	entries, oldest = l.finalizeSearchResults(entries, params, oldest)

	l.logger.DebugContext(
		ctx,
		"prepared data",
		"count", len(entries),
		"total", total,
		"older_than", params.olderThan,
		"elapsed", time.Since(start),
	)

	return entries, oldest
}

// finalizeSearchResults sorts entries and applies offset trimming, and updates
// the oldest timestamp.  params must not be nil.
func (l *queryLog) finalizeSearchResults(
	entries []*logEntry,
	params *searchParams,
	oldest time.Time,
) (res []*logEntry, t time.Time) {
	// Resort entries on start time to partially mitigate query log looking
	// weird on the frontend.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/2293.
	slices.SortStableFunc(entries, func(a, b *logEntry) (res int) {
		return -a.Time.Compare(b.Time)
	})

	if params.offset > 0 {
		if len(entries) > params.offset {
			entries = entries[params.offset:]
		} else {
			return nil, time.Time{}
		}
	}

	if len(entries) > 0 {
		// Update oldest after merging in the memory buffer.
		oldest = entries[len(entries)-1].Time
	}

	return entries, oldest
}
