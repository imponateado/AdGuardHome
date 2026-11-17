// Package stats provides units for managing statistics of the filtering DNS
// server.
package stats

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/AdGuardHome/internal/configmgr"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/google/renameio/v2/maybe"
)

// validateIvl returns an error if ivl is less than an hour or more than a
// year.
func validateIvl(ivl time.Duration) (err error) {
	if ivl < time.Hour {
		return errors.Error("less than an hour")
	}

	if ivl > timeutil.Day*365 {
		return errors.Error("more than a year")
	}

	return nil
}

// QueryLogReader is the query log, from which the statistics are computed.
type QueryLogReader interface {
	// RangeEntries calls f for each logged query not older than since,
	// including the ones not yet written to disk.  ids are the identifiers of
	// the client, see [Interface.ShouldCount].
	RangeEntries(ctx context.Context, since time.Time, f func(t time.Time, ids []string, e *Entry))
}

// Config is the configuration structure for the statistics collecting.
//
// Do not alter any fields of this structure after using it.
type Config struct {
	// Logger is used for logging the operation of the statistics management.
	// It must not be nil.
	Logger *slog.Logger

	// UnitID is the function to generate the identifier for current unit.  If
	// nil, the default function is used, see newUnitID.
	UnitID UnitIDGenFunc

	// ConfigModifier is used to update the global configuration.  It must not
	// be nil.
	ConfigModifier agh.ConfigModifier

	// ShouldCountClient returns client's ignore setting.
	ShouldCountClient func([]string) bool

	// HTTPRegister is the function that registers handlers for the stats
	// endpoints.
	HTTPReg aghhttp.Registrar

	// Ignored contains the list of host names, which should not be counted,
	// and matches them.
	Ignored *aghnet.IgnoreEngine

	// QueryLog is the query log to compute the statistics from.  If nil, the
	// statistics are empty.
	QueryLog QueryLogReader

	// Filename is the file storing the time of the last statistics reset, since
	// the statistics are computed from the query log, which a reset keeps.
	Filename string

	// Limit is an upper limit for collecting statistics.
	Limit time.Duration

	// Enabled tells if the statistics are enabled.
	Enabled bool
}

// Interface is the statistics interface to be used by other packages.
type Interface interface {
	// Start begins the statistics collecting.
	Start()

	io.Closer

	// Update collects the incoming statistics data.
	Update(e *Entry)

	// GetTopClientIP returns at most limit IP addresses corresponding to the
	// clients with the most number of requests.
	TopClientsIP(limit uint) []netip.Addr

	// WriteDiskConfig puts the Interface's configuration to the dc.  dc must
	// not be nil.
	WriteDiskConfig(dc *configmgr.StatsConfig)

	// ShouldCount returns true if request for the host should be counted.
	ShouldCount(host string, qType, qClass uint16, ids []string) bool
}

// StatsCtx computes the statistics from the query log by hourly units.
type StatsCtx struct {
	// logger is used for logging the operation of the statistics management.
	// It must not be nil.
	logger *slog.Logger

	// queryLog is the source of the statistics, if any.
	queryLog QueryLogReader

	// unitIDGen is the function that generates an identifier for the current
	// unit.  It's here for only testing purposes.
	unitIDGen UnitIDGenFunc

	// httpReg registers HTTP handlers.  It must not be nil.
	httpReg aghhttp.Registrar

	// configModifier is used to update the global configuration.
	configModifier agh.ConfigModifier

	// confMu protects ignored, limit, and enabled.
	confMu *sync.RWMutex

	// ignored contains the list of host names, which should not be counted,
	// and matches them.
	ignored *aghnet.IgnoreEngine

	// shouldCountClient returns client's ignore setting.
	shouldCountClient func([]string) bool

	// filename is the file storing resetTime.
	filename string

	// resetTime is the Unix time in nanoseconds of the last reset.  Older
	// queries aren't counted.
	resetTime atomic.Int64

	// limit is an upper limit for collecting statistics.
	limit time.Duration

	// enabled tells if the statistics are enabled.
	enabled bool
}

// New creates s from conf and properly initializes it.  Don't use s before
// calling it's Start method.
func New(conf Config) (s Interface, err error) {
	defer withRecovered(&err)

	err = validateIvl(conf.Limit)
	if err != nil {
		return nil, fmt.Errorf("unsupported interval: %w", err)
	}

	if conf.ShouldCountClient == nil {
		return nil, errors.Error("should count client is unspecified")
	}

	ctx := &StatsCtx{
		logger:         conf.Logger,
		queryLog:       conf.QueryLog,
		httpReg:        conf.HTTPReg,
		configModifier: conf.ConfigModifier,
		filename:       conf.Filename,

		confMu:            &sync.RWMutex{},
		ignored:           conf.Ignored,
		shouldCountClient: conf.ShouldCountClient,
		limit:             conf.Limit,
		enabled:           conf.Enabled,
	}

	if ctx.unitIDGen = newUnitID; conf.UnitID != nil {
		ctx.unitIDGen = conf.UnitID
	}

	data, err := os.ReadFile(ctx.filename)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading reset time: %w", err)
	} else if err == nil {
		var reset int64
		reset, err = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing reset time: %w", err)
		}

		ctx.resetTime.Store(reset)
	}

	ctx.logger.Debug("initialized")

	return ctx, nil
}

// withRecovered turns the value recovered from panic if any into an error and
// combines it with the one pointed by orig.  orig must be non-nil.
func withRecovered(orig *error) {
	p := recover()
	if p == nil {
		return
	}

	var err error
	switch p := p.(type) {
	case error:
		err = fmt.Errorf("panic: %w", p)
	default:
		err = fmt.Errorf("panic: recovered value of type %[1]T: %[1]v", p)
	}

	*orig = errors.WithDeferred(*orig, err)
}

// type check
var _ Interface = (*StatsCtx)(nil)

// Start implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) Start() {
	s.initWeb()
}

// Close implements the [io.Closer] interface for *StatsCtx.  There is nothing
// to write, since the query log keeps the data.
func (s *StatsCtx) Close() (err error) {
	return nil
}

// Update implements the [Interface] interface for *StatsCtx.  It does nothing,
// since the statistics are computed from the query log.
func (s *StatsCtx) Update(_ *Entry) {}

// WriteDiskConfig implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) WriteDiskConfig(dc *configmgr.StatsConfig) {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	dc.Enabled = s.enabled
	dc.Ignored = s.ignored.Values()
	dc.IgnoredEnabled = s.ignored.IsEnabled()
	dc.Interval = timeutil.Duration(s.limit)
}

// TopClientsIP implements the [Interface] interface for *StatsCtx.
func (s *StatsCtx) TopClientsIP(maxCount uint) (ips []netip.Addr) {
	s.confMu.RLock()
	limit := uint32(s.limit.Hours())
	s.confMu.RUnlock()

	if limit == 0 {
		return nil
	}

	units, _ := s.loadUnits(limit)
	if units == nil {
		return nil
	}

	// Collect data for all the clients to sort and crop it afterwards.
	m := map[string]uint64{}
	for _, u := range units {
		for _, it := range u.Clients {
			m[it.Name] += it.Count
		}
	}

	a := convertMapToSlice(m, int(maxCount))
	ips = []netip.Addr{}
	for _, it := range a {
		ip, err := netip.ParseAddr(it.Name)
		if err == nil {
			ips = append(ips, ip)
		}
	}

	return ips
}

// clear makes the statistics ignore the queries logged so far.  The query log
// itself is kept.
func (s *StatsCtx) clear() (err error) {
	now := time.Now().UnixNano()
	s.resetTime.Store(now)

	err = maybe.WriteFile(s.filename, []byte(strconv.FormatInt(now, 10)), aghos.DefaultPermFile)
	if err != nil {
		return fmt.Errorf("clearing: writing reset time: %w", err)
	}

	s.logger.Debug("cleared")

	return nil
}

// loadUnits returns the hourly units of the last limit hours computed from the
// query log and the current unit ID.  The units are empty if the statistics
// are disabled.
func (s *StatsCtx) loadUnits(limit uint32) (units []*unitDB, curID uint32) {
	s.confMu.RLock()
	enabled, ignored, shouldCount := s.enabled, s.ignored, s.shouldCountClient
	s.confMu.RUnlock()

	curID = s.unitIDGen()
	firstID := curID - limit + 1

	hours := make([]*unit, limit)
	for i := range hours {
		hours[i] = newUnit(firstID + uint32(i))
	}

	if enabled && s.queryLog != nil {
		since := time.Unix((int64(curID)-int64(limit)+1)*secsInHour, 0)
		if reset := time.Unix(0, s.resetTime.Load()); reset.After(since) {
			since = reset
		}

		s.queryLog.RangeEntries(context.TODO(), since, newUnitAdder(hours, firstID, ignored, shouldCount))
	}

	units = make([]*unitDB, limit)
	for i, u := range hours {
		units[i] = u.serialize()
	}

	return units, curID
}

// newUnitAdder returns a function that adds the query log entries that are
// counted to the hourly unit of hours they belong to.  The first of hours has
// the ID firstID.
func newUnitAdder(
	hours []*unit,
	firstID uint32,
	ignored *aghnet.IgnoreEngine,
	shouldCount func(ids []string) (ok bool),
) (add func(t time.Time, ids []string, e *Entry)) {
	// Cache the client settings, since there are few clients and many queries.
	counted := map[string]bool{}

	return func(t time.Time, ids []string, e *Entry) {
		// Unit IDs may wrap around in tests, so compare the offset.
		off := uint32(t.Unix()/secsInHour) - firstID
		if off >= uint32(len(hours)) || ignored.Has(e.Domain) {
			return
		}

		key := strings.Join(ids, " ")
		ok, found := counted[key]
		if !found {
			ok = shouldCount(ids)
			counted[key] = ok
		}

		if ok {
			hours[off].add(e)
		}
	}
}

// ShouldCount returns true if request for the host should be counted.
func (s *StatsCtx) ShouldCount(host string, _, _ uint16, ids []string) bool {
	s.confMu.RLock()
	defer s.confMu.RUnlock()

	if !s.shouldCountClient(ids) {
		return false
	}

	return !s.isIgnored(host)
}

// isIgnored returns true if the host is in the ignored domains list.  It
// assumes that s.confMu is locked for reading.
func (s *StatsCtx) isIgnored(host string) bool {
	return s.ignored.Has(host)
}
