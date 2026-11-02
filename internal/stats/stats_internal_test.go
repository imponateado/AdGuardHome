package stats

import (
	"cmp"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// newTestStatsCtx returns StatsCtx initialised with given values.  All empty
// values from c will be replaced with defaults.
func newTestStatsCtx(tb testing.TB, c Config) (s *StatsCtx) {
	c.Logger = cmp.Or(c.Logger, testLogger)
	c.ConfigModifier = cmp.Or[agh.ConfigModifier](c.ConfigModifier, agh.EmptyConfigModifier{})
	c.HTTPReg = cmp.Or[aghhttp.Registrar](c.HTTPReg, aghhttp.EmptyRegistrar{})
	c.Filename = cmp.Or(c.Filename, filepath.Join(tb.TempDir(), "stats_reset"))
	c.Limit = cmp.Or(c.Limit, timeutil.Day)
	if c.ShouldCountClient == nil {
		c.ShouldCountClient = func([]string) bool { return true }
	}

	if c.UnitID == nil {
		c.UnitID = newUnitID
	}

	var err error
	var i Interface
	i, err = New(c)
	require.NoError(tb, err)

	s, ok := i.(*StatsCtx)
	require.True(tb, ok)

	return s
}

func TestStats_races(t *testing.T) {
	var currentRound atomic.Uint32
	ql := &TestQueryLog{}
	s := newTestStatsCtx(t, Config{
		UnitID:   currentRound.Load,
		Enabled:  true,
		QueryLog: ql,
	})

	s.Start()
	startTime := time.Now()
	testutil.CleanupAndRequireSuccess(t, s.Close)

	writeFunc := func(start, fin *sync.WaitGroup, waitCh <-chan unit, i int) {
		e := &Entry{
			Domain:         fmt.Sprintf("example-%d.org", i),
			Client:         fmt.Sprintf("client_%d", i),
			Result:         Result(i)%(resultLast-1) + 1,
			ProcessingTime: time.Since(startTime),
		}

		start.Done()
		defer fin.Done()

		<-waitCh

		ql.Add(currentRound.Load(), e)
	}
	readFunc := func(start, fin *sync.WaitGroup, waitCh <-chan unit) {
		start.Done()
		defer fin.Done()

		<-waitCh

		_, _ = s.getData(24)
	}

	const (
		roundsNum uint32 = 3

		writersNum = 10
		readersNum = 5
	)

	for round := range roundsNum {
		currentRound.Store(round)

		startWG, finWG := &sync.WaitGroup{}, &sync.WaitGroup{}
		waitCh := make(chan unit)

		for i := range writersNum {
			startWG.Add(1)
			finWG.Add(1)
			go writeFunc(startWG, finWG, waitCh, i)
		}

		for range readersNum {
			startWG.Add(1)
			finWG.Add(1)
			go readFunc(startWG, finWG, waitCh)
		}

		startWG.Wait()
		close(waitCh)
		finWG.Wait()
	}
}

func TestStatsCtx_FillCollectedStats_daily(t *testing.T) {
	const (
		daysCount = 10

		timeUnits = "days"
	)

	s := newTestStatsCtx(t, Config{
		Limit:   time.Hour,
		Enabled: true,
	})

	testutil.CleanupAndRequireSuccess(t, s.Close)

	sum := make([][]uint64, resultLast)
	sum[RFiltered] = make([]uint64, daysCount)
	sum[RSafeBrowsing] = make([]uint64, daysCount)
	sum[RParental] = make([]uint64, daysCount)

	total := make([]uint64, daysCount)

	dailyData := []*unitDB{}

	for i := range daysCount * 24 {
		n := uint64(i)
		nResult := make([]uint64, resultLast)
		nResult[RFiltered] = n
		nResult[RSafeBrowsing] = n
		nResult[RParental] = n

		day := i / 24
		sum[RFiltered][day] += n
		sum[RSafeBrowsing][day] += n
		sum[RParental][day] += n

		t := n * 3

		total[day] += t

		dailyData = append(dailyData, &unitDB{
			NTotal:  t,
			NResult: nResult,
		})
	}

	data := &StatsResp{}

	// In this way we will not skip first hours.
	curID := uint32(daysCount * 24)

	s.fillCollectedStats(data, dailyData, curID)

	assert.Equal(t, timeUnits, data.TimeUnits)
	assert.Equal(t, sum[RFiltered], data.BlockedFiltering)
	assert.Equal(t, sum[RSafeBrowsing], data.ReplacedSafebrowsing)
	assert.Equal(t, sum[RParental], data.ReplacedParental)
	assert.Equal(t, total, data.DNSQueries)
}

func TestStatsCtx_DataFromUnits_month(t *testing.T) {
	const hoursInMonth = 720

	s := newTestStatsCtx(t, Config{
		Limit:   time.Hour,
		Enabled: true,
	})

	testutil.CleanupAndRequireSuccess(t, s.Close)

	units, curID := s.loadUnits(hoursInMonth)
	require.Len(t, units, hoursInMonth)

	var h uint32
	for h = 1; h <= hoursInMonth; h++ {
		data := s.dataFromUnits(units[:h], curID)
		require.NotNil(t, data)
	}
}

func TestStatsCtx_reset(t *testing.T) {
	const curID uint32 = 1_000

	ql := &TestQueryLog{}
	ql.Add(curID, &Entry{Domain: "example.org", Client: "client", Result: RNotFiltered})

	conf := Config{
		Filename: filepath.Join(t.TempDir(), "stats_reset"),
		UnitID:   func() (id uint32) { return curID },
		Enabled:  true,
		QueryLog: ql,
	}

	s := newTestStatsCtx(t, conf)
	units, _ := s.loadUnits(24)
	require.Equal(t, uint64(1), units[23].NTotal)

	require.NoError(t, s.clear())

	// The reset survives a restart, and the log keeps the query.
	s = newTestStatsCtx(t, conf)
	units, _ = s.loadUnits(24)

	assert.Zero(t, units[23].NTotal)
	assert.Len(t, ql.entries, 1)
}
