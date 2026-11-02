package querylog

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestParquetLog returns a query log writing to a temporary directory.
func newTestParquetLog(tb testing.TB) (l *queryLog) {
	tb.Helper()

	l, err := newQueryLog(Config{
		Logger:      testLogger,
		Enabled:     true,
		FileEnabled: true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     tb.TempDir(),
	})
	require.NoError(tb, err)

	return l
}

func TestQueryLog_parquetRoundTrip(t *testing.T) {
	ans := (&dns.Msg{MsgHdr: dns.MsgHdr{Id: 1, Response: true}}).SetQuestion("example.org.", dns.TypeA)
	ansData, err := ans.Pack()
	require.NoError(t, err)

	want := &logEntry{
		Time:        time.Unix(1_700_000_000, 123).UTC(),
		QHost:       "example.org",
		QType:       "A",
		QClass:      "IN",
		ReqECS:      "1.2.3.0/24",
		ClientID:    "cli42",
		ClientProto: ClientProtoDoH,
		Upstream:    "https://some.upstream",
		Answer:      ansData,
		OrigAnswer:  ansData,
		IP:          net.IPv4(127, 0, 0, 1),
		Result: filtering.Result{
			DNSRewriteResult: &filtering.DNSRewriteResult{
				RCode: dns.RcodeSuccess,
				Response: filtering.DNSRewriteResultResponse{
					dns.TypeA: []rules.RRValue{net.IPv4(127, 0, 0, 2)},
				},
			},
			Rules: []*filtering.ResultRule{{
				FilterListID: 42,
				Text:         "||example.org^",
				IP:           netip.AddrFrom4([4]byte{127, 0, 0, 2}),
			}},
			Reason:     filtering.FilteredBlockList,
			IsFiltered: true,
		},
		Elapsed:           837429,
		Cached:            true,
		AuthenticatedData: true,
	}

	l := newTestParquetLog(t)
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, l.writeParquet(ctx, []*logEntry{want}))

	got, _, _ := l.searchFiles(ctx, newSearchParams(), clientCache{})
	require.Len(t, got, 1)

	got[0].Time = got[0].Time.UTC()
	assert.Equal(t, want, got[0])
}

func TestQueryLog_parquetFiles(t *testing.T) {
	l := newTestParquetLog(t)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	now := time.Now()
	times := []time.Time{now.Add(-3 * time.Hour), now.Add(-2 * time.Hour), now.Add(-time.Hour)}
	for i, ts := range times {
		e := &logEntry{Time: ts, QHost: "example.org", IP: net.IPv4(127, 0, 0, byte(i))}
		if i == 0 {
			e.Result = filtering.Result{Reason: filtering.FilteredBlockList, IsFiltered: true}
		}

		require.NoError(t, l.writeParquet(ctx, []*logEntry{e}))
	}

	t.Run("older_than", func(t *testing.T) {
		params := newSearchParams()
		params.olderThan = times[2]

		got, oldest, _ := l.searchFiles(ctx, params, clientCache{})
		require.Len(t, got, 2)

		assert.True(t, got[0].Time.Equal(times[1]))
		assert.True(t, got[1].Time.Equal(times[0]))
		assert.True(t, oldest.IsZero())
	})

	t.Run("processed", func(t *testing.T) {
		params := newSearchParams()
		params.searchCriteria = []searchCriterion{{
			criterionType: ctFilteringStatus,
			value:         filteringStatusProcessed,
		}}

		got, _, _ := l.searchFiles(ctx, params, clientCache{})
		assert.Len(t, got, 2)
	})

	t.Run("retention", func(t *testing.T) {
		l.deleteOld(ctx, times[1].Add(time.Nanosecond))

		files, err := l.listFiles()
		require.NoError(t, err)
		require.Len(t, files, 1)

		assert.Equal(t, times[2].UnixNano(), files[0].newest)
	})

	t.Run("clear", func(t *testing.T) {
		l.clear(ctx)

		files, err := l.listFiles()
		require.NoError(t, err)

		assert.Empty(t, files)
		assert.DirExists(t, l.logDir)
	})
}
