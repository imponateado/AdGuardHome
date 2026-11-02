package stats

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTopUpstreamsPairs(t *testing.T) {
	testCases := []struct {
		db            *unitDB
		name          string
		wantResponses []topAddrs
		wantAvgTime   []topAddrsFloat
	}{{
		name: "empty",
		db: &unitDB{
			NResult:            []uint64{0, 0, 0, 0, 0, 0},
			Domains:            []countPair{},
			BlockedDomains:     []countPair{},
			Clients:            []countPair{},
			NTotal:             0,
			TimeAvg:            0,
			UpstreamsResponses: []countPair{},
			UpstreamsTimeSum:   []countPair{},
		},
		wantResponses: []topAddrs{},
		wantAvgTime:   []topAddrsFloat{},
	}, {
		name: "basic",
		db: &unitDB{
			NResult:        []uint64{0, 0, 0, 0, 0, 0},
			Domains:        []countPair{},
			BlockedDomains: []countPair{},
			Clients:        []countPair{},
			NTotal:         0,
			TimeAvg:        0,
			UpstreamsResponses: []countPair{{
				"1.2.3.4", 2,
			}},
			UpstreamsTimeSum: []countPair{{
				"1.2.3.4", 246912,
			}},
		},
		wantResponses: []topAddrs{{
			"1.2.3.4": 2,
		}},
		wantAvgTime: []topAddrsFloat{{
			"1.2.3.4": 0.123456,
		}},
	}, {
		name: "sorted",
		db: &unitDB{
			NResult:        []uint64{0, 0, 0, 0, 0, 0},
			Domains:        []countPair{},
			BlockedDomains: []countPair{},
			Clients:        []countPair{},
			NTotal:         0,
			TimeAvg:        0,
			UpstreamsResponses: []countPair{
				{"3.3.3.3", 8},
				{"2.2.2.2", 4},
				{"4.4.4.4", 16},
				{"1.1.1.1", 2},
			},
			UpstreamsTimeSum: []countPair{
				{"3.3.3.3", 800_000_000},
				{"2.2.2.2", 40_000_000},
				{"4.4.4.4", 16_000_000_000},
				{"1.1.1.1", 2_000_000},
			},
		},
		wantResponses: []topAddrs{
			{"4.4.4.4": 16},
			{"3.3.3.3": 8},
			{"2.2.2.2": 4},
			{"1.1.1.1": 2},
		},
		wantAvgTime: []topAddrsFloat{
			{"4.4.4.4": 1000},
			{"3.3.3.3": 100},
			{"2.2.2.2": 10},
			{"1.1.1.1": 1},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotResponses, gotAvgTime := topUpstreamsPairs([]*unitDB{tc.db})
			assert.Equal(t, tc.wantResponses, gotResponses)
			assert.Equal(t, tc.wantAvgTime, gotAvgTime)
		})
	}
}
