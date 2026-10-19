package api

import (
	"fmt"
	"testing"

	"github.com/feirai/averin/server/internal/store"
)

// ordinalSpy records which record reads segmentRecords makes. RecordsPage pages newest-first, so a month read
// through it walks every newer record before reaching the month: its cost grows with the history after the month.
type ordinalSpy struct {
	store.Store
	pageCalls  int
	afterCalls [][2]int64
}

func (s *ordinalSpy) RecordsPage(projectID string, limit, offset int) ([]store.Record, error) {
	s.pageCalls++
	return s.Store.RecordsPage(projectID, limit, offset)
}

func (s *ordinalSpy) RecordsAfter(projectID string, after int64, limit int) ([]store.Record, error) {
	s.afterCalls = append(s.afterCalls, [2]int64{after, int64(limit)})
	return s.Store.RecordsAfter(projectID, after, limit)
}

// TestSegmentRecordsReadsTheMonthByOrdinal: the month's range is one RecordsAfter(From, To-From) read, whatever
// the history after the month. The read's start and size are the same for the oldest month at 1, 3 and 12
// months of history, and the records returned are exactly ordinals (From, To], oldest first.
func TestSegmentRecordsReadsTheMonthByOrdinal(t *testing.T) {
	const perMonth = 6
	var first [2]int64
	for i, months := range []int{1, 3, 12} {
		m := store.NewMem()
		for g := 1; g <= months*perMonth; g++ {
			if _, _, err := m.PutRecord("p", fmt.Sprintf("k%d", g), store.Record{ContentHash: fmt.Sprintf("sha256:%d", g)}); err != nil {
				t.Fatal(err)
			}
		}
		spy := &ordinalSpy{Store: m}
		recs, err := segmentRecords(spy, "p", segmentPlan{Month: "2026-01", From: 0, To: perMonth})
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != perMonth {
			t.Fatalf("%d months: got %d records, want %d", months, len(recs), perMonth)
		}
		for j, r := range recs {
			if want := fmt.Sprintf("sha256:%d", j+1); r.ContentHash != want {
				t.Fatalf("%d months: record %d = %s, want %s", months, j, r.ContentHash, want)
			}
		}
		if spy.pageCalls != 0 || len(spy.afterCalls) != 1 {
			t.Fatalf("%d months: RecordsPage calls %d, RecordsAfter calls %v; want 0 and one", months, spy.pageCalls, spy.afterCalls)
		}
		if i == 0 {
			first = spy.afterCalls[0]
		} else if spy.afterCalls[0] != first {
			t.Fatalf("%d months: read %v, 1 month read %v", months, spy.afterCalls[0], first)
		}
	}
}
