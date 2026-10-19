package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/feirai/averin/server/internal/store"
)

type irCheckpoint struct {
	Seq         int64  `json:"seq"`
	Hash        string `json:"hash"`
	RecordCount int64  `json:"record_count"`
}

type irResp struct {
	Records []json.RawMessage `json:"records"`
	Total   int64             `json:"total"`
	After   int64             `json:"after"`
	Next    int64             `json:"next_after"`
	More    bool              `json:"more"`
	Latest  *irCheckpoint     `json:"latest_checkpoint"`
	AtSeq   *irCheckpoint     `json:"at_seq"`
}

func irGet(t *testing.T, h http.Handler, q url.Values) (int, irResp) {
	t.Helper()
	code, body := do(t, h, "GET", "/v2/records?"+q.Encode(), "")
	var r irResp
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatalf("decode: %v: %s", err, body)
		}
	}
	return code, r
}

func irQuery(after int64, limit int, extra ...string) url.Values {
	q := url.Values{"project": {"p"}, "after": {fmt.Sprint(after)}, "order": {"asc"}, "limit": {fmt.Sprint(limit)}}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	return q
}

func cpBody(t *testing.T, cp store.Checkpoint) int64 {
	var b struct {
		Count int64 `json:"record_count"`
	}
	if err := json.Unmarshal([]byte(cp.JSON), &b); err != nil {
		t.Fatal(err)
	}
	return b.Count
}

// TestIncrementalReadSnapshotAgreesWithStore: the page is the AllRecords slice after the ordinal, oldest first, and
// the snapshot fields (total, latest checkpoint, checkpoint at_seq) agree with RecordCount and Checkpoints.
func TestIncrementalReadSnapshotAgreesWithStore(t *testing.T) {
	st := store.NewMem()
	s := cutServer(t, st, "")
	h := newCutHistory(t, st, "p", 3)
	for i := 0; i < 40; i++ {
		h.plain()
		if (i+1)%15 == 0 {
			if _, err := cutOnce(t, s, st, "p"); err != nil {
				t.Fatal(err)
			}
		}
	}
	all, _ := st.AllRecords("p")
	cps, _ := st.Checkpoints("p")
	n, _ := st.RecordCount("p")
	if len(cps) != 2 || len(all) != 40 {
		t.Fatalf("setup: %d checkpoints %d records", len(cps), len(all))
	}
	r := s.Routes()

	code, got := irGet(t, r, irQuery(10, 1000, "at_seq", "1"))
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	if got.Total != int64(n) || got.After != 10 || got.Next != 40 || got.More || len(got.Records) != 30 {
		t.Fatalf("page: total=%d after=%d next=%d more=%v len=%d", got.Total, got.After, got.Next, got.More, len(got.Records))
	}
	for i, raw := range got.Records {
		if string(raw) != all[10+i].JSON {
			t.Fatalf("record %d is not ordinal %d of the store", i, 11+i)
		}
	}
	last := cps[len(cps)-1]
	if got.Latest == nil || got.Latest.Seq != last.Seq || got.Latest.Hash != last.CheckpointHash || got.Latest.RecordCount != cpBody(t, last) {
		t.Fatalf("latest checkpoint %+v vs store %+v", got.Latest, last)
	}
	if got.AtSeq == nil || got.AtSeq.Seq != 1 || got.AtSeq.Hash != cps[1].CheckpointHash || got.AtSeq.RecordCount != cpBody(t, cps[1]) {
		t.Fatalf("at_seq checkpoint %+v vs store %+v", got.AtSeq, cps[1])
	}
	_, got = irGet(t, r, irQuery(0, 5, "at_seq", "0"))
	if got.AtSeq == nil || got.AtSeq.Hash != cps[0].CheckpointHash {
		t.Fatalf("at_seq 0: %+v", got.AtSeq)
	}
	// A seq the project does not have is absent, never an error and never another checkpoint.
	_, got = irGet(t, r, irQuery(0, 5, "at_seq", "9"))
	if got.AtSeq != nil {
		t.Fatalf("at_seq 9 should be absent, got %+v", got.AtSeq)
	}
	// Without at_seq there is no at_seq block.
	_, got = irGet(t, r, irQuery(0, 5))
	if got.AtSeq != nil || got.Latest == nil {
		t.Fatalf("no at_seq requested: %+v / %+v", got.AtSeq, got.Latest)
	}
}

// TestIncrementalReadPagesConcatenate: following next_after page by page yields every record exactly once, in order,
// past the end is an empty page that still carries the snapshot, and an empty project has no latest checkpoint.
func TestIncrementalReadPagesConcatenate(t *testing.T) {
	st := store.NewMem()
	s := cutServer(t, st, "")
	r := s.Routes()
	if code, got := irGet(t, r, irQuery(0, 10)); code != http.StatusOK || got.Total != 0 || got.Latest != nil || len(got.Records) != 0 || got.More {
		t.Fatalf("empty project: %d %+v", code, got)
	}
	h := newCutHistory(t, st, "p", 5)
	for i := 0; i < 23; i++ {
		h.plain()
	}
	all, _ := st.AllRecords("p")
	var seen []string
	after := int64(0)
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("did not terminate")
		}
		_, got := irGet(t, r, irQuery(after, 7))
		for _, raw := range got.Records {
			seen = append(seen, string(raw))
		}
		if got.Next != after+int64(len(got.Records)) {
			t.Fatalf("next_after %d, want %d", got.Next, after+int64(len(got.Records)))
		}
		if !got.More {
			after = got.Next
			break
		}
		after = got.Next
	}
	if len(seen) != len(all) {
		t.Fatalf("saw %d of %d", len(seen), len(all))
	}
	for i := range all {
		if seen[i] != all[i].JSON {
			t.Fatalf("record %d differs", i)
		}
	}
	_, got := irGet(t, r, irQuery(int64(len(all)), 7))
	if len(got.Records) != 0 || got.More || got.Total != int64(len(all)) {
		t.Fatalf("past the end: %+v", got)
	}
	// after beyond total: empty page, next_after echoes after, the caller sees total < after (a truncation signal).
	_, got = irGet(t, r, irQuery(500, 7))
	if len(got.Records) != 0 || got.Next != 500 || got.Total != int64(len(all)) {
		t.Fatalf("after beyond total: %+v", got)
	}
}

func TestIncrementalReadRejectsBadParameters(t *testing.T) {
	r := newSrv(t)
	for name, q := range map[string]string{
		"negative after":              "project=p&after=-1&order=asc",
		"non-numeric after":           "project=p&after=x&order=asc",
		"after with desc":             "project=p&after=0&order=desc",
		"after without order":         "project=p&after=0",
		"order asc without after":     "project=p&order=asc",
		"at_seq without after":        "project=p&at_seq=1",
		"negative at_seq":             "project=p&after=0&order=asc&at_seq=-1",
		"non-numeric at_seq":          "project=p&after=0&order=asc&at_seq=x",
		"after with offset":           "project=p&after=0&order=asc&offset=3",
		"unknown order":               "project=p&after=0&order=sideways",
		"zero limit":                  "project=p&after=0&order=asc&limit=0",
		"incremental without project": "after=0&order=asc",
	} {
		if code, _ := do(t, r, "GET", "/v2/records?"+q, ""); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, code)
		}
	}
	// The newest-first list is unchanged.
	if code, _ := do(t, r, "GET", "/v2/records?project=p&limit=5", ""); code != http.StatusOK {
		t.Fatalf("plain list: %d", code)
	}
}

// TestIncrementalReadCostIsConstantInHistory: one read after a frontier that counted everything but 50 records
// reads the same number of rows whether the project holds 1, 3 or 12 months of history (rows counted, not wall
// time). Reading from the frontier must not read the history before it.
func TestIncrementalReadCostIsConstantInHistory(t *testing.T) {
	runReadScale(t, func(t *testing.T) (store.Store, func(int)) { return store.NewMem(), nil }, 400, 50)
}

func runReadScale(t *testing.T, mk func(*testing.T) (store.Store, func(int)), perMonth, newRecords int) {
	var first int64
	for i, months := range []int{1, 3, 12} {
		st, bulk := mk(t)
		spy := newRowSpy(st)
		s := cutServer(t, spy, "")
		h := newCutHistory(t, st, "p", 7)
		hist := months * perMonth
		if bulk != nil {
			bulk(hist)
			h.n, h.hashes = hist, nil
		} else {
			for j := 0; j < hist; j++ {
				h.plain()
			}
		}
		cp, err := cutOnce(t, s, spy, "p")
		if err != nil {
			t.Fatal(err)
		}
		frontier := cpBody(t, cp)
		for j := 0; j < newRecords; j++ {
			h.plain()
		}
		spy.rows.take()
		code, got := irGet(t, s.Routes(), irQuery(frontier, 1000, "at_seq", fmt.Sprint(cp.Seq)))
		if code != http.StatusOK {
			t.Fatalf("read: %d", code)
		}
		rows := spy.rows.take()
		if len(got.Records) != newRecords || got.Total != int64(hist+newRecords) {
			t.Fatalf("%d months: served %d records total %d", months, len(got.Records), got.Total)
		}
		t.Logf("%d months (%d records): rows read = %d", months, hist, rows)
		if i == 0 {
			first = rows
			if rows > int64(newRecords)+5 {
				t.Fatalf("a read of %d records read %d rows", newRecords, rows)
			}
		} else if rows != first {
			t.Fatalf("%d months read %d rows, 1 month read %d: the read grows with history", months, rows, first)
		}
	}
}

// TestIncrementalReadCapsLimit: a limit above 1000 is served as 1000, like the newest-first list.
func TestIncrementalReadCapsLimit(t *testing.T) {
	st := store.NewMem()
	h := newCutHistory(t, st, "p", 9)
	for i := 0; i < 1005; i++ {
		h.plain()
	}
	_, got := irGet(t, cutServer(t, st, "").Routes(), irQuery(0, 5000))
	if len(got.Records) != 1000 || !got.More || got.Next != 1000 {
		t.Fatalf("len=%d more=%v next=%d", len(got.Records), got.More, got.Next)
	}
}

// failingReadStore fails RecordsAfter (and only that), as a store outage would.
type failingReadStore struct{ store.Store }

func (f failingReadStore) WithProjectRead(ctx context.Context, p string, fn func(store.Store) error) error {
	return f.Store.WithProjectRead(ctx, p, func(b store.Store) error { return fn(failingReadStore{b}) })
}
func (failingReadStore) RecordsAfter(string, int64, int) ([]store.Record, error) {
	return nil, errors.New("store down")
}

// TestIncrementalReadFailsClosed: a store error is a 500, never an empty page that reads as "nothing new"; a
// latest checkpoint whose record_count cannot be read is a 500, never a frontier of zero.
func TestIncrementalReadFailsClosed(t *testing.T) {
	st := store.NewMem()
	h := newCutHistory(t, st, "p", 4)
	h.plain()
	if code, _ := do(t, cutServer(t, failingReadStore{st}, "").Routes(), "GET", "/v2/records?"+irQuery(0, 10).Encode(), ""); code != http.StatusInternalServerError {
		t.Fatalf("store error: want 500, got %d", code)
	}
	if err := st.PutCheckpoint("p", store.Checkpoint{Seq: 0, CheckpointHash: "sha256:bad", JSON: `{"record_count":"many"}`}); err != nil {
		t.Fatal(err)
	}
	if code, _ := do(t, cutServer(t, st, "").Routes(), "GET", "/v2/records?"+irQuery(0, 10).Encode(), ""); code != http.StatusInternalServerError {
		t.Fatalf("unreadable checkpoint count: want 500, got %d", code)
	}
	if code, _ := do(t, cutServer(t, st, "").Routes(), "GET", "/v2/records?"+irQuery(0, 10, "at_seq", "0").Encode(), ""); code != http.StatusInternalServerError {
		t.Fatalf("unreadable at_seq count: want 500, got %d", code)
	}
}
