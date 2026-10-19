package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	// A store error at after == total (the page is empty and the total is reached) is still a 500, and the body
	// carries the store error, not an ordinal-gap message: an empty page there would otherwise read as "nothing new".
	code, body := do(t, cutServer(t, failingReadStore{st}, "").Routes(), "GET", "/v2/records?"+irQuery(1, 10).Encode(), "")
	if code != http.StatusInternalServerError {
		t.Fatalf("store error at after == total: want 500, got %d (%s)", code, body)
	}
	if !strings.Contains(body, "store down") || strings.Contains(body, "ordinal") {
		t.Fatalf("store error at after == total: body %q must carry the store error and no ordinal-gap message", body)
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

// gapReadStore hides the record at ordinal gap from RecordsAfter, as a store whose ordinals have a hole would
// (an owner-role delete, a hand-edited restore): the page then holds the next ordinal in its place.
type gapReadStore struct {
	store.Store
	gap int64
}

func (g gapReadStore) WithProjectRead(ctx context.Context, p string, fn func(store.Store) error) error {
	return g.Store.WithProjectRead(ctx, p, func(b store.Store) error { return fn(gapReadStore{b, g.gap}) })
}
func (g gapReadStore) RecordsAfter(p string, a int64, l int) ([]store.Record, error) {
	v, err := g.Store.RecordsAfter(p, a, l+1)
	if err != nil {
		return nil, err
	}
	out := v[:0:0]
	for _, r := range v {
		if r.Ord != g.gap && len(out) < l {
			out = append(out, r)
		}
	}
	return out, nil
}

// checkGapRefused: with ordinal 5 of 10 missing and limit 3, the pages [1 2 3] and [7 8 9] (from after=6) are
// intact and served; every page that spans the hole, and the short page that ends below the total, is a 500.
func checkGapRefused(t *testing.T, r http.Handler) {
	t.Helper()
	for _, c := range []struct {
		after int64
		limit int
		want  int
	}{{0, 3, 200}, {3, 3, 500}, {4, 3, 500}, {0, 100, 500}, {5, 3, 200}, {6, 3, 200}, {9, 3, 200}, {0, 4, 200}, {0, 5, 500}} {
		code, _ := irGet(t, r, irQuery(c.after, c.limit))
		if code != c.want {
			t.Errorf("after=%d limit=%d: want %d, got %d", c.after, c.limit, c.want, code)
		}
	}
}

// TestIncrementalReadRefusesOrdinalGap: next_after is positional but the store selects by ordinal, so a gap would
// repeat one record and hide another under a 200; the read refuses any page that is not exactly after+1..after+len.
func TestIncrementalReadRefusesOrdinalGap(t *testing.T) {
	st := store.NewMem()
	h := newCutHistory(t, st, "p", 3)
	for i := 0; i < 10; i++ {
		h.plain()
	}
	checkGapRefused(t, cutServer(t, gapReadStore{st, 5}, "").Routes())
	// The last record missing leaves every page contiguous, so only the short-page clause (a short page must end at
	// the total) sees it: the page that ends at 9 of 10, and the empty page at after=9, are refused; a full page
	// that does not reach the end is served, and an empty page at the total is not a gap.
	last := cutServer(t, gapReadStore{st, 10}, "").Routes()
	for _, c := range []struct {
		after int64
		limit int
		want  int
	}{{0, 100, 500}, {6, 100, 500}, {9, 3, 500}, {6, 3, 200}, {0, 3, 200}} {
		if code, _ := irGet(t, last, irQuery(c.after, c.limit)); code != c.want {
			t.Errorf("last record missing, after=%d limit=%d: want %d, got %d", c.after, c.limit, c.want, code)
		}
	}
	// Without a gap the same requests are all served, and an empty page past the total (a reader ahead of the
	// store) is not a gap.
	r := cutServer(t, st, "").Routes()
	for _, after := range []int64{0, 3, 9, 10, 25} {
		if code, _ := irGet(t, r, irQuery(after, 3)); code != http.StatusOK {
			t.Fatalf("no gap, after=%d: %d", after, code)
		}
	}
}

// interleaving runs hook once, from inside the read transaction, right after the store method named by at
// ("RecordCount", "RecordsAfter" or "LatestCheckpoint") returns. Hooking after each read in turn puts the writes
// before, between and after every read the handler makes, so a read that escapes the transaction (or is made
// after a write that the snapshot must not show) is seen at the position where it differs.
type interleaving struct {
	store.Store
	at   string
	once *sync.Once
	hook func()
}

func (s interleaving) rebind(b store.Store) interleaving {
	return interleaving{Store: b, at: s.at, once: s.once, hook: s.hook}
}
func (s interleaving) WithProjectRead(ctx context.Context, p string, fn func(store.Store) error) error {
	return s.Store.WithProjectRead(ctx, p, func(b store.Store) error { return fn(s.rebind(b)) })
}
func (s interleaving) fire(name string) {
	if name == s.at {
		s.once.Do(s.hook)
	}
}
func (s interleaving) RecordCount(p string) (int, error) {
	v, err := s.Store.RecordCount(p)
	s.fire("RecordCount")
	return v, err
}
func (s interleaving) RecordsAfter(p string, a int64, l int) ([]store.Record, error) {
	v, err := s.Store.RecordsAfter(p, a, l)
	s.fire("RecordsAfter")
	return v, err
}
func (s interleaving) LatestCheckpoint(p string) (store.Checkpoint, bool, error) {
	v, ok, err := s.Store.LatestCheckpoint(p)
	s.fire("LatestCheckpoint")
	return v, ok, err
}

// checkSnapshotUnderCut: after each read the handler makes in turn (the total, the page, the latest checkpoint),
// 30 records are written and a checkpoint is cut on the outer store. The response must still be one snapshot of
// the state before the writes: total 40, the 40 records, and the pre-write checkpoint (seq and count). The hook
// must have fired at every position (a wrapper that never runs would prove nothing).
func checkSnapshotUnderCut(t *testing.T, mk func(t *testing.T) store.Store) {
	t.Helper()
	for _, at := range []string{"RecordCount", "RecordsAfter", "LatestCheckpoint"} {
		t.Run("write after "+at, func(t *testing.T) {
			st := mk(t)
			h := newCutHistory(t, st, "p", 11)
			plain := cutServer(t, st, "")
			for i := 0; i < 40; i++ {
				h.plain()
			}
			cp0, err := cutOnce(t, plain, st, "p")
			if err != nil {
				t.Fatal(err)
			}
			fired := false
			wrapped := interleaving{Store: st, at: at, once: &sync.Once{}}
			wrapped.hook = func() {
				fired = true
				for i := 0; i < 30; i++ {
					h.plain()
				}
				if _, err := cutOnce(t, plain, st, "p"); err != nil {
					t.Error(err)
				}
			}
			code, got := irGet(t, cutServer(t, wrapped, "").Routes(), irQuery(0, 1000))
			if code != http.StatusOK {
				t.Fatalf("code %d", code)
			}
			if !fired {
				t.Fatal("the interleaved write never ran: the test proved nothing")
			}
			if got.Total != 40 || len(got.Records) != 40 || got.Latest == nil || got.Latest.Seq != cp0.Seq || got.Latest.RecordCount != 40 {
				t.Fatalf("fields from different snapshots: total=%d records=%d latest=%+v (pre-write checkpoint seq %d, 40 records)", got.Total, len(got.Records), got.Latest, cp0.Seq)
			}
		})
	}
}

// TestIncrementalReadSnapshotHoldsUnderConcurrentCut: total, page and checkpoints come from one snapshot.
func TestIncrementalReadSnapshotHoldsUnderConcurrentCut(t *testing.T) {
	checkSnapshotUnderCut(t, func(*testing.T) store.Store { return store.NewMem() })
}

// An incremental read is a contiguous page of every record, so a record_kind or exclude_record_kind
// filter (feir-ops#1) cannot be honoured there: the combination is refused, never silently ignored.
func TestIncrementalReadRefusesAKindFilter(t *testing.T) {
	st := store.NewMem()
	h := newCutHistory(t, st, "p", 4)
	h.plain()
	for _, kv := range [][2]string{{"record_kind", "refusal"}, {"exclude_record_kind", "refusal"}, {"record_kind", "no-such-kind"}} {
		code, body := do(t, cutServer(t, st, "").Routes(), "GET", "/v2/records?"+irQuery(0, 10, kv[0], kv[1]).Encode(), "")
		if code != http.StatusBadRequest || !strings.Contains(body, "cannot be combined with an incremental read") {
			t.Fatalf("%s=%s with an incremental read: want 400 naming the conflict, got %d (%s)", kv[0], kv[1], code, body)
		}
	}
}
