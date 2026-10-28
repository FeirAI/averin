package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// rowSpy counts the rows every read method of the store returns, through WithProjectWrite as well. The
// counter is shared by every bound copy, so a cut run inside a project transaction is counted too.
type rowSpy struct {
	store.Store
	rows *rowCount
	// tamper, when set, rewrites the latest checkpoint a cut reads (a corrupted or hostile base).
	tamper func(store.Checkpoint) store.Checkpoint
	// failFull makes the full computation's frontier read fail; slowFull makes it take that long (the two ways a
	// shadow cannot run). dropOrd hides the record with that ordinal from RecordsAfter, as if it were deleted.
	failFull error
	slowFull time.Duration
	dropOrd  int64
	// pause, when set, blocks the first full computation (ProjectHeads is called only by it during a cut) until the
	// test releases it, so the test can act while a shadow is in flight.
	pause *pauseHook
	// onSnapLatest, when set, runs after a LatestCheckpoint read made on a read snapshot (WithProjectRead), the
	// first read of an off-lock shadow. snap marks the bound copy handed to such a snapshot.
	onSnapLatest func()
	snap         bool
}

// pauseHook parks one caller: entered closes when it arrives, and release lets it go.
type pauseHook struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	relOnce sync.Once
}

// let releases the parked caller; it is safe to call more than once and after the test has failed.
func (p *pauseHook) let() { p.relOnce.Do(func() { close(p.release) }) }

func newPauseHook() *pauseHook {
	return &pauseHook{entered: make(chan struct{}), release: make(chan struct{})}
}

func (p *pauseHook) fire() {
	p.once.Do(func() {
		close(p.entered)
		<-p.release
	})
}

type rowCount struct {
	mu sync.Mutex
	n  int64
}

func (c *rowCount) add(n int) { c.mu.Lock(); c.n += int64(n); c.mu.Unlock() }
func (c *rowCount) take() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.n
	c.n = 0
	return n
}

func newRowSpy(s store.Store) *rowSpy { return &rowSpy{Store: s, rows: &rowCount{}} }

func (r *rowSpy) WithProjectWrite(ctx context.Context, p string, fn func(store.Store) error) error {
	return r.Store.WithProjectWrite(ctx, p, func(b store.Store) error {
		return fn(r.bind(b))
	})
}
func (r *rowSpy) WithProjectRead(ctx context.Context, p string, fn func(store.Store) error) error {
	return r.Store.WithProjectRead(ctx, p, func(b store.Store) error {
		c := r.bind(b)
		c.snap = true
		return fn(c)
	})
}
func (r *rowSpy) WithBudget(d time.Duration, fn func(store.Store) error) error {
	return r.Store.WithBudget(d, func(b store.Store) error { return fn(r.bind(b)) })
}
func (r *rowSpy) bind(b store.Store) *rowSpy {
	return &rowSpy{Store: b, rows: r.rows, tamper: r.tamper, failFull: r.failFull, slowFull: r.slowFull, dropOrd: r.dropOrd, pause: r.pause, onSnapLatest: r.onSnapLatest}
}
func (r *rowSpy) AllRecords(p string) ([]store.Record, error) {
	v, err := r.Store.AllRecords(p)
	r.rows.add(len(v))
	return v, err
}
func (r *rowSpy) RecordsAfter(p string, after int64, limit int) ([]store.Record, error) {
	v, err := r.Store.RecordsAfter(p, after, limit)
	if r.dropOrd > 0 {
		kept := v[:0:0]
		for _, rec := range v {
			if rec.Ord != r.dropOrd {
				kept = append(kept, rec)
			}
		}
		v = kept
	}
	r.rows.add(len(v))
	return v, err
}
func (r *rowSpy) RecordsPage(p string, limit, off int) ([]store.Record, error) {
	v, err := r.Store.RecordsPage(p, limit, off)
	r.rows.add(len(v))
	return v, err
}
func (r *rowSpy) GrantRecords(p string) ([]store.Record, error) {
	v, err := r.Store.GrantRecords(p)
	r.rows.add(len(v))
	return v, err
}
func (r *rowSpy) SessionRecords(p, s string) ([]store.Record, error) {
	v, err := r.Store.SessionRecords(p, s)
	r.rows.add(len(v))
	return v, err
}
func (r *rowSpy) Checkpoints(p string) ([]store.Checkpoint, error) {
	v, err := r.Store.Checkpoints(p)
	r.rows.add(len(v))
	return v, err
}
func (r *rowSpy) CheckpointsRange(p string, a, b int64) ([]store.Checkpoint, error) {
	v, err := r.Store.CheckpointsRange(p, a, b)
	r.rows.add(len(v))
	return v, err
}

// ProjectHeads is the full anti-join: it examines every record of the project, whatever it returns.
func (r *rowSpy) ProjectHeads(p string) ([]string, error) {
	if r.pause != nil {
		r.pause.fire()
	}
	if r.slowFull > 0 {
		time.Sleep(r.slowFull)
	}
	if r.failFull != nil {
		return nil, r.failFull
	}
	v, err := r.Store.ProjectHeads(p)
	if n, cerr := r.Store.RecordCount(p); cerr == nil {
		r.rows.add(n)
	}
	return v, err
}
func (r *rowSpy) LatestCheckpoint(p string) (store.Checkpoint, bool, error) {
	cp, ok, err := r.Store.LatestCheckpoint(p)
	if ok {
		r.rows.add(1)
		if r.tamper != nil {
			cp = r.tamper(cp)
		}
	}
	if r.snap && r.onSnapLatest != nil {
		r.onSnapLatest()
	}
	return cp, ok, err
}

// cutHistory writes a project's history through the store the way the write path does: a record
// chain per session with parents from the session's heads, an occasional forced older parent, grants and voids
// with allocated broker_seqs, idempotent retries. It tracks what it wrote so parents are always earlier records.
type cutHistory struct {
	t       *testing.T
	st      store.Store
	project string
	rng     *rand.Rand
	hashes  []string
	heads   map[string][]string // session -> heads
	grants  int
	n       int
}

func newCutHistory(t *testing.T, st store.Store, project string, seed int64) *cutHistory {
	return &cutHistory{t: t, st: st, project: project, rng: rand.New(rand.NewSource(seed)), heads: map[string][]string{}}
}

func (h *cutHistory) put(session, idem, js string, parents []string) {
	h.t.Helper()
	h.n++
	hash := fmt.Sprintf("sha256:%s-%06d", h.project, h.n)
	rec, created, err := h.st.PutRecord(h.project, idem, store.Record{JSON: js, ContentHash: hash, SessionID: session, Parents: parents})
	if err != nil {
		h.t.Fatalf("put %s: %v", hash, err)
	}
	if !created {
		return
	}
	h.hashes = append(h.hashes, rec.ContentHash)
	h.heads[session] = []string{rec.ContentHash}
}

func (h *cutHistory) plain() {
	session := fmt.Sprintf("s%d", h.rng.Intn(5))
	parents := append([]string(nil), h.heads[session]...)
	if len(h.hashes) > 0 && h.rng.Intn(8) == 0 { // a forced parent: an earlier record that is not a head
		parents = append(parents, h.hashes[h.rng.Intn(len(h.hashes))])
	}
	h.put(session, fmt.Sprintf("i%d", h.n+1), `{"extensions":{}}`, parents)
}

func (h *cutHistory) grant(void bool) {
	h.t.Helper()
	h.grants++
	gid := fmt.Sprintf("g-%s-%d", h.project, h.grants)
	seq, _, err := h.st.AllocateBrokerSeq(h.project, gid)
	if err != nil {
		h.t.Fatal(err)
	}
	kind, ev := "grant", "grant_evidence"
	if void {
		if err := h.st.VoidBrokerSeq(h.project, gid, seq); err != nil {
			h.t.Fatal(err)
		}
		kind, ev = "grant_void", "void_evidence"
	}
	js := fmt.Sprintf(`{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"kind":%q,%q:{"broker_seq":%d}}}}`, kind, ev, seq)
	session := fmt.Sprintf("s%d", h.rng.Intn(5))
	h.put(session, "grant-"+gid, js, append([]string(nil), h.heads[session]...))
	if h.rng.Intn(3) == 0 { // an idempotent retry of the same grant: no new row, no new seq
		h.put(session, "grant-"+gid, js, nil)
	}
}

func (h *cutHistory) step() {
	switch r := h.rng.Intn(10); {
	case r < 6:
		h.plain()
	case r < 8:
		h.grant(false)
	case r < 9:
		h.grant(true)
	default:
		h.variant()
	}
}

// variant writes a record the generic ingest accepts (it reserves only the exact-case extensions.broker) whose
// keys or value types differ from a grant's: case-variant keys and type mismatches. Neither cut may count it as a
// grant or fail on it, exactly as the verifier's classify_role does not.
func (h *cutHistory) variant() {
	variants := []string{
		`{"authority":{"enforcement_point":"credential_broker"},"extensions":{"Broker":{"kind":"grant","grant_evidence":{"broker_seq":9}}}}`,
		`{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"Kind":"grant","grant_evidence":{"broker_seq":9}}}}`,
		`{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"KIND":"grant_void","void_evidence":{"broker_seq":9}}}}`,
		`{"authority":{"enforcement_point":"credential_broker"},"extensions":{"BROKER":{"kind":"grant_void","void_evidence":{"broker_seq":9}}}}`,
		`{"extensions":{"Broker":1}}`,
		`{"extensions":{"broker":"x"}}`,
		`{"extensions":{"broker":{"kind":5}}}`,
		`{"extensions":{"broker":{"kind":["grant"]}}}`,
		`{"extensions":[]}`,
	}
	session := fmt.Sprintf("s%d", h.rng.Intn(5))
	h.put(session, fmt.Sprintf("i%d", h.n+1), variants[h.rng.Intn(len(variants))], append([]string(nil), h.heads[session]...))
}

func cutServer(t *testing.T, st store.Store, brokerID string) *api.Server {
	t.Helper()
	s := api.New(mustCore(t), st, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowEvery(1 << 30)
	if brokerID != "" {
		s = s.WithBroker(brokerIssuingKey()).WithBrokerID(brokerID)
	}
	return s
}

func cutOnce(t *testing.T, s *api.Server, st store.Store, project string) (store.Checkpoint, error) {
	t.Helper()
	_ = st // every caller passes the server's own store; the cut runs through it
	return s.CutCheckpointForTest(context.Background(), project)
}

func bodiesEqual(t *testing.T, inc, full map[string]any, where string) {
	t.Helper()
	a, _ := json.Marshal(inc)
	b, _ := json.Marshal(full)
	if string(a) != string(b) {
		t.Fatalf("%s: incremental cut differs from the full computation\n incremental %s\n full        %s", where, a, b)
	}
}

func bothBodies(t *testing.T, s *api.Server, st store.Store, project string) (inc, full map[string]any, used bool) {
	t.Helper()
	err := st.WithProjectWrite(context.Background(), project, func(b store.Store) error {
		var e error
		inc, full, used, e = s.CutBodiesForTest(b, project)
		return e
	})
	if err != nil {
		t.Fatalf("cut bodies: %v", err)
	}
	return
}

// TestCheckpointCutDifferential: on random histories (sessions, forced older parents, grants, voids, idempotent
// retries, idle cuts) the incremental body equals the full body after every cut, for a single broker and for a
// federated one, and every cut after the first takes the incremental path.
func TestCheckpointCutDifferential(t *testing.T) {
	for _, brokerID := range []string{"", "b1"} {
		for seed := int64(1); seed <= 25; seed++ {
			t.Run(fmt.Sprintf("broker=%q/seed=%d", brokerID, seed), func(t *testing.T) {
				runDifferential(t, store.NewMem(), brokerID, seed, 60)
			})
		}
	}
}

func runDifferential(t *testing.T, st store.Store, brokerID string, seed int64, ops int) {
	s := cutServer(t, st, brokerID)
	h := newCutHistory(t, st, "p", seed)
	incSeen := 0
	for i := 0; i < ops; i++ {
		for k := h.rng.Intn(6); k > 0; k-- { // 0 new records is an idle cut
			h.step()
		}
		inc, full, used := bothBodies(t, s, st, "p")
		if used {
			incSeen++
			bodiesEqual(t, inc, full, fmt.Sprintf("seed %d cut %d", seed, i))
		}
		if _, err := cutOnce(t, s, st, "p"); err != nil {
			t.Fatalf("cut %d: %v", i, err)
		}
	}
	if incSeen < ops-2 {
		t.Fatalf("only %d of %d cuts were incremental", incSeen, ops)
	}
}

// TestCheckpointCutCostIsConstant: one cut after the same 50 new records reads the same number of rows whether
// the project holds 1, 3 or 12 months of history (a month is modelled as perMonth records; the store reads are
// counted, not wall time). The previous cut read every record, grant and checkpoint.
func TestCheckpointCutCostIsConstant(t *testing.T) {
	const perMonth, newRecords = 400, 50
	runCostScale(t, func(t *testing.T) (store.Store, func(int)) { return store.NewMem(), nil }, perMonth, newRecords)
}

// runCostScale: mk returns a fresh store and, optionally, a bulk loader for n backdated history records.
func runCostScale(t *testing.T, mk func(*testing.T) (store.Store, func(int)), perMonth, newRecords int) {
	var first int64
	for i, months := range []int{1, 3, 12} {
		st, bulk := mk(t)
		spy := newRowSpy(st)
		s := cutServer(t, spy, "")
		h := newCutHistory(t, st, "p", 7)
		hist := months * perMonth
		if bulk != nil {
			bulk(hist)
			h.n = hist
			h.hashes = nil
		} else {
			for j := 0; j < hist; j++ {
				if j%97 == 0 {
					h.grant(false)
				} else {
					h.plain()
				}
				if (j+1)%perMonth == 0 { // a checkpoint a month, as history accumulates
					if _, err := cutOnce(t, s, spy, "p"); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		if _, err := cutOnce(t, s, spy, "p"); err != nil { // the base checkpoint (full: no checkpoint yet)
			t.Fatal(err)
		}
		// The first incremental cut of a project after process start is also shadow-checked (O(history), once), so
		// take that one before measuring the steady state.
		h.plain()
		if _, err := cutOnce(t, s, spy, "p"); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < newRecords; j++ {
			h.plain()
		}
		spy.rows.take()
		incBefore, _, _, _ := s.CutStatsForTest()
		cp, err := cutOnce(t, s, spy, "p")
		if err != nil {
			t.Fatal(err)
		}
		rows := spy.rows.take()
		var body struct {
			Count int `json:"record_count"`
		}
		_ = json.Unmarshal([]byte(cp.JSON), &body)
		if want := hist + newRecords + 1; body.Count != want {
			t.Fatalf("%d months: record_count %d, want %d", months, body.Count, want)
		}
		t.Logf("%d months (%d records): rows read by the cut = %d", months, hist, rows)
		if i == 0 {
			first = rows
			if rows > int64(newRecords)+5 {
				t.Fatalf("a cut of %d new records read %d rows", newRecords, rows)
			}
		} else if rows != first {
			t.Fatalf("work grew with history: 1 month read %d rows, %d months read %d", first, months, rows)
		}
		if incAfter, _, _, _ := s.CutStatsForTest(); incAfter-incBefore != 1 {
			t.Fatalf("%d months: %d incremental cuts in the measured cut, want 1", months, incAfter-incBefore)
		}
	}
}

// TestCheckpointCutRefusesAGapInTheNewGrants: a reserved seq with no recorded grant, a grant whose seq repeats one
// already folded into the latest checkpoint, and a seq gap among the new grants each refuse to sign, as the full
// computation does.
func TestCheckpointCutRefusesAGapInTheNewGrants(t *testing.T) {
	st := store.NewMem()
	s := cutServer(t, st, "")
	h := newCutHistory(t, st, "p", 3)
	h.grant(false)
	h.grant(false)
	if _, err := cutOnce(t, s, st, "p"); err != nil {
		t.Fatal(err)
	}
	h.plain() // consume the first-cut-after-start shadow check, so the refusal below is the incremental cut's own
	if _, err := cutOnce(t, s, st, "p"); err != nil {
		t.Fatal(err)
	}
	// A reservation with no record (commit-ambiguous grant): MaxBrokerSeq 3, recorded 2.
	if _, _, err := st.AllocateBrokerSeq("p", "reserved-only"); err != nil {
		t.Fatal(err)
	}
	h.plain()
	if _, err := cutOnce(t, s, st, "p"); err == nil || !strings.Contains(err.Error(), "checkpoint refused") {
		t.Fatalf("a reserved seq with no recorded grant must refuse, got %v", err)
	}
	// A new grant that claims a seq at or below the latest head's max_seq.
	st2 := store.NewMem()
	s2 := cutServer(t, st2, "")
	h2 := newCutHistory(t, st2, "p", 3)
	h2.grant(false)
	h2.grant(false)
	if _, err := cutOnce(t, s2, st2, "p"); err != nil {
		t.Fatal(err)
	}
	h2.plain() // consume the first-cut-after-start shadow check, so the refusal below is the incremental cut's own
	if _, err := cutOnce(t, s2, st2, "p"); err != nil {
		t.Fatal(err)
	}
	js := `{"authority":{"enforcement_point":"credential_broker"},"extensions":{"broker":{"kind":"grant","grant_evidence":{"broker_seq":2}}}}`
	h2.put("s0", "dup-seq", js, nil)
	if _, err := cutOnce(t, s2, st2, "p"); err == nil || !strings.Contains(err.Error(), "checkpoint refused") {
		t.Fatalf("a grant reusing a folded seq must refuse, got %v", err)
	}
}

// TestCheckpointCutShadowRefusesAMismatch: a base checkpoint whose frontier is wrong (a corrupted store row) makes
// the incremental cut differ from the full computation; the shadow check refuses to sign, counts the mismatch,
// and after the first mismatch every later cut is checked, so a second corrupted cut cannot slip through.
func TestCheckpointCutShadowRefusesAMismatch(t *testing.T) {
	st := store.NewMem()
	spy := newRowSpy(st)
	s := api.New(mustCore(t), spy, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowEvery(100).WithCheckpointShadowMinInterval(0)
	h := newCutHistory(t, st, "p", 5)
	for i := 0; i < 5; i++ {
		h.plain()
	}
	if _, err := cutOnce(t, s, spy, "p"); err != nil {
		t.Fatal(err)
	}
	// Incremental cuts 1..99 are not shadow-checked at 1 in 100: the corrupted base is not shadow-checked (the stated 1-in-100 bound).
	for i := 0; i < 99; i++ {
		h.plain()
		if _, err := cutOnce(t, s, spy, "p"); err != nil {
			t.Fatalf("cut %d: %v", i, err)
		}
	}
	// The 100th incremental cut is shadow-checked and refused when its base is corrupted.
	h.plain()
	spy.tamper = func(cp store.Checkpoint) store.Checkpoint {
		var m map[string]any
		_ = json.Unmarshal([]byte(cp.JSON), &m)
		m["frontier"] = append(m["frontier"].([]any), "sha256:bogus-head")
		b, _ := json.Marshal(m)
		cp.JSON = string(b)
		return cp
	}
	_, err := cutOnce(t, s, spy, "p")
	if err == nil || !strings.Contains(err.Error(), "disagrees with the full computation") {
		t.Fatalf("the shadow-checked cut must refuse a mismatching incremental body, got %v", err)
	}
	if _, _, checks, mism := s.CutStatsForTest(); checks != 2 || mism != 1 {
		t.Fatalf("shadow checks %d mismatches %d, want 2 (the first cut after start, and seq 100) and 1", checks, mism)
	}
	// Latched: the very next cut (cut 101, not a multiple of 100) is shadow-checked too and refused.
	if _, err := cutOnce(t, s, spy, "p"); err == nil {
		t.Fatal("after a mismatch every cut must be shadow-checked; a corrupted base signed")
	}
	// With an honest base the checked cut matches and signs.
	spy.tamper = nil
	if _, err := cutOnce(t, s, spy, "p"); err != nil {
		t.Fatalf("an honest cut must sign: %v", err)
	}
}

// TestCheckpointCutShadowCadence: the first incremental cut after start is always computed in full. A cut whose
// checkpoint seq is a multiple of 100 is too, but only when the project's last shadow attempt is at least the min
// interval old. With the interval off (0) that is every such cut; with the default (1 h) and 250 cuts inside one
// hour, only the first-cut shadow runs.
func TestCheckpointCutShadowCadence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ival   time.Duration
		checks int64
	}{{"interval off", 0, 3}, {"default interval", -1, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			st := store.NewMem()
			s := api.New(mustCore(t), st, "k0").WithAuth(auth.NewOpenStore())
			if tc.ival >= 0 {
				s.WithCheckpointShadowMinInterval(tc.ival)
			}
			h := newCutHistory(t, st, "p", 9)
			h.plain()
			if _, err := cutOnce(t, s, st, "p"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 250; i++ {
				h.plain()
				if _, err := cutOnce(t, s, st, "p"); err != nil {
					t.Fatal(err)
				}
			}
			if inc, full, checks, mism := s.CutStatsForTest(); inc != 250 || full != 1 || checks != tc.checks || mism != 0 {
				t.Fatalf("incremental %d full %d shadow checks %d mismatches %d; want 250, 1, %d, 0", inc, full, checks, mism, tc.checks)
			}
		})
	}
}
