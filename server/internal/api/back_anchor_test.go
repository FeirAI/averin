package api_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
	"github.com/feirai/averin/server/internal/witness"
)

// switchTSA is a hermetic TSA that fails on demand and records how many stamps were attempted.
type switchTSA struct {
	mu    sync.Mutex
	fail  bool
	calls int
	// failAfter, when > 0, makes every call after that many successes in the current run fail.
	succeedN int
	limited  bool
}

func (f *switchTSA) set(fail bool) { f.mu.Lock(); f.fail = fail; f.limited = false; f.mu.Unlock() }

// allowOnly makes the next n stamps succeed and every one after fail.
func (f *switchTSA) allowOnly(n int) {
	f.mu.Lock()
	f.fail, f.limited, f.succeedN = false, true, n
	f.mu.Unlock()
}
func (f *switchTSA) callCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func (f *switchTSA) Stamp(ctx context.Context, imprint []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	if f.fail || (f.limited && f.succeedN <= 0) {
		f.mu.Unlock()
		return nil, errors.New("TSA down")
	}
	if f.limited {
		f.succeedN--
	}
	f.mu.Unlock()
	return witness.StubTSA{}.Stamp(ctx, imprint)
}

func newBackAnchorServer(t *testing.T, tsa witness.TSA) (http.Handler, store.Store) {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMem()
	s := api.New(c, st, "k0").WithAuth(auth.NewOpenStore())
	if tsa != nil {
		s = s.WithTSA(tsa)
	}
	return s.Routes(), st
}

func cut(t *testing.T, h http.Handler) {
	t.Helper()
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
}

// unanchored lists EVERY checkpoint seq with no anchor (not only the tail).
func unanchored(t *testing.T, st store.Store) []int64 {
	t.Helper()
	cps, err := st.Checkpoints("p1")
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := st.Anchors("p1")
	if err != nil {
		t.Fatal(err)
	}
	seqs := []int64{}
	for _, c := range cps {
		if _, ok := anchors[c.Seq]; !ok {
			seqs = append(seqs, c.Seq)
		}
	}
	return seqs
}

func eqSeqs(a []int64, b ...int64) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

type backfillResp struct {
	BackAnchored int  `json:"back_anchored"`
	Remaining    int  `json:"remaining_unanchored"`
	Stopped      bool `json:"stopped_on_error"`
}

func backfill(t *testing.T, h http.Handler) backfillResp {
	t.Helper()
	code, resp := do(t, h, "POST", "/v2/anchors/backfill?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("backfill: %d %s", code, resp)
	}
	var out backfillResp
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// There is NO automatic retry: a successful cut stamps only itself, so a checkpoint that missed its
// stamp stays un-anchored (it is a gap below the newest anchor, which is committed by the chain).
func TestNoAutomaticBackAnchorOnCut(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	cut(t, h) // seq 0 fails
	tsa.set(false)
	before := tsa.callCount()
	cut(t, h) // seq 1 anchors
	if n := tsa.callCount() - before; n != 1 {
		t.Fatalf("a successful cut made %d TSA calls; want exactly 1 (no sweep)", n)
	}
	if got := unanchored(t, st); !eqSeqs(got, 0) {
		t.Fatalf("seq 0 should stay un-anchored; unanchored seqs = %v", got)
	}
}

// Only the un-anchored TAIL (above the newest anchored seq) is back-anchored: a gap below the newest
// anchor is left alone, because stamping it now would make anchor times decrease with seq.
func TestBackfillStampsOnlyTheTail(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	cut(t, h) // seq 0 fails (gap)
	tsa.set(false)
	cut(t, h) // seq 1 anchored
	tsa.set(true)
	cut(t, h) // seq 2 fails (tail)
	cut(t, h) // seq 3 fails (tail)
	tsa.set(false)
	out := backfill(t, h)
	if out.BackAnchored != 2 || out.Remaining != 0 || out.Stopped {
		t.Fatalf("response = %+v; want 2 back-anchored (seqs 2, 3), 0 remaining, not stopped", out)
	}
	if got := unanchored(t, st); !eqSeqs(got, 0) {
		t.Fatalf("the mid-chain gap (seq 0) must stay un-anchored; unanchored seqs = %v", got)
	}
	_, metrics := do(t, h, "GET", "/metrics", "")
	if !strings.Contains(metrics, "averin_checkpoint_backanchored_total 2") {
		t.Fatalf("backanchored counter missing/wrong:\n%s", metrics)
	}
}

func TestBackfillBoundOldestFirst(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	for i := 0; i < 15; i++ {
		cut(t, h)
	}
	tsa.set(false)
	out := backfill(t, h)
	if out.BackAnchored != 10 || out.Remaining != 5 || out.Stopped {
		t.Fatalf("response = %+v; want 10 back-anchored, 5 remaining, not stopped", out)
	}
	// oldest first: the first ten are stamped, so the newest anchored seq is 9 and the tail is 10..14.
	if got := unanchored(t, st); !eqSeqs(got, 10, 11, 12, 13, 14) {
		t.Fatalf("unanchored tail = %v", got)
	}
	out = backfill(t, h)
	if out.BackAnchored != 5 || out.Remaining != 0 || out.Stopped {
		t.Fatalf("final response = %+v", out)
	}
}

func TestBackfillStopsAtFirstFailure(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	for i := 0; i < 3; i++ {
		cut(t, h)
	}
	before := tsa.callCount()
	out := backfill(t, h) // failing TSA: one attempt, stop
	if out.BackAnchored != 0 || out.Remaining != 3 || !out.Stopped || tsa.callCount()-before != 1 {
		t.Fatalf("failing-TSA response = %+v calls=%d", out, tsa.callCount()-before)
	}
	tsa.allowOnly(1) // seq 0 stamps, seq 1 fails, stop
	before = tsa.callCount()
	out = backfill(t, h)
	if out.BackAnchored != 1 || out.Remaining != 2 || !out.Stopped || tsa.callCount()-before != 2 {
		t.Fatalf("partial response = %+v calls=%d", out, tsa.callCount()-before)
	}
	if got := unanchored(t, st); !eqSeqs(got, 1, 2) {
		t.Fatalf("unanchored = %v; want [1 2]", got)
	}
	_, metrics := do(t, h, "GET", "/metrics", "")
	if !strings.Contains(metrics, "averin_checkpoint_backanchor_failures_total 2") {
		t.Fatalf("failure counter missing:\n%s", metrics)
	}
}

// blockTSA blocks every stamp until released, to hold a backfill in flight.
type blockTSA struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockTSA) Stamp(ctx context.Context, imprint []byte) ([]byte, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return witness.StubTSA{}.Stamp(ctx, imprint)
}

func TestBackfillSingleFlight(t *testing.T) {
	tsa := &switchTSA{}
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	bt := &blockTSA{entered: make(chan struct{}, 1), release: make(chan struct{})}
	var cur witness.TSA = tsa
	sw := &swapTSA{cur: &cur}
	h := api.New(c, store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).WithTSA(sw).Routes()
	tsa.set(true)
	cut(t, h)
	cut(t, h)
	sw.set(bt)
	done := make(chan int, 1)
	go func() { code, _ := do(t, h, "POST", "/v2/anchors/backfill?project=p1", ""); done <- code }()
	<-bt.entered
	if code, resp := do(t, h, "POST", "/v2/anchors/backfill?project=p1", ""); code != http.StatusConflict || !strings.Contains(resp, "already running") {
		t.Fatalf("concurrent backfill = %d %s; want 409 already running", code, resp)
	}
	close(bt.release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first backfill = %d", code)
	}
	if code, _ := do(t, h, "POST", "/v2/anchors/backfill?project=p1", ""); code != http.StatusOK {
		t.Fatalf("backfill after the first finished = %d; want 200", code)
	}
}

// swapTSA lets a test switch the TSA behind a running server.
type swapTSA struct {
	mu  sync.Mutex
	cur *witness.TSA
}

func (w *swapTSA) set(t witness.TSA) { w.mu.Lock(); *w.cur = t; w.mu.Unlock() }
func (w *swapTSA) Stamp(ctx context.Context, imprint []byte) ([]byte, error) {
	w.mu.Lock()
	t := *w.cur
	w.mu.Unlock()
	return t.Stamp(ctx, imprint)
}

func TestBackfillEndpointNoTSA(t *testing.T) {
	h, _ := newBackAnchorServer(t, nil)
	code, resp := do(t, h, "POST", "/v2/anchors/backfill?project=p1", "")
	if code != http.StatusConflict || !strings.Contains(resp, "no TSA configured") {
		t.Fatalf("no-TSA backfill = %d %s; want 409 with a clear message", code, resp)
	}
	if code, _ := do(t, h, "POST", "/v2/anchors/backfill", ""); code != http.StatusBadRequest {
		t.Fatalf("missing project = %d; want 400", code)
	}
}

func TestBackfillEndpointAuth(t *testing.T) {
	ks, _, err := auth.ParseKeysConfig(`[
	  {"project":"p","token":"rtok","role":"read"},
	  {"project":"p","token":"wtok","role":"write"},
	  {"project":"p","token":"atok","role":"admin"},
	  {"project":"q","token":"qtok","role":"admin"}]`)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := core.New(seed)
	h := api.New(c, store.NewMem(), "k0").WithAuth(ks).WithTSA(witness.StubTSA{}).Routes()
	for _, tc := range []struct {
		token string
		want  int
	}{{"", 401}, {"bad", 401}, {"rtok", 403}, {"wtok", 403}, {"qtok", 401}, {"atok", 200}} {
		if got := doAs(h, "POST", "/v2/anchors/backfill?project=p", tc.token, ""); got != tc.want {
			t.Fatalf("token %q: got %d want %d", tc.token, got, tc.want)
		}
	}
}

// lateAnchorBundle rewrites every checkpoint in the bundle to carry a hermetic test-anchor whose
// anchored_ts is the supplied per-index time.
func lateAnchorBundle(t *testing.T, bundleJSON string, tsa ed25519.PrivateKey, tsFor func(i int, createdTS string) string) string {
	t.Helper()
	var bundle map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bundleJSON), &bundle); err != nil {
		t.Fatal(err)
	}
	var cps []map[string]json.RawMessage
	if err := json.Unmarshal(bundle["checkpoints"], &cps); err != nil {
		t.Fatal(err)
	}
	for i, cp := range cps {
		var hash, created string
		json.Unmarshal(cp["checkpoint_hash"], &hash)
		json.Unmarshal(cp["created_ts"], &created)
		a, _ := json.Marshal(makeTestAnchor(hash, tsFor(i, created), "test-tsa", tsa))
		cp["anchor"] = a
	}
	bundle["checkpoints"], _ = json.Marshal(cps)
	out, _ := json.Marshal(bundle)
	return string(out)
}

// FINDING (pinned, not endorsed): the offline verifier's backdating gate (RCP 10.1 step 5, threat #3,
// check_anchor_backdating) requires VERIFIED anchor times to be non-decreasing with checkpoint seq. A
// back-anchor's genTime is, by construction, later than the genTime of any newer checkpoint that was
// anchored on time, so a bundle carrying such a late anchor is flagged "anchor time decreased ... (backdating)"
// and fails integrity, even though every checkpoint is then anchored. This test pins that current behaviour so
// the interaction is visible and cannot change silently; relaxing the gate is a verifier/spec decision.
func TestMidChainLateBackAnchorTripsBackdatingGateToday(t *testing.T) {
	h, _ := newBackAnchorServer(t, nil)
	do(t, h, "POST", "/v2/records", `{"idempotency_key":"a1","project_id":"p1","session_id":"s1","action":"a"}`)
	cut(t, h)
	cut(t, h)
	cut(t, h)
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	c, _ := core.New(seed)
	tsa := testTSAKey()
	opts := fmt.Sprintf(`{"tsa_keys":[%q]}`, tsaPubEncoded(tsa))

	// control: every checkpoint anchored at its own created_ts (monotone) verifies, 3 of 3 anchored.
	ok := lateAnchorBundle(t, exp, tsa, func(i int, created string) string { return created })
	rep := c.VerifyBundleWith(ok, opts)
	if !strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, `"checkpoints_anchored":3`) {
		t.Fatalf("monotone anchors must verify with 3 of 3 anchored: %s", rep)
	}

	// checkpoint 0 anchored LATE (after checkpoints 1 and 2 were anchored): trips the gate today.
	late := lateAnchorBundle(t, exp, tsa, func(i int, created string) string {
		if i == 0 {
			return "2099-01-01T00:00:00.000Z"
		}
		return created
	})
	rep = c.VerifyBundleWith(late, opts)
	if !strings.Contains(rep, `"checkpoints_anchored":3`) {
		t.Fatalf("all three anchors should verify cryptographically: %s", rep)
	}
	if strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, "anchor time decreased across checkpoints 0 -> 1") {
		t.Fatalf("expected the backdating gate to flag the late back-anchor today: %s", rep)
	}
}

// An anchor added LATE to the un-anchored TAIL keeps anchor times non-decreasing with seq, so the
// bundle verifies with every checkpoint anchored: this is the only back-anchor the server performs.
func TestLateTailBackAnchorVerifies(t *testing.T) {
	h, _ := newBackAnchorServer(t, nil)
	do(t, h, "POST", "/v2/records", `{"idempotency_key":"a1","project_id":"p1","session_id":"s1","action":"a"}`)
	cut(t, h)
	cut(t, h)
	cut(t, h)
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	c, _ := core.New(seed)
	tsa := testTSAKey()
	opts := fmt.Sprintf(`{"tsa_keys":[%q]}`, tsaPubEncoded(tsa))
	late := lateAnchorBundle(t, exp, tsa, func(i int, created string) string {
		if i == 2 { // the tail checkpoint, stamped long after its created_ts
			return "2099-01-01T00:00:00.000Z"
		}
		return created
	})
	rep := c.VerifyBundleWith(late, opts)
	if !strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, `"checkpoints_anchored":3`) {
		t.Fatalf("a late tail back-anchor must verify with 3 of 3 anchored: %s", rep)
	}
}

// Structural only: the server's StubTSA tokens are never trusted by the self-verify, so no anchor is
// COUNTED here (checkpoints_anchored is 0). This checks the export carries an anchor block per
// back-anchored checkpoint; the verification outcome with trusted anchors is TestLateTailBackAnchorVerifies.
func TestExportAfterBackfillCarriesAnchorBlocks(t *testing.T) {
	tsa := &switchTSA{}
	h, _ := newBackAnchorServer(t, tsa)
	do(t, h, "POST", "/v2/records", `{"idempotency_key":"a1","project_id":"p1","session_id":"s1","action":"a"}`)
	tsa.set(true)
	cut(t, h)
	cut(t, h)
	cut(t, h)
	tsa.set(false)
	if out := backfill(t, h); out.BackAnchored != 3 || out.Remaining != 0 {
		t.Fatalf("backfill = %+v", out)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1&mode=proof_only", "")
	var bundle struct {
		Checkpoints []map[string]json.RawMessage `json:"checkpoints"`
	}
	if err := json.Unmarshal([]byte(exp), &bundle); err != nil || len(bundle.Checkpoints) != 3 {
		t.Fatalf("decode export: %v\n%s", err, exp)
	}
	for i, cp := range bundle.Checkpoints {
		if _, ok := cp["anchor"]; !ok {
			t.Fatalf("checkpoint %d has no anchor block after back-anchoring", i)
		}
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"checkpoints_anchored":0`) || !strings.Contains(report, `"checkpoints_anchors_attached":3`) {
		t.Fatalf("expected structural-only anchors (0 counted, 3 attached): %s", report)
	}
}
