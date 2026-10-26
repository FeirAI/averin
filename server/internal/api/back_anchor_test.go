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

func unanchored(t *testing.T, st store.Store) []int64 {
	t.Helper()
	u, err := st.UnanchoredCheckpointSeqs("p1", 1000)
	if err != nil {
		t.Fatal(err)
	}
	seqs := []int64{}
	for _, x := range u {
		seqs = append(seqs, x.Seq)
	}
	return seqs
}

func eqSeqs(a []int64, b ...int64) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

func TestBackAnchorFailedThenSuccessfulCut(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	cut(t, h) // seq 0 fails
	if got := unanchored(t, st); !eqSeqs(got, 0) {
		t.Fatalf("after failed cut unanchored = %v; want [0]", got)
	}
	tsa.set(false)
	cut(t, h) // seq 1 anchors, then sweeps seq 0
	if got := unanchored(t, st); len(got) != 0 {
		t.Fatalf("seq 0 should be back-anchored by the next successful cut; unanchored = %v", got)
	}
	_, metrics := do(t, h, "GET", "/metrics", "")
	if !strings.Contains(metrics, "averin_checkpoint_backanchored_total 1") {
		t.Fatalf("backanchored counter missing/wrong:\n%s", metrics)
	}
}

func TestBackAnchorAtMostKOldestFirst(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	for i := 0; i < 6; i++ {
		cut(t, h) // seqs 0..5 un-anchored
	}
	tsa.set(false)
	cut(t, h) // seq 6 anchors; sweep stamps 0,1,2 only
	if got := unanchored(t, st); !eqSeqs(got, 3, 4, 5) {
		t.Fatalf("after one cut unanchored = %v; want [3 4 5] (K=3, oldest first)", got)
	}
	before := tsa.callCount()
	cut(t, h) // seq 7 + 3,4,5
	if got := unanchored(t, st); len(got) != 0 {
		t.Fatalf("unanchored = %v; want none", got)
	}
	if n := tsa.callCount() - before; n != 4 {
		t.Fatalf("stamps in the second cut = %d; want 4 (own + K=3)", n)
	}
}

func TestBackAnchorNoSweepWhenNewAnchorFailed(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	cut(t, h)
	before := tsa.callCount()
	cut(t, h)
	if n := tsa.callCount() - before; n != 1 {
		t.Fatalf("a cut whose own stamp failed made %d TSA calls; want exactly 1 (no sweep)", n)
	}
	if got := unanchored(t, st); !eqSeqs(got, 0, 1) {
		t.Fatalf("unanchored = %v; want [0 1]", got)
	}
}

func TestBackAnchorSweepStopsAtFirstFailure(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	for i := 0; i < 4; i++ {
		cut(t, h) // 0..3
	}
	tsa.allowOnly(2) // seq 4 anchors, seq 0 back-anchors, then seq 1 fails
	before := tsa.callCount()
	cut(t, h)
	if n := tsa.callCount() - before; n != 3 {
		t.Fatalf("TSA calls = %d; want 3 (own, seq 0, seq 1 fails, stop)", n)
	}
	if got := unanchored(t, st); !eqSeqs(got, 1, 2, 3) {
		t.Fatalf("unanchored = %v; want [1 2 3]", got)
	}
	_, metrics := do(t, h, "GET", "/metrics", "")
	if !strings.Contains(metrics, "averin_checkpoint_backanchor_failures_total 1") {
		t.Fatalf("failure counter missing:\n%s", metrics)
	}
}

func TestBackfillEndpointBoundAndResponse(t *testing.T) {
	tsa := &switchTSA{}
	h, st := newBackAnchorServer(t, tsa)
	tsa.set(true)
	for i := 0; i < 105; i++ {
		cut(t, h)
	}
	tsa.set(false)
	code, resp := do(t, h, "POST", "/v2/anchors/backfill?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("backfill: %d %s", code, resp)
	}
	var out struct {
		BackAnchored int  `json:"back_anchored"`
		Remaining    int  `json:"remaining_unanchored"`
		Stopped      bool `json:"stopped_on_error"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatal(err)
	}
	if out.BackAnchored != 100 || out.Remaining != 5 || out.Stopped {
		t.Fatalf("response = %+v; want 100 back-anchored, 5 remaining, not stopped", out)
	}
	if got := unanchored(t, st); !eqSeqs(got, 100, 101, 102, 103, 104) {
		t.Fatalf("unanchored = %v", got)
	}
	// A failing TSA: stops at the first failure and says so.
	tsa.set(true)
	_, resp = do(t, h, "POST", "/v2/anchors/backfill?project=p1", "")
	json.Unmarshal([]byte(resp), &out)
	if out.BackAnchored != 0 || out.Remaining != 5 || !out.Stopped {
		t.Fatalf("failing-TSA response = %+v", out)
	}
	tsa.set(false)
	_, resp = do(t, h, "POST", "/v2/anchors/backfill?project=p1", "")
	json.Unmarshal([]byte(resp), &out)
	if out.BackAnchored != 5 || out.Remaining != 0 || out.Stopped {
		t.Fatalf("final response = %+v", out)
	}
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
func TestLateBackAnchorTripsBackdatingGateToday(t *testing.T) {
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

// End to end through the server: an export after back-anchoring carries an anchor block on every
// checkpoint, and the bundle still verifies structurally.
func TestExportAfterBackAnchoringAnchorsEveryCheckpoint(t *testing.T) {
	tsa := &switchTSA{}
	h, _ := newBackAnchorServer(t, tsa)
	do(t, h, "POST", "/v2/records", `{"idempotency_key":"a1","project_id":"p1","session_id":"s1","action":"a"}`)
	tsa.set(true)
	cut(t, h)
	cut(t, h)
	tsa.set(false)
	cut(t, h)
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
	if _, report := do(t, h, "GET", "/v2/verify?project=p1", ""); !strings.Contains(report, `"ok":true`) {
		t.Fatalf("export after back-anchoring should verify: %s", report)
	}
}
