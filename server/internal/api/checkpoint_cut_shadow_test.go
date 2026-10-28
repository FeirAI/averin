package api_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// shadowRig is a server over a spy store whose clock the test moves, with a shadow on every cut.
type shadowRig struct {
	t   *testing.T
	st  store.Store
	spy *rowSpy
	s   *api.Server
	h   *cutHistory
	now time.Time
}

func newShadowRig(t *testing.T, budget time.Duration) *shadowRig {
	return newShadowRigOn(t, store.NewMem(), budget)
}

func newShadowRigOn(t *testing.T, st store.Store, budget time.Duration) *shadowRig {
	spy := newRowSpy(st)
	r := &shadowRig{t: t, st: st, spy: spy, now: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)}
	r.s = api.New(mustCore(t), spy, "k0").WithAuth(auth.NewOpenStore()).
		WithCheckpointShadowEvery(1).WithCheckpointShadowMinInterval(0).WithCheckpointShadowBudget(budget).WithCheckpointShadowBackoff(10 * time.Minute).
		WithClock(func() time.Time { return r.now })
	r.h = newCutHistory(t, st, "p", 3)
	r.h.plain()
	if _, err := cutOnce(t, r.s, spy, "p"); err != nil { // seq 0: the full computation (no base yet)
		t.Fatal(err)
	}
	return r
}

func (r *shadowRig) cut() (store.Checkpoint, error) {
	r.t.Helper()
	r.h.plain()
	return cutOnce(r.t, r.s, r.spy, "p")
}

// TestCheckpointCutShadowThatCannotRunSigns: a full computation that errors does not stop the checkpoint. The
// incremental body is signed, the failed counter moves, and the project's next shadow waits for the backoff: not the
// next cut, and not the same seq again. After the backoff the shadow runs again and, once it succeeds, the project
// is back on the normal cadence.
func TestCheckpointCutShadowThatCannotRunSigns(t *testing.T) {
	r := newShadowRig(t, time.Second)
	r.spy.failFull = errors.New("read project snapshot: connection reset")
	cp, err := r.cut()
	if err != nil {
		t.Fatalf("a shadow that cannot run must not refuse the cut: %v", err)
	}
	if cp.Seq != 1 {
		t.Fatalf("signed seq %d, want 1", cp.Seq)
	}
	if _, _, checks, mism := r.s.CutStatsForTest(); checks != 1 || mism != 0 || r.s.ShadowFailedForTest() != 1 {
		t.Fatalf("checks %d mismatches %d failed %d, want 1, 0, 1", checks, mism, r.s.ShadowFailedForTest())
	}
	// Inside the backoff: cuts are signed without a shadow attempt (the counters do not move).
	for i := 0; i < 3; i++ {
		r.now = r.now.Add(time.Minute)
		if _, err := r.cut(); err != nil {
			t.Fatalf("cut inside the backoff: %v", err)
		}
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 1 || r.s.ShadowFailedForTest() != 1 {
		t.Fatalf("shadow attempts %d failed %d inside the backoff, want 1 and 1", checks, r.s.ShadowFailedForTest())
	}
	// Past the first backoff the shadow is attempted again; it fails again, and the wait doubles.
	r.now = r.now.Add(10 * time.Minute)
	if _, err := r.cut(); err != nil {
		t.Fatal(err)
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 2 || r.s.ShadowFailedForTest() != 2 {
		t.Fatalf("attempts %d failed %d after the backoff, want 2 and 2", checks, r.s.ShadowFailedForTest())
	}
	r.now = r.now.Add(11 * time.Minute) // 11 < 20: still inside the doubled wait
	if _, err := r.cut(); err != nil {
		t.Fatal(err)
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 2 {
		t.Fatalf("the wait must double after a second failure; attempts %d, want 2", checks)
	}
	// The full computation works again: after the wait the shadow runs, passes, and the backoff is gone.
	r.spy.failFull = nil
	r.now = r.now.Add(10 * time.Minute)
	if _, err := r.cut(); err != nil {
		t.Fatal(err)
	}
	if _, _, checks, mism := r.s.CutStatsForTest(); checks != 3 || mism != 0 || r.s.ShadowFailedForTest() != 2 {
		t.Fatalf("attempts %d mismatches %d failed %d, want 3, 0, 2", checks, mism, r.s.ShadowFailedForTest())
	}
	if _, err := r.cut(); err != nil {
		t.Fatal(err)
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 4 {
		t.Fatalf("after a shadow ran the next cut must be shadowed again (1 in 1), attempts %d", checks)
	}
}

// TestCheckpointCutShadowOverBudgetSigns: a full computation that does not finish inside the shadow's own budget is
// the same as one that errors: the cut signs, the failed counter moves, the next shadow waits.
func TestCheckpointCutShadowOverBudgetSigns(t *testing.T) {
	r := newShadowRig(t, 20*time.Millisecond)
	r.spy.slowFull = 80 * time.Millisecond
	cp, err := r.cut()
	if err != nil {
		t.Fatalf("a shadow over its budget must not refuse the cut: %v", err)
	}
	if cp.Seq != 1 || r.s.ShadowFailedForTest() != 1 {
		t.Fatalf("seq %d failed %d, want 1 and 1", cp.Seq, r.s.ShadowFailedForTest())
	}
	if _, err := r.cut(); err != nil {
		t.Fatal(err)
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 1 {
		t.Fatalf("the next cut re-ran the shadow inside the backoff: attempts %d", checks)
	}
}

// TestCheckpointCutShadowMismatchStillRefusesAfterFailure: a mismatch refuses even on a project that has a shadow
// failure behind it, once its backoff has passed; the "cannot run" rule never turns a disagreement into a signature.
func TestCheckpointCutShadowMismatchStillRefusesAfterFailure(t *testing.T) {
	r := newShadowRig(t, time.Second)
	r.spy.failFull = errors.New("boom")
	if _, err := r.cut(); err != nil {
		t.Fatal(err)
	}
	r.spy.failFull = nil
	r.spy.tamper = bogusBase("p")
	r.now = r.now.Add(11 * time.Minute)
	_, err := r.cut()
	if err == nil || !strings.Contains(err.Error(), "disagrees with the full computation") {
		t.Fatalf("a mismatching shadow must refuse, got %v", err)
	}
	if _, _, _, mism := r.s.CutStatsForTest(); mism != 1 {
		t.Fatalf("mismatches %d, want 1", mism)
	}
}

// TestCheckpointCutShadowOverBudgetFullBodyStillCompares: a full body that came back late was computed, so it is
// compared. With a tampered base the incremental cut disagrees with it and must refuse and latch, however slow
// the full computation was.
func TestCheckpointCutShadowOverBudgetFullBodyStillCompares(t *testing.T) {
	r := newShadowRig(t, 20*time.Millisecond)
	r.spy.slowFull = 80 * time.Millisecond
	r.spy.tamper = bogusBase("p")
	_, err := r.cut()
	if err == nil || !strings.Contains(err.Error(), "disagrees with the full computation") {
		t.Fatalf("an over-budget full body that disagrees must refuse, got %v", err)
	}
	if _, _, _, mism := r.s.CutStatsForTest(); mism != 1 {
		t.Fatalf("mismatches %d, want 1", mism)
	}
	if r.s.ShadowFailedForTest() != 0 {
		t.Fatalf("a computed body is not a shadow that could not run; failed %d, want 0", r.s.ShadowFailedForTest())
	}
}

// TestCheckpointCutShadowBudgetIsClamped: the shadow's budget has a ceiling below the statement timeout, and a
// request above it is clamped to it.
func TestCheckpointCutShadowBudgetIsClamped(t *testing.T) {
	if api.MaxCheckpointShadowBudget >= 30*time.Second || api.DefaultCheckpointShadowBudget > api.MaxCheckpointShadowBudget {
		t.Fatalf("default %s and ceiling %s must sit below the 30 s statement timeout", api.DefaultCheckpointShadowBudget, api.MaxCheckpointShadowBudget)
	}
	s := api.New(mustCore(t), store.NewMem(), "k0").WithCheckpointShadowBudget(60 * time.Second)
	if got := s.ShadowBudgetForTest(); got != api.MaxCheckpointShadowBudget {
		t.Fatalf("effective budget %s after asking for 60s, want the ceiling %s", got, api.MaxCheckpointShadowBudget)
	}
	if api.DefaultCheckpointShadowBudget != 20*time.Second {
		t.Fatalf("default shadow budget %s, want 20s (the shadow runs outside the write lock, so the budget bounds one cut response and one pool connection, not a write stall)", api.DefaultCheckpointShadowBudget)
	}
	if got := api.New(mustCore(t), store.NewMem(), "k0").ShadowBudgetForTest(); got != api.DefaultCheckpointShadowBudget {
		t.Fatalf("default effective budget %s, want %s", got, api.DefaultCheckpointShadowBudget)
	}
}
