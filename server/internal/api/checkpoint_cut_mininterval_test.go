package api_test

import (
	"errors"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// defIval asks newMinRig to keep the default minimum interval.
const defIval = time.Duration(-1 << 62)

// minRig is a server whose scheduled shadow is due on every 3rd cut, over a movable clock. minIval == defIval keeps the
// default minimum interval.
type minRig struct {
	t   *testing.T
	st  store.Store
	spy *rowSpy
	s   *api.Server
	hs  map[string]*cutHistory
	now time.Time
}

func newMinRig(t *testing.T, minIval time.Duration, projects ...string) *minRig {
	st := store.NewMem()
	spy := newRowSpy(st)
	r := &minRig{t: t, st: st, spy: spy, hs: map[string]*cutHistory{}, now: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)}
	r.s = api.New(mustCore(t), spy, "k0").WithAuth(auth.NewOpenStore()).
		WithCheckpointShadowEvery(3).WithCheckpointShadowBackoff(10 * time.Minute).
		WithClock(func() time.Time { return r.now })
	if minIval != defIval {
		r.s.WithCheckpointShadowMinInterval(minIval)
	}
	for _, p := range projects {
		r.hs[p] = newCutHistory(t, st, p, 3)
		r.cut(p) // seq 0: the full computation, no shadow
	}
	return r
}

func (r *minRig) cut(p string) (store.Checkpoint, error) {
	r.t.Helper()
	r.hs[p].plain()
	return cutOnce(r.t, r.s, r.spy, p)
}

func (r *minRig) cuts(p string, n int) {
	r.t.Helper()
	for i := 0; i < n; i++ {
		if _, err := r.cut(p); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *minRig) checks() int64 { _, _, c, _ := r.s.CutStatsForTest(); return c }

// Seq 3 and 6 are both due within one hour: only the first-cut shadow (seq 1) runs, the due ones are rate-limited.
// After the interval the next due cut (seq 9) shadows.
func TestCheckpointCutShadowMinIntervalLimitsScheduled(t *testing.T) {
	r := newMinRig(t, defIval, "p")
	r.cuts("p", 1) // seq 1: first incremental cut, always shadowed
	if r.checks() != 1 {
		t.Fatalf("first incremental cut: checks %d, want 1", r.checks())
	}
	r.cuts("p", 5) // seq 2..6: seq 3 and 6 are due but inside the hour
	if r.checks() != 1 {
		t.Fatalf("due cuts inside the min interval must not shadow: checks %d, want 1", r.checks())
	}
	r.now = r.now.Add(api.DefaultCheckpointShadowMinInterval + time.Second)
	r.cuts("p", 3) // seq 7..9: seq 9 is due and the interval has passed
	if r.checks() != 2 {
		t.Fatalf("a due cut after the min interval must shadow: checks %d, want 2", r.checks())
	}
}

// The first incremental cut of another project shadows even right after a shadow of the first.
func TestCheckpointCutShadowMinIntervalFirstCutIsPerProject(t *testing.T) {
	r := newMinRig(t, defIval, "p", "q")
	r.cuts("p", 1)
	r.cuts("q", 1)
	if r.checks() != 2 {
		t.Fatalf("each project's first incremental cut shadows: checks %d, want 2", r.checks())
	}
}

// Once a mismatch has latched, every cut shadows whatever the interval says.
func TestCheckpointCutShadowMinIntervalLatchedIgnoresInterval(t *testing.T) {
	r := newMinRig(t, defIval, "p")
	r.spy.tamper = bogusBase("p")
	if _, err := r.cut("p"); err == nil {
		t.Fatal("first incremental cut over a tampered base must refuse")
	}
	r.spy.tamper = nil
	for i := 0; i < 4; i++ { // none of these is a due seq at the same time as the interval being open
		b := r.checks()
		_, _ = r.cut("p")
		if r.checks() != b+1 {
			t.Fatalf("latched: every cut must shadow (cut %d)", i)
		}
	}
}

// A min interval of 0 restores the old cadence: every due cut shadows.
func TestCheckpointCutShadowMinIntervalZeroDisables(t *testing.T) {
	r := newMinRig(t, 0, "p")
	r.cuts("p", 6) // seq 1 (first), 3, 6
	if r.checks() != 3 {
		t.Fatalf("min interval 0: checks %d, want 3", r.checks())
	}
}

// A negative value is 0, and a value above the default is clamped to the default.
func TestCheckpointCutShadowMinIntervalClamp(t *testing.T) {
	r := newMinRig(t, -time.Minute, "p")
	r.cuts("p", 6)
	if r.checks() != 3 {
		t.Fatalf("negative min interval must behave as 0: checks %d, want 3", r.checks())
	}
	r = newMinRig(t, 24*time.Hour, "p")
	r.cuts("p", 1)
	r.now = r.now.Add(api.DefaultCheckpointShadowMinInterval + time.Second)
	r.cuts("p", 2) // seq 3 is due; a 24 h request is clamped to 1 h, so it shadows
	if r.checks() != 2 {
		t.Fatalf("a 24h request must clamp to the default 1h: checks %d, want 2", r.checks())
	}
}

// A shadow that fails still sets the backoff, and the failed attempt counts toward the min interval.
func TestCheckpointCutShadowMinIntervalFailedAttemptCounts(t *testing.T) {
	r := newMinRig(t, defIval, "p")
	r.cuts("p", 1) // seq 1 verified, attempt at t0
	r.now = r.now.Add(api.DefaultCheckpointShadowMinInterval + time.Second)
	r.spy.failFull = errors.New("boom")
	r.cuts("p", 2) // seq 2 not due; seq 3 due and past the interval: shadow attempted, fails
	if r.checks() != 2 || r.s.ShadowFailedForTest() != 1 {
		t.Fatalf("checks %d failed %d, want 2 and 1", r.checks(), r.s.ShadowFailedForTest())
	}
	r.spy.failFull = nil
	r.now = r.now.Add(11 * time.Minute) // past the 10 min backoff, far inside the min interval
	r.cuts("p", 3)                      // seq 6 is due
	if r.checks() != 2 {
		t.Fatalf("the failed attempt must count toward the min interval: checks %d, want 2", r.checks())
	}
	r.now = r.now.Add(api.DefaultCheckpointShadowMinInterval)
	r.cuts("p", 3) // seq 9 is due, interval and backoff both passed
	if r.checks() != 3 {
		t.Fatalf("checks %d, want 3", r.checks())
	}
}

// The backoff itself still holds when the min interval is off.
func TestCheckpointCutShadowMinIntervalBackoffStillHolds(t *testing.T) {
	r := newMinRig(t, 0, "p")
	r.spy.failFull = errors.New("boom")
	r.cuts("p", 1) // seq 1: unverified, shadow attempted and fails
	r.cuts("p", 3) // inside the backoff, including the due seq 3
	if r.checks() != 1 {
		t.Fatalf("the backoff must still suppress attempts: checks %d, want 1", r.checks())
	}
}
