package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

// These tests cover the off-lock shadow: a due shadow runs on a read snapshot outside the project write lock and
// the compared bytes are signed under the lock after a base check (see shadowOffLock in checkpoint_cut.go).

type cutResult struct {
	cp  store.Checkpoint
	err error
}

func startCut(s *api.Server, ctx context.Context, project string) <-chan cutResult {
	out := make(chan cutResult, 1)
	go func() {
		cp, err := s.CutCheckpointForTest(ctx, project)
		out <- cutResult{cp, err}
	}()
	return out
}

func waitCut(t *testing.T, c <-chan cutResult) cutResult {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("cut did not finish")
		return cutResult{}
	}
}

func waitPaused(t *testing.T, p *pauseHook) {
	t.Helper()
	select {
	case <-p.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the shadow never reached its pause point")
	}
}

// writeWhilePaused does n writes, each inside a deadline: a write that waits on a lock held by the paused cut
// fails the test instead of hanging it.
func writeWhilePaused(t *testing.T, h *cutHistory, n int) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			h.plain()
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writes stalled while the shadow was running")
	}
}

func latestSeq(t *testing.T, st store.Store, project string) int64 {
	t.Helper()
	cp, ok, err := st.LatestCheckpoint(project)
	if err != nil || !ok {
		t.Fatalf("latest checkpoint: ok=%v err=%v", ok, err)
	}
	return cp.Seq
}

// sameBody asserts every field of the expected body is present, byte for byte, in the sealed checkpoint.
func sameBody(t *testing.T, sealed string, want map[string]any) {
	t.Helper()
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(sealed), &got); err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		w, _ := json.Marshal(v)
		if string(got[k]) != string(w) {
			t.Fatalf("signed body field %s = %s, want %s", k, got[k], w)
		}
	}
}

func runOffLockWritesContinue(t *testing.T, r *shadowRig) {
	r.h.plain()
	exp, full, _ := bothBodies(t, r.s, r.st, "p") // the body of seq 1 at the lock state before the cut, same fixed clock
	bodiesEqual(t, exp, full, "before the cut")
	r.spy.pause = newPauseHook()
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	before, _ := r.st.RecordCount("p")
	writeWhilePaused(t, r.h, 20)
	if got := latestSeq(t, r.st, "p"); got != 0 {
		t.Fatalf("a checkpoint was stored before the comparison finished: latest seq %d, want 0", got)
	}
	close(r.spy.pause.release)
	out := waitCut(t, res)
	if out.err != nil || out.cp.Seq != 1 {
		t.Fatalf("cut: seq %d err %v, want seq 1", out.cp.Seq, out.err)
	}
	sameBody(t, out.cp.JSON, exp) // the snapshot's record_count, not the count after the 20 writes
	after, _ := r.st.RecordCount("p")
	if after != before+20 {
		t.Fatalf("record count %d, want %d", after, before+20)
	}
	if _, _, checks, mism := r.s.CutStatsForTest(); checks != 1 || mism != 0 {
		t.Fatalf("checks %d mismatches %d, want 1 and 0", checks, mism)
	}
	if r.s.CutGateCountForTest() != 0 {
		t.Fatal("cut gate leaked")
	}
	// The next cut covers everything and still agrees with the full computation.
	cp, err := r.cut()
	if err != nil || cp.Seq != 2 || !strings.Contains(cp.JSON, `"record_count":`+itoa(int(after)+1)) {
		t.Fatalf("next cut: seq %d err %v json %s", cp.Seq, err, cp.JSON)
	}
	inc, full2, _ := bothBodies(t, r.s, r.st, "p")
	bodiesEqual(t, inc, full2, "after the next cut")
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// TestCheckpointCutShadowOffLockWritesContinue: while a shadow is in flight writes complete, nothing is signed
// before the comparison finishes, and the signed checkpoint is the compared body of the snapshot.
func TestCheckpointCutShadowOffLockWritesContinue(t *testing.T) {
	runOffLockWritesContinue(t, newShadowRig(t, 5*time.Second))
}

// TestCheckpointCutShadowOffLockMismatchRefusesWhileWritesContinue: a tampered base is refused after the
// off-lock comparison, nothing is stored, and the next cut is shadowed (latched).
func TestCheckpointCutShadowOffLockMismatchRefusesWhileWritesContinue(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	r.h.plain()
	r.spy.tamper = bogusBase("p")
	r.spy.pause = newPauseHook()
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	writeWhilePaused(t, r.h, 10)
	close(r.spy.pause.release)
	out := waitCut(t, res)
	if out.err == nil || !strings.Contains(out.err.Error(), "disagrees with the full computation") {
		t.Fatalf("want a refusal, got %v", out.err)
	}
	if got := latestSeq(t, r.st, "p"); got != 0 {
		t.Fatalf("a divergent checkpoint was stored: latest seq %d", got)
	}
	if _, _, checks, mism := r.s.CutStatsForTest(); checks != 1 || mism != 1 {
		t.Fatalf("checks %d mismatches %d, want 1 and 1", checks, mism)
	}
	if _, err := r.cut(); err == nil { // latched: shadowed again, still tampered, refused again
		t.Fatal("the next cut must be shadowed and refused")
	}
	if _, _, checks, mism := r.s.CutStatsForTest(); checks != 2 || mism != 2 {
		t.Fatalf("checks %d mismatches %d after the next cut, want 2 and 2", checks, mism)
	}
}

// TestCheckpointCutShadowOffLockRacedByAnotherWriter: another writer process (a second server over the same
// store) cuts the seq while this shadow runs. This cut signs nothing, and the chain keeps one checkpoint per seq.
func TestCheckpointCutShadowOffLockRacedByAnotherWriter(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	r.h.plain()
	r.spy.pause = newPauseHook()
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	other := api.New(mustCore(t), r.st, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowEvery(1 << 30).
		WithClock(func() time.Time { return r.now })
	ocp, err := other.CutCheckpointForTest(context.Background(), "p")
	if err != nil || ocp.Seq != 1 {
		t.Fatalf("other writer cut: seq %d err %v", ocp.Seq, err)
	}
	close(r.spy.pause.release)
	out := waitCut(t, res)
	if !api.IsShadowRacedForTest(out.err) {
		t.Fatalf("want the raced refusal, got %v", out.err)
	}
	cps, err := r.st.Checkpoints("p")
	if err != nil || len(cps) != 2 || cps[1].Seq != 1 || cps[1].CheckpointHash != ocp.CheckpointHash {
		t.Fatalf("chain forked or changed: %d checkpoints, err %v", len(cps), err)
	}
	if _, _, checks, mism := r.s.CutStatsForTest(); checks != 1 || mism != 0 {
		t.Fatalf("checks %d mismatches %d, want 1 and 0", checks, mism)
	}
	if r.s.ShadowRacedForTest() != 1 {
		t.Fatalf("raced counter %d, want 1", r.s.ShadowRacedForTest())
	}
}

// TestCheckpointCutShadowOffLockSameProcessCutsWait: a second cut of the same project in this process waits on
// the gate during the shadow, then cuts the next seq. Without the gate it would sign seq 1 first and race the
// first cut.
func TestCheckpointCutShadowOffLockSameProcessCutsWait(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	r.h.plain()
	r.spy.pause = newPauseHook()
	a := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	b := startCut(r.s, context.Background(), "p")
	select {
	case <-b:
		t.Fatal("the second cut did not wait for the gate")
	case <-time.After(200 * time.Millisecond):
	}
	if got := latestSeq(t, r.st, "p"); got != 0 {
		t.Fatalf("latest seq %d while the first shadow runs, want 0", got)
	}
	close(r.spy.pause.release)
	ra, rb := waitCut(t, a), waitCut(t, b)
	if ra.err != nil || rb.err != nil || ra.cp.Seq != 1 || rb.cp.Seq != 2 {
		t.Fatalf("cuts: %d/%v and %d/%v, want seqs 1 and 2", ra.cp.Seq, ra.err, rb.cp.Seq, rb.err)
	}
	if r.s.CutGateCountForTest() != 0 {
		t.Fatal("cut gate leaked")
	}
}

// TestCheckpointCutShadowOffLockGateWaitIsCancellable: a cut waiting for the gate gives up with its context and
// leaves no gate entry behind.
func TestCheckpointCutShadowOffLockGateWaitIsCancellable(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	r.h.plain()
	r.spy.pause = newPauseHook()
	a := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := r.s.CutCheckpointForTest(ctx, "p"); err == nil {
		t.Fatal("a cut waiting on the gate must fail with its context")
	}
	close(r.spy.pause.release)
	if out := waitCut(t, a); out.err != nil {
		t.Fatal(out.err)
	}
	if r.s.CutGateCountForTest() != 0 {
		t.Fatal("cut gate leaked")
	}
}

// TestCheckpointCutShadowOffLockClientCancel: a client that hangs up mid-shadow does not turn the shadow into a
// failed one (it runs detached), and the cut stores nothing.
func TestCheckpointCutShadowOffLockClientCancel(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	r.h.plain()
	r.spy.pause = newPauseHook()
	ctx, cancel := context.WithCancel(context.Background())
	res := startCut(r.s, ctx, "p")
	waitPaused(t, r.spy.pause)
	cancel()
	close(r.spy.pause.release)
	out := waitCut(t, res)
	if out.err == nil {
		t.Fatal("a cancelled cut must return an error")
	}
	if got := latestSeq(t, r.st, "p"); got != 0 {
		t.Fatalf("a checkpoint was stored by a cancelled cut: latest seq %d", got)
	}
	if r.s.ShadowFailedForTest() != 0 {
		t.Fatalf("a client hang-up counted as a failed shadow: %d", r.s.ShadowFailedForTest())
	}
	if r.s.CutGateCountForTest() != 0 {
		t.Fatal("cut gate leaked")
	}
}

// TestCheckpointCutInTxShadowDueWritesNothing: phase 1 inside a write transaction, with a shadow due, returns the
// internal sentinel and stores nothing.
func TestCheckpointCutInTxShadowDueWritesNothing(t *testing.T) {
	r := newShadowRig(t, time.Second)
	r.h.plain()
	var gotErr error
	_ = r.st.WithProjectWrite(context.Background(), "p", func(b store.Store) error {
		_, gotErr = r.s.CreateCheckpointTxForTest(b, "p")
		return gotErr
	})
	if !api.IsShadowDueForTest(gotErr) {
		t.Fatalf("want the shadow-due sentinel, got %v", gotErr)
	}
	if got := latestSeq(t, r.st, "p"); got != 0 {
		t.Fatalf("phase 1 stored a checkpoint: latest seq %d", got)
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 0 {
		t.Fatalf("phase 1 counted a shadow check: %d", checks)
	}
}

// TestCheckpointCutShadowOffLockConcurrentWritersRace hammers writes while repeated shadowed cuts run, for the
// race detector, and checks the chain and the next cut stay consistent.
func TestCheckpointCutShadowOffLockConcurrentWritersRace(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				r.h.plain()
			}
		}
	}()
	for i := 0; i < 6; i++ {
		if _, err := r.s.CutCheckpointForTest(context.Background(), "p"); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("cut %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	if _, _, _, mism := r.s.CutStatsForTest(); mism != 0 {
		t.Fatalf("mismatches %d under concurrent writes, want 0", mism)
	}
	if _, err := r.cut(); err != nil {
		t.Fatal(err)
	}
	inc, full, _ := bothBodies(t, r.s, r.st, "p")
	bodiesEqual(t, inc, full, "after the hammer")
}

// TestCheckpointCutShadowOffLockWritesContinuePostgres: the same on the real store, where the shadow runs in a
// repeatable-read read-only transaction under a statement-timeout savepoint and writes take the project guard.
// Skips without AVERIN_TEST_DATABASE_URL.
func TestCheckpointCutShadowOffLockWritesContinuePostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	runOffLockWritesContinue(t, newShadowRigOn(t, pg, 5*time.Second))
}

// TestCheckpointCutShadowOffLockRacedByAnotherWriterPostgres: another writer cuts the seq during the shadow; the
// (project, seq) key and the phase 3 base check leave one checkpoint per seq.
func TestCheckpointCutShadowOffLockRacedByAnotherWriterPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	r := newShadowRigOn(t, pg, 5*time.Second)
	r.h.plain()
	r.spy.pause = newPauseHook()
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	other := api.New(mustCore(t), pg, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowEvery(1 << 30).
		WithClock(func() time.Time { return r.now })
	if cp, err := other.CutCheckpointForTest(context.Background(), "p"); err != nil || cp.Seq != 1 {
		t.Fatalf("other writer cut: seq %d err %v", cp.Seq, err)
	}
	close(r.spy.pause.release)
	if out := waitCut(t, res); !api.IsShadowRacedForTest(out.err) {
		t.Fatalf("want the raced refusal, got %v", out.err)
	}
	cps, err := pg.Checkpoints("p")
	if err != nil || len(cps) != 2 {
		t.Fatalf("%d checkpoints, err %v, want 2", len(cps), err)
	}
}
