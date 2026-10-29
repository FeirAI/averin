package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
	"github.com/feirai/averin/server/internal/witness"
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

// armPause makes a pause hook that is released when the test ends, pass or fail, so a failing assertion never leaves
// a cut parked in the hook (and the test binary hanging until go test's own timeout).
func armPause(t *testing.T) *pauseHook {
	p := newPauseHook()
	t.Cleanup(p.let)
	return p
}

// cutWithin runs a cut of the project on s and fails the test if it has not returned within d.
func cutWithin(t *testing.T, s *api.Server, ctx context.Context, d time.Duration) cutResult {
	t.Helper()
	c := startCut(s, ctx, "p")
	select {
	case r := <-c:
		return r
	case <-time.After(d):
		t.Fatalf("a cut did not return within %s", d)
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
	r.spy.pause = armPause(t)
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	before, _ := r.st.RecordCount("p")
	writeWhilePaused(t, r.h, 20)
	if got := latestSeq(t, r.st, "p"); got != 0 {
		t.Fatalf("a checkpoint was stored before the comparison finished: latest seq %d, want 0", got)
	}
	r.spy.pause.let()
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
	r.spy.pause = armPause(t)
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	writeWhilePaused(t, r.h, 10)
	r.spy.pause.let()
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
	r.s.WithCheckpointShadowEvery(1 << 30) // only the first-cut rule can make a later cut shadowed
	r.h.plain()
	r.spy.pause = armPause(t)
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	other := api.New(mustCore(t), r.st, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowEvery(1 << 30).
		WithClock(func() time.Time { return r.now })
	o := cutWithin(t, other, context.Background(), 5*time.Second)
	ocp := o.cp
	if o.err != nil || ocp.Seq != 1 {
		t.Fatalf("other writer cut: seq %d err %v", ocp.Seq, o.err)
	}
	r.spy.pause.let()
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
	// The matching comparison was against a base another writer replaced: it must not count as this project's
	// first-cut check, so the next cut is shadowed again.
	if _, err := r.cut(); err != nil {
		t.Fatal(err)
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 2 {
		t.Fatalf("checks %d after the next cut, want 2 (the raced cut must not mark the project verified)", checks)
	}
}

// TestCheckpointCutShadowOffLockSameProcessCutsWait: a second cut of the same project in this process waits on
// the gate during the shadow, then cuts the next seq. Without the gate it would sign seq 1 first and race the
// first cut.
func TestCheckpointCutShadowOffLockSameProcessCutsWait(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	r.h.plain()
	r.spy.pause = armPause(t)
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
	r.spy.pause.let()
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
	r.spy.pause = armPause(t)
	a := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if p := cutWithin(t, r.s, ctx, 5*time.Second); p.err == nil {
		t.Fatal("a cut waiting on the gate must fail with its context")
	}
	r.spy.pause.let()
	if out := waitCut(t, a); out.err != nil {
		t.Fatal(out.err)
	}
	if r.s.CutGateCountForTest() != 0 {
		t.Fatal("cut gate leaked")
	}
}

// TestCheckpointCutShadowOffLockClientCancel: a client that hangs up mid-shadow neither turns the shadow into a
// failed one (it runs detached) nor discards the matched comparison: the signing step does not follow the caller's
// cancellation, so the cut stores the compared body.
func TestCheckpointCutShadowOffLockClientCancel(t *testing.T) {
	runOffLockClientCancel(t, newShadowRig(t, 5*time.Second))
}

// TestCheckpointCutShadowOffLockClientCancelPostgres: the same on the real store. On Mem the read snapshot and
// WithBudget never look at the context, so only Postgres proves the shadow's context is detached from the client's
// (a hang-up must not turn the shadow into a failed one). Skips without AVERIN_TEST_DATABASE_URL.
func TestCheckpointCutShadowOffLockClientCancelPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	runOffLockClientCancel(t, newShadowRigOn(t, pg, 5*time.Second))
}

func runOffLockClientCancel(t *testing.T, r *shadowRig) {
	r.h.plain()
	exp, _, _ := bothBodies(t, r.s, r.st, "p") // the body of seq 1 at the lock state before the cut, same fixed clock
	r.spy.pause = armPause(t)
	ctx, cancel := context.WithCancel(context.Background())
	res := startCut(r.s, ctx, "p")
	waitPaused(t, r.spy.pause)
	cancel() // the client hangs up after the comparison has started
	r.spy.pause.let()
	out := waitCut(t, res)
	if out.err != nil || out.cp.Seq != 1 {
		t.Fatalf("a cut whose client hung up mid-shadow: seq %d err %v, want seq 1 stored", out.cp.Seq, out.err)
	}
	if got := latestSeq(t, r.st, "p"); got != 1 {
		t.Fatalf("no checkpoint was stored after the client hung up: latest seq %d, want 1", got)
	}
	sameBody(t, out.cp.JSON, exp) // exactly the compared body
	if _, _, checks, mism := r.s.CutStatsForTest(); checks != 1 || mism != 0 {
		t.Fatalf("checks %d mismatches %d, want 1 and 0", checks, mism)
	}
	if r.s.ShadowFailedForTest() != 0 {
		t.Fatalf("a client hang-up counted as a failed shadow: %d", r.s.ShadowFailedForTest())
	}
	if r.s.CutGateCountForTest() != 0 {
		t.Fatal("cut gate leaked")
	}
}

// captureLog routes the standard logger to a mutex-guarded buffer until the test ends. The api package runs no
// test in parallel, so the global writer is safe to swap.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	oldWriter, oldFlags, oldPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(lockedWriter{&mu, &buf})
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})
	return func() string { mu.Lock(); defer mu.Unlock(); return buf.String() }
}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// TestCheckpointCutShadowOffLockClientCancelWitnessedAndAnchored: a client that hangs up mid-shadow still gets the
// stored checkpoint witnessed and anchored (the witness append and the TSA stamp are detached from the caller too).
func TestCheckpointCutShadowOffLockClientCancelWitnessedAndAnchored(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	w := witness.NewMemWitness()
	r.s.WithWitness(w).WithTSA(witness.StubTSA{})
	r.h.plain()
	r.spy.pause = armPause(t)
	ctx, cancel := context.WithCancel(context.Background())
	type created struct {
		sealed      string
		warn, fatal error
	}
	done := make(chan created, 1)
	go func() {
		sealed, warn, fatal := r.s.CreateCheckpointForTest(ctx, "p")
		done <- created{sealed, warn, fatal}
	}()
	waitPaused(t, r.spy.pause)
	cancel()
	r.spy.pause.let()
	var out created
	select {
	case out = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("checkpoint creation did not finish")
	}
	if out.fatal != nil || out.warn != nil {
		t.Fatalf("create after a hang-up: warn %v fatal %v, want neither", out.warn, out.fatal)
	}
	got, err := w.List(context.Background(), "p")
	if err != nil || len(got) != 1 || string(got[0]) != out.sealed {
		t.Fatalf("witness holds %d entries (err %v), want exactly the new checkpoint", len(got), err)
	}
	anchors, err := r.st.Anchors("p")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := anchors[1]; !ok {
		t.Fatalf("seq 1 was not anchored after the hang-up: anchors %v", anchors)
	}
}

// TestCheckpointCutShadowOffLockSignStepIsBounded: the signing step has its own bound. With the full computation
// unable to run (the could-not-run path) and the project write lock held elsewhere, phase 3 gives up after the
// bound, nothing is stored, the shadow's counter is not undone, and a WARNING line follows the earlier ALERT.
func TestCheckpointCutShadowOffLockSignStepIsBounded(t *testing.T) {
	if got := api.New(mustCore(t), store.NewMem(), "k0").CutSignTimeoutForTest(); got != 15*time.Second {
		t.Fatalf("default signing bound %s, want 15s (docs/dev/API.md states it)", got)
	}
	logs := captureLog(t)
	r := newShadowRig(t, 5*time.Second)
	r.s.WithCutSignTimeoutForTest(200 * time.Millisecond)
	r.spy.failFull = errors.New("read project snapshot: connection reset")
	r.h.plain()
	r.spy.pause = armPause(t)
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	held, unblock := make(chan struct{}), make(chan struct{})
	holderDone := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(func() { release(); <-holderDone })
	go func() {
		defer close(holderDone)
		_ = r.st.WithProjectWrite(context.Background(), "p", func(store.Store) error {
			close(held)
			<-unblock
			return errors.New("test: lock released")
		})
	}()
	<-held
	r.spy.pause.let()
	var out cutResult
	select {
	case out = <-res:
	case <-time.After(5 * time.Second):
		t.Fatal("the signing step did not give up within its bound")
	}
	if !errors.Is(out.err, context.DeadlineExceeded) {
		t.Fatalf("want the signing step's deadline, got %v", out.err)
	}
	release()
	if got := latestSeq(t, r.st, "p"); got != 0 {
		t.Fatalf("a checkpoint was stored by a cut whose signing step timed out: latest seq %d", got)
	}
	if r.s.CutGateCountForTest() != 0 {
		t.Fatal("cut gate leaked")
	}
	if r.s.ShadowFailedForTest() != 1 {
		t.Fatalf("failed counter %d, want 1 (recorded before signing, not undone)", r.s.ShadowFailedForTest())
	}
	text := logs()
	alert := strings.Index(text, "ALERT: checkpoint cut for project p signed WITHOUT its shadow check")
	warn := strings.Index(text, "WARNING: checkpoint cut for project p failed at the signing step after its shadow check")
	if alert < 0 || warn < alert {
		t.Fatalf("want the could-not-run ALERT and then the signing WARNING, got:\n%s", text)
	}
	if !strings.Contains(text[warn:], "(the earlier ALERT said this cut was signed WITHOUT its shadow check)") {
		t.Fatalf("the WARNING lacks the could-not-run note:\n%s", text)
	}
	if strings.Count(text, "ALERT:") != 1 {
		t.Fatalf("the signing failure must not log a second ALERT:\n%s", text)
	}
	// Inside the backoff the next cut is signed unshadowed.
	r.spy.failFull = nil
	cp, err := r.cut()
	if err != nil || cp.Seq != 1 {
		t.Fatalf("next cut: seq %d err %v, want seq 1", cp.Seq, err)
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 1 {
		t.Fatalf("checks %d after the next cut, want 1 (backoff, unshadowed)", checks)
	}
}

// TestCheckpointCutShadowOffLockRacedBeforeSnapshot: another writer cuts between phase 1 and the snapshot. The
// snapshot's first read sees a base that is not the one phase 1 decided on, so the cut is abandoned before the full
// computation runs: the raced counter moves and no shadow check is counted.
func TestCheckpointCutShadowOffLockRacedBeforeSnapshot(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	r.s.WithCheckpointShadowEvery(1 << 30) // only the first-cut rule can make a later cut shadowed
	r.h.plain()
	other := api.New(mustCore(t), r.st, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowEvery(1 << 30).
		WithClock(func() time.Time { return r.now })
	var once sync.Once
	var otherErr error
	var otherSeq int64
	r.spy.beforeSnap = func() {
		once.Do(func() {
			cp, err := other.CutCheckpointForTest(context.Background(), "p")
			otherSeq, otherErr = cp.Seq, err
		})
	}
	out := cutWithin(t, r.s, context.Background(), 5*time.Second)
	if otherErr != nil || otherSeq != 1 {
		t.Fatalf("other writer cut: seq %d err %v", otherSeq, otherErr)
	}
	if !api.IsShadowRacedForTest(out.err) {
		t.Fatalf("want the raced refusal, got %v", out.err)
	}
	if _, _, checks, mism := r.s.CutStatsForTest(); checks != 0 || mism != 0 {
		t.Fatalf("checks %d mismatches %d, want 0 and 0 (the full computation must not run on a moved base)", checks, mism)
	}
	if r.s.ShadowRacedForTest() != 1 || r.s.ShadowFailedForTest() != 0 {
		t.Fatalf("raced %d failed %d, want 1 and 0", r.s.ShadowRacedForTest(), r.s.ShadowFailedForTest())
	}
	cps, err := r.st.Checkpoints("p")
	if err != nil || len(cps) != 2 || cps[1].Seq != 1 {
		t.Fatalf("%d checkpoints, err %v, want seq 0 and the other writer's seq 1", len(cps), err)
	}
	cp, err := r.cut() // never verified: shadowed again, on the new base
	if err != nil || cp.Seq != 2 {
		t.Fatalf("next cut: seq %d err %v, want seq 2", cp.Seq, err)
	}
	if _, _, checks, _ := r.s.CutStatsForTest(); checks != 1 {
		t.Fatalf("checks %d after the next cut, want 1", checks)
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
	r.spy.pause = armPause(t)
	res := startCut(r.s, context.Background(), "p")
	waitPaused(t, r.spy.pause)
	other := api.New(mustCore(t), pg, "k0").WithAuth(auth.NewOpenStore()).WithCheckpointShadowEvery(1 << 30).
		WithClock(func() time.Time { return r.now })
	if o := cutWithin(t, other, context.Background(), 5*time.Second); o.err != nil || o.cp.Seq != 1 {
		t.Fatalf("other writer cut: seq %d err %v", o.cp.Seq, o.err)
	}
	r.spy.pause.let()
	if out := waitCut(t, res); !api.IsShadowRacedForTest(out.err) {
		t.Fatalf("want the raced refusal, got %v", out.err)
	}
	cps, err := pg.Checkpoints("p")
	if err != nil || len(cps) != 2 {
		t.Fatalf("%d checkpoints, err %v, want 2", len(cps), err)
	}
}

// TestCheckpointCutShadowOffLockCreatedTsAfterSnapshotRead: created_ts of a shadowed checkpoint is taken after the
// snapshot's first read, so it is not earlier than any commit in the snapshot. The hook moves the clock forward as
// the snapshot reads the latest checkpoint (a commit landing just before the snapshot); the signed created_ts must
// carry that later time.
func TestCheckpointCutShadowOffLockCreatedTsAfterSnapshotRead(t *testing.T) {
	r := newShadowRig(t, 5*time.Second)
	r.h.plain()
	var once sync.Once
	r.spy.onSnapLatest = func() { once.Do(func() { r.now = r.now.Add(time.Hour) }) }
	cp, err := r.s.CutCheckpointForTest(context.Background(), "p")
	if err != nil || cp.Seq != 1 {
		t.Fatalf("cut: seq %d err %v", cp.Seq, err)
	}
	var body struct {
		Created string `json:"created_ts"`
	}
	if err := json.Unmarshal([]byte(cp.JSON), &body); err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339Nano, body.Created)
	if err != nil {
		t.Fatal(err)
	}
	if want := r.now; got.Before(want) {
		t.Fatalf("created_ts %s is earlier than the clock at the snapshot's first read (%s)", got, want)
	}
}
