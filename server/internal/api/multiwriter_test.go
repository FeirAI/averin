package api_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/feirai/averin/server/internal/store"
)

// TestMultiWriterFailureMatrix is plan AVE-08's two-process failure matrix. Two (or three) real
// averin HTTP servers run as separate operating-system processes on one PostgreSQL schema. Each leg
// injects one failure at a named point of a project transaction (see multiwriter_child_test.go and
// multiwriter_proxy_test.go), then the trace monitor (multiwriter_monitor_test.go) checks the
// recorded run and the committed state against the ProjectTx invariants.
//
// Legs, with the question each answers:
//
//	same_nonce_two_processes        one capability, one nonce, eight racing uses over two processes: one admitted?
//	same_idempotency_key            one use request sent six times over two processes: one receipt?
//	revoke_waits_for_held_use       a use that already read "not revoked" is paused; does a revoke on the other process wait for it?
//	use_waits_for_uncommitted_revoke a revoke is paused before commit; does a use on the other process wait and then see it?
//	kill9_during_prepare            SIGKILL with the pending grant inserted, uncommitted; a waiter on the other process takes over?
//	kill9_during_finalize           SIGKILL with the grant record inserted, uncommitted; same
//	stranded_seq_recovery_while_other_writes recovery's terminal transaction is paused while the other process writes
//	stranded_seq_recovery_killed_between_fence_and_terminal the recovering process dies after the fence committed
//	lost_commit_ack_finalize|use|revoke COMMIT lost on the way back, cut before and after the server committed, then a retry on the other process
//	concurrent_checkpoints          checkpoints and grants from both processes at once
//
// Injection is a store wrapper in the test binary plus an in-test TCP proxy (no toxiproxy), so no
// fault point exists in the shipped server.
func TestMultiWriterFailureMatrix(t *testing.T) {
	legs := []struct {
		name string
		run  func(*testing.T, *mwEnv)
	}{
		{"same_nonce_two_processes", legSameNonce},
		{"same_idempotency_key", legSameIdempotencyKey},
		{"revoke_waits_for_held_use_prospective", func(t *testing.T, e *mwEnv) { legRevokeWaitsForHeldUse(t, e, "prospective") }},
		{"revoke_waits_for_held_use_total", func(t *testing.T, e *mwEnv) { legRevokeWaitsForHeldUse(t, e, "total") }},
		{"use_waits_for_uncommitted_revoke", legUseWaitsForUncommittedRevoke},
		{"kill9_during_prepare", legKillDuringPrepare},
		{"kill9_during_finalize", legKillDuringFinalize},
		{"stranded_seq_recovery_while_other_writes", legRecoveryWhileOtherWrites},
		{"stranded_seq_recovery_killed_between_fence_and_terminal", legRecoveryKilledBetweenTransactions},
		{"lost_commit_ack_finalize", legLostAckFinalize},
		{"lost_commit_ack_use", legLostAckUse},
		{"lost_commit_ack_revoke", legLostAckRevoke},
		{"concurrent_checkpoints", legConcurrentCheckpoints},
	}
	for _, leg := range legs {
		t.Run(leg.name, func(t *testing.T) { leg.run(t, newMWEnv(t)) })
	}
}

type mwEnv struct {
	t     *testing.T
	pg    *store.Postgres
	admin *pgxpool.Pool
	dsn   string
	dir   string
	tr    *mwTrace
	ak    ed25519.PrivateKey
}

func newMWEnv(t *testing.T) *mwEnv {
	t.Helper()
	pg, admin := newVoidTestPostgres(t)
	return &mwEnv{t: t, pg: pg, admin: admin, dsn: admin.Config().ConnConfig.ConnString(), dir: t.TempDir(), tr: &mwTrace{}, ak: grantAgentKey()}
}

// grant creates a finalized grant through process p (setup, not traced).
func (e *mwEnv) grant(p *projectTxProcess, idem string) (grantID, capability string) {
	e.t.Helper()
	finalize, _ := preparedProcessGrant(e.t, p, idem, e.ak)
	code, body := callProjectTxProcess(e.t, p, http.MethodPost, "/v2/grants/finalize", finalize)
	if code != http.StatusCreated {
		e.t.Fatalf("setup grant %s (%d): %s", idem, code, body)
	}
	return processGrantResult(e.t, body)
}

func (e *mwEnv) async(p *projectTxProcess, ev mwEvent, path, body string) <-chan mwEvent {
	ch := make(chan mwEvent, 1)
	go func() { ch <- e.tr.call(p, ev, path, body) }()
	return ch
}

// requireBlocked fails when ch answers within the window: the operation should be waiting for the
// project guard held by the paused transaction on the other process.
func (e *mwEnv) requireBlocked(ch <-chan mwEvent, what string) {
	e.t.Helper()
	select {
	case ev := <-ch:
		e.t.Fatalf("%s answered (%d, err %v) while the other process held the project guard: %s", what, ev.Code, ev.Err, clip(ev.Body))
	case <-time.After(1500 * time.Millisecond):
	}
}

func (e *mwEnv) await(ch <-chan mwEvent, what string) mwEvent {
	e.t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(60 * time.Second):
		e.t.Fatalf("%s never answered", what)
		return mwEvent{}
	}
}

func (e *mwEnv) useEvent(proc, grant, capability, idem, nonce string) (mwEvent, string) {
	return mwEvent{Proc: proc, Op: "use", Grant: grant, Nonce: nonce, Idem: idem}, useBody(e.t, idem, capability, grant, e.ak, "SELECT 1", nonce)
}

func (e *mwEnv) use(p *projectTxProcess, proc, grant, capability, idem, nonce string) mwEvent {
	ev, body := e.useEvent(proc, grant, capability, idem, nonce)
	return e.tr.call(p, ev, "/v2/use", body)
}

func (e *mwEnv) revoke(p *projectTxProcess, proc, grant, mode string) mwEvent {
	return e.tr.call(p, mwEvent{Proc: proc, Op: "revoke", Grant: grant, Mode: mode}, "/v2/revoke?project=p1", revokeBody(grant, mode))
}

func (e *mwEnv) revokeAsync(p *projectTxProcess, proc, grant, mode string) <-chan mwEvent {
	return e.async(p, mwEvent{Proc: proc, Op: "revoke", Grant: grant, Mode: mode}, "/v2/revoke?project=p1", revokeBody(grant, mode))
}

func (e *mwEnv) requireCode(ev mwEvent, want int, what string) {
	e.t.Helper()
	if ev.Err != nil || ev.Code != want {
		e.t.Fatalf("%s: want %d, got %d (err %v): %s", what, want, ev.Code, ev.Err, clip(ev.Body))
	}
}

func (e *mwEnv) requireUnavailable(ev mwEvent, what string) {
	e.t.Helper()
	if ev.Err != nil || ev.Code < 500 || ev.Code > 599 {
		e.t.Fatalf("%s: want a 5xx for an unknown commit outcome, got %d (err %v): %s", what, ev.Code, ev.Err, clip(ev.Body))
	}
}

func (e *mwEnv) orderNow() int64 { return guardOrder(e.t, e.admin) }

func (e *mwEnv) recordExists(idem string) (store.Record, bool) {
	e.t.Helper()
	rec, found, err := e.pg.RecordByIdem("p1", idem)
	if err != nil {
		e.t.Fatal(err)
	}
	return rec, found
}

// finish takes a checkpoint after every write has returned, then runs the monitor.
func (e *mwEnv) finish(p *projectTxProcess, proc string) {
	e.t.Helper()
	ev := e.tr.call(p, mwEvent{Proc: proc, Op: "checkpoint"}, "/v2/checkpoints?project=p1", "")
	e.requireCode(ev, http.StatusCreated, "final checkpoint")
	mwRequireClean(e.t, e.pg, e.admin, e.tr, true)
}

// clip keeps a failure message readable: sealed records run to several kilobytes.
func clip(s string) string {
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}

func ordinalOf(t *testing.T, ev mwEvent) int64 {
	t.Helper()
	o, _, ok := receiptOrder(t, responseRecord(t, ev.Body))
	if !ok {
		t.Fatalf("use reply carries no authorization order: %s", clip(ev.Body))
	}
	return o
}

func cutoffOf(t *testing.T, ev mwEvent) int64 {
	t.Helper()
	var r revokeReply
	if err := json.Unmarshal([]byte(ev.Body), &r); err != nil {
		t.Fatalf("revoke reply: %v %s", err, clip(ev.Body))
	}
	return r.CutoffOrder
}

// ---- concurrent use of one capability ---------------------------------------------------------

func legSameNonce(t *testing.T, e *mwEnv) {
	a, b := startMW(t, e.dsn, e.dir, mwFault{}), startMW(t, e.dsn, e.dir, mwFault{})
	grantID, capability := e.grant(a, "g-same-nonce")
	procs := []*projectTxProcess{a, b}
	names := []string{"A", "B"}
	const n = 8
	type req struct {
		ev   mwEvent
		body string
	}
	reqs := make([]req, n)
	for i := range reqs {
		ev, body := e.useEvent(names[i%2], grantID, capability, fmt.Sprintf("use-same-nonce-%d", i), "the-one-nonce")
		reqs[i] = req{ev, body}
	}
	results := make([]mwEvent, n)
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = e.tr.call(procs[i%2], reqs[i].ev, "/v2/use", reqs[i].body)
		}(i)
	}
	wg.Wait()
	admitted := 0
	for i, r := range results {
		switch {
		case r.Err == nil && r.Code == http.StatusCreated && !r.Idempotent:
			admitted++
		case r.Err == nil && r.Code == http.StatusBadRequest:
		default:
			t.Fatalf("use %d over process %s: want 201 or a 400 replay refusal, got %d (err %v): %s", i, r.Proc, r.Code, r.Err, clip(r.Body))
		}
	}
	if admitted != 1 {
		t.Fatalf("%d of %d racing uses of one nonce were admitted over two processes, want exactly 1", admitted, n)
	}
	var receipts int
	if err := e.admin.QueryRow(t.Context(), `SELECT count(*) FROM authorization_receipts WHERE grant_id=$1`, grantID).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("receipts for the grant: %d (err %v), want 1", receipts, err)
	}
	e.finish(b, "B")
}

func legSameIdempotencyKey(t *testing.T, e *mwEnv) {
	a, b := startMW(t, e.dsn, e.dir, mwFault{}), startMW(t, e.dsn, e.dir, mwFault{})
	grantID, capability := e.grant(b, "g-same-idem")
	procs := []*projectTxProcess{a, b}
	names := []string{"A", "B"}
	const n = 6
	ev, body := e.useEvent("A", grantID, capability, "use-one-identity", "nonce-one-identity")
	results := make([]mwEvent, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := ev
			c.Proc = names[i%2]
			results[i] = e.tr.call(procs[i%2], c, "/v2/use", body)
		}(i)
	}
	wg.Wait()
	fresh := 0
	for i, r := range results {
		if r.Err != nil || r.Code != http.StatusCreated {
			t.Fatalf("request %d of one use identity over %s: want 201, got %d (err %v): %s", i, r.Proc, r.Code, r.Err, clip(r.Body))
		}
		if !r.Idempotent {
			fresh++
		}
	}
	if fresh != 1 {
		t.Fatalf("%d replies claim to have created the receipt of one identity, want exactly 1", fresh)
	}
	var receipts int
	if err := e.admin.QueryRow(t.Context(), `SELECT count(*) FROM authorization_receipts WHERE grant_id=$1`, grantID).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("receipts for the grant: %d (err %v), want 1", receipts, err)
	}
	e.finish(a, "A")
}

// ---- revoke against use on the other process --------------------------------------------------

// legRevokeWaitsForHeldUse pauses a use on B after it read "not revoked" and before it commits.
// A revoke on A must not be acknowledged until that use has committed (the guard is held), and a
// use started after the acknowledgment must be refused. Without the guard the revoke is
// acknowledged at once, and the use then commits against a state it did not read.
func legRevokeWaitsForHeldUse(t *testing.T, e *mwEnv, mode string) {
	a := startMW(t, e.dsn, e.dir, mwFault{})
	setup := startMW(t, e.dsn, e.dir, mwFault{})
	grantID, capability := e.grant(setup, "g-revoke-vs-use-"+mode)
	b := startMWHold(t, e.dsn, e.dir, "use_after_revocation_read", grantID)
	useCh := e.async(b.projectTxProcess, mwEvent{Proc: "B", Op: "use", Grant: grantID, Nonce: "n-held", Idem: "use-held"}, "/v2/use",
		useBody(t, "use-held", capability, grantID, e.ak, "SELECT 1", "n-held"))
	b.waitReached(t)
	revCh := e.revokeAsync(a, "A", grantID, mode)
	e.requireBlocked(revCh, "revoke ("+mode+") on A")
	b.letGo(t)
	use := e.await(useCh, "held use")
	rev := e.await(revCh, "revoke")
	e.requireCode(use, http.StatusCreated, "held use")
	e.requireCode(rev, http.StatusCreated, "revoke after the held use")
	if mode == "prospective" {
		if o, c := ordinalOf(t, use), cutoffOf(t, rev); o >= c {
			t.Fatalf("held use has ordinal %d, not below the cutoff %d of the revoke that waited for it", o, c)
		}
	}
	late := e.use(a, "A", grantID, capability, "use-late-"+mode, "n-late-"+mode)
	if late.Err != nil || late.Code == http.StatusCreated || !strings.Contains(late.Body, "revoked") {
		t.Fatalf("a use after the acknowledged revoke was not refused as revoked: %d %s", late.Code, clip(late.Body))
	}
	e.finish(a, "A")
}

// legUseWaitsForUncommittedRevoke pauses a revoke on A with its event inserted and uncommitted. A use
// on B must wait for the guard and then be refused as revoked.
func legUseWaitsForUncommittedRevoke(t *testing.T, e *mwEnv) {
	b := startMW(t, e.dsn, e.dir, mwFault{})
	grantID, capability := e.grant(b, "g-use-vs-revoke")
	a := startMWHold(t, e.dsn, e.dir, "after_revocation_event", grantID)
	revCh := e.revokeAsync(a.projectTxProcess, "A", grantID, "prospective")
	a.waitReached(t)
	ev, body := e.useEvent("B", grantID, capability, "use-behind-revoke", "n-behind-revoke")
	useCh := e.async(b, ev, "/v2/use", body)
	e.requireBlocked(useCh, "use on B")
	a.letGo(t)
	rev := e.await(revCh, "revoke")
	use := e.await(useCh, "use behind the revoke")
	e.requireCode(rev, http.StatusCreated, "revoke")
	if use.Err != nil || use.Code == http.StatusCreated || !strings.Contains(use.Body, "revoked") {
		t.Fatalf("a use that waited for the revoke's guard was not refused as revoked: %d %s", use.Code, clip(use.Body))
	}
	e.finish(b, "B")
}

// ---- kill -9 ----------------------------------------------------------------------------------

func legKillDuringPrepare(t *testing.T, e *mwEnv) {
	b := startMW(t, e.dsn, e.dir, mwFault{})
	a := startMWHold(t, e.dsn, e.dir, "after_pending_put", "idem-prepare-killed")
	killed := sendProjectTxAsync(a.projectTxProcess, "/v2/grants/prepare", grantBody("idem-prepare-killed", "read:orders", e.ak, e.ak))
	a.waitReached(t)
	waiter := e.async(b, mwEvent{Proc: "B", Op: "prepare", Idem: "idem-prepare-waiter"}, "/v2/grants/prepare", grantBody("idem-prepare-waiter", "read:orders", e.ak, e.ak))
	e.requireBlocked(waiter, "prepare on B")
	a.stop() // SIGKILL: no rollback runs in the process, the database sees a dead client
	<-killed
	e.requireCode(e.await(waiter, "prepare waiting on the killed process"), http.StatusOK, "prepare on B after the kill")
	if _, found, err := e.pg.PendingGrant("p1", "idem-prepare-killed"); err != nil || found {
		t.Fatalf("pending grant of the killed prepare survived: found=%v err=%v", found, err)
	}
	// The same operation identity succeeds on the surviving process and finalizes.
	finalize, _ := preparedProcessGrant(t, b, "idem-prepare-killed", e.ak) // prepare retried on B, must be 200
	fin := e.tr.call(b, mwEvent{Proc: "B", Op: "finalize", Idem: "idem-prepare-killed"}, "/v2/grants/finalize", finalize)
	e.requireCode(fin, http.StatusCreated, "finalize of the retried prepare")
	e.finish(b, "B")
}

func legKillDuringFinalize(t *testing.T, e *mwEnv) {
	b := startMW(t, e.dsn, e.dir, mwFault{})
	killedFinalize, _ := preparedProcessGrant(t, b, "idem-finalize-killed", e.ak)
	waiterFinalize, _ := preparedProcessGrant(t, b, "idem-finalize-waiter", e.ak)
	a := startMWHold(t, e.dsn, e.dir, "after_put_record", "idem-finalize-killed")
	killed := sendProjectTxAsync(a.projectTxProcess, "/v2/grants/finalize", killedFinalize)
	a.waitReached(t)
	waiter := e.async(b, mwEvent{Proc: "B", Op: "finalize", Idem: "idem-finalize-waiter"}, "/v2/grants/finalize", waiterFinalize)
	e.requireBlocked(waiter, "finalize on B")
	a.stop()
	<-killed
	e.requireCode(e.await(waiter, "finalize waiting on the killed process"), http.StatusCreated, "finalize on B after the kill")
	if _, found := e.recordExists("idem-finalize-killed"); found {
		t.Fatal("record of the killed finalize survived")
	}
	retry := e.tr.call(b, mwEvent{Proc: "B", Op: "finalize", Idem: "idem-finalize-killed"}, "/v2/grants/finalize", killedFinalize)
	e.requireCode(retry, http.StatusCreated, "finalize retry on B")
	if retry.Created != true {
		t.Fatalf("retry of a rolled-back finalize reports created=false: %s", clip(retry.Body))
	}
	e.finish(b, "B")
}

// ---- stranded broker_seq recovery while the other process writes ------------------------------

func legRecoveryWhileOtherWrites(t *testing.T, e *mwEnv) {
	b := startMW(t, e.dsn, e.dir, mwFault{})
	if seq := reserveGrantSeq(t, e.pg, "stranded-while-writing"); seq != 1 {
		t.Fatalf("stranded reservation got seq %d, want 1", seq)
	}
	finalize, _ := preparedProcessGrant(t, b, "idem-written-during-recovery", e.ak)
	a := startMWHold(t, e.dsn, e.dir, "after_recovery_result_put", "")
	voidCh := e.async(a.projectTxProcess, mwEvent{Proc: "A", Op: "void"}, "/v2/broker-seq/void?project=p1", voidBody(1))
	a.waitReached(t)
	writeCh := e.async(b, mwEvent{Proc: "B", Op: "finalize", Idem: "idem-written-during-recovery"}, "/v2/grants/finalize", finalize)
	e.requireBlocked(writeCh, "finalize on B during recovery's terminal transaction")
	a.letGo(t)
	void := e.await(voidCh, "void")
	write := e.await(writeCh, "finalize")
	e.requireCode(void, http.StatusCreated, "void")
	if !strings.Contains(void.Body, `"outcome":"voided"`) {
		t.Fatalf("recovery did not void the stranded sequence: %s", clip(void.Body))
	}
	e.requireCode(write, http.StatusCreated, "finalize that waited for recovery")
	if res := reservation(t, e.pg, 1); !res.Voided {
		t.Fatalf("reservation 1 not voided: %+v", res)
	}
	e.finish(b, "B")
}

func legRecoveryKilledBetweenTransactions(t *testing.T, e *mwEnv) {
	b := startMW(t, e.dsn, e.dir, mwFault{})
	if seq := reserveGrantSeq(t, e.pg, "stranded-then-killed"); seq != 1 {
		t.Fatalf("stranded reservation got seq %d, want 1", seq)
	}
	finalize, _ := preparedProcessGrant(t, b, "idem-written-after-kill", e.ak)
	a := startMWHold(t, e.dsn, e.dir, "after_recovery_fence_commit", "")
	killed := sendProjectTxAsync(a.projectTxProcess, "/v2/broker-seq/void?project=p1", voidBody(1))
	a.waitReached(t)
	a.stop() // the fence is committed, the terminal transaction never ran
	<-killed
	if f, found, err := e.pg.RecoveryFenceAt("p1", 1); err != nil || !found || f.OperationID != "recovery-test-1" {
		t.Fatalf("fence did not survive the kill: %+v %v %v", f, found, err)
	}
	if _, found, err := e.pg.RecoveryResultAt("p1", 1); err != nil || found {
		t.Fatalf("terminal result exists after the kill: %v %v", found, err)
	}
	// The surviving process resumes the same operation while it also writes.
	voidCh := e.async(b, mwEvent{Proc: "B", Op: "void"}, "/v2/broker-seq/void?project=p1", voidBody(1))
	writeCh := e.async(b, mwEvent{Proc: "B", Op: "finalize", Idem: "idem-written-after-kill"}, "/v2/grants/finalize", finalize)
	e.requireCode(e.await(voidCh, "resumed void"), http.StatusCreated, "resumed void")
	e.requireCode(e.await(writeCh, "finalize beside the resumed void"), http.StatusCreated, "finalize beside the resumed void")
	if res := reservation(t, e.pg, 1); !res.Voided {
		t.Fatalf("reservation 1 not voided by the surviving process: %+v", res)
	}
	e.finish(b, "B")
}

// ---- lost COMMIT acknowledgment ---------------------------------------------------------------

// lostAckEnv is process A reaching PostgreSQL through the fault proxy, process B directly.
func (e *mwEnv) lostAckEnv(t *testing.T) (a, b *projectTxProcess, proxy *pgFaultProxy) {
	t.Helper()
	proxy, proxied := newPGFaultProxy(t, e.dsn)
	return startMW(t, proxied, e.dir, mwFault{}), startMW(t, e.dsn, e.dir, mwFault{}), proxy
}

func requireFired(t *testing.T, proxy *pgFaultProxy, what string) {
	t.Helper()
	if n := proxy.fired.Load(); n != 1 {
		t.Fatalf("%s: the proxy cut %d commits, want exactly 1", what, n)
	}
}

func legLostAckFinalize(t *testing.T, e *mwEnv) {
	a, b, proxy := e.lostAckEnv(t)

	// Cut before the server committed: nothing is durable and the retry is a fresh grant.
	finalize, _ := preparedProcessGrant(t, b, "idem-lost-before", e.ak)
	proxy.arm(pgCutBeforeCommit)
	cut := e.tr.call(a, mwEvent{Proc: "A", Op: "finalize", Idem: "idem-lost-before"}, "/v2/grants/finalize", finalize)
	e.requireUnavailable(cut, "finalize with the COMMIT cut before the server")
	requireFired(t, proxy, "finalize before")
	if _, found := e.recordExists("idem-lost-before"); found {
		t.Fatal("grant is durable although its COMMIT never reached the server")
	}
	if max, err := e.pg.MaxBrokerSeq("p1"); err != nil || max != 0 {
		t.Fatalf("broker_seq %d survived a rolled-back finalize (err %v)", max, err)
	}
	retry := e.tr.call(b, mwEvent{Proc: "B", Op: "finalize", Idem: "idem-lost-before"}, "/v2/grants/finalize", finalize)
	e.requireCode(retry, http.StatusCreated, "retry on B after the cut before the commit")
	if !retry.Created {
		t.Fatalf("retry after a rolled-back commit should create the grant: %s", clip(retry.Body))
	}

	// Cut after the server committed: the grant is durable, the retry returns it unchanged.
	finalize2, _ := preparedProcessGrant(t, b, "idem-lost-after", e.ak)
	proxy.arm(pgCutAfterCommit)
	cut = e.tr.call(a, mwEvent{Proc: "A", Op: "finalize", Idem: "idem-lost-after"}, "/v2/grants/finalize", finalize2)
	e.requireUnavailable(cut, "finalize with the acknowledgment lost after the server committed")
	requireFired(t, proxy, "finalize after")
	stored, found := e.recordExists("idem-lost-after")
	if !found {
		t.Fatal("grant is not durable although the server committed it")
	}
	seqBefore, err := e.pg.MaxBrokerSeq("p1")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		proc  string
		proc_ *projectTxProcess
	}{{"B", b}, {"A", a}} {
		again := e.tr.call(p.proc_, mwEvent{Proc: p.proc, Op: "finalize", Idem: "idem-lost-after"}, "/v2/grants/finalize", finalize2)
		e.requireCode(again, http.StatusCreated, "retry on "+p.proc+" after the lost acknowledgment")
		if again.Created || !strings.Contains(again.Body, stored.ContentHash) {
			t.Fatalf("retry on %s did not return the committed grant unchanged: %s", p.proc, clip(again.Body))
		}
	}
	if seqAfter, err := e.pg.MaxBrokerSeq("p1"); err != nil || seqAfter != seqBefore {
		t.Fatalf("retries after the lost acknowledgment moved broker_seq from %d to %d (err %v)", seqBefore, seqAfter, err)
	}
	e.finish(b, "B")
}

func legLostAckUse(t *testing.T, e *mwEnv) {
	a, b, proxy := e.lostAckEnv(t)
	grantID, capability := e.grant(b, "g-lost-ack-use-before")
	grantAfter, capAfter := e.grant(b, "g-lost-ack-use-after") // a capability is single-use: the retry above spends the first one

	// Cut before: no receipt and no ordinal is burned; the retry takes the next ordinal.
	order0 := e.orderNow()
	ev, body := e.useEvent("A", grantID, capability, "use-lost-before", "n-lost-before")
	proxy.arm(pgCutBeforeCommit)
	cut := e.tr.call(a, ev, "/v2/use", body)
	e.requireUnavailable(cut, "use with the COMMIT cut before the server")
	requireFired(t, proxy, "use before")
	if _, found := e.recordExists("use-lost-before"); found {
		t.Fatal("receipt is durable although its COMMIT never reached the server")
	}
	if n := e.orderNow(); n != order0 {
		t.Fatalf("authorization order moved from %d to %d across a rolled-back use", order0, n)
	}
	ev.Proc = "B"
	retry := e.tr.call(b, ev, "/v2/use", body)
	e.requireCode(retry, http.StatusCreated, "retry on B after the cut before the commit")
	if retry.Idempotent || ordinalOf(t, retry) != order0+1 {
		t.Fatalf("retry after a rolled-back use: idempotent=%v ordinal=%d, want a fresh receipt at %d", retry.Idempotent, ordinalOf(t, retry), order0+1)
	}

	// Cut after: the receipt is durable, the nonce is spent, the retry returns the same receipt.
	ev2, body2 := e.useEvent("A", grantAfter, capAfter, "use-lost-after", "n-lost-after")
	proxy.arm(pgCutAfterCommit)
	cut = e.tr.call(a, ev2, "/v2/use", body2)
	e.requireUnavailable(cut, "use with the acknowledgment lost after the server committed")
	requireFired(t, proxy, "use after")
	stored, found := e.recordExists("use-lost-after")
	if !found {
		t.Fatal("receipt is not durable although the server committed it")
	}
	order1 := e.orderNow()
	for _, p := range []struct {
		proc  string
		proc_ *projectTxProcess
	}{{"B", b}, {"A", a}} {
		ev2.Proc = p.proc
		again := e.tr.call(p.proc_, ev2, "/v2/use", body2)
		e.requireCode(again, http.StatusCreated, "retry on "+p.proc+" after the lost acknowledgment")
		if !again.Idempotent || !strings.Contains(again.Body, stored.ContentHash) {
			t.Fatalf("retry on %s did not return the committed receipt: %s", p.proc, clip(again.Body))
		}
	}
	if n := e.orderNow(); n != order1 {
		t.Fatalf("retries moved the authorization order from %d to %d", order1, n)
	}
	e.finish(b, "B")
}

func legLostAckRevoke(t *testing.T, e *mwEnv) {
	a, b, proxy := e.lostAckEnv(t)
	gBefore, capBefore := e.grant(b, "g-lost-revoke-before")
	gAfter, capAfter := e.grant(b, "g-lost-revoke-after")

	// Cut before: the grant is still usable and the retry allocates the next cutoff.
	order0 := e.orderNow()
	proxy.arm(pgCutBeforeCommit)
	cut := e.revoke(a, "A", gBefore, "prospective")
	e.requireUnavailable(cut, "revoke with the COMMIT cut before the server")
	requireFired(t, proxy, "revoke before")
	if revoked, err := e.pg.IsRevoked("p1", gBefore); err != nil || revoked {
		t.Fatalf("grant is revoked although the revoke's COMMIT never reached the server: %v %v", revoked, err)
	}
	if n := e.orderNow(); n != order0 {
		t.Fatalf("authorization order moved from %d to %d across a rolled-back revoke", order0, n)
	}
	retry := e.revoke(b, "B", gBefore, "prospective")
	e.requireCode(retry, http.StatusCreated, "revoke retry on B")
	if !retry.Created || cutoffOf(t, retry) != order0+1 {
		t.Fatalf("retry after a rolled-back revoke: created=%v cutoff=%d, want a fresh event at %d: %s", retry.Created, cutoffOf(t, retry), order0+1, clip(retry.Body))
	}
	if late := e.use(a, "A", gBefore, capBefore, "use-after-revoke-before", "n-after-revoke-before"); late.Err != nil || late.Code == http.StatusCreated {
		t.Fatalf("use of a revoked grant admitted on A: %d %s", late.Code, clip(late.Body))
	}

	// Cut after: the event is durable, the retry returns the same cutoff, no second ordinal.
	proxy.arm(pgCutAfterCommit)
	cut = e.revoke(a, "A", gAfter, "prospective")
	e.requireUnavailable(cut, "revoke with the acknowledgment lost after the server committed")
	requireFired(t, proxy, "revoke after")
	events, err := e.pg.RevocationEvents("p1")
	if err != nil {
		t.Fatal(err)
	}
	var cutoff int64
	for _, ev := range events {
		if ev.GrantID == gAfter {
			cutoff = ev.CutoffOrder
		}
	}
	if cutoff == 0 {
		t.Fatalf("revocation of %s is not durable although the server committed it: %+v", gAfter, events)
	}
	order1 := e.orderNow()
	for _, p := range []struct {
		proc  string
		proc_ *projectTxProcess
	}{{"B", b}, {"A", a}} {
		again := e.revoke(p.proc_, p.proc, gAfter, "prospective")
		e.requireCode(again, http.StatusCreated, "revoke retry on "+p.proc)
		if again.Created || cutoffOf(t, again) != cutoff {
			t.Fatalf("retry on %s: created=%v cutoff=%d, want the committed cutoff %d unchanged", p.proc, again.Created, cutoffOf(t, again), cutoff)
		}
	}
	if n := e.orderNow(); n != order1 {
		t.Fatalf("revoke retries moved the authorization order from %d to %d", order1, n)
	}
	if late := e.use(b, "B", gAfter, capAfter, "use-after-revoke-after", "n-after-revoke-after"); late.Err != nil || late.Code == http.StatusCreated {
		t.Fatalf("use of a revoked grant admitted on B: %d %s", late.Code, clip(late.Body))
	}
	e.finish(b, "B")
}

// ---- checkpoints from both processes ----------------------------------------------------------

func legConcurrentCheckpoints(t *testing.T, e *mwEnv) {
	a, b := startMW(t, e.dsn, e.dir, mwFault{}), startMW(t, e.dsn, e.dir, mwFault{})
	procs := []*projectTxProcess{a, b}
	names := []string{"A", "B"}
	finalizes := make([]string, 4)
	for i := range finalizes {
		finalizes[i], _ = preparedProcessGrant(t, procs[i%2], fmt.Sprintf("idem-cp-%d", i), e.ak)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	checkpointsOK := 0
	for i := range finalizes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := e.tr.call(procs[i%2], mwEvent{Proc: names[i%2], Op: "finalize", Idem: fmt.Sprintf("idem-cp-%d", i)}, "/v2/grants/finalize", finalizes[i])
			if ev.Err != nil || ev.Code != http.StatusCreated {
				t.Errorf("finalize %d: %d (err %v): %s", i, ev.Code, ev.Err, ev.Body)
			}
		}(i)
	}
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := e.tr.call(procs[i%2], mwEvent{Proc: names[i%2], Op: "checkpoint"}, "/v2/checkpoints?project=p1", "")
			// A checkpoint may be refused while a grant is between its sequence reservation and its
			// record (fail closed); a refusal is not a violation, a wrong checkpoint is.
			if ev.Err == nil && ev.Code == http.StatusCreated {
				mu.Lock()
				checkpointsOK++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	if checkpointsOK == 0 {
		t.Fatal("no concurrent checkpoint succeeded; the leg did not exercise concurrent checkpoint creation")
	}
	e.finish(b, "B")
}
