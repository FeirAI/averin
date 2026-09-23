package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/store"
)

// failMarkStore fails the next VoidBrokerSeq (the void marker) — the void has already sealed its tombstone by then.
type failMarkStore struct {
	store.Store
	failMark bool
}

func (f *failMarkStore) VoidBrokerSeq(projectID, grantID string, seq int64) error {
	if f.failMark {
		f.failMark = false
		return errors.New("injected void-marker write failure")
	}
	return f.Store.VoidBrokerSeq(projectID, grantID, seq)
}

// landOnTombstoneStore lands the held (in-flight) grant commit the moment the void tries to store its tombstone —
// the Mem analogue of a Postgres tombstone INSERT that waits on the grant's uncommitted record_id index entry and
// then conflicts once the grant commits.
type landOnTombstoneStore struct {
	*lateCommitStore
	t *testing.T
}

func (l *landOnTombstoneStore) PutRecord(p, k string, rec store.Record) (store.Record, bool, error) {
	if strings.HasPrefix(k, "grant-void:") {
		l.land(l.t)
	}
	return l.lateCommitStore.PutRecord(p, k, rec)
}

func reservation(t *testing.T, s store.Store, seq int64) store.BrokerSeqReservation {
	t.Helper()
	res, found, err := s.BrokerSeqAt("p1", seq)
	if err != nil || !found {
		t.Fatalf("BrokerSeqAt(%d): found=%v err=%v", seq, found, err)
	}
	return res
}

// exerciseVoidGrantLandsFirst: the grant's commit is in flight when the void runs; the database backstop (record_id
// uniqueness) lets the GRANT win. The void must answer 409 "grant landed; nothing to void" and write NO void marker
// (the grant_id stays allocatable), and the grant's retry idempotently returns its record at the reserved seq.
// The caller has already started the grant's in-flight commit; voidRun runs the void and makes that commit land
// while the void is sealing its tombstone.
func exerciseVoidGrantLandsFirst(t *testing.T, base store.Store, h http.Handler, voidRun func() (int, string)) {
	t.Helper()
	ak := grantAgentKey()
	code, resp := voidRun()
	if code != http.StatusConflict || !strings.Contains(resp, "grant landed; nothing to void") {
		t.Fatalf("a void that loses the record_id race to the grant must 409 'grant landed' (got %d): %s", code, resp)
	}
	if strings.Contains(resp, "INERT") {
		t.Fatalf("no marker existed, so none may be called inert: %s", resp)
	}
	if res := reservation(t, base, 1); res.Voided {
		t.Fatalf("a void that lost must write NO void marker: %+v", res)
	}
	if _, ok, err := base.RecordByIdem("p1", "grant-void:1"); err != nil || ok {
		t.Fatalf("a void that lost must leave no tombstone: ok=%v err=%v", ok, err)
	}
	code, resp = do(t, h, "POST", "/v2/grants", grantBody("idem-land", "read:orders", ak, ak))
	if code != http.StatusCreated || !strings.Contains(resp, `"created":false`) || grantSeqOf(t, resp) != 1 {
		t.Fatalf("the grant's retry must idempotently return its landed record at seq 1 (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "is recorded") {
		t.Fatalf("a repeat void of the landed seq must 409 as recorded (got %d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("the landed grant fills seq 1, so a checkpoint signs (%d): %s", code, resp)
	}
}

func TestBrokerSeqVoidGrantLandsFirstMem(t *testing.T) {
	ls := &lateCommitStore{flakyGrantStore: flakyGrantStore{Store: store.NewMem()}}
	ws := &landOnTombstoneStore{lateCommitStore: ls, t: t}
	h := api.New(mustCore(t), ws, "k0").WithBroker(brokerIssuingKey()).WithRevocation(revocationKey()).WithBrokerSeqVoidMinAge(0).Routes()
	ak := grantAgentKey()
	ls.holdNext = true
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-land", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("the grant's in-flight commit must 500 (got %d): %s", code, resp)
	}
	exerciseVoidGrantLandsFirst(t, ls.Store, h, func() (int, string) {
		return do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
	})
	// revocation-on-void runs only for a void that WON: the landed grant must not have been revoked (the revoked set
	// is still empty, so revoking an unrelated id makes it exactly 1).
	if code, r := do(t, h, "POST", "/v2/revoke?project=p1", `{"project_id":"p1","grant_id":"unrelated"}`); code != http.StatusCreated || !strings.Contains(r, `"revoked_total":1`) {
		t.Fatalf("a void that lost must not revoke the landed grant (%d): %s", code, r)
	}
}

// exerciseVoidMarkerFails: the tombstone is sealed but the void-marker write fails. The call is a 500 that asks for
// a repeat; in between, the grant's retry allocates its reserved seq, loses on record_id to the tombstone and gets a
// clean 409 WITHOUT the seq being released (a new grant still gets 2, never the voided 1); the repeat finds the
// tombstone and just writes the marker; after that the grant's retry is refused at allocation.
func exerciseVoidMarkerFails(t *testing.T, base store.Store) {
	t.Helper()
	fs := &flakyGrantStore{Store: base}
	fm := &failMarkStore{Store: fs}
	h := api.New(mustCore(t), fm, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
	ak := grantAgentKey()

	fs.ambiguousPut = true // seq 1 (the max) is reserved by a commit that never lands
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-mf1", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("ambiguous commit must 500 (got %d): %s", code, resp)
	}
	fm.failMark = true
	code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
	if code != http.StatusInternalServerError || !strings.Contains(resp, "tombstone is sealed but marking the reservation voided FAILED") || !strings.Contains(resp, "repeat this call to finish") {
		t.Fatalf("a failed marker write after the seal must 500 and ask for a repeat (got %d): %s", code, resp)
	}
	if res := reservation(t, base, 1); res.Voided {
		t.Fatalf("the marker write failed, so the reservation is not (yet) marked: %+v", res)
	}
	if _, ok, err := base.RecordByIdem("p1", "grant-void:1"); err != nil || !ok {
		t.Fatalf("the tombstone must already be sealed: ok=%v err=%v", ok, err)
	}
	// the window: the grant's retry reuses seq 1, loses on record_id to the tombstone — a clean 409, seq kept.
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-mf1", "read:orders", ak, ak)); code != http.StatusConflict || !strings.Contains(resp, "already held by a different record") {
		t.Fatalf("a retry in the tombstone-without-marker window must 409 (got %d): %s", code, resp)
	}
	if max, err := base.MaxBrokerSeq("p1"); err != nil || max != 1 {
		t.Fatalf("the voided seq must stay allocated (max=%d err=%v)", max, err)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-mf2", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 2 {
		t.Fatalf("a new grant must take seq 2, never the tombstoned 1 (%d): %s", code, resp)
	}
	// the repeat finishes: returns the existing tombstone and writes the marker.
	code, resp = do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
	if code != http.StatusOK || !strings.Contains(resp, `"created":false`) || !strings.Contains(resp, `"grant_void"`) {
		t.Fatalf("the repeat must return the sealed tombstone (got %d): %s", code, resp)
	}
	if res := reservation(t, base, 1); !res.Voided {
		t.Fatalf("the repeat must write the void marker: %+v", res)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-mf1", "read:orders", ak, ak)); code != http.StatusConflict || !strings.Contains(resp, "voided") {
		t.Fatalf("after the marker a retry of the voided grant must 409 at allocation (got %d): %s", code, resp)
	}
	if max, err := base.MaxBrokerSeq("p1"); err != nil || max != 2 {
		t.Fatalf("max must stay 2 (max=%d err=%v)", max, err)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint over {void 1, grant 2} (%d): %s", code, resp)
	}
	if code, report := do(t, h, "GET", "/v2/verify?project=p1", ""); code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("self-verify after the finished void (%d): %s", code, report)
	}
}

func TestBrokerSeqVoidMarkerFailsMem(t *testing.T) {
	exerciseVoidMarkerFails(t, store.NewMem())
}

// TestBrokerSeqVoidInertLegacyMarker: a reservation carrying a void marker but no tombstone (a void from before the
// tombstone-first ordering whose seal failed) whose grant then landed must NOT be tombstoned: the call re-checks the
// store, answers 409 "grant landed; nothing to void" and names the marker inert.
func TestBrokerSeqVoidInertLegacyMarker(t *testing.T) {
	ls := &lateCommitStore{flakyGrantStore: flakyGrantStore{Store: store.NewMem()}}
	h := api.New(mustCore(t), ls, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
	ak := grantAgentKey()
	ls.holdNext = true
	do(t, h, "POST", "/v2/grants", grantBody("idem-inert", "read:orders", ak, ak))
	res := reservation(t, ls.Store, 1)
	if err := ls.Store.VoidBrokerSeq("p1", res.GrantID, 1); err != nil { // the old marker-first write
		t.Fatal(err)
	}
	ls.land(t)
	code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
	if code != http.StatusConflict || !strings.Contains(resp, "grant landed; nothing to void") || !strings.Contains(resp, "INERT") {
		t.Fatalf("a legacy marker over a landed grant must 409 and be named inert (got %d): %s", code, resp)
	}
	if _, ok, _ := ls.Store.RecordByIdem("p1", "grant-void:1"); ok {
		t.Fatal("no tombstone may be sealed over a landed grant")
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("the landed grant fills seq 1 (%d): %s", code, resp)
	}
}

// TestBrokerSeqVoidBootFloor (finding: last-attempt tracking is in-memory): the attempt map is empty after a
// restart, so a retry made by the PREVIOUS process minutes before it died is forgotten. The age must count from
// max(allocated_at, last attempt, process start): right after a (simulated) restart the void is refused until the
// minimum age has elapsed since the start, however old the reservation is.
func TestBrokerSeqVoidBootFloor(t *testing.T) {
	ak := grantAgentKey()
	clk := newFakeClock()
	fs := &flakyGrantStore{Store: store.NewMem().WithClock(clk.Now)}
	h1 := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithClock(clk.Now).Routes()
	fs.ambiguousPut = true
	do(t, h1, "POST", "/v2/grants", grantBody("idem-boot", "read:orders", ak, ak)) // T0: reserved, never lands
	clk.Advance(3 * time.Hour)

	// "restart": a new Server over the same store, constructed now (T0+3h).
	h2 := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithClock(clk.Now).Routes()
	clk.Advance(10 * time.Minute)
	code, resp := do(t, h2, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
	if code != http.StatusConflict || !strings.Contains(resp, "before this process started") || !strings.Contains(resp, "AVERIN_BROKER_SEQ_VOID_MIN_AGE") {
		t.Fatalf("a void within the min age of the process start must 409 (got %d): %s", code, resp)
	}
	if res := reservation(t, fs.Store, 1); res.Voided {
		t.Fatalf("a refused void must not mark: %+v", res)
	}
	clk.Advance(51 * time.Minute) // T0+4h01m: 61m after the start
	if code, resp := do(t, h2, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
		t.Fatalf("once the min age has passed since the start the void must succeed (got %d): %s", code, resp)
	}
}
