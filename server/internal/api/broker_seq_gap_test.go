package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/store"
)

// flakyGrantStore injects ONE transient failure into the grant seal path AFTER the broker_seq is allocated:
// failHeads fails the session-heads read (a pre-persistence error), ambiguousPut returns store.ErrCommitAmbiguous
// from PutRecord WITHOUT persisting (a commit whose outcome is unknown and here did not land).
type flakyGrantStore struct {
	store.Store
	failHeads    bool
	ambiguousPut bool
	parent       *flakyGrantStore
}

func (f *flakyGrantStore) Heads(projectID, sessionID string) ([]string, error) {
	if f.parent != nil {
		if f.parent.failHeads {
			f.parent.failHeads = false
			return nil, errors.New("injected transient heads read failure")
		}
		return f.Store.Heads(projectID, sessionID)
	}
	if f.failHeads {
		f.failHeads = false
		return nil, errors.New("injected transient heads read failure")
	}
	return f.Store.Heads(projectID, sessionID)
}

func (f *flakyGrantStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return f.Store.WithProjectWrite(ctx, projectID, func(st store.Store) error {
		return fn(&flakyGrantStore{Store: st, parent: f})
	})
}

func reservedGrantID(idem string) string {
	sum := sha256.Sum256([]byte("averin.grant.id.v1\x00p1\x00" + idem))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func reserveGrantSeq(t *testing.T, st store.Store, idem string) int64 {
	t.Helper()
	seq, _, err := st.AllocateBrokerSeq("p1", reservedGrantID(idem))
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

func (f *flakyGrantStore) PutRecord(p, k string, rec store.Record) (store.Record, bool, error) {
	if f.ambiguousPut {
		f.ambiguousPut = false
		return store.Record{}, false, fmt.Errorf("%w: injected", store.ErrCommitAmbiguous)
	}
	return f.Store.PutRecord(p, k, rec)
}

func grantSeqOf(t *testing.T, resp string) int64 {
	t.Helper()
	var out struct {
		Record struct {
			Extensions struct {
				Broker struct {
					GrantEvidence struct {
						BrokerSeq int64 `json:"broker_seq"`
					} `json:"grant_evidence"`
				} `json:"broker"`
			} `json:"extensions"`
		} `json:"record"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatalf("decode grant: %v\n%s", err, resp)
	}
	return out.Record.Extensions.Broker.GrantEvidence.BrokerSeq
}

// TestGrantTransientSealErrorReleasesSeq: a NON-ambiguous failure after broker_seq allocation (here a transient
// Heads read error inside sealAndStore) persisted nothing, so the seq must be RELEASED — otherwise the next grant
// takes seq 2, the recorded set is {2}, and every later checkpoint anchors a permanent D6 gap.
func TestGrantTransientSealErrorReleasesSeq(t *testing.T) {
	fs := &flakyGrantStore{Store: store.NewMem()}
	h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()

	fs.failHeads = true
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-fail", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("a transient seal failure must 500 (got %d): %s", code, resp)
	}
	// A DIFFERENT grant (the failed one is abandoned, never retried) must reuse seq 1.
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-next", "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("next grant (%d): %s", code, resp)
	}
	if seq := grantSeqOf(t, resp); seq != 1 {
		t.Fatalf("next grant broker_seq = %d, want 1 (the failed grant's seq must be released, not left as a gap)", seq)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, resp)
	}
	if code, report := do(t, h, "GET", "/v2/verify?project=p1", ""); code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("bundle must verify (no broker_seq gap) (%d): %s", code, report)
	}
}

// TestNonMaxReservedSeqIsRefilledNotReleased (TLA+ GrantLog.tla): grant g1 keeps seq 1 RESERVED (ambiguous
// commit), g2 then takes and records seq 2, and g1's next retry fails with a plain (releasable) error. Releasing
// g1's seq now would punch a hole at 1 that no allocation refills (g1's next allocation would be MAX+1=3) —
// checkpoints could never be signed again. The store must KEEP it, so g1's successful retry records seq 1.
func TestFailedGrantTransactionDoesNotReserveSequence(t *testing.T) {
	fs := &flakyGrantStore{Store: store.NewMem()}
	h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()
	fs.failHeads = true
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g1", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("failed grant should 500 (%d): %s", code, resp)
	}
	if max, err := fs.Store.MaxBrokerSeq("p1"); err != nil || max != 0 {
		t.Fatalf("failed transaction leaked allocation: max=%d err=%v", max, err)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g2", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 1 {
		t.Fatalf("next committed grant must take seq 1 (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g1", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 2 {
		t.Fatalf("retry must take seq 2 (%d): %s", code, resp)
	}
}

// TestCheckpointRefusesReservedSeqGap: a commit-AMBIGUOUS failure correctly keeps its seq RESERVED, but until the
// grant is retried that seq has no recorded grant — a checkpoint signed now would anchor the gap forever. It must
// FAIL CLOSED (refuse to sign); once the retry records the grant, checkpointing succeeds and verifies.
func TestCheckpointRefusesReservedSeqGap(t *testing.T) {
	base := store.NewMem()
	h := api.New(mustCore(t), base, "k0").WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()
	if seq := reserveGrantSeq(t, base, "idem-amb"); seq != 1 {
		t.Fatalf("reserved seq = %d", seq)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusInternalServerError || !strings.Contains(resp, "checkpoint refused") {
		t.Fatalf("checkpoint over an orphaned reservation must fail (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-amb", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 1 {
		t.Fatalf("retry must reclaim reserved seq 1 (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint after gap closed (%d): %s", code, resp)
	}
}

// heldCommit is a record whose commit was acknowledged as ambiguous and has not landed yet.
type heldCommit struct {
	project, idem string
	rec           store.Record
}

// lateCommitStore models a Postgres commit whose ack is lost but which DOES land later: PutRecord returns
// store.ErrCommitAmbiguous and holds the record back (invisible to RecordByIdem) until land() persists it.
type lateCommitStore struct {
	flakyGrantStore
	holdNext bool
	held     []heldCommit
}

func (l *lateCommitStore) PutRecord(p, k string, rec store.Record) (store.Record, bool, error) {
	if l.holdNext {
		l.holdNext = false
		l.held = append(l.held, heldCommit{p, k, rec})
		return store.Record{}, false, fmt.Errorf("%w: injected (commit in flight)", store.ErrCommitAmbiguous)
	}
	return l.flakyGrantStore.PutRecord(p, k, rec)
}

func (l *lateCommitStore) land(t *testing.T) {
	t.Helper()
	for _, h := range l.held {
		if _, _, err := l.flakyGrantStore.Store.PutRecord(h.project, h.idem, h.rec); err != nil {
			t.Fatalf("land held commit: %v", err)
		}
	}
	l.held = nil
}

// TestRetryNeverReleasesReusedSeq (review finding 5): g1's commit is ambiguous at seq 1 (the max) and is still in
// flight. The client retries at once: RecordByIdem cannot see the row yet, AllocateBrokerSeq hands back the SAME
// reserved seq 1, and the retry then fails with a plain (non-ambiguous) error. Releasing seq 1 there deleted a
// number the in-flight commit still holds: once it lands, the next grant was allocated seq 1 AGAIN — a duplicate
// broker_seq no checkpoint could ever sign over. A retry must only release a seq it freshly allocated.
func TestRetryNeverReleasesReusedSeq(t *testing.T) {
	base := store.NewMem()
	fs := &flakyGrantStore{Store: base}
	h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()
	reserveGrantSeq(t, base, "idem-g1")
	fs.failHeads = true
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g1", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("retry over reserved seq should fail before commit (%d): %s", code, resp)
	}
	if res, ok, err := base.BrokerSeqAt("p1", 1); err != nil || !ok || res.GrantID != reservedGrantID("idem-g1") {
		t.Fatalf("preexisting reservation lost: %+v ok=%v err=%v", res, ok, err)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g2", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 2 {
		t.Fatalf("new grant must take seq 2 (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g1", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 1 {
		t.Fatalf("retry must refill seq 1 (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint over refilled log (%d): %s", code, resp)
	}
}
