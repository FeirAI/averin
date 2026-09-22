package api_test

import (
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
}

func (f *flakyGrantStore) Heads(projectID, sessionID string) ([]string, error) {
	if f.failHeads {
		f.failHeads = false
		return nil, errors.New("injected transient heads read failure")
	}
	return f.Store.Heads(projectID, sessionID)
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
func TestNonMaxReservedSeqIsRefilledNotReleased(t *testing.T) {
	fs := &flakyGrantStore{Store: store.NewMem()}
	h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()

	fs.ambiguousPut = true
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g1", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("g1 ambiguous commit must 500 (got %d): %s", code, resp)
	}
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g2", "read:orders", ak, ak))
	if code != http.StatusCreated || grantSeqOf(t, resp) != 2 {
		t.Fatalf("g2 must record seq 2 while g1 holds 1 (%d): %s", code, resp)
	}
	fs.failHeads = true // g1's retry fails with a NON-ambiguous error → release attempted on a non-max seq
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g1", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("g1 retry with a transient failure must 500 (got %d): %s", code, resp)
	}
	code, resp = do(t, h, "POST", "/v2/grants", grantBody("idem-g1", "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("g1 retry (%d): %s", code, resp)
	}
	if seq := grantSeqOf(t, resp); seq != 1 {
		t.Fatalf("g1 retry broker_seq = %d, want the kept reservation 1 (a released non-max seq leaves a permanent hole)", seq)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint over the gapless {1,2} (%d): %s", code, resp)
	}
	if code, report := do(t, h, "GET", "/v2/verify?project=p1", ""); code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("bundle must verify (%d): %s", code, report)
	}
}

// TestCheckpointRefusesReservedSeqGap: a commit-AMBIGUOUS failure correctly keeps its seq RESERVED, but until the
// grant is retried that seq has no recorded grant — a checkpoint signed now would anchor the gap forever. It must
// FAIL CLOSED (refuse to sign); once the retry records the grant, checkpointing succeeds and verifies.
func TestCheckpointRefusesReservedSeqGap(t *testing.T) {
	fs := &flakyGrantStore{Store: store.NewMem()}
	h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()

	fs.ambiguousPut = true
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-amb", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("an ambiguous commit must 500 (got %d): %s", code, resp)
	}
	code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	if code != http.StatusInternalServerError || !strings.Contains(resp, "checkpoint refused") {
		t.Fatalf("a checkpoint over a reserved-but-unrecorded broker_seq must be refused (got %d): %s", code, resp)
	}
	// the retry reclaims the reserved seq 1 and records it; the gap closes.
	code, resp = do(t, h, "POST", "/v2/grants", grantBody("idem-amb", "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("retry (%d): %s", code, resp)
	}
	if seq := grantSeqOf(t, resp); seq != 1 {
		t.Fatalf("retry broker_seq = %d, want the reserved 1", seq)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint after the gap closed (%d): %s", code, resp)
	}
	if code, report := do(t, h, "GET", "/v2/verify?project=p1", ""); code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("bundle must verify (%d): %s", code, report)
	}
}
