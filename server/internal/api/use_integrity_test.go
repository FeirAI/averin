package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// mkIntent records a use_intent for a fresh grant and returns its record_id.
func mkIntent(t *testing.T, h http.Handler) string {
	t.Helper()
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	if err := json.Unmarshal([]byte(resp), &intent); err != nil {
		t.Fatalf("decode intent: %v", err)
	}
	return intent.UseID
}

func outcomeBody(idem, intentID, status string) string {
	b, _ := json.Marshal(map[string]any{"idempotency_key": idem, "project_id": "p1", "session_id": "s1", "intent_record_id": intentID, "status": status})
	return string(b)
}

// TestRevokedGrantUseRejected (M5): /v2/use (and /v2/use-intent) of a grant revoked via /v2/revoke used to 201 —
// revocation only took effect in the next export's signed list. It must be rejected at use time, before the
// credential is consumed; an unrevoked grant keeps working.
func TestRevokedGrantUseRejected(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithRevocation(revocationKey()).
		Routes()
	ak := grantAgentKey()
	grantID, capb := mkGrant(t, h, ak, "idem-grant")
	otherID, otherCap := mkGrant(t, h, ak, "idem-grant-2")

	rb, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": grantID})
	if code, r := do(t, h, "POST", "/v2/revoke?project=p1", string(rb)); code != http.StatusCreated {
		t.Fatalf("revoke (%d): %s", code, r)
	}
	for _, path := range []string{"/v2/use", "/v2/use-intent"} {
		code, resp := do(t, h, "POST", path, useBody(t, "idem"+path, capb, grantID, ak, "SELECT 1", "nonce"+path))
		if code != http.StatusBadRequest || !strings.Contains(resp, "revoked") {
			t.Fatalf("%s of a revoked grant must be rejected, got %d: %s", path, code, resp)
		}
	}
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-other", otherCap, otherID, ak, "SELECT 1", "nonce-other")); code != http.StatusCreated {
		t.Fatalf("an unrevoked grant must still be usable (%d): %s", code, resp)
	}
}

// staleIdemStore hides chosen idempotency keys from RecordByIdem (PutRecord still sees them), reproducing a
// same-key insert that raced past the handler's up-front idempotency check (e.g. another instance) — the
// seal then COLLAPSES onto the existing row with created=false.
type staleIdemStore struct {
	store.Store
	hide map[string]bool
}

func (s *staleIdemStore) RecordByIdem(p, k string) (store.Record, bool, error) {
	if s.hide[k] {
		return store.Record{}, false, nil
	}
	return s.Store.RecordByIdem(p, k)
}

func newStaleIdemServer(t *testing.T) (http.Handler, *staleIdemStore) {
	t.Helper()
	rc, _ := core.New(resourceSeed)
	st := &staleIdemStore{Store: store.NewMem(), hide: map[string]bool{}}
	return api.New(mustCore(t), st, "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes(), st
}

// TestUseCollapseOntoForeignReceiptIs409: when the seal collapses (created=false) onto a row stored under the same
// idempotency key by a DIFFERENT operation, /v2/use used to return 201 with THAT record's receipt — reporting an
// action with no receipt of its own. It must 409 and release the credential it consumed.
func TestUseCollapseOntoForeignReceiptIs409(t *testing.T) {
	h, st := newStaleIdemServer(t)
	ak := grantAgentKey()
	gA, capA := mkGrant(t, h, ak, "idem-grant-a")
	gB, capB := mkGrant(t, h, ak, "idem-grant-b")
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capA, gA, ak, "SELECT 1", "nonce-a")); code != http.StatusCreated {
		t.Fatalf("use A (%d): %s", code, resp)
	}
	st.hide["idem-use"] = true
	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capB, gB, ak, "SELECT 2", "nonce-b"))
	if code != http.StatusConflict {
		t.Fatalf("a use whose seal collapsed onto another operation's receipt must 409, got %d: %s", code, resp)
	}
	st.hide["idem-use"] = false
	// B's credential + nonce were released: the same operation under a fresh key still validates.
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use-b", capB, gB, ak, "SELECT 2", "nonce-b")); code != http.StatusCreated {
		t.Fatalf("the rejected use must not have consumed B's credential (%d): %s", code, resp)
	}
}

// TestUseOutcomeCollapseOntoForeignOutcomeIs409: the /v2/use-outcome analogue — a collapse onto ANOTHER intent's
// outcome must 409, not echo that outcome as this intent's.
func TestUseOutcomeCollapseOntoForeignOutcomeIs409(t *testing.T) {
	h, st := newStaleIdemServer(t)
	ak := grantAgentKey()
	intent := func(grantIdem, idem, nonce string) string {
		gid, capb := mkGrant(t, h, ak, grantIdem)
		code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, idem, capb, gid, ak, "SELECT 1", nonce))
		if code != http.StatusCreated {
			t.Fatalf("use-intent (%d): %s", code, resp)
		}
		var in struct {
			UseID string `json:"use_id"`
		}
		json.Unmarshal([]byte(resp), &in)
		return in.UseID
	}
	i1 := intent("g1", "intent-1", "n1")
	i2 := intent("g2", "intent-2", "n2")
	if code, resp := do(t, h, "POST", "/v2/use-outcome", outcomeBody("idem-out", i1, "ok")); code != http.StatusCreated {
		t.Fatalf("outcome 1 (%d): %s", code, resp)
	}
	st.hide["idem-out"] = true
	code, resp := do(t, h, "POST", "/v2/use-outcome", outcomeBody("idem-out", i2, "ok"))
	if code != http.StatusConflict {
		t.Fatalf("an outcome whose seal collapsed onto another intent's outcome must 409, got %d: %s", code, resp)
	}
}

// TestUseOutcomeExactlyOncePerIntent: a SECOND use_outcome for the same intent under a different idempotency key
// (e.g. "ok" then "failed") used to 201 too, and the anchored bundle then failed verification. It must be a 409
// that seals nothing, while the honest retry of the ORIGINAL outcome still returns it idempotently.
func TestUseOutcomeExactlyOncePerIntent(t *testing.T) {
	h := newBrokerResourceServer(t)
	intentID := mkIntent(t, h)

	if code, resp := do(t, h, "POST", "/v2/use-outcome", outcomeBody("idem-out-1", intentID, "ok")); code != http.StatusCreated {
		t.Fatalf("first outcome (%d): %s", code, resp)
	}
	for _, status := range []string{"failed", "ok"} {
		if code, resp := do(t, h, "POST", "/v2/use-outcome", outcomeBody("idem-out-2-"+status, intentID, status)); code != http.StatusConflict {
			t.Fatalf("a second outcome (%s) for the same intent must 409, got %d: %s", status, code, resp)
		}
	}
	code, resp := do(t, h, "POST", "/v2/use-outcome", outcomeBody("idem-out-1", intentID, "ok"))
	if code != http.StatusCreated || !strings.Contains(resp, `"idempotent":true`) {
		t.Fatalf("the honest retry of the original outcome must return it idempotently (%d): %s", code, resp)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, r)
	}
	if code, report := do(t, h, "GET", "/v2/verify?project=p1", ""); code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("bundle must verify with exactly one outcome per intent (%d): %s", code, report)
	}
}
