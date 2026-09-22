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
