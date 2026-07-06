package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/averin-dev/averin/server/internal/api"
	"github.com/averin-dev/averin/server/internal/core"
	"github.com/averin-dev/averin/server/internal/store"
)

// TestRevocationServerBlocksRevokedUseEndToEnd (M5 server wiring): a server WithRevocation records a grant_id as
// revoked via POST /v2/revoke, and the NEXT /v2/export carries a signed, time-bounded revocation_list over the
// project's revoked set — so the Rust verifier blocks the use of the revoked grant. An export BEFORE the revoke
// carries no list (clean); the export AFTER blocks it.
func TestRevocationServerBlocksRevokedUseEndToEnd(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	rev := revocationKey()
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithRevocation(rev).
		Routes()
	ak := grantAgentKey()
	grantID, capb := mkGrant(t, h, ak, "idem-grant")
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capb, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("use (%d): %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}

	revPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(rev.Public().(ed25519.PublicKey))
	pinned := `{"broker_authority_keys":["` + c.PubKey() + `"],"resource_authority_keys":["` + rc.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"],"revocation_keys":["` + revPub + `"]}`

	// BEFORE the revoke: export carries NO revocation_list -> the use verifies clean.
	_, exp0 := do(t, h, "GET", "/v2/export?project=p1", "")
	if strings.Contains(exp0, `"revocation_list"`) {
		t.Fatalf("a pre-revoke export must carry no revocation_list:\n%s", exp0)
	}
	if rep := c.VerifyBundleWith(attachTestAnchor(t, exp0, tsa), pinned); !strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, `"uses_matched":1`) {
		t.Fatalf("pre-revoke bundle must verify clean: %s", rep)
	}

	// revoke the grant.
	rb, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": grantID, "reason": "compromised"})
	if code, r := do(t, h, "POST", "/v2/revoke?project=p1", string(rb)); code != http.StatusCreated {
		t.Fatalf("revoke (%d): %s", code, r)
	}

	// AFTER the revoke: export carries the signed list -> the use of the revoked grant is BLOCKED.
	_, exp1 := do(t, h, "GET", "/v2/export?project=p1", "")
	if !strings.Contains(exp1, `"revocation_list"`) {
		t.Fatalf("a post-revoke export must carry a revocation_list:\n%s", exp1)
	}
	rep := c.VerifyBundleWith(attachTestAnchor(t, exp1, tsa), pinned)
	for _, want := range []string{`"ok":false`, `"revocation_status":"revoked_present"`, `"revoked_uses_blocked":1`, `"uses_matched":0`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("a server-revoked grant's use must be blocked (missing %s):\n%s", want, rep)
		}
	}

	// revoking a DIFFERENT grant_id leaves THIS use clean but the list stays fresh (selective + present).
	rb2, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": "some-other-grant"})
	do(t, h, "POST", "/v2/revoke?project=p1", string(rb2))
	_, exp2 := do(t, h, "GET", "/v2/export?project=p1", "")
	rep2 := c.VerifyBundleWith(attachTestAnchor(t, exp2, tsa), pinned)
	// grantID is still revoked from above, so this stays blocked — assert the list is fresh + carries both ids.
	if !strings.Contains(rep2, `"revocation_status":"revoked_present"`) || !strings.Contains(exp2, "some-other-grant") {
		t.Fatalf("the revocation_list must accumulate revoked ids and stay fresh:\n%s\n%s", exp2, rep2)
	}
}

// TestRevocationDisabledNoList (regression): a server WITHOUT WithRevocation never emits a revocation_list and
// 501s POST /v2/revoke.
func TestRevocationDisabledNoList(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	h := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()
	ak := grantAgentKey()
	grantID, _ := mkGrant(t, h, ak, "idem-grant")
	rb, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": grantID})
	if code, _ := do(t, h, "POST", "/v2/revoke?project=p1", string(rb)); code != http.StatusNotImplemented {
		t.Fatalf("revoke without WithRevocation must 501, got %d", code)
	}
	do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if strings.Contains(exp, `"revocation_list"`) {
		t.Fatalf("a server without revocation must never emit a revocation_list:\n%s", exp)
	}
}
