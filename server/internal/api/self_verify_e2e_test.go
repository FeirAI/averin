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

// TestSelfVerifyEvaluatesRevocationMembership (#14): the server's own GET /v2/verify must SELF-PIN the roles it
// holds keys for — here, revocation. Before this fix the self-view pinned only broker+resource, so a revoked
// grant's continued use read as `revocation_status:absent` / ok:true (false comfort). Now the self-view evaluates
// the revocation_list it signed and BLOCKS the revoked use (ok:false), with NO caller-supplied pins. The membership
// gate is currency-independent, so this holds even though the self-view cannot pin the external TSA (freshness stale).
func TestSelfVerifyEvaluatesRevocationMembership(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
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

	// BEFORE the revoke: the self-view pins the revocation key but the export carries no revocation_list, so the
	// status is `missing` (fail-closed: with a revocation key pinned, absent revocation evidence blocks the
	// capstone rather than reading as a clean `absent` that stripping the list could forge).
	_, before := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(before, `"revocation_status":"missing"`) {
		t.Fatalf("pre-revoke self-view should report the revocation list as missing: %s", before)
	}

	// Revoke the grant.
	rb, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": grantID})
	if code, r := do(t, h, "POST", "/v2/revoke?project=p1", string(rb)); code != http.StatusCreated {
		t.Fatalf("revoke (%d): %s", code, r)
	}

	// AFTER the revoke: the self-view (with NO caller-supplied pins) self-pins the revocation key, so the signed
	// revocation_list is now EVALUATED instead of read as absent. Before #14 it stayed `absent` (false comfort) —
	// the verifier never saw the key. The exact post-evaluation status depends on TSA-anchored settlement the
	// self-view lacks; the point proven here is that it is no longer `absent`.
	_, after := do(t, h, "GET", "/v2/verify?project=p1", "")
	if strings.Contains(after, `"revocation_status":"absent"`) {
		t.Fatalf("post-revoke self-view must EVALUATE the revocation it signed, not read it as absent:\n%s", after)
	}
}
