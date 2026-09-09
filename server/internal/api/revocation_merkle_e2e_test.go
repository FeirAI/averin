package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
)

// attachMerkleRevocation splices a signed revocation_merkle_root + a revocation_proofs map into a bundle JSON.
func attachMerkleRevocation(t *testing.T, bundleJSON string, root map[string]any, proofs map[string]any) string {
	t.Helper()
	var b map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bundleJSON), &b); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	rj, _ := json.Marshal(root)
	b["revocation_merkle_root"] = rj
	pj, _ := json.Marshal(proofs)
	b["revocation_proofs"] = pj
	out, _ := json.Marshal(b)
	return string(out)
}

// TestRevocationMerkleNonDisclosureEndToEnd (M5 privacy tier): a Go-built signed revocation_merkle_root (which
// does NOT disclose the revoked set) + a per-grant proof, spliced into a REAL anchored grant+two-phase-use
// bundle and verified through the Rust core. A non-membership proof lets the use proceed; a membership proof (or
// a MISSING proof) blocks it — proving the producer↔verifier Merkle contract end-to-end across languages.
func TestRevocationMerkleNonDisclosureEndToEnd(t *testing.T) {
	h := newBrokerResourceServer(t)
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	ak := grantAgentKey()
	grantID, capb := mkGrant(t, h, ak, "idem-grant")

	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", capb, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(resp), &intent)
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	if code, r := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	rev := revocationKey()
	revPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(rev.Public().(ed25519.PublicKey))
	pinned := `{"broker_authority_keys":["` + c.PubKey() + `"],"resource_authority_keys":["` + rc.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"],"revocation_keys":["` + revPub + `"]}`
	const from, to = "2020-01-01T00:00:00.000Z", "2099-01-01T00:00:00.000Z"

	// NON-REVOKED: a root committing to a DIFFERENT grant + a non-membership proof for THIS grant -> clean.
	treeClean := broker.BuildRevocationTree([]string{"some-other-grant", "and-another"})
	rootClean, err := api.BuildRevocationMerkleRoot(c, rev, from, to, treeClean)
	if err != nil {
		t.Fatalf("BuildRevocationMerkleRoot: %v", err)
	}
	proofClean := map[string]any{grantID: treeClean.NonMembershipProof(grantID)}
	repC := c.VerifyBundleWith(attachMerkleRevocation(t, anchored, rootClean, proofClean), pinned)
	for _, want := range []string{`"ok":true`, `"revocation_merkle_status":"fresh"`, `"revocation_nonmembership_verified":1`, `"uses_matched":1`} {
		if !strings.Contains(repC, want) {
			t.Fatalf("a non-membership proof must let the use proceed (missing %s): %s", want, repC)
		}
	}

	// REVOKED: a root committing to THIS grant + a membership proof -> the use is blocked.
	treeRev := broker.BuildRevocationTree([]string{grantID, "some-other-grant"})
	rootRev, _ := api.BuildRevocationMerkleRoot(c, rev, from, to, treeRev)
	proofRev := map[string]any{grantID: treeRev.MembershipProof(grantID)}
	repR := c.VerifyBundleWith(attachMerkleRevocation(t, anchored, rootRev, proofRev), pinned)
	for _, want := range []string{`"ok":false`, `"revoked_uses_blocked":1`, `"uses_matched":0`} {
		if !strings.Contains(repR, want) {
			t.Fatalf("a membership proof must block the use (missing %s): %s", want, repR)
		}
	}

	// MISSING PROOF (fail-closed): a fresh root present but NO proof for the use's grant -> blocked (the revoked
	// set is undisclosed, so an unproven use cannot be assumed safe).
	repM := c.VerifyBundleWith(attachMerkleRevocation(t, anchored, rootRev, map[string]any{}), pinned)
	if !strings.Contains(repM, `"ok":false`) || !strings.Contains(repM, `"revoked_uses_blocked":1`) || !strings.Contains(repM, `"uses_matched":0`) {
		t.Fatalf("a fresh root with no proof must fail closed: %s", repM)
	}
}
