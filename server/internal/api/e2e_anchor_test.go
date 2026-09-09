package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/core"
)

// testTSAKey is the hermetic test timestamp-authority key — distinct from the server signing key, the
// broker issuing key, the resource recording key, and the attestation key (the verifier requires the TSA
// key disjoint from every signing role, R2/D7).
func testTSAKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("tsa99999tsa99999tsa99999tsa99999"))
}

func tsaPubEncoded(k ed25519.PrivateKey) string {
	return "ed25519pub:" + base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

// lp is the length-prefix framing the core uses for signature preimages: uint32-BE(len) ‖ utf8(s).
func lp(s string) []byte {
	b := make([]byte, 4, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, []byte(s)...)
}

// makeTestAnchor mints the hermetic "test-anchor" the Rust verifier trusts via a pinned tsa_keys entry:
// Ed25519 over LP("averin.anchor.v1") ‖ LP(checkpoint_hash) ‖ LP(anchored_ts), token = b64url-nopad(sig).
// (This is the same scheme the Rust adversarial suite uses; it needs no RFC 3161 / DER / network.)
func makeTestAnchor(checkpointHash, anchoredTS, keyID string, tsa ed25519.PrivateKey) map[string]any {
	pre := append(append(lp("averin.anchor.v1"), lp(checkpointHash)...), lp(anchoredTS)...)
	sig := ed25519.Sign(tsa, pre)
	return map[string]any{
		"scheme":      "test-anchor",
		"anchored_ts": anchoredTS,
		"tsa_key_id":  keyID,
		"token_b64":   base64.RawURLEncoding.EncodeToString(sig),
	}
}

// attachTestAnchor rewrites every checkpoint in an exported bundle to carry a crypto-valid hermetic
// test-anchor, with anchored_ts = the checkpoint's own created_ts (a valid TSA time that also lands inside
// the deployment-attestation freshness window). The anchor is EXCLUDED from the checkpoint hash/sig (the
// verifier strips + re-canonicalizes the body), so replacing it does not invalidate the signature. This
// gives the Go suite a verified+anchored checkpoint — which the non-crypto-valid StubTSA cannot produce —
// so two-phase use-matching and attested_claims become reachable end-to-end from Go.
func attachTestAnchor(t *testing.T, bundleJSON string, tsa ed25519.PrivateKey) string {
	t.Helper()
	var bundle map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bundleJSON), &bundle); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	var checkpoints []map[string]json.RawMessage
	if err := json.Unmarshal(bundle["checkpoints"], &checkpoints); err != nil {
		t.Fatalf("parse checkpoints: %v", err)
	}
	if len(checkpoints) == 0 {
		t.Fatalf("bundle has no checkpoints to anchor")
	}
	for _, cp := range checkpoints {
		var hash, createdTS string
		json.Unmarshal(cp["checkpoint_hash"], &hash)
		json.Unmarshal(cp["created_ts"], &createdTS)
		anchor, _ := json.Marshal(makeTestAnchor(hash, createdTS, "test-tsa", tsa))
		cp["anchor"] = anchor
	}
	cpsJSON, _ := json.Marshal(checkpoints)
	bundle["checkpoints"] = cpsJSON
	out, _ := json.Marshal(bundle)
	return string(out)
}

// TestTwoPhaseUseMatchesUnderAnchor (T9): with a CRYPTO-VALID checkpoint anchor, the offline verifier
// completes the two-phase pair — the Go producer's use_intent + use_outcome MATCH (uses_matched:1,
// intent_without_outcome:0). This is the matching semantics the StubTSA could never exercise from Go (only
// the Rust adversarial suite could); it proves the Go producer's intent↔outcome join wiring end-to-end.
func TestTwoPhaseUseMatchesUnderAnchor(t *testing.T) {
	h := newBrokerResourceServer(t)
	c, _ := core.New(seed) // same key the server signs with (deterministic from the seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")

	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(resp), &intent)
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	if code, oresp := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, oresp)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q]}`,
		c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa))
	rep := c.VerifyBundleWith(anchored, opts)
	if !strings.Contains(rep, `"ok":true`) {
		t.Fatalf("a two-phase bundle with a verified anchor should verify clean: %s", rep)
	}
	if !strings.Contains(rep, `"uses_matched":1`) {
		t.Fatalf("the closed two-phase pair should MATCH (uses_matched:1): %s", rep)
	}
	if !strings.Contains(rep, `"intent_without_outcome":0`) {
		t.Fatalf("the intent must be completed by its outcome (intent_without_outcome:0): %s", rep)
	}
}

// TestAttestationElevatesToAttestedClaimsUnderAnchor (T9): with the issuer pinned AND a crypto-valid anchor
// inside the freshness window, the deployment attestation elevates to attested_claims — the full D7 path
// the StubTSA blocked from Go (the existing TestExportEmitsDeploymentAttestation asserts the failure is
// ONLY the missing anchor; supplying it flips the status).
func TestAttestationElevatesToAttestedClaimsUnderAnchor(t *testing.T) {
	h, c, rc, att := newAttestingServer(t)
	tsa := testTSAKey()
	ak := grantAgentKey()
	mkGrant(t, h, ak, "idem-grant")
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"attestation_keys":[%q],"tsa_keys":[%q]}`,
		c.PubKey(), rc.PubKey(), attestPubEncoded(att), tsaPubEncoded(tsa))
	rep := c.VerifyBundleWith(anchored, opts)
	if !strings.Contains(rep, `"attestation_status":"attested_claims"`) {
		t.Fatalf("a pinned issuer + a verified anchor inside the window should elevate to attested_claims: %s", rep)
	}
	if !strings.Contains(rep, `"ok":true`) {
		t.Fatalf("the bundle should verify clean: %s", rep)
	}
}
