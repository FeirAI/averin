package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/broker"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
)

// attestationKey is the D7.2 deployment-attestation issuer — distinct from the server signing key, the
// broker issuing key, and the resource recording key (role separation).
func attestationKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("88888888attest88888888attest8888"))
}

func attestPubEncoded(k ed25519.PrivateKey) string {
	return "ed25519pub:" + base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

func newAttestingServer(t *testing.T) (http.Handler, *core.Core, *core.Core, ed25519.PrivateKey) {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	att := attestationKey()
	h := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").WithAttestation(att).Routes()
	return h, c, rc, att
}

// TestAttestationBindsRevocationDigestStripDetectedEndToEnd (#3 deep review): the deployment_attestation binds
// the digest of the exported revocation_list. A real attested+revocation bundle reaches attested_claims under the
// Rust verifier; STRIPPING the revocation_list (the soft-tier downgrade) makes the bundle's revocation digest ""
// mismatch the signed subject → subject mismatch → !ok. Closes the strip-downgrade for attested deployments.
func TestAttestationBindsRevocationDigestStripDetectedEndToEnd(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	att := attestationKey()
	rev := revocationKey()
	tsa := testTSAKey()
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithAttestation(att).
		WithRevocation(rev).
		Routes()
	ak := grantAgentKey()
	grantID, capb := mkGrant(t, h, ak, "idem-grant")
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capb, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("use: %d %s", code, r)
	}
	// revoke a DIFFERENT (unused) grant so the revocation_list is non-empty but does not block the used grant.
	rb, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": "some-other-grant"})
	if code, r := do(t, h, "POST", "/v2/revoke?project=p1", string(rb)); code != http.StatusCreated {
		t.Fatalf("revoke: %d %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	revPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(rev.Public().(ed25519.PublicKey))
	pinned := `{"broker_authority_keys":["` + c.PubKey() + `"],"resource_authority_keys":["` + rc.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"],"attestation_keys":["` + attestPubEncoded(att) + `"],"revocation_keys":["` + revPub + `"]}`

	// PRESENT: the attestation binds the revocation_list digest -> attested_claims, ok.
	rep := c.VerifyBundleWith(anchored, pinned)
	for _, want := range []string{`"ok":true`, `"attestation_status":"attested_claims"`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("present attested+revocation bundle (missing %s):\n%s", want, rep)
		}
	}
	// ATTACK: strip the revocation_list -> the attestation's bound digest no longer matches -> !ok.
	var b map[string]json.RawMessage
	json.Unmarshal([]byte(anchored), &b)
	delete(b, "revocation_list")
	stripped, _ := json.Marshal(b)
	rep2 := c.VerifyBundleWith(string(stripped), pinned)
	if !strings.Contains(rep2, `"ok":false`) || !strings.Contains(rep2, "revocation_digest") {
		t.Fatalf("stripping the bound revocation_list must fail the attestation subject match:\n%s", rep2)
	}
}

// TestExportEmitsDeploymentAttestation (D7.2): /v2/export emits a top-level deployment_attestation binding
// this bundle's latest checkpoint + authority/resource set, signed by the issuer key. When the issuer key
// is PINNED, the verifier's signature + issuer checks pass cross-language (it only fails on the missing
// verifiable anchor — the test StubTSA is not crypto-valid); when unpinned it is `unevaluated` and never
// breaks verification. The full attested_claims path is exercised in the Rust adversarial suite.
func TestExportEmitsDeploymentAttestation(t *testing.T) {
	h, c, rc, att := newAttestingServer(t)
	ak := grantAgentKey()
	mkGrant(t, h, ak, "idem-grant")
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	code, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("export (%d): %s", code, exp)
	}
	var bundle struct {
		DeploymentAttestation map[string]json.RawMessage `json:"deployment_attestation"`
	}
	if err := json.Unmarshal([]byte(exp), &bundle); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if bundle.DeploymentAttestation == nil {
		t.Fatalf("export missing deployment_attestation: %s", exp)
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(bundle.DeploymentAttestation[k], &s)
		return s
	}
	if str("issuer_kid") != broker.KeyID(att.Public().(ed25519.PublicKey)) {
		t.Fatalf("issuer_kid %q != attestation key id", str("issuer_kid"))
	}
	if !strings.HasPrefix(str("sig"), "ed25519:") {
		t.Fatalf("attestation sig malformed: %q", str("sig"))
	}
	var subj struct {
		ProjectID      string   `json:"project_id"`
		CheckpointHash string   `json:"checkpoint_hash"`
		ResourceIDs    []string `json:"resource_ids"`
	}
	json.Unmarshal(bundle.DeploymentAttestation["subject"], &subj)
	if subj.ProjectID != "p1" || subj.CheckpointHash == "" {
		t.Fatalf("subject does not bind the bundle: %+v", subj)
	}
	if len(subj.ResourceIDs) != 1 || subj.ResourceIDs[0] != "orders-db" {
		t.Fatalf("subject resource_ids = %v, want [orders-db]", subj.ResourceIDs)
	}

	// PIN the attestation issuer: the verifier's sig + issuer_kid checks must PASS cross-language. The only
	// remaining failure is the absent verifiable anchor (the freshness step), proving the producer signs the
	// attestation exactly as the verifier expects — NOT a sig/issuer/subject mismatch.
	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"attestation_keys":[%q]}`,
		c.PubKey(), rc.PubKey(), attestPubEncoded(att))
	pinned := c.VerifyBundleWith(exp, opts)
	if !strings.Contains(pinned, `"attestation_status":"failed"`) {
		t.Fatalf("with a pinned issuer + no verifiable anchor, attestation_status should be failed: %s", pinned)
	}
	if !strings.Contains(pinned, "no verified+anchored checkpoint") {
		t.Fatalf("the ONLY attestation failure should be the missing anchor (sig/issuer must pass): %s", pinned)
	}
	if strings.Contains(pinned, "sig does not verify") || strings.Contains(pinned, "issuer_kid does not match") || strings.Contains(pinned, "substitution/replay") {
		t.Fatalf("the producer signed/bound the attestation incorrectly: %s", pinned)
	}

	// UNPINNED: the attestation is simply not evaluated and never breaks verification.
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"ok":true`) {
		t.Fatalf("a bundle with an attestation should still verify when the issuer is unpinned: %s", report)
	}
	if !strings.Contains(report, `"attestation_status":"unevaluated"`) {
		t.Fatalf("with no pinned attestation key, status should be unevaluated: %s", report)
	}
}

// TestExportWithoutAttestationKeyOmitsAttestation: the attestation is only emitted when configured.
func TestExportWithoutAttestationKeyOmitsAttestation(t *testing.T) {
	h := newBrokerResourceServer(t) // no WithAttestation
	ak := grantAgentKey()
	mkGrant(t, h, ak, "idem-grant")
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if strings.Contains(exp, "deployment_attestation") {
		t.Fatalf("no attestation key configured, but export carries a deployment_attestation: %s", exp)
	}
}
