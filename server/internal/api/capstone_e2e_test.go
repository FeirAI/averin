package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
	"github.com/feirai/averin/server/internal/taxonomy"
)

// TestCapstoneAttestedCompleteEndToEnd proves the D8 capstone end-to-end from a REAL Go-produced bundle:
// a gateway_enforced grant + a two-phase PoP use + an anchored broker_grant_head + a validated taxonomy
// + a pinned-issuer deployment attestation + an operator-declared coverage_manifest whose digest the
// attestation binds. The offline verifier elevates action_completeness all the way to
// attested_complete_over_brokered_surface (always bounded by resource_trust:assumed_truthful). Until the
// producer could emit a coverage_manifest, this verdict was only reachable in native Rust fixtures.
func TestCapstoneAttestedCompleteEndToEnd(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	att := attestationKey()
	taxKey := taxonomyKey()
	tsa := testTSAKey()
	ak := grantAgentKey()

	// The operator's affirmative side-effect closure: the deployment may touch orders-db under the read
	// action and nothing else. The verifier checks the brokered surface stayed within this.
	manifest := `{"side_effect_closure":[{"resource_id":"orders-db","action":"db.query:orders-ro","may_touch":[]}]}`
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithAttestation(att).
		WithCoverageManifest(manifest).
		Routes()

	grantID, cap := mkGrant(t, h, ak, "idem-grant")

	// Two-phase use (the capstone forbids a one-phase `use`): use-intent then use-outcome.
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
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

	// A Go-signed taxonomy listing the grant's (resource_id, action), pinned into the verify opts.
	taxJSON, digest, ver, err := taxonomy.Sign(c, taxKey, 1, 0, 9_999_999_999,
		[]taxonomy.Entry{{ResourceID: "orders-db", Action: "db.query:orders-ro"}}, nil)
	if err != nil {
		t.Fatalf("taxonomy.Sign: %v", err)
	}

	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q],"attestation_keys":[%q],"taxonomy":%s,"taxonomy_keys":[%q],"taxonomy_digest":%q,"taxonomy_version":%d}`,
		c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa), attestPubEncoded(att), taxJSON, attestPubEncoded(taxKey), digest, ver)
	rep := c.VerifyBundleWith(anchored, opts)

	for _, want := range []string{
		`"ok":true`,
		`"action_completeness":"attested_complete_over_brokered_surface"`,
		`"resource_trust":"assumed_truthful"`, // MF1: the capstone is ALWAYS bounded by this
		`"side_effect_closure_status":"closed"`,
		`"attestation_status":"attested_claims"`,
		`"taxonomy_status":"validated"`,
		`"broker_trust":"sequence_verified"`,
		`"uses_matched":1`,
		`"uses_pop_reverified":1`, // the two-phase use's PoP was independently re-run offline (D2)
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("capstone bundle must verify with %s\nreport: %s", want, rep)
		}
	}
}

// TestCapstoneWithRevocationConfigured (review finding 2): a deployment with a revocation authority configured
// (AVERIN_REVOCATION_SEED) and ZERO revocations must still reach the capstone. The verifier pins revocation_keys and
// reads a bundle with no revocation evidence as `missing` (which blocks the capstone), so the producer must emit a
// signed EMPTY revocation_list — which the attestation then binds — and the verifier must read it `fresh`.
func TestCapstoneWithRevocationConfigured(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	att := attestationKey()
	taxKey := taxonomyKey()
	tsa := testTSAKey()
	rev := revocationKey()
	ak := grantAgentKey()

	manifest := `{"side_effect_closure":[{"resource_id":"orders-db","action":"db.query:orders-ro","may_touch":[]}]}`
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithAttestation(att).
		WithCoverageManifest(manifest).
		WithRevocation(rev).
		Routes()

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
	if code, r := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if !strings.Contains(exp, `"revoked_grant_ids":[]`) {
		t.Fatalf("with revocation configured and nothing revoked, the export must carry a signed empty revocation_list:\n%s", exp)
	}
	anchored := attachTestAnchor(t, exp, tsa)

	taxJSON, digest, ver, err := taxonomy.Sign(c, taxKey, 1, 0, 9_999_999_999,
		[]taxonomy.Entry{{ResourceID: "orders-db", Action: "db.query:orders-ro"}}, nil)
	if err != nil {
		t.Fatalf("taxonomy.Sign: %v", err)
	}
	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q],"attestation_keys":[%q],"revocation_keys":[%q],"taxonomy":%s,"taxonomy_keys":[%q],"taxonomy_digest":%q,"taxonomy_version":%d}`,
		c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa), attestPubEncoded(att), attestPubEncoded(rev), taxJSON, attestPubEncoded(taxKey), digest, ver)
	rep := c.VerifyBundleWith(anchored, opts)
	for _, want := range []string{
		`"ok":true`,
		`"revocation_status":"fresh"`,
		`"revoked_uses_blocked":0`,
		`"attestation_status":"attested_claims"`,
		`"action_completeness":"attested_complete_over_brokered_surface"`,
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("capstone with revocation configured must verify with %s\nreport: %s", want, rep)
		}
	}
}

// TestCapstoneOverBoundedReuseEndToEnd proves the capstone over an N-Use (bounded_reuse) credential: one
// grant exercised TWICE via two-phase PoP uses (usn 1 and 2) reaches attested_complete_over_brokered_surface
// with bounded_reuse_grants:1 and no overspend/replay — the cross-cutting bounded_reuse × capstone path.
func TestCapstoneOverBoundedReuseEndToEnd(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	att := attestationKey()
	taxKey := taxonomyKey()
	tsa := testTSAKey()
	ak := grantAgentKey()

	manifest := `{"side_effect_closure":[{"resource_id":"orders-db","action":"db.query:orders-ro","may_touch":[]}]}`
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithAttestation(att).
		WithCoverageManifest(manifest).
		Routes()

	code, resp := do(t, h, "POST", "/v2/grants", boundedGrantBody("idem-grant", 2, ak))
	if code != http.StatusCreated {
		t.Fatalf("bounded_reuse grant (%d): %s", code, resp)
	}
	var g struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	json.Unmarshal([]byte(resp), &g)

	// Exercise the one credential twice, each a two-phase use at its own sequence number.
	for i, u := range []struct {
		nonce string
		usn   int
	}{{"nonce-1", 1}, {"nonce-2", 2}} {
		code, ir := do(t, h, "POST", "/v2/use-intent", boundedUseBody(t, fmt.Sprintf("idem-intent-%d", u.usn), g.Capability, g.GrantID, ak, "SELECT 1", u.nonce, u.usn))
		if code != http.StatusCreated {
			t.Fatalf("use-intent %d (%d): %s", i+1, code, ir)
		}
		var intent struct {
			UseID string `json:"use_id"`
		}
		json.Unmarshal([]byte(ir), &intent)
		ob, _ := json.Marshal(map[string]any{"idempotency_key": fmt.Sprintf("idem-outcome-%d", u.usn), "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
		if code, or := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
			t.Fatalf("use-outcome %d (%d): %s", i+1, code, or)
		}
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	taxJSON, digest, ver, err := taxonomy.Sign(c, taxKey, 1, 0, 9_999_999_999,
		[]taxonomy.Entry{{ResourceID: "orders-db", Action: "db.query:orders-ro"}}, nil)
	if err != nil {
		t.Fatalf("taxonomy.Sign: %v", err)
	}
	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q],"attestation_keys":[%q],"taxonomy":%s,"taxonomy_keys":[%q],"taxonomy_digest":%q,"taxonomy_version":%d}`,
		c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa), attestPubEncoded(att), taxJSON, attestPubEncoded(taxKey), digest, ver)
	rep := c.VerifyBundleWith(anchored, opts)

	for _, want := range []string{
		`"ok":true`,
		`"action_completeness":"attested_complete_over_brokered_surface"`,
		`"bounded_reuse_grants":1`,
		`"uses_matched":2`,        // BOTH exercises of the one N-Use credential matched
		`"uses_pop_reverified":2`, // each was independently PoP-reverified
		`"bounded_reuse_overspent":0`,
		`"bounded_reuse_seq_replays":0`,
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("capstone over bounded_reuse must verify with %s\nreport: %s", want, rep)
		}
	}
}
