package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
	"github.com/feir-dev/feir/server/internal/taxonomy"
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
