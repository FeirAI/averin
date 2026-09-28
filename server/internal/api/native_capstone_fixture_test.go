package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
	"github.com/feirai/averin/server/internal/taxonomy"
)

// TestExportNativeCapstoneV3Fixture is an opt-in exact-byte corpus producer. It deliberately
// goes through the Go API's native grant, resource introspection, checkpoint, and export paths;
// no VerifyReport field is synthesized. The generated fixture is replayed by all three verifier
// targets in the committed verdict corpus.
func TestExportNativeCapstoneV3Fixture(t *testing.T) {
	output := os.Getenv("AVERIN_WRITE_V3_NATIVE_CAPSTONE_FIXTURE")
	if output == "" {
		t.Skip("set AVERIN_WRITE_V3_NATIVE_CAPSTONE_FIXTURE to generate the fixture")
	}
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	resSeed, _ := hex.DecodeString(resourceSeed)
	att := attestationKey()
	taxKey := taxonomyKey()
	tsa := testTSAKey()
	manifest := `{"side_effect_closure":[{"resource_id":"orders-db","action":"db.query:orders-ro","may_touch":[]}]}`
	fixedNow := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	h := api.New(c, store.NewMem().WithClock(fixedNow), "k0").
		WithClock(fixedNow).
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithIntrospection(ed25519.NewKeyFromSeed(resSeed)).
		WithAttestation(att).
		WithCoverageManifest(manifest).
		Routes()

	grantBody, _ := json.Marshal(map[string]any{
		"idempotency_key": "native-capstone-grant", "project_id": "p1", "session_id": "s1",
		"agent_id": "agent-x", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": "read:orders write:orders", "mode": "token_exchange", "lease_id": "lease-sts-capstone", "ttl_seconds": 3600,
	})
	code, response := do(t, h, "POST", "/v2/grants", string(grantBody))
	if code != http.StatusCreated {
		t.Fatalf("native grant (%d): %s", code, response)
	}
	var grant struct {
		GrantID string          `json:"grant_id"`
		Record  json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal([]byte(response), &grant); err != nil {
		t.Fatal(err)
	}
	introBody, _ := json.Marshal(map[string]any{
		"idempotency_key": "native-capstone-intro", "project_id": "p1", "session_id": "s1",
		"grant_id": grant.GrantID, "credential_ref": "lease-sts-capstone", "effective_scope": "read:orders",
		"effective_exp": grantEvidenceExp(t, grant.Record),
	})
	code, response = do(t, h, "POST", "/v2/introspection", string(introBody))
	if code != http.StatusCreated {
		t.Fatalf("native introspection (%d): %s", code, response)
	}
	if code, response = do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, response)
	}
	_, exported := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exported, tsa)

	taxJSON, digest, version, err := taxonomy.Sign(c, taxKey, 1, 0, 9_999_999_999,
		[]taxonomy.Entry{{ResourceID: "orders-db", Action: "db.query:orders-ro"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := fmt.Sprintf(`{"signing_keys":[%q],"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q],"attestation_keys":[%q],"taxonomy":%s,"taxonomy_keys":[%q],"taxonomy_digest":%q,"taxonomy_version":%d,"claim_policy":{"requested":"complete_introspected","require_attestation":true}}`,
		c.PubKey(), c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa), attestPubEncoded(att), taxJSON, attestPubEncoded(taxKey), digest, version)
	report := c.VerifyBundleWith(anchored, opts)
	for _, want := range []string{
		`"ok":true`, `"native_credential_present":true`, `"introspection_status":"attested"`,
		`"broker_trust":"sequence_verified"`, `"attestation_status":"attested_claims"`,
		`"side_effect_closure_status":"closed"`, `"complete_introspected":"satisfied"`,
		`"requested_decision":"satisfied"`,
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("real native capstone did not satisfy %s: %s", want, report)
		}
	}
	fixture, err := json.Marshal(map[string]json.RawMessage{
		"bundle": json.RawMessage(anchored), "opts": json.RawMessage(opts),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, fixture, 0o644); err != nil {
		t.Fatal(err)
	}
}
