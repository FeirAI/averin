package api_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
	"github.com/feirai/averin/server/internal/taxonomy"
)

// TEST-ONLY KEYS. The vectors under spec/fixtures (capstone-with-refusals-v3.json and the gateway-refusal-*
// samples) are signed by seeds derived from the PUBLIC labels below: seed = sha256(label). Anyone can
// recompute them, so they prove nothing about a deployment and must never be pinned in one. The public keys
// are listed in spec/test-keys.json (checked by TestTestKeysFileMatchesLabels); feir-os verify-posture
// refuses a deployment that pins any of them (PS-TEST-KEY-PINNED). The production Solo taxonomy rotation
// (FEI-36) is a separate release step with the owner's key.
var testKeyLabels = map[string]string{
	"record":      "averin-TEST-ONLY-record-v1",
	"resource":    "averin-TEST-ONLY-resource-v1",
	"broker":      "averin-TEST-ONLY-broker-v1",
	"attestation": "averin-TEST-ONLY-attestation-v1",
	"taxonomy":    "averin-TEST-ONLY-taxonomy-v1",
	"tsa":         "averin-TEST-ONLY-tsa-v1",
	"agent":       "averin-TEST-ONLY-agent-v1",
}

func labelSeed(role string) []byte {
	sum := sha256.Sum256([]byte(testKeyLabels[role]))
	return sum[:]
}

func labelKey(role string) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(labelSeed(role)) }

func labelCore(t *testing.T, role string) *core.Core {
	t.Helper()
	c, err := core.New(hex.EncodeToString(labelSeed(role)))
	if err != nil {
		t.Fatalf("core %s: %v", role, err)
	}
	return c
}

// refusalCapstone builds a real capstone history (grant, two-phase use, checkpoint, anchor) with gateway
// refusals of UNGRANTED actions sealed into the same session, and returns the anchored bundle and the
// verifier options. Everything is signed by the label-derived test keys.
func refusalCapstone(t *testing.T) (anchored, opts string, c *core.Core) {
	t.Helper()
	c = labelCore(t, "record")
	rc := labelCore(t, "resource")
	att, taxKey, tsa := labelKey("attestation"), labelKey("taxonomy"), labelKey("tsa")
	manifest := `{"side_effect_closure":[{"resource_id":"orders-db","action":"db.query:orders-ro","may_touch":[]}]}`
	fixedNow := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	h := api.New(c, store.NewMem().WithClock(fixedNow), "k0").WithAuth(auth.NewOpenStore()).
		WithClock(fixedNow).
		WithBroker(labelKey("broker")).
		WithResource(rc, "orders-db").
		WithAttestation(att).
		WithCoverageManifest(manifest).
		Routes()
	ak := labelKey("agent")
	grantID, cap := mkGrantAt(t, h, ak, "idem-grant", fixedNow())
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	_ = json.Unmarshal([]byte(resp), &intent)

	// Refusals of actions that were never granted (one coalesced record, one single, one summary), sealed
	// between the intent and the outcome so they interleave with the use in one session.
	at := "2026-01-01T00:00:00Z"
	for i, r := range []map[string]any{
		{"action": "change_payout_details", "entry_point": "mcp", "reason_class": "not_granted", "attempts": 50},
		{"action": "db.drop_table", "entry_point": "execute", "reason_class": "policy_deny", "attempts": 1},
		{"action": "*", "summary": true, "attempts": 7, "by_class": map[string]any{"rate_limit": 4, "model_unpriced": 3}},
	} {
		r["project_id"], r["session_id"], r["agent_id"] = "p1", "s1", "agent-x"
		r["idempotency_key"] = fmt.Sprintf("refusal-capstone-%d", i)
		r["first_at"], r["last_at"] = at, at
		b, _ := json.Marshal(r)
		if code, resp := do(t, h, "POST", "/v2/refusals", string(b)); code != http.StatusCreated {
			t.Fatalf("refusal %d (%d): %s", i, code, resp)
		}
	}
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	if code, r := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored = attachTestAnchor(t, exp, tsa)
	// A taxonomy signed by the TEST taxonomy key at a version no production Solo taxonomy uses (testTaxonomyVersion,
	// far above any release number), so this pin set cannot be mistaken for or copied as a production one. It
	// lists only the granted pair; refusals never add to it, and no rotation is needed to record a refusal.
	taxJSON, digest, ver, err := taxonomy.Sign(c, taxKey, testTaxonomyVersion, 0, 9_999_999_999,
		[]taxonomy.Entry{{ResourceID: "orders-db", Action: "db.query:orders-ro"}}, nil)
	if err != nil {
		t.Fatalf("taxonomy.Sign: %v", err)
	}
	opts = fmt.Sprintf(`{"signing_keys":[%q],"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q],"attestation_keys":[%q],"taxonomy":%s,"taxonomy_keys":[%q],"taxonomy_digest":%q,"taxonomy_version":%d,"claim_policy":{"requested":"complete_brokered"}}`,
		c.PubKey(), c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa), attestPubEncoded(att), taxJSON, attestPubEncoded(taxKey), digest, ver)
	return anchored, opts, c
}

// testTaxonomyVersion is deliberately not a release version: a TEST-signed taxonomy must never share a version
// number with one a deployment could pin.
const testTaxonomyVersion = 9_000_001

func wantRefusalCapstone(t *testing.T, rep string) {
	t.Helper()
	for _, want := range []string{
		`"ok":true`,
		`"action_completeness":"attested_complete_over_brokered_surface"`,
		`"side_effect_closure_status":"closed"`,
		`"attestation_status":"attested_claims"`,
		`"taxonomy_status":"validated"`,
		`"uses_matched":1`,
		`"complete_brokered":"satisfied"`,
		`"gateway_refusals":3`,
		`"gateway_refusal_attempts":58`,
		`"gateway_refusals_by_class":{"model_unpriced":3,"not_granted":50,"policy_deny":1,"rate_limit":4}`,
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("refusals must leave the capstone intact; want %s\nreport: %s", want, rep)
		}
	}
	if strings.Contains(rep, "change_payout_details") {
		t.Fatalf("an ungranted action must not appear in the report surface: %s", rep)
	}
}

// gateway-refusal-never-widens-surface: refusals of ungranted actions leave the capstone attested_complete and
// T6 closed, and the attested resource set unchanged.
func TestCapstoneWithRefusalsStaysClosed(t *testing.T) {
	anchored, opts, c := refusalCapstone(t)
	wantRefusalCapstone(t, c.VerifyBundleWith(anchored, opts))
	if path := os.Getenv("AVERIN_WRITE_REFUSAL_CAPSTONE_FIXTURE"); path != "" {
		fixture, _ := json.Marshal(map[string]json.RawMessage{"bundle": json.RawMessage(anchored), "opts": json.RawMessage(opts)})
		if err := os.WriteFile(path, fixture, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The committed vector replays to the same verdict under the Go-linked core (the Rust and WASM targets replay
// it in core/tests/gateway_refusal.rs and verifier/test).
func TestCommittedRefusalCapstoneFixtureVerifies(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/fixtures/capstone-with-refusals-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Bundle json.RawMessage `json:"bundle"`
		Opts   json.RawMessage `json:"opts"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	wantRefusalCapstone(t, labelCore(t, "record").VerifyBundleWith(string(fx.Bundle), string(fx.Opts)))
}

// spec/test-keys.json lists the public half of every label-derived test key, marked test-only.
func TestTestKeysFileMatchesLabels(t *testing.T) {
	type entry struct {
		Role   string `json:"role"`
		Label  string `json:"label"`
		Public string `json:"public_key"`
	}
	computed := map[string]entry{}
	for role, label := range testKeyLabels {
		pub := labelKey(role).Public().(ed25519.PublicKey)
		computed[role] = entry{role, label, "ed25519pub:" + base64.RawURLEncoding.EncodeToString(pub)}
	}
	if path := os.Getenv("AVERIN_WRITE_TEST_KEYS"); path != "" {
		var list []entry
		for _, role := range []string{"record", "resource", "broker", "attestation", "taxonomy", "tsa", "agent"} {
			list = append(list, computed[role])
		}
		out, _ := json.MarshalIndent(map[string]any{
			"$comment":  "TEST-ONLY KEYS. Seeds are sha256(label) of the public labels below; anyone can recompute them. They sign only the committed test vectors. Never pin one in a deployment (feir-os verify-posture PS-TEST-KEY-PINNED). Production signatures are a separate release step (FEI-36).",
			"test_only": true,
			"keys":      list,
		}, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("../../../spec/test-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		TestOnly bool    `json:"test_only"`
		Keys     []entry `json:"keys"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if !file.TestOnly || len(file.Keys) != len(computed) {
		t.Fatalf("spec/test-keys.json must be test_only and list all %d keys", len(computed))
	}
	for _, k := range file.Keys {
		if want, ok := computed[k.Role]; !ok || want != k {
			t.Fatalf("spec/test-keys.json entry %q differs from the label-derived key: %+v", k.Role, k)
		}
	}
}
