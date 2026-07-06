package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/averin-dev/averin/server/internal/api"
	"github.com/averin-dev/averin/server/internal/core"
	"github.com/averin-dev/averin/server/internal/store"
)

// grantEvidenceExp parses extensions.broker.grant_evidence.exp (unix) from a sealed grant record.
func grantEvidenceExp(t *testing.T, record json.RawMessage) int64 {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal(record, &rec); err != nil {
		t.Fatalf("parse grant record: %v", err)
	}
	ge := rec["extensions"].(map[string]any)["broker"].(map[string]any)["grant_evidence"].(map[string]any)
	return int64(ge["exp"].(float64))
}

// TestNativeGrantAndIntrospectionRoundTripsThroughRustVerifier is the M3 ONLINE end-to-end: a native
// (token_exchange) grant issued via POST /v2/grants + a resource-signed introspection transcript recorded via
// POST /v2/introspection, checkpointed + exported + anchored, then verified offline by the Rust verifier —
// reaching native_credential_present:true + introspection_status:"attested" (the native surface), uses_matched:0.
func TestNativeGrantAndIntrospectionRoundTripsThroughRustVerifier(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	rawSeed, _ := hex.DecodeString(resourceSeed)
	rawRes := ed25519.NewKeyFromSeed(rawSeed)
	tsa := testTSAKey()
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithIntrospection(rawRes).
		Routes()

	// 1) a NATIVE (token_exchange) grant — no agent PoP, no minted capability.
	grantBody, _ := json.Marshal(map[string]any{
		"idempotency_key": "native-1", "project_id": "p1", "session_id": "s1",
		"agent_id": "agent-x", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": "read:orders write:orders", "mode": "token_exchange", "lease_id": "lease-sts-1", "ttl_seconds": 3600,
	})
	code, resp := do(t, h, "POST", "/v2/grants", string(grantBody))
	if code != http.StatusCreated {
		t.Fatalf("native grant (%d): %s", code, resp)
	}
	var gout struct {
		GrantID string          `json:"grant_id"`
		Record  json.RawMessage `json:"record"`
	}
	json.Unmarshal([]byte(resp), &gout)
	if !strings.Contains(resp, `"mode":"token_exchange"`) {
		t.Fatalf("native grant response missing mode: %s", resp)
	}
	grantExp := grantEvidenceExp(t, gout.Record)

	// 2) a resource-signed introspection transcript: credential_ref == lease_id, effective_scope ⊆ grant scope,
	//    effective_exp <= grant exp.
	introBody, _ := json.Marshal(map[string]any{
		"idempotency_key": "intro-1", "project_id": "p1", "session_id": "s1",
		"grant_id": gout.GrantID, "credential_ref": "lease-sts-1", "effective_scope": "read:orders",
		"effective_exp": grantExp,
	})
	code, resp = do(t, h, "POST", "/v2/introspection", string(introBody))
	if code != http.StatusCreated {
		t.Fatalf("introspection (%d): %s", code, resp)
	}

	// 3) checkpoint + export + anchor.
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	// 4) verify offline (pin the role-disjoint broker + resource + tsa keys).
	opts := `{"broker_authority_keys":["` + c.PubKey() + `"],"resource_authority_keys":["` + rc.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"]}`
	rep := c.VerifyBundleWith(anchored, opts)
	for _, want := range []string{
		`"ok":true`,
		`"native_credential_present":true`,
		`"introspection_transcripts_total":1`,
		`"introspection_transcripts_verified":1`,
		`"introspection_status":"attested"`,
		`"uses_matched":0`, // a native surface uses NO brokered PoP receipts
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("native+introspection bundle did not verify (missing %s):\n%s", want, rep)
		}
	}

	// NEGATIVE: an introspection whose credential_ref != the grant's lease_id must not verify (the verifier
	// re-checks credential_ref == lease_id). Build a second grant+transcript with a mismatched credential_ref.
	introBad, _ := json.Marshal(map[string]any{
		"idempotency_key": "intro-bad", "project_id": "p1", "session_id": "s1",
		"grant_id": gout.GrantID, "credential_ref": "lease-OTHER", "effective_scope": "read:orders",
		"effective_exp": grantExp,
	})
	if code, _ := do(t, h, "POST", "/v2/introspection", string(introBad)); code != http.StatusCreated {
		t.Fatalf("the server records the transcript regardless (the verifier enforces the binding); code %d", code)
	}
	do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	_, exp2 := do(t, h, "GET", "/v2/export?project=p1", "")
	rep2 := c.VerifyBundleWith(attachTestAnchor(t, exp2, tsa), opts)
	if !strings.Contains(rep2, `"ok":false`) || !strings.Contains(rep2, "credential_ref") {
		t.Fatalf("a credential_ref-mismatched transcript must fail offline:\n%s", rep2)
	}
}
