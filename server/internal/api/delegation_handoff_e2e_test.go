package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/feir-dev/feir/server/internal/broker"
)

// handoffWireRecord builds a sub-agent-handoff record using govder's mapper
// wire value for event_type ("handoff", NOT the raw govder enum
// "sub-agent-handoff") and carries the signed delegation_hop in the handoff
// payload block govder's provisioner seals (govder/internal/connectors/
// provisioner.go sealSubAgentHandoff). The hop is signed by the policy-engine
// root exactly as govder's SignHandoffHop does (DerivePolicyEngineKey +
// evidenceScopeDigest + SignHop), replicated here against feir's own
// broker.DelegationHop / DelegationHopChallenge / KeyID (byte-identical to
// govder's internal/delegation per ADR 0005 M2) so the test stays
// self-contained in feir's package without a cross-module import.
func handoffWireRecord(t *testing.T, root, leaf ed25519.PrivateKey, handoffID string) string {
	t.Helper()
	rootPub := root.Public().(ed25519.PublicKey)
	leafPub := leaf.Public().(ed25519.PublicKey)
	exp := time.Now().Add(time.Hour).Unix()
	scopeDigest, err := testDelegationScopeDigest(map[string]any{
		"from_agent_id":   "parent@1",
		"to_agent_id":     "child@1",
		"delegated_scope": []string{"cap-read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	hop := broker.DelegationHop{
		DelegatorCnf: base64.RawURLEncoding.EncodeToString(rootPub),
		DelegateCnf:  base64.RawURLEncoding.EncodeToString(leafPub),
		Scope:        scopeDigest,
		Action:       "spawn_child",
		ResourceID:   "parent@1->child@1",
		Exp:          exp,
	}
	challenge := broker.DelegationHopChallenge(
		handoffID, 0, broker.KeyID(rootPub), broker.KeyID(leafPub),
		hop.Scope, hop.Action, hop.ResourceID, hop.Exp,
	)
	hop.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(root, challenge))
	record := map[string]any{
		"idempotency_key": handoffID,
		"project_id":      "p1",
		"session_id":      "delegation-handoff",
		"event_type":      "handoff",
		"extensions": map[string]any{"govder": map[string]any{
			"payload": map[string]any{
				"handoff_id":      handoffID,
				"from_agent_id":   "parent@1",
				"to_agent_id":     "child@1",
				"delegated_scope": []string{"cap-read"},
				"handoff_kind":    "sub-agent-spawn",
				"delegation_hop":  hop,
			},
		}},
	}
	b, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSubAgentHandoff_ViaGovderMapperWireValue_VerifiesAtFeir closes the loop
// finding F18: govder's mapper maps EventSubAgentHandoff onto the feir wire
// value "handoff" (govder/internal/feir/mapper.go:72), and the production
// governor path is mapper -> POST /v2/records -> feir /v2/verify. The prior
// feir-side test (TestGenericRecordVerifiesDelegationHopAgainstPinnedAuthority)
// posted records DIRECTLY with event_type "spawn_child" and never exercised the
// mapper's actual "handoff" wire value nor the /v2/verify elevation. This test
// posts a handoff row carrying a policy_engine_signed-pinned delegation_hop with
// the REAL "handoff" wire value, asserts 201, and then asserts feir's
// /v2/verify reads the chain as ok with the record integrity-proven.
func TestSubAgentHandoff_ViaGovderMapperWireValue_VerifiesAtFeir(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(nil)
	_, leaf, _ := ed25519.GenerateKey(nil)
	srv := newServer(t).WithPolicyEngineKey("policy_engine_signed", root.Public().(ed25519.PublicKey))
	h := srv.Routes()

	// Positive: a handoff row whose delegation_hop is signed by the pinned
	// policy-engine key is accepted at /v2/records (201) — the hop signature
	// verifies AND the delegator is the pinned policy_engine_signed authority.
	rec, created := postRecord(t, h, handoffWireRecord(t, root, leaf, "handoff-e2e-1"))
	if !created {
		t.Fatalf("valid handoff (mapper wire value) with pinned delegation hop was not created: %v", rec)
	}
	handoffRecordID, _ := rec["record_id"].(string)
	if handoffRecordID == "" {
		t.Fatalf("sealed handoff record has no record_id: %v", rec)
	}

	// Checkpoint, then verify the project chain via the self-verify endpoint.
	if code, resp := do(t, h, http.MethodPost, "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint failed (%d): %s", code, resp)
	}
	vcode, vreport := do(t, h, http.MethodGet, "/v2/verify?project=p1", "")
	if vcode != http.StatusOK || !strings.Contains(vreport, `"ok":true`) {
		t.Fatalf("/v2/verify not ok over the handoff chain (%d): %s", vcode, vreport)
	}
	if !strings.Contains(vreport, `"records_proven":1`) {
		t.Fatalf("expected 1 proven record (the sealed handoff) in /v2/verify report: %s", vreport)
	}
	// The sealed handoff record must read integrity_proven — its content_hash +
	// signature verify under feir's signing key (the elevate target of the
	// closed-loop hop pinned to policy_engine_signed).
	var report struct {
		RecordTrust []struct {
			RecordID    string `json:"record_id"`
			IntegrityOK bool   `json:"integrity_ok"`
			SignatureOK bool   `json:"signature_ok"`
			Trust       string `json:"trust"`
		} `json:"record_trust"`
	}
	if err := json.Unmarshal([]byte(vreport), &report); err != nil {
		t.Fatalf("decode /v2/verify report: %v\n%s", err, vreport)
	}
	var found bool
	for _, rt := range report.RecordTrust {
		if rt.RecordID == handoffRecordID {
			found = true
			if !rt.IntegrityOK || !rt.SignatureOK || rt.Trust != "integrity_proven" {
				t.Fatalf("handoff record %s trust = integrity_ok=%v signature_ok=%v trust=%q, want integrity_proven: %s",
					handoffRecordID, rt.IntegrityOK, rt.SignatureOK, rt.Trust, vreport)
			}
		}
	}
	if !found {
		t.Fatalf("handoff record %s missing from /v2/verify record_trust: %s", handoffRecordID, vreport)
	}

	// Negative (i): a handoff row whose hop is signed by an ATTACKER key (not the
	// pinned policy_engine_signed authority) is rejected at /v2/records (400) —
	// feir's validateDelegationEvidence pins the delegator to the policy key.
	_, attacker, _ := ed25519.GenerateKey(nil)
	code, _ := do(t, h, http.MethodPost, "/v2/records", handoffWireRecord(t, attacker, leaf, "handoff-e2e-2"))
	if code != http.StatusBadRequest {
		t.Fatalf("attacker-signed delegation hop (not the pinned policy-engine key): want 400, got %d", code)
	}

	// Negative (ii): a handoff row whose delegated_scope is tampered AFTER signing
	// — so the re-derived scope digest no longer matches hop.Scope — is rejected
	// at /v2/records (400).
	var tampered map[string]any
	if err := json.Unmarshal([]byte(handoffWireRecord(t, root, leaf, "handoff-e2e-3")), &tampered); err != nil {
		t.Fatal(err)
	}
	payload := tampered["extensions"].(map[string]any)["govder"].(map[string]any)["payload"].(map[string]any)
	payload["delegated_scope"] = []string{"cap-admin"}
	tb, _ := json.Marshal(tampered)
	code, _ = do(t, h, http.MethodPost, "/v2/records", string(tb))
	if code != http.StatusBadRequest {
		t.Fatalf("tampered delegated_scope (hop.Scope no longer binds the carried scope): want 400, got %d", code)
	}
}
