package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/averin-dev/averin/server/internal/broker"
)

func signedDelegationRecord(t *testing.T, root, leaf ed25519.PrivateKey, id string) string {
	t.Helper()
	rootPub := root.Public().(ed25519.PublicKey)
	leafPub := leaf.Public().(ed25519.PublicKey)
	exp := time.Now().Add(time.Hour).Unix()
	scopeDigest, err := testDelegationScopeDigest(map[string]any{
		"from_agent_id": "parent@1", "to_agent_id": "child@1",
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
		id, 0, broker.KeyID(rootPub), broker.KeyID(leafPub),
		hop.Scope, hop.Action, hop.ResourceID, hop.Exp,
	)
	hop.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(root, challenge))
	record := map[string]any{
		"idempotency_key": id,
		"project_id":      "p1",
		"session_id":      "delegation",
		"event_type":      "spawn_child",
		"extensions": map[string]any{"govder": map[string]any{
			"payload": map[string]any{
				"handoff_id": id, "from_agent_id": "parent@1", "to_agent_id": "child@1",
				"delegated_scope": []string{"cap-read"},
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

func testDelegationScopeDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var canonical any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&canonical); err != nil {
		return "", err
	}
	b, err = json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func TestGenericRecordVerifiesDelegationHopAgainstPinnedAuthority(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(nil)
	_, leaf, _ := ed25519.GenerateKey(nil)
	srv := newServer(t).WithPolicyEngineKey("policy_engine_signed", root.Public().(ed25519.PublicKey))
	code, body := do(t, srv.Routes(), http.MethodPost, "/v2/records", signedDelegationRecord(t, root, leaf, "handoff-1"))
	if code != http.StatusCreated {
		t.Fatalf("valid pinned delegation hop: %d %s", code, body)
	}

	_, attacker, _ := ed25519.GenerateKey(nil)
	code, _ = do(t, srv.Routes(), http.MethodPost, "/v2/records", signedDelegationRecord(t, attacker, leaf, "handoff-2"))
	if code != http.StatusBadRequest {
		t.Fatalf("attacker-selected delegation root: want 400, got %d", code)
	}

	var tampered map[string]any
	if err := json.Unmarshal([]byte(signedDelegationRecord(t, root, leaf, "handoff-3")), &tampered); err != nil {
		t.Fatal(err)
	}
	payload := tampered["extensions"].(map[string]any)["govder"].(map[string]any)["payload"].(map[string]any)
	payload["delegated_scope"] = []string{"cap-admin"}
	b, _ := json.Marshal(tampered)
	code, _ = do(t, srv.Routes(), http.MethodPost, "/v2/records", string(b))
	if code != http.StatusBadRequest {
		t.Fatalf("tampered delegated scope: want 400, got %d", code)
	}
}

func TestGenericRecordRejectsUnsignedDelegationClaim(t *testing.T) {
	srv := newServer(t)
	record := map[string]any{
		"idempotency_key": "unsigned-handoff", "project_id": "p1", "session_id": "delegation",
		"event_type": "sub-agent-handoff",
		"extensions": map[string]any{"govder": map[string]any{"payload": map[string]any{
			"handoff_id": "h1", "handoff_kind": "sub-agent-spawn",
		}}},
	}
	b, _ := json.Marshal(record)
	code, _ := do(t, srv.Routes(), http.MethodPost, "/v2/records", string(b))
	if code != http.StatusBadRequest {
		t.Fatalf("unsigned delegation claim: want 400, got %d", code)
	}
}
