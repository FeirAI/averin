package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/resourceshim"
)

// boundedGrantBody is grantBody for a bounded_reuse grant capped at useLimit (ADR 0005 M1). The PoP
// challenge is over agent_id/action/resource/scope/agent_pubkey only, so scope_class/use_limit do not
// affect the signature.
func boundedGrantBody(idem string, useLimit int, ak ed25519.PrivateKey) string {
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	req := broker.Request{AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: "read:orders", AgentPubKey: pub}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge()))
	b, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": "p1", "session_id": "s1",
		"agent_id": "agent-1", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": "read:orders", "scope_class": "bounded_reuse", "use_limit": useLimit,
		"agent_pubkey": pub, "agent_sig": sig, "ttl_seconds": 60,
	})
	return string(b)
}

// boundedUseBody is useBody plus a use_sequence_number (the 1-based exercise index).
func boundedUseBody(t *testing.T, idem, capability, grantID string, ak ed25519.PrivateKey, params, nonce string, usn int) string {
	t.Helper()
	binding, err := resourceshim.CredentialBinding(capability)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	c, _ := core.New(seed)
	paramsNonce := strings.Repeat("ab", 32)
	paramsCommitment, err := c.Commit("input", []byte(params), paramsNonce)
	if err != nil {
		t.Fatalf("commit params: %v", err)
	}
	ch := resourceshim.UsePoPChallenge(grantID, "orders-db", "db.query:orders-ro", paramsCommitment, binding, nonce)
	useSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, ch))
	b, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": "p1", "session_id": "s1",
		"capability": capability, "use_sig": useSig,
		"action": "db.query:orders-ro", "params": params, "nonce": nonce,
		"params_nonce": paramsNonce, "use_sequence_number": usn,
	})
	return string(b)
}

// TestBoundedReuseEndToEnd: the Go producer issues a bounded_reuse grant (use_limit=2), the agent uses
// it twice (usn 1 and 2), and the offline verifier accepts BOTH uses against the one credential
// (uses_matched:2, bounded_reuse_grants:1, no overspend/replay).
func TestBoundedReuseEndToEnd(t *testing.T) {
	h := newBrokerResourceServer(t)
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	ak := grantAgentKey()

	code, resp := do(t, h, "POST", "/v2/grants", boundedGrantBody("idem-grant", 2, ak))
	if code != http.StatusCreated {
		t.Fatalf("bounded_reuse grant failed (%d): %s", code, resp)
	}
	var g struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	json.Unmarshal([]byte(resp), &g)

	for i, u := range []struct {
		idem, nonce string
		usn         int
	}{{"idem-use-1", "nonce-1", 1}, {"idem-use-2", "nonce-2", 2}} {
		if code, r := do(t, h, "POST", "/v2/use", boundedUseBody(t, u.idem, g.Capability, g.GrantID, ak, "SELECT 1", u.nonce, u.usn)); code != http.StatusCreated {
			t.Fatalf("use %d (usn %d) failed (%d): %s", i+1, u.usn, code, r)
		}
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q]}`,
		c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa))
	rep := c.VerifyBundleWith(anchored, opts)
	for _, want := range []string{`"ok":true`, `"uses_matched":2`, `"bounded_reuse_grants":1`, `"bounded_reuse_overspent":0`, `"bounded_reuse_seq_replays":0`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("bounded_reuse bundle must verify with %s; report: %s", want, rep)
		}
	}
}

// TestBoundedReuseOverspendRejectedAtUse: a use_sequence_number above use_limit is rejected by the shim
// at /v2/use (the producer never seals an out-of-cap receipt).
func TestBoundedReuseOverspendRejectedAtUse(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", boundedGrantBody("idem-grant", 1, ak))
	if code != http.StatusCreated {
		t.Fatalf("grant failed (%d): %s", code, resp)
	}
	var g struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	json.Unmarshal([]byte(resp), &g)
	// use_limit=1 but the agent claims sequence number 2.
	if code, r := do(t, h, "POST", "/v2/use", boundedUseBody(t, "idem-use", g.Capability, g.GrantID, ak, "SELECT 1", "nonce-1", 2)); code == http.StatusCreated {
		t.Fatalf("a use_sequence_number above use_limit must be rejected, got 201: %s", r)
	}
}

// TestBoundedReuseSequenceReplayRejectedAtUse: re-using a sequence number (distinct nonce) is a
// double-spend caught by the consume-before-act ledger keyed on (grant_id, usn).
func TestBoundedReuseSequenceReplayRejectedAtUse(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", boundedGrantBody("idem-grant", 2, ak))
	if code != http.StatusCreated {
		t.Fatalf("grant failed (%d): %s", code, resp)
	}
	var g struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	json.Unmarshal([]byte(resp), &g)
	if code, r := do(t, h, "POST", "/v2/use", boundedUseBody(t, "idem-use-1", g.Capability, g.GrantID, ak, "SELECT 1", "nonce-1", 1)); code != http.StatusCreated {
		t.Fatalf("first use (usn 1) should succeed (%d): %s", code, r)
	}
	// same usn=1 with a DIFFERENT nonce -> not a nonce replay, but a (grant_id, usn) double-spend.
	if code, r := do(t, h, "POST", "/v2/use", boundedUseBody(t, "idem-use-2", g.Capability, g.GrantID, ak, "SELECT 1", "nonce-2", 1)); code == http.StatusCreated {
		t.Fatalf("re-using sequence number 1 must be rejected, got 201: %s", r)
	}
}

// TestBoundedReuseIdempotencyCapMismatch: an idempotency-key retry with a DIFFERENT use_limit is a 409
// (not a silent collapse onto the original cap); an identical retry collapses.
func TestBoundedReuseIdempotencyCapMismatch(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	if code, r := do(t, h, "POST", "/v2/grants", boundedGrantBody("idem-grant", 2, ak)); code != http.StatusCreated {
		t.Fatalf("first grant (%d): %s", code, r)
	}
	if code, _ := do(t, h, "POST", "/v2/grants", boundedGrantBody("idem-grant", 5, ak)); code != http.StatusConflict {
		t.Fatalf("a retry with a different use_limit must 409, got %d", code)
	}
	if code, r := do(t, h, "POST", "/v2/grants", boundedGrantBody("idem-grant", 2, ak)); code != http.StatusCreated {
		t.Fatalf("an identical retry must collapse to 201, got %d: %s", code, r)
	}
}
