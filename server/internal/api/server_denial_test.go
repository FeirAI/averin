package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/broker"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
)

func denyLogServer(t *testing.T) http.Handler {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	return api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithDeniedGrantLog().Routes()
}

// TestForbiddenScopeSealsDenialRecord (B11): with the denied-grant log enabled, a forbidden single_operation
// scope is rejected (400, no capability) AND sealed as a grant_denied record that classifies to
// BrokerRole::None — recording the requested scope, carrying NO capability / broker_seq / grant_evidence,
// never counted as a grant, and not tripping the R2 fail-closed or D6 suppression checks.
func TestForbiddenScopeSealsDenialRecord(t *testing.T) {
	h := denyLogServer(t)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-deny", "iam:reset", ak, ak))
	if code != http.StatusBadRequest {
		t.Fatalf("forbidden scope should be 400, got %d: %s", code, resp)
	}
	if strings.Contains(resp, "capability") {
		t.Fatalf("a denied grant must not return a capability: %s", resp)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if !strings.Contains(exp, `"event_type":"credential_grant_denied"`) {
		t.Fatalf("the forbidden-scope denial should be sealed: %s", exp)
	}
	if !strings.Contains(exp, `"kind":"grant_denied"`) || !strings.Contains(exp, `"scope":"iam:reset"`) {
		t.Fatalf("the denial must record the requested scope metadata: %s", exp)
	}
	if strings.Contains(exp, `"broker_seq"`) {
		t.Fatalf("a denial must not carry a broker_seq (would corrupt the gapless D6 log): %s", exp)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"ok":true`) {
		t.Fatalf("a bundle with only a denial must verify ok (classifies to None, no R2/D6 trip): %s", report)
	}
	if !strings.Contains(report, `"grant_total":0`) {
		t.Fatalf("a denial must not count as a grant (grant_total:0): %s", report)
	}
	// the verifier SURFACES the denial as evidence (B11): denied_grants counts it, separate from grants.
	if !strings.Contains(report, `"denied_grants":1`) {
		t.Fatalf("the verifier should surface the sealed denial (denied_grants:1): %s", report)
	}
}

// TestPoPFailureSealsDenialButMalformedDoesNot (B11): a well-formed request that fails proof-of-possession is
// a policy denial (sealed, reason pop_failed, only the CLAIMED pubkey — never a verified cnf); a malformed
// request (missing required field) is NOT a policy denial and seals nothing.
func TestPoPFailureSealsDenialButMalformedDoesNot(t *testing.T) {
	h := denyLogServer(t)
	ak, thief := grantAgentKey(), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	// a thief signs the PoP challenge with the WRONG key -> agent_sig does not prove possession.
	if code, _ := do(t, h, "POST", "/v2/grants", grantBody("idem-pop", "read:orders", ak, thief)); code != http.StatusBadRequest {
		t.Fatalf("bad PoP should be 400, got %d", code)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if !strings.Contains(exp, `"denial_reason":"pop_failed"`) {
		t.Fatalf("a PoP-failure denial should be sealed: %s", exp)
	}
	if !strings.Contains(exp, "claimed_agent_pubkey") || strings.Contains(exp, `"cnf_kid"`) {
		t.Fatalf("a PoP-failure denial must record only the CLAIMED pubkey, never a verified cnf_kid: %s", exp)
	}

	// a MALFORMED request (missing action) carries no policy signal -> nothing is sealed.
	mh := denyLogServer(t)
	bad := `{"idempotency_key":"idem-bad","project_id":"p1","session_id":"s1","agent_id":"a","resource":"r","scope":"read:x","agent_pubkey":"AAAA","agent_sig":"AAAA","ttl_seconds":60}`
	if code, _ := do(t, mh, "POST", "/v2/grants", bad); code != http.StatusBadRequest {
		t.Fatalf("malformed grant should be 400")
	}
	_, exp2 := do(t, mh, "GET", "/v2/export?project=p1", "")
	if strings.Contains(exp2, "credential_grant_denied") {
		t.Fatalf("a malformed request must NOT seal a denial (no policy signal): %s", exp2)
	}
}

// TestTTLExceededDenialRecordsClaimedKeyNotProvenCnf (B11): an over-cap TTL is refused by Validate() BEFORE
// the proof-of-possession check, so the agent key is UNPROVEN — the denial must record only the CLAIMED
// pubkey, never a verified cnf_kid (else a forged-sig over-cap request could bind a victim's key as "proven").
func TestTTLExceededDenialRecordsClaimedKeyNotProvenCnf(t *testing.T) {
	h := denyLogServer(t)
	ak := grantAgentKey()
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	req := broker.Request{AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: "read:orders", AgentPubKey: pub}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge()))
	body, _ := json.Marshal(map[string]any{
		"idempotency_key": "idem-ttl", "project_id": "p1", "session_id": "s1",
		"agent_id": "agent-1", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": "read:orders", "agent_pubkey": pub, "agent_sig": sig, "ttl_seconds": 99999, // over MaxTTL (1h)
	})
	if code, r := do(t, h, "POST", "/v2/grants", string(body)); code != http.StatusBadRequest {
		t.Fatalf("over-cap ttl should be 400, got %d: %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if !strings.Contains(exp, `"denial_reason":"ttl_exceeded"`) {
		t.Fatalf("a ttl-over-cap denial should be sealed: %s", exp)
	}
	if !strings.Contains(exp, "claimed_agent_pubkey") || strings.Contains(exp, `"cnf_kid"`) {
		t.Fatalf("a ttl_exceeded denial must record only the CLAIMED pubkey (PoP unproven before the TTL check): %s", exp)
	}
}

// TestDeniedGrantLogOffByDefault: without WithDeniedGrantLog the forbidden scope is still rejected but NO
// denial is sealed (opt-in — avoids a probe-driven storage/billing DoS by default).
func TestDeniedGrantLogOffByDefault(t *testing.T) {
	h := newBrokerServer(t) // no WithDeniedGrantLog
	ak := grantAgentKey()
	if code, _ := do(t, h, "POST", "/v2/grants", grantBody("idem-deny", "iam:reset", ak, ak)); code != http.StatusBadRequest {
		t.Fatalf("forbidden scope should still be 400")
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if strings.Contains(exp, "credential_grant_denied") {
		t.Fatalf("denial logging is opt-in; nothing should be sealed by default: %s", exp)
	}
}
