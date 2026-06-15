package api_test

import (
	"bytes"
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

func brokerIssuingKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
}
func grantAgentKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
}

func newBrokerServer(t *testing.T) http.Handler {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	return api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).Routes()
}

// grantBody builds a JSON grant request whose agent_sig proves possession of the agent key (PoP),
// carrying idempotency key `idem`.
func grantBody(idem, scope string, ak ed25519.PrivateKey, sigKey ed25519.PrivateKey) string {
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	// the challenge is over agent_id/action/resource/scope/agent_pubkey
	req := broker.Request{
		AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db",
		Scope: scope, AgentPubKey: pub,
	}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(sigKey, req.Challenge()))
	b, _ := json.Marshal(map[string]any{
		"idempotency_key": idem,
		"project_id":      "p1", "session_id": "s1",
		"agent_id": "agent-1", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": scope, "agent_pubkey": pub, "agent_sig": sig, "ttl_seconds": 60,
	})
	return string(b)
}

func TestCredentialGrantRecordedBeforeIssue(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("grant failed (%d): %s", code, resp)
	}
	var out struct {
		GrantID    string                     `json:"grant_id"`
		Capability string                     `json:"capability"`
		ScopeClass string                     `json:"scope_class"`
		Record     map[string]json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, resp)
	}
	if out.ScopeClass != "single_operation" {
		t.Fatalf("scope_class = %q, want single_operation", out.ScopeClass)
	}

	// the returned capability verifies under the broker's issuing key and is bound to the grant
	claims, err := broker.VerifyCapability(out.Capability, brokerIssuingKey().Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("capability does not verify: %v", err)
	}
	if claims.Jti != out.GrantID || claims.Aud != "orders-db" || !claims.SingleUse {
		t.Fatalf("capability claims wrong: %+v", claims)
	}
	if claims.Cnf != base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey)) {
		t.Fatalf("capability not sender-bound to the agent key")
	}

	// the sealed grant record is a gateway_enforced credential_grant with a real evidence_sig
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(out.Record[k], &s)
		return s
	}
	if str("event_type") != "credential_grant" || str("observed_via") != "broker" {
		t.Fatalf("record not a broker grant: %s", resp)
	}
	if str("content_hash") == "" || str("sig") == "" {
		t.Fatalf("grant record not sealed")
	}
	var authority struct {
		Source      string `json:"source"`
		GrantID     string `json:"grant_id"`
		EvidenceSig string `json:"evidence_sig"`
		EvidenceHsh string `json:"evidence_hash"`
	}
	json.Unmarshal(out.Record["authority"], &authority)
	if authority.Source != "gateway_enforced" {
		t.Fatalf("authority.source = %q, want gateway_enforced", authority.Source)
	}
	if authority.GrantID != out.GrantID || !strings.HasPrefix(authority.EvidenceSig, "ed25519:") || !strings.HasPrefix(authority.EvidenceHsh, "sha256:") {
		t.Fatalf("authority block malformed: %+v", authority)
	}
	var ext struct {
		Broker struct {
			IssuanceStatus    string `json:"issuance_status"`
			ConformanceLevel  string `json:"conformance_level"`
			CredentialBinding string `json:"credential_binding"`
		} `json:"broker"`
	}
	json.Unmarshal(out.Record["extensions"], &ext)
	if ext.Broker.IssuanceStatus != "recorded" || ext.Broker.ConformanceLevel != "L1_grant_only" {
		t.Fatalf("extensions.broker wrong: %+v", ext.Broker)
	}

	// the grant is durably stored, the bundle verifies, and the grant elevates to gateway_enforced
	// under the pinned broker recording key (Tier-A grant accountability).
	if c, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); c != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", c, resp)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"ok":true`) || !strings.Contains(report, `"records_proven":1`) {
		t.Fatalf("grant bundle should verify: %s", report)
	}
	if !strings.Contains(report, `"grant_total":1`) || !strings.Contains(report, `"grant_verified":1`) {
		t.Fatalf("the grant should verify to gateway_enforced under the pinned broker key: %s", report)
	}
	if !strings.Contains(report, `"grant_accountability":"complete"`) {
		t.Fatalf("expected complete grant accountability: %s", report)
	}
}

func TestGrantIsIdempotent(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	body := grantBody("retry-key", "read:orders", ak, ak)

	parse := func(resp string) (grantID, cap string, created bool) {
		var o struct {
			GrantID    string `json:"grant_id"`
			Capability string `json:"capability"`
			Created    bool   `json:"created"`
		}
		json.Unmarshal([]byte(resp), &o)
		return o.GrantID, o.Capability, o.Created
	}

	code1, r1 := do(t, h, "POST", "/v2/grants", body)
	if code1 != http.StatusCreated {
		t.Fatalf("first grant (%d): %s", code1, r1)
	}
	g1, c1, created1 := parse(r1)
	if !created1 {
		t.Fatal("first grant should be created")
	}

	// a retry of the identical request (lost response) must COLLAPSE: same grant_id, same capability,
	// created=false — never a second live credential.
	code2, r2 := do(t, h, "POST", "/v2/grants", body)
	if code2 != http.StatusCreated {
		t.Fatalf("retry grant (%d): %s", code2, r2)
	}
	g2, c2, created2 := parse(r2)
	if created2 {
		t.Fatal("a retry must NOT create a second grant")
	}
	if g1 != g2 {
		t.Fatalf("retry grant_id changed: %s vs %s", g1, g2)
	}
	if c1 != c2 {
		t.Fatalf("retry returned a DIFFERENT capability (double-issue!):\n%s\n%s", c1, c2)
	}

	// only one grant exists in the project
	_, dag := do(t, h, "GET", "/v2/dag?project=p1&session=s1", "")
	if n := strings.Count(dag, `"event_type":"credential_grant"`); n != 1 {
		t.Fatalf("expected exactly 1 grant record, found %d", n)
	}
}

func TestGrantRequiresIdempotencyKey(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("", "read:orders", ak, ak))
	if code != http.StatusBadRequest {
		t.Fatalf("missing idempotency_key should be 400, got %d: %s", code, resp)
	}
}

func TestGrantRejectsForbiddenScope(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-2", "iam:reset", ak, ak))
	if code != http.StatusBadRequest {
		t.Fatalf("forbidden scope should be 400, got %d: %s", code, resp)
	}
}

func TestGrantRejectsBadProofOfPossession(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	// sign the challenge with a DIFFERENT key than agent_pubkey → PoP fails
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-3", "read:orders", ak, wrong))
	if code != http.StatusBadRequest {
		t.Fatalf("bad PoP should be 400, got %d: %s", code, resp)
	}
}

func TestGrantDisabledWithoutBroker(t *testing.T) {
	h := newSrv(t) // no WithBroker
	code, _ := do(t, h, "POST", "/v2/grants", grantBody("idem-4", "read:orders", grantAgentKey(), grantAgentKey()))
	if code != http.StatusNotImplemented {
		t.Fatalf("grants without a broker key should be 501, got %d", code)
	}
}
