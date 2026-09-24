package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
)

func tenantGrantBody(t *testing.T, project string, ak ed25519.PrivateKey) string {
	t.Helper()
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	now := time.Now()
	req := broker.Request{PoPVersion: 2, ProjectID: project, IdempotencyKey: "grant-" + project,
		SessionID: "s1", IssuedAt: now.Unix(), RequestExpiresAt: now.Add(broker.MaxRequestAge).Unix(),
		AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: "read:orders",
		AgentPubKey: pub, TTL: time.Minute}
	body, err := json.Marshal(map[string]any{
		"pop_version": 2, "issued_at": req.IssuedAt, "request_expires_at": req.RequestExpiresAt,
		"idempotency_key": req.IdempotencyKey, "project_id": project, "session_id": "s1",
		"agent_id": "agent-1", "action": req.Action, "resource": req.Resource, "scope": req.Scope,
		"agent_pubkey": pub, "agent_sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge())),
		"ttl_seconds": 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// The nonce set in the unchanged receipt commitment is evaluated within one
// authenticated project. Equal nonces in two independently signed project
// bundles are valid; splicing their signed records/checkpoints must fail even
// if the attacker omits the bundle's top-level project_id.
func TestTenantNonceOfflineProjectComposition(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q]}`,
		c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa))
	bundles := map[string]map[string]json.RawMessage{}
	for _, project := range []string{"p1", "p2"} {
		code, response := do(t, h, "POST", "/v2/grants", tenantGrantBody(t, project, ak))
		if code != http.StatusCreated {
			t.Fatalf("%s grant (%d): %s", project, code, response)
		}
		var grant struct {
			GrantID    string `json:"grant_id"`
			Capability string `json:"capability"`
		}
		if err := json.Unmarshal([]byte(response), &grant); err != nil {
			t.Fatal(err)
		}
		use := mutateGrantBody(t, useBody(t, "use-"+project, grant.Capability, grant.GrantID, ak, "SELECT 1", "equal-nonce"), "project_id", project)
		if code, response = do(t, h, "POST", "/v2/use", use); code != http.StatusCreated {
			t.Fatalf("%s equal nonce use (%d): %s", project, code, response)
		}
		if code, response = do(t, h, "POST", "/v2/checkpoints?project="+project, ""); code != http.StatusCreated {
			t.Fatalf("%s checkpoint (%d): %s", project, code, response)
		}
		_, exported := do(t, h, "GET", "/v2/export?project="+project, "")
		anchored := attachTestAnchor(t, exported, tsa)
		if report := c.VerifyBundleWith(anchored, opts); !strings.Contains(report, `"ok":true`) || !strings.Contains(report, `"uses_matched":1`) {
			t.Fatalf("%s independent bundle rejected: %s", project, report)
		}
		var bundle map[string]json.RawMessage
		if err := json.Unmarshal([]byte(anchored), &bundle); err != nil {
			t.Fatal(err)
		}
		bundles[project] = bundle
	}
	mixed := bundles["p1"]
	for _, field := range []string{"records", "checkpoints"} {
		var left, right []json.RawMessage
		if err := json.Unmarshal(mixed[field], &left); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(bundles["p2"][field], &right); err != nil {
			t.Fatal(err)
		}
		mixed[field], _ = json.Marshal(append(left, right...))
	}
	for _, omitProject := range []bool{false, true} {
		if omitProject {
			delete(mixed, "project_id")
		}
		body, err := json.Marshal(mixed)
		if err != nil {
			t.Fatal(err)
		}
		report := c.VerifyBundleWith(string(body), opts)
		if !strings.Contains(report, `"ok":false`) || !strings.Contains(report, "project_id does not match bundle") {
			t.Fatalf("mixed projects accepted or wrong failure (omit=%v): %s", omitProject, report)
		}
	}
}
