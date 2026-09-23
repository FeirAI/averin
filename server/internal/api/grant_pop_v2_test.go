package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

type countingContentStore struct {
	content.Store
	puts int
}

func (s *countingContentStore) Put(ctx context.Context, data []byte) (content.Address, error) {
	s.puts++
	return s.Store.Put(ctx, data)
}

func popTestServer(t *testing.T, clock func() time.Time) http.Handler {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	return api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithClock(clock).Routes()
}

func mutateGrantBody(t *testing.T, body, field string, value any) string {
	t.Helper()
	var m map[string]any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&m); err != nil {
		t.Fatal(err)
	}
	m[field] = value
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGrantPoPV2RouteRejectsEveryUnsignedSubstitution(t *testing.T) {
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	h := popTestServer(t, func() time.Time { return now })
	ak := grantAgentKey()
	body := grantBodyAt("idem-original", "read:orders", ak, ak, now)
	changes := map[string]any{
		"project_id": "p2", "idempotency_key": "idem-other", "session_id": "s2",
		"agent_id": "other", "action": "db.query:other", "resource": "other-db",
		"scope": "read:other", "scope_class": "session_grant", "use_limit": 1,
		"agent_pubkey": base64.RawURLEncoding.EncodeToString(brokerIssuingKey().Public().(ed25519.PublicKey)),
		"agent_sig":    "AAAA", "lease_id": "other-lease", "mode": "unexpected",
		"authorizing_principal": "other", "delegation_chain": []string{"other"},
		"justification": "other", "ttl_seconds": 120, "issued_at": now.Unix() + 1,
		"request_expires_at": now.Add(broker.MaxRequestAge).Unix() - 1, "pop_version": 1,
	}
	for field, value := range changes {
		t.Run(field, func(t *testing.T) {
			if code, response := do(t, h, "POST", "/v2/grants", mutateGrantBody(t, body, field, value)); code != http.StatusBadRequest {
				t.Fatalf("substitution accepted: %d %s", code, response)
			}
		})
	}
	for _, project := range []string{"p1", "p2"} {
		_, exported := do(t, h, "GET", "/v2/export?project="+project, "")
		if strings.Contains(exported, `"credential_grant"`) || strings.Contains(exported, `"credential_grant_denied"`) {
			t.Fatalf("rejected proof persisted a record under %s: %s", project, exported)
		}
	}
}

func TestGrantPoPV2SignsEffectiveClassAndUseLimit(t *testing.T) {
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	h := popTestServer(t, func() time.Time { return now })
	ak := grantAgentKey()
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	req := broker.Request{
		PoPVersion: 2, ProjectID: "p1", IdempotencyKey: "idem-bounded", SessionID: "s1",
		IssuedAt: now.Unix(), RequestExpiresAt: now.Add(broker.MaxRequestAge).Unix(),
		AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db",
		Scope: "read:orders", ScopeClass: broker.ScopeBoundedReuse, UseLimit: 2,
		AgentPubKey: pub, TTL: time.Minute,
	}
	body, err := json.Marshal(map[string]any{
		"pop_version": 2, "project_id": "p1", "idempotency_key": "idem-bounded", "session_id": "s1",
		"issued_at": req.IssuedAt, "request_expires_at": req.RequestExpiresAt,
		"agent_id": req.AgentID, "action": req.Action, "resource": req.Resource, "scope": req.Scope,
		"scope_class": string(req.ScopeClass), "use_limit": req.UseLimit,
		"agent_pubkey": pub, "agent_sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge())),
		"ttl_seconds": 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, response := do(t, h, "POST", "/v2/grants", string(body)); code != http.StatusCreated {
		t.Fatalf("valid bounded request: %d %s", code, response)
	}
	if code, response := do(t, h, "POST", "/v2/grants", mutateGrantBody(t, string(body), "use_limit", 3)); code != http.StatusBadRequest {
		t.Fatalf("mutated use limit bypassed signature: %d %s", code, response)
	}
	defaultBody := grantBodyAt("idem-defaults", "read:orders", ak, ak, now)
	defaultBody = mutateGrantBody(t, defaultBody, "scope_class", "single_operation")
	defaultBody = mutateGrantBody(t, defaultBody, "use_limit", 0)
	if code, response := do(t, h, "POST", "/v2/grants", defaultBody); code != http.StatusCreated {
		t.Fatalf("explicit effective defaults changed signature subject: %d %s", code, response)
	}
}

func TestGrantPoPV2ExpiredNewProofButCommittedExactRetry(t *testing.T) {
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	h := popTestServer(t, func() time.Time { return now })
	ak := grantAgentKey()
	body := grantBodyAt("idem-committed", "read:orders", ak, ak, now)
	code, original := do(t, h, "POST", "/v2/grants", body)
	if code != http.StatusCreated {
		t.Fatalf("initial grant: %d %s", code, original)
	}
	now = now.Add(broker.MaxRequestAge + broker.RequestClockSkew + time.Second)
	if code, response := do(t, h, "POST", "/v2/grants", grantBodyAt("idem-new", "read:orders", ak, ak, now.Add(-time.Hour))); code != http.StatusBadRequest {
		t.Fatalf("expired new proof: %d %s", code, response)
	}
	code, retried := do(t, h, "POST", "/v2/grants", body)
	if code != http.StatusCreated {
		t.Fatalf("committed retry: %d %s", code, retried)
	}
	var a, b map[string]any
	if err := json.Unmarshal([]byte(original), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(retried), &b); err != nil {
		t.Fatal(err)
	}
	if a["capability"] != b["capability"] || a["expires_at"] != b["expires_at"] {
		t.Fatalf("retry changed credential or expiry: %s / %s", original, retried)
	}
}

func TestGrantPoPV2ChangedSenderKeyRetryCannotMintSecondGrant(t *testing.T) {
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	h := popTestServer(t, func() time.Time { return now })
	firstKey := grantAgentKey()
	secondKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, ed25519.SeedSize))
	first := grantBodyAt("idem-lost-response", "read:orders", firstKey, firstKey, now)
	code, original := do(t, h, "POST", "/v2/grants", first)
	if code != http.StatusCreated {
		t.Fatalf("first grant: %d %s", code, original)
	}
	if code, response := do(t, h, "POST", "/v2/grants", grantBodyAt("idem-lost-response", "read:orders", secondKey, secondKey, now)); code != http.StatusConflict {
		t.Fatalf("new sender key under existing idempotency key: %d %s", code, response)
	}
	code, retried := do(t, h, "POST", "/v2/grants", first)
	if code != http.StatusCreated {
		t.Fatalf("original proof no longer retrieves its grant: %d %s", code, retried)
	}
	var a, b map[string]any
	if err := json.Unmarshal([]byte(original), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(retried), &b); err != nil {
		t.Fatal(err)
	}
	if a["capability"] != b["capability"] || a["expires_at"] != b["expires_at"] {
		t.Fatalf("exact retry changed capability or expiry: %s / %s", original, retried)
	}
	_, exported := do(t, h, "GET", "/v2/export?project=p1", "")
	var bundle struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal([]byte(exported), &bundle); err != nil {
		t.Fatal(err)
	}
	if len(bundle.Records) != 1 {
		t.Fatalf("changed key created a second grant record: %s", exported)
	}
}

func TestGrantPoPV2RejectsConflictingIdempotencyRepresentations(t *testing.T) {
	now := time.Now().UTC()
	h := popTestServer(t, func() time.Time { return now })
	ak := grantAgentKey()
	body := grantBodyAt("idem-body", "read:orders", ak, ak, now)
	req := httptest.NewRequest(http.MethodPost, "/v2/grants", bytes.NewBufferString(body))
	req.Header.Set("Idempotency-Key", "idem-header")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "conflicts") {
		t.Fatalf("conflicting header/body accepted: %d %s", w.Code, w.Body.String())
	}
	if code, response := do(t, h, "POST", "/v2/grants?project=p2", body); code != http.StatusForbidden {
		t.Fatalf("conflicting authenticated project accepted: %d %s", code, response)
	}
	var headerOnly map[string]any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&headerOnly); err != nil {
		t.Fatal(err)
	}
	delete(headerOnly, "idempotency_key")
	delete(headerOnly, "project_id")
	encoded, err := json.Marshal(headerOnly)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v2/grants?project=p1", bytes.NewReader(encoded))
	req.Header.Set("Idempotency-Key", "idem-body")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("authenticated route and matching header did not resolve signed defaults: %d %s", w.Code, w.Body.String())
	}
}

func TestGrantPoPV2PendingDeadlineDoesNotExtendOnResign(t *testing.T) {
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	h := popTestServer(t, func() time.Time { return now })
	ak := grantAgentKey()
	if code, response := do(t, h, "POST", "/v2/grants/prepare", grantBodyAt("idem-pending", "read:orders", ak, ak, now)); code != http.StatusOK {
		t.Fatalf("prepare: %d %s", code, response)
	}
	now = now.Add(broker.MaxRequestAge + broker.RequestClockSkew + time.Second)
	fresh := grantBodyAt("idem-pending", "read:orders", ak, ak, now)
	if code, response := do(t, h, "POST", "/v2/grants/finalize", finalizeBody(fresh, nil)); code != http.StatusBadRequest {
		t.Fatalf("resigned finalize extended original deadline: %d %s", code, response)
	}
}

func TestGrantPoPV2FinalizeRejectsResignedDifferentSubject(t *testing.T) {
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	h := popTestServer(t, func() time.Time { return now })
	ak := grantAgentKey()
	body := grantBodyAt("idem-mismatch", "read:orders", ak, ak, now)
	if code, response := do(t, h, "POST", "/v2/grants/prepare", body); code != http.StatusOK {
		t.Fatalf("prepare: %d %s", code, response)
	}
	var changed map[string]any
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&changed); err != nil {
		t.Fatal(err)
	}
	changed["justification"] = "changed"
	req := broker.Request{PoPVersion: 2, ProjectID: "p1", IdempotencyKey: "idem-mismatch", SessionID: "s1",
		IssuedAt: now.Unix(), RequestExpiresAt: now.Add(broker.MaxRequestAge).Unix(),
		AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: "read:orders",
		AgentPubKey: changed["agent_pubkey"].(string), Justification: "changed", TTL: time.Minute}
	changed["agent_sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge()))
	different, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if code, response := do(t, h, "POST", "/v2/grants/finalize", finalizeBody(string(different), nil)); code != http.StatusConflict {
		t.Fatalf("resigned different semantic subject accepted: %d %s", code, response)
	}
	if code, response := do(t, h, "POST", "/v2/grants/finalize", finalizeBody(body, nil)); code != http.StatusCreated {
		t.Fatalf("original pending subject no longer finalized: %d %s", code, response)
	}
}

func TestUseRejectsCapabilityUnderWrongAuthenticatedProjectWithoutBurn(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, capability := mkGrant(t, h, ak, "idem-project-grant")
	valid := useBody(t, "idem-project-use", capability, grantID, ak, "SELECT 1", "nonce-project")
	wrong := mutateGrantBody(t, valid, "project_id", "p2")
	if code, response := do(t, h, "POST", "/v2/use?project=p2", wrong); code != http.StatusBadRequest {
		t.Fatalf("wrong-project capability accepted: %d %s", code, response)
	}
	if code, response := do(t, h, "POST", "/v2/use?project=p1", valid); code != http.StatusCreated {
		t.Fatalf("wrong-project attempt burned nonce/JTI: %d %s", code, response)
	}
}

func TestOldV1WorkerProofCannotMintAfterOnlineCutoff(t *testing.T) {
	now := time.Now().UTC()
	h := popTestServer(t, func() time.Time { return now })
	ak := grantAgentKey()
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	legacy := broker.Request{AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db",
		Scope: "read:orders", AgentPubKey: pub, TTL: time.Minute}
	body, err := json.Marshal(map[string]any{
		"idempotency_key": "idem-old-worker", "project_id": "p1", "session_id": "s1",
		"agent_id": legacy.AgentID, "action": legacy.Action, "resource": legacy.Resource,
		"scope": legacy.Scope, "agent_pubkey": pub, "ttl_seconds": 60,
		"agent_sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, legacy.Challenge())),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, response := do(t, h, "POST", "/v2/grants", string(body)); code != http.StatusBadRequest || !strings.Contains(response, "v2") {
		t.Fatalf("old worker minted after cutoff: %d %s", code, response)
	}
	_, exported := do(t, h, "GET", "/v2/export?project=p1", "")
	if strings.Contains(exported, `"credential_grant"`) {
		t.Fatalf("old worker proof persisted grant: %s", exported)
	}
}

func TestUsePreflightRejectsUnverifiedRequestsBeforeContentWrite(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	contentStore := &countingContentStore{Store: content.NewMemStore()}
	h := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").WithContent(contentStore).Routes()
	ak := grantAgentKey()
	grantID, capability := mkGrant(t, h, ak, "idem-preflight-grant")
	baseline := contentStore.puts
	valid := useBody(t, "idem-preflight-use", capability, grantID, ak, "SELECT 1", "nonce-preflight")
	badSig := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	cases := []struct {
		name, path, body string
	}{
		{"malformed-capability", "/v2/use?project=p1", mutateGrantBody(t, valid, "capability", "bad.token")},
		{"wrong-signed-project", "/v2/use?project=p2", mutateGrantBody(t, valid, "project_id", "p2")},
		{"bad-use-pop", "/v2/use?project=p1", mutateGrantBody(t, valid, "use_sig", badSig)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, response := do(t, h, "POST", tc.path, tc.body); code != http.StatusBadRequest {
				t.Fatalf("unverified use accepted: %d %s", code, response)
			}
			if contentStore.puts != baseline {
				t.Fatalf("unverified use wrote content: got %d puts, want %d", contentStore.puts, baseline)
			}
		})
	}
	_, exported := do(t, h, "GET", "/v2/export?project=p1", "")
	var bundle struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal([]byte(exported), &bundle); err != nil {
		t.Fatal(err)
	}
	if len(bundle.Records) != 1 {
		t.Fatalf("unverified use persisted a receipt: %s", exported)
	}
	if code, response := do(t, h, "POST", "/v2/use?project=p1", valid); code != http.StatusCreated {
		t.Fatalf("rejected proofs consumed valid nonce or capability: %d %s", code, response)
	}
	if contentStore.puts != baseline+1 {
		t.Fatalf("valid use wrote %d content blobs, want one", contentStore.puts-baseline)
	}
}

func TestUsePreflightPreservesExpiredCommittedExactRetry(t *testing.T) {
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	contentStore := &countingContentStore{Store: content.NewMemStore()}
	h := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").WithContent(contentStore).WithClock(func() time.Time { return now }).Routes()
	ak := grantAgentKey()
	code, grantResponse := do(t, h, "POST", "/v2/grants", grantBodyAt("idem-use-expiry-grant", "read:orders", ak, ak, now))
	if code != http.StatusCreated {
		t.Fatalf("grant: %d %s", code, grantResponse)
	}
	var grant struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal([]byte(grantResponse), &grant); err != nil {
		t.Fatal(err)
	}
	use := useBody(t, "idem-use-expiry-use", grant.Capability, grant.GrantID, ak, "SELECT 1", "nonce-use-expiry")
	if code, response := do(t, h, "POST", "/v2/use?project=p1", use); code != http.StatusCreated {
		t.Fatalf("first use: %d %s", code, response)
	}
	puts := contentStore.puts
	now = now.Add(2 * time.Minute) // capability TTL is one minute
	if code, response := do(t, h, "POST", "/v2/use?project=p1", use); code != http.StatusCreated || !strings.Contains(response, `"idempotent":true`) {
		t.Fatalf("expired exact committed use retry: %d %s", code, response)
	}
	if code, response := do(t, h, "POST", "/v2/use?project=p1", mutateGrantBody(t, use, "params", "SELECT 2")); code != http.StatusConflict {
		t.Fatalf("changed request reused expired use idempotency key: %d %s", code, response)
	}
	if contentStore.puts != puts {
		t.Fatalf("committed retry or changed request wrote content: got %d puts, want %d", contentStore.puts, puts)
	}
}
