package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

func assertRecordCount(t *testing.T, st *store.Mem, project string, want int) {
	t.Helper()
	got, err := st.RecordCount(project)
	if err != nil || got != want {
		t.Fatalf("record count for %q = %d, %v; want %d", project, got, err, want)
	}
}

func TestGrantAndUseRejectNonNFCAliasesBeforePoPAndDedup(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	st := store.NewMem()
	h := api.New(c, st, "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()
	ak := grantAgentKey()
	badGrant := grantBody("e\u0301", "read:orders", ak, ak)
	if code, resp := do(t, h, "POST", "/v2/grants", badGrant); code != http.StatusBadRequest || !strings.Contains(resp, "NFC") {
		t.Fatalf("non-NFC grant idempotency alias (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 0)
	grantID, capability := mkGrant(t, h, ak, "é")
	assertRecordCount(t, st, "p1", 1)
	if code, resp := do(t, h, "POST", "/v2/grants", badGrant); code != http.StatusBadRequest || !strings.Contains(resp, "NFC") {
		t.Fatalf("non-NFC alias reached finalized grant lookup (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 1)

	badUse := useBody(t, "use-e\u0301", capability, grantID, ak, "SELECT 1", "nonce-1")
	if code, resp := do(t, h, "POST", "/v2/use-intent", badUse); code != http.StatusBadRequest || !strings.Contains(resp, "NFC") {
		t.Fatalf("non-NFC use alias reached PoP or consume (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 1)
	goodUse := useBody(t, "use-é", capability, grantID, ak, "SELECT 1", "nonce-1")
	if code, resp := do(t, h, "POST", "/v2/use-intent", goodUse); code != http.StatusCreated {
		t.Fatalf("canonical alias should still consume once (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 2)
}

func TestNonNFCPrepareCannotCreatePendingGrant(t *testing.T) {
	c, _ := core.New(seed)
	st := store.NewMem()
	ap := seedKey(40)
	h := api.New(c, st, "k0").WithBroker(brokerIssuingKey()).WithCosigPolicy(1, []ed25519.PublicKey{ap.Public().(ed25519.PublicKey)}).Routes()
	ak := grantAgentKey()
	bad := grantBody("e\u0301", "read:orders", ak, ak)
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", bad); code != http.StatusBadRequest || !strings.Contains(resp, "NFC") {
		t.Fatalf("non-NFC prepare (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 0)
	good := grantBody("é", "read:orders", ak, ak)
	if code, resp := do(t, h, "POST", "/v2/grants/finalize", finalizeBody(good, nil)); code != http.StatusConflict || !strings.Contains(resp, "no pending grant") {
		t.Fatalf("non-NFC prepare created pending state (%d): %s", code, resp)
	}
	code, resp := do(t, h, "POST", "/v2/grants/prepare", good)
	if code != http.StatusOK {
		t.Fatalf("canonical prepare (%d): %s", code, resp)
	}
	var pr prepareResp
	if err := json.Unmarshal([]byte(resp), &pr); err != nil {
		t.Fatal(err)
	}
	kid := broker.KeyID(ap.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(ap, broker.CosigApprovalChallenge(pr.GrantID, kid, pr.CredentialBinding, 1, pr.Exp))
	fin := finalizeBody(good, map[string]any{"cosignatures": []broker.Cosignature{{ApproverKid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}}})
	if code, resp := do(t, h, "POST", "/v2/grants/finalize", fin); code != http.StatusCreated {
		t.Fatalf("canonical finalize (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 1)
}

func TestNativeCredentialRefRejectsNonNFCAliasBeforeTranscript(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	rawSeed, _ := hex.DecodeString(resourceSeed)
	st := store.NewMem()
	h := api.New(c, st, "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").WithIntrospection(ed25519.NewKeyFromSeed(rawSeed)).Routes()
	grant := map[string]any{
		"idempotency_key": "native-1", "project_id": "p1", "session_id": "s1", "agent_id": "agent-x",
		"action": "db.query:orders-ro", "resource": "orders-db", "scope": "read:orders",
		"mode": "token_exchange", "lease_id": "léase", "ttl_seconds": 3600,
	}
	encoded, _ := json.Marshal(grant)
	code, resp := do(t, h, "POST", "/v2/grants", string(encoded))
	if code != http.StatusCreated {
		t.Fatalf("canonical native grant (%d): %s", code, resp)
	}
	var out struct {
		GrantID string          `json:"grant_id"`
		Record  json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatal(err)
	}
	assertRecordCount(t, st, "p1", 1)
	intro := map[string]any{
		"idempotency_key": "intro-1", "project_id": "p1", "session_id": "s1", "grant_id": out.GrantID,
		"credential_ref": "le\u0301ase", "effective_scope": "read:orders", "effective_exp": grantEvidenceExp(t, out.Record),
	}
	encoded, _ = json.Marshal(intro)
	if code, resp := do(t, h, "POST", "/v2/introspection", string(encoded)); code != http.StatusBadRequest || !strings.Contains(resp, "NFC") {
		t.Fatalf("non-NFC credential ref signed as transcript (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 1)
	intro["credential_ref"] = "léase"
	encoded, _ = json.Marshal(intro)
	if code, resp := do(t, h, "POST", "/v2/introspection", string(encoded)); code != http.StatusCreated {
		t.Fatalf("canonical credential ref (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 2)
}

func TestPostNFCDuplicateKeysFailBeforeSeal(t *testing.T) {
	c, _ := core.New(seed)
	st := store.NewMem()
	h := api.New(c, st, "k0").Routes()
	body := `{"idempotency_key":"k","project_id":"p1","session_id":"s1","content":{"e\u0301":1,"é":2}}`
	if code, resp := do(t, h, "POST", "/v2/records", body); code != http.StatusBadRequest {
		t.Fatalf("post-NFC duplicate key sealed (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 0)
}

func TestGrantDelegationChainRejectsNonNFCBeforeSeal(t *testing.T) {
	c, _ := core.New(seed)
	st := store.NewMem()
	h := api.New(c, st, "k0").WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()
	var gr map[string]any
	if err := json.Unmarshal([]byte(grantBody("delegation-1", "read:orders", ak, ak)), &gr); err != nil {
		t.Fatal(err)
	}
	gr["delegation_chain"] = []string{"e\u0301"}
	body, _ := json.Marshal(gr)
	if code, resp := do(t, h, "POST", "/v2/grants", string(body)); code != http.StatusBadRequest || !strings.Contains(resp, "NFC") {
		t.Fatalf("non-NFC delegation identity was sealed (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 0)
	gr["delegation_chain"] = []string{"é"}
	body, _ = json.Marshal(gr)
	if code, resp := do(t, h, "POST", "/v2/grants", string(body)); code != http.StatusCreated {
		t.Fatalf("canonical delegation identity rejected (%d): %s", code, resp)
	}
	assertRecordCount(t, st, "p1", 1)
}

func TestConfiguredOpaqueIDsRejectNonNFC(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*api.Server)
	}{
		{"broker_id", func(s *api.Server) { s.WithBroker(brokerIssuingKey()).WithBrokerID("e\u0301") }},
		{"resource_id", func(s *api.Server) {
			rc, _ := core.New(resourceSeed)
			s.WithBroker(brokerIssuingKey()).WithResource(rc, "e\u0301")
		}},
		{"authority_project_id", func(s *api.Server) {
			s.WithProjectAuthorityKey("e\u0301", "human_signed", seedKey(40).Public().(ed25519.PublicKey))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := core.New(seed)
			s := api.New(c, store.NewMem(), "k0")
			defer func() {
				if got := recover(); got == nil || !strings.Contains(fmt.Sprint(got), "NFC") {
					t.Fatalf("non-NFC configured ID must fail at setup with NFC error, got %v", got)
				}
			}()
			tc.set(s)
		})
	}
}
