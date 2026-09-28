package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

func seedKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytesSeed(b)) }

// prepareResp is the /v2/grants/prepare response (the revealed challenge inputs).
type prepareResp struct {
	GrantID           string `json:"grant_id"`
	CredentialBinding string `json:"credential_binding"`
	CnfKid            string `json:"cnf_kid"`
	Exp               int64  `json:"exp"`
	CosigThreshold    int    `json:"cosig_threshold"`
	Finalized         bool   `json:"finalized"`
}

func newCosigBrokerServer(t *testing.T, threshold int, approvers []ed25519.PublicKey) http.Handler {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	return api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithCosigPolicy(threshold, approvers).Routes()
}

// TestSinglePhaseGrantRejectedUnderCosigPolicy: a pinned cosig policy must not be bypassable by issuing via the
// single-phase /v2/grants endpoint — that path mints a grant with NO cosignatures (cosig is verifier-enforced
// only on grants declaring cosig_threshold, which single-phase never sets). Single-phase brokered issuance is
// rejected (400) so the only way to mint is the two-phase prepare/finalize flow that binds the M-of-N.
func TestSinglePhaseGrantRejectedUnderCosigPolicy(t *testing.T) {
	a1, a2 := seedKey(40), seedKey(41)
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	h := newCosigBrokerServer(t, 2, approvers)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-bypass", "read:orders", ak, ak))
	if code != http.StatusBadRequest {
		t.Fatalf("single-phase issuance under a cosig policy must be rejected (got %d): %s", code, resp)
	}
	if !strings.Contains(resp, "cosig") {
		t.Fatalf("rejection should explain the cosig policy: %s", resp)
	}
	// CONTROL: a server WITHOUT a cosig policy still accepts single-phase issuance.
	hNoCosig := api.New(mustCore(t), store.NewMem(), "k0").WithBroker(brokerIssuingKey()).Routes()
	if code, r := do(t, hNoCosig, "POST", "/v2/grants", grantBody("idem-ok", "read:orders", ak, ak)); code != http.StatusCreated {
		t.Fatalf("single-phase issuance without a cosig policy must work (got %d): %s", code, r)
	}
}

// finalizeBody is a /v2/grants/finalize body: the SAME PoP-signed grant request posted to prepare (grantJSON)
// plus the collected approvals in extra (cosignatures / delegation_hops).
func finalizeBody(grantJSON string, extra map[string]any) string {
	var m map[string]any
	_ = json.Unmarshal([]byte(grantJSON), &m)
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func mustCore(t *testing.T) *core.Core {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	return c
}

// nativeGrantBody is a token_exchange (native) grant request — no agent PoP, no minted
// capability (mirrors native_grant_test.go's body).
func nativeGrantBody(idem string) string {
	b, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": "p1", "session_id": "s1",
		"agent_id": "agent-x", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": "read:orders", "mode": "token_exchange", "lease_id": "lease-sts-1", "ttl_seconds": 3600,
	})
	return string(b)
}

// TestNativeGrantRejectedUnderCosigPolicy (averin#0): the M-of-N cosig gate was bypassable by
// selecting mode:token_exchange — the native branch returned before the cosig check, so a
// project-token holder could self-issue a sealed gateway_enforced grant with ZERO approver
// signatures. A native grant carries no cosignatures and there is no cosigned native path, so
// under a pinned policy it must be REFUSED (fail-closed), not silently issued.
func TestNativeGrantRejectedUnderCosigPolicy(t *testing.T) {
	a1, a2 := seedKey(40), seedKey(41)
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	h := newCosigBrokerServer(t, 2, approvers)
	code, resp := do(t, h, "POST", "/v2/grants", nativeGrantBody("native-under-cosig"))
	if code != http.StatusBadRequest {
		t.Fatalf("native (token_exchange) issuance under a cosig policy must be rejected (got %d): %s", code, resp)
	}
	if !strings.Contains(resp, "cosig") || !strings.Contains(resp, "native") {
		t.Fatalf("rejection should name the cosig policy AND that native cannot be cosigned: %s", resp)
	}
	// CONTROL: without a cosig policy (threshold 0, the default) native issuance still works —
	// the guard is >0-gated so a no-cosig deployment is unaffected.
	hNoCosig := api.New(mustCore(t), store.NewMem(), "k0").WithBroker(brokerIssuingKey()).Routes()
	if code, r := do(t, hNoCosig, "POST", "/v2/grants", nativeGrantBody("native-no-cosig")); code != http.StatusCreated {
		t.Fatalf("native issuance without a cosig policy must work (got %d): %s", code, r)
	}
}

// TestOnlineCosigGrantPrepareFinalize is the M6 online two-phase flow: prepare reveals the challenge, the
// approvers sign it, finalize binds the cosignatures + commits the grant.
func TestOnlineCosigGrantPrepareFinalize(t *testing.T) {
	a1, a2 := seedKey(40), seedKey(41)
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	h := newCosigBrokerServer(t, 2, approvers)
	ak := grantAgentKey()

	// PHASE 1: prepare -> reveal grant_id / credential_binding / exp / threshold.
	code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-cosig-1", "read:orders", ak, ak))
	if code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", code, resp)
	}
	var pr prepareResp
	if err := json.Unmarshal([]byte(resp), &pr); err != nil {
		t.Fatalf("decode prepare: %v\n%s", err, resp)
	}
	if pr.CosigThreshold != 2 || pr.GrantID == "" || pr.CredentialBinding == "" {
		t.Fatalf("prepare response incomplete: %s", resp)
	}

	// the approvers sign the REVEALED challenge (off-server).
	mkCosig := func(ap ed25519.PrivateKey) broker.Cosignature {
		kid := broker.KeyID(ap.Public().(ed25519.PublicKey))
		sig := ed25519.Sign(ap, broker.CosigApprovalChallenge(pr.GrantID, kid, pr.CredentialBinding, 2, pr.Exp))
		return broker.Cosignature{ApproverKid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	}
	finBody := finalizeBody(grantBody("idem-cosig-1", "read:orders", ak, ak), map[string]any{
		"cosignatures": []broker.Cosignature{mkCosig(a1), mkCosig(a2)},
	})

	// PHASE 2: finalize -> bind cosignatures + commit.
	code, resp = do(t, h, "POST", "/v2/grants/finalize", finBody)
	if code != http.StatusCreated {
		t.Fatalf("finalize (%d): %s", code, resp)
	}
	if !strings.Contains(resp, `"cosig_threshold":2`) || !strings.Contains(resp, `"cosignatures"`) {
		t.Fatalf("finalized record missing cosig evidence: %s", resp)
	}
	if !strings.Contains(resp, `"capability"`) {
		t.Fatalf("finalize must return the minted capability: %s", resp)
	}

	// idempotent re-finalize returns the same committed grant.
	code2, resp2 := do(t, h, "POST", "/v2/grants/finalize", finBody)
	if code2 != http.StatusCreated || !strings.Contains(resp2, pr.GrantID) {
		t.Fatalf("re-finalize must be idempotent (%d): %s", code2, resp2)
	}
}

func TestOnlineCosigBelowThresholdRejected(t *testing.T) {
	a1, a2 := seedKey(40), seedKey(41)
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	h := newCosigBrokerServer(t, 2, approvers)
	ak := grantAgentKey()

	code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-cosig-2", "read:orders", ak, ak))
	if code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", code, resp)
	}
	var pr prepareResp
	json.Unmarshal([]byte(resp), &pr)
	kid := broker.KeyID(a1.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(a1, broker.CosigApprovalChallenge(pr.GrantID, kid, pr.CredentialBinding, 2, pr.Exp))
	finBody := finalizeBody(grantBody("idem-cosig-2", "read:orders", ak, ak), map[string]any{
		"cosignatures": []broker.Cosignature{{ApproverKid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}}, // only 1 of 2
	})
	code, resp = do(t, h, "POST", "/v2/grants/finalize", finBody)
	if code != http.StatusBadRequest || !strings.Contains(resp, "cosignatures rejected") {
		t.Fatalf("a sub-threshold finalize must be rejected (%d): %s", code, resp)
	}
}

func TestOnlineFinalizeWithoutPrepareRejected(t *testing.T) {
	h := newCosigBrokerServer(t, 1, []ed25519.PublicKey{seedKey(40).Public().(ed25519.PublicKey)})
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants/finalize", finalizeBody(grantBody("never-prepared", "read:orders", ak, ak), nil))
	if code != http.StatusConflict || !strings.Contains(resp, "no pending grant") {
		t.Fatalf("finalize without prepare must 409 (%d): %s", code, resp)
	}
}

// TestOnlineCosigPolicyRequiresCosignatures: with a cosig policy pinned, a finalize carrying NO cosignatures
// must be rejected (the broker honors its own policy; it must not silently mint an un-cosigned grant).
func TestOnlineCosigPolicyRequiresCosignatures(t *testing.T) {
	a1, a2 := seedKey(40), seedKey(41)
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	h := newCosigBrokerServer(t, 2, approvers)
	ak := grantAgentKey()
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-cosig-empty", "read:orders", ak, ak)); code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", code, resp)
	}
	finBody := finalizeBody(grantBody("idem-cosig-empty", "read:orders", ak, ak), nil) // no cosignatures
	code, resp := do(t, h, "POST", "/v2/grants/finalize", finBody)
	if code != http.StatusBadRequest || !strings.Contains(resp, "requires cosignatures") {
		t.Fatalf("an empty-cosignatures finalize under a pinned policy must be rejected (%d): %s", code, resp)
	}
}

// TestOnlineFinalizeConcurrentSameKey fires many concurrent finalizes for ONE idempotency key — they must not
// race on the shared pending evidence map (run under -race; previously a fatal concurrent-map-write crash), and
// must collapse idempotently to exactly one committed grant.
func TestOnlineFinalizeConcurrentSameKey(t *testing.T) {
	a1, a2 := seedKey(40), seedKey(41)
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	h := newCosigBrokerServer(t, 2, approvers)
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-race", "read:orders", ak, ak))
	if code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", code, resp)
	}
	var pr prepareResp
	json.Unmarshal([]byte(resp), &pr)
	mkCosig := func(ap ed25519.PrivateKey) broker.Cosignature {
		kid := broker.KeyID(ap.Public().(ed25519.PublicKey))
		sig := ed25519.Sign(ap, broker.CosigApprovalChallenge(pr.GrantID, kid, pr.CredentialBinding, 2, pr.Exp))
		return broker.Cosignature{ApproverKid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	}
	finBody := finalizeBody(grantBody("idem-race", "read:orders", ak, ak), map[string]any{
		"cosignatures": []broker.Cosignature{mkCosig(a1), mkCosig(a2)},
	})

	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	created := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, r := do(t, h, "POST", "/v2/grants/finalize", finBody)
			codes[i] = c
			created[i] = strings.Contains(r, `"created":true`)
		}(i)
	}
	wg.Wait()
	createdCount := 0
	for i := 0; i < n; i++ {
		if codes[i] != http.StatusCreated {
			t.Fatalf("concurrent finalize %d: code %d (all must succeed idempotently)", i, codes[i])
		}
		if created[i] {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("exactly one finalize must create the grant; got created=%d", createdCount)
	}
}

// TestFinalizeRequiresPoPAndMatchingRequest: finalize used to return a committed grant's live capability (and
// commit a pending one) given ONLY project_id + idempotency_key — no proof-of-possession, no request match. It
// must require the SAME PoP-signed grant request prepared: a bare key is a 400, and another agent's validly
// signed request under the victim's key is a 409 (pending AND committed), leaking no capability.
func TestFinalizeRequiresPoPAndMatchingRequest(t *testing.T) {
	h := newBrokerServer(t)
	victim, attacker := grantAgentKey(), seedKey(77)
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-v", "read:orders", victim, victim)); code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", code, resp)
	}
	bare := `{"idempotency_key":"idem-v","project_id":"p1","session_id":"s1"}`
	stolen := finalizeBody(grantBody("idem-v", "read:orders", attacker, attacker), nil)
	check := func(phase string) {
		t.Helper()
		if code, resp := do(t, h, "POST", "/v2/grants/finalize", bare); code != http.StatusBadRequest || strings.Contains(resp, `"capability"`) {
			t.Fatalf("%s: a finalize with no PoP must 400 without a capability, got %d: %s", phase, code, resp)
		}
		if code, resp := do(t, h, "POST", "/v2/grants/finalize", stolen); code != http.StatusConflict || strings.Contains(resp, `"capability"`) {
			t.Fatalf("%s: another agent's request under the victim's key must 409 without a capability, got %d: %s", phase, code, resp)
		}
	}
	check("pending")
	if code, resp := do(t, h, "POST", "/v2/grants/finalize", finalizeBody(grantBody("idem-v", "read:orders", victim, victim), nil)); code != http.StatusCreated {
		t.Fatalf("the victim's own finalize (%d): %s", code, resp)
	}
	check("committed")
}

// TestPrepareOnlyEchoesMatchingGrant: prepare used to echo ANY record stored under the idempotency key — before
// validating PoP, and even a non-grant record. It must validate PoP first and only echo a committed grant to the
// SAME request (409 otherwise), and only re-serve a pending challenge to the request that minted it.
func TestPrepareOnlyEchoesMatchingGrant(t *testing.T) {
	h := newBrokerServer(t)
	victim, attacker := grantAgentKey(), seedKey(77)
	// a generic record squatting an idempotency key, then a prepare under it.
	postRecord(t, h, `{"idempotency_key":"idem-generic","project_id":"p1","session_id":"s1"}`)
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-generic", "read:orders", victim, victim)); code != http.StatusConflict {
		t.Fatalf("prepare over a NON-grant record must 409, got %d: %s", code, resp)
	}
	// a pending mint is not re-served to another agent.
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-v", "read:orders", victim, victim)); code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-v", "read:orders", attacker, attacker)); code != http.StatusConflict {
		t.Fatalf("a pending challenge must not be re-served to a different request, got %d: %s", code, resp)
	}
	// a committed grant is only echoed to the same request; an unsigned probe is a 400.
	do(t, h, "POST", "/v2/grants/finalize", finalizeBody(grantBody("idem-v", "read:orders", victim, victim), nil))
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-v", "read:orders", attacker, attacker)); code != http.StatusConflict {
		t.Fatalf("a committed grant must not be echoed to a different request, got %d: %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", `{"idempotency_key":"idem-v","project_id":"p1","session_id":"s1"}`); code != http.StatusBadRequest {
		t.Fatalf("an unsigned prepare probe must 400, got %d: %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-v", "read:orders", victim, victim)); code != http.StatusOK || !strings.Contains(resp, `"finalized":true`) {
		t.Fatalf("the same request's prepare-after-finalize must still return the committed grant (%d): %s", code, resp)
	}
}

// TestOnlineDelegationGrantPrepareFinalize is the M2 online two-phase flow: prepare reveals grant_id + cnf_kid,
// the delegator signs a hop, finalize binds the delegation chain.
func TestOnlineDelegationGrantPrepareFinalize(t *testing.T) {
	h := newBrokerServer(t) // delegation needs no server-side approver policy
	ak := grantAgentKey()   // the root agent = the grant's cnf
	leaf := seedKey(43)

	code, resp := do(t, h, "POST", "/v2/grants/prepare", grantBody("idem-deleg-1", "read:orders", ak, ak))
	if code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", code, resp)
	}
	var pr prepareResp
	json.Unmarshal([]byte(resp), &pr)

	rootPub := ak.Public().(ed25519.PublicKey)
	leafPub := leaf.Public().(ed25519.PublicKey)
	scope, action, resource := "read:orders", "db.query:orders-ro", "orders-db"
	// hop 0: root delegates to leaf, signed by the root over DelegationHopChallenge (demonstrator: scope equal).
	ch := broker.DelegationHopChallenge(pr.GrantID, 0, broker.KeyID(rootPub), broker.KeyID(leafPub), scope, action, resource, pr.Exp)
	hop := broker.DelegationHop{
		DelegatorCnf: base64.RawURLEncoding.EncodeToString(rootPub),
		DelegateCnf:  base64.RawURLEncoding.EncodeToString(leafPub),
		Scope:        scope, Action: action, ResourceID: resource, Exp: pr.Exp,
		Sig: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, ch)),
	}
	finBody := finalizeBody(grantBody("idem-deleg-1", "read:orders", ak, ak), map[string]any{
		"delegation_hops": []broker.DelegationHop{hop},
	})
	code, resp = do(t, h, "POST", "/v2/grants/finalize", finBody)
	if code != http.StatusCreated {
		t.Fatalf("finalize (%d): %s", code, resp)
	}
	if !strings.Contains(resp, `"delegation_assertions"`) {
		t.Fatalf("finalized record missing delegation_assertions: %s", resp)
	}
}
