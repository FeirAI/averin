package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/feirai/averin/server/internal/store"
)

// resourceSeed is the RESOURCE recording key — DISTINCT from the server signing key (seed) and the
// broker issuing key, so the verifier's R2 broker∩resource disjointness invariant holds.
const resourceSeed = "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100"

func newBrokerResourceServer(t *testing.T) http.Handler {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	return api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		Routes()
}

// useBody builds a /v2/use request (ADR 0004 D2 flow): the agent commits the params under a hiding
// params_nonce, signs the PoP over THAT commitment with its cnf key, and sends (params, params_nonce,
// use_sig) so the offline verifier can re-run the PoP.
func useBody(t *testing.T, idem, capability, grantID string, ak ed25519.PrivateKey, params, nonce string) string {
	t.Helper()
	binding, err := resourceshim.CredentialBinding(capability)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	paramsNonce := strings.Repeat("ab", 32) // 64-hex params hiding-commitment nonce (commit is keyless)
	paramsCommitment, err := c.Commit("input", []byte(params), paramsNonce)
	if err != nil {
		t.Fatalf("commit params: %v", err)
	}
	ch := resourceshim.UsePoPChallenge(grantID, "orders-db", "db.query:orders-ro", paramsCommitment, binding, nonce)
	useSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, ch))
	b, _ := json.Marshal(map[string]any{
		"idempotency_key": idem,
		"project_id":      "p1", "session_id": "s1",
		"capability": capability, "use_sig": useSig,
		"action": "db.query:orders-ro", "params": params, "nonce": nonce,
		"params_nonce": paramsNonce,
	})
	return string(b)
}

// mkGrant creates a grant and returns (grantID, capability).
func mkGrant(t *testing.T, h http.Handler, ak ed25519.PrivateKey, idem string) (string, string) {
	t.Helper()
	code, resp := do(t, h, "POST", "/v2/grants", grantBody(idem, "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("grant failed (%d): %s", code, resp)
	}
	var g struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal([]byte(resp), &g); err != nil {
		t.Fatalf("decode grant: %v", err)
	}
	return g.GrantID, g.Capability
}

func TestUseReceiptRecordedAndVerifies(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")

	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use failed (%d): %s", code, resp)
	}
	var u struct {
		UseID   string                     `json:"use_id"`
		GrantID string                     `json:"grant_id"`
		Record  map[string]json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal([]byte(resp), &u); err != nil {
		t.Fatalf("decode use: %v\n%s", err, resp)
	}
	if u.GrantID != grantID {
		t.Fatalf("use grant_id %q != grant %q", u.GrantID, grantID)
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(u.Record[k], &s)
		return s
	}
	if str("event_type") != "tool_call" || str("observed_via") != "broker" {
		t.Fatalf("use record not a broker tool_call: %s", resp)
	}
	if str("content_hash") == "" || str("sig") == "" {
		t.Fatalf("use record not sealed")
	}
	var authority struct {
		Source           string `json:"source"`
		EnforcementPoint string `json:"enforcement_point"`
		GrantID          string `json:"grant_id"`
		EvidenceSig      string `json:"evidence_sig"`
		EvidenceHash     string `json:"evidence_hash"`
	}
	json.Unmarshal(u.Record["authority"], &authority)
	if authority.Source != "gateway_enforced" || authority.EnforcementPoint != "tool_gateway" {
		t.Fatalf("use authority wrong: %+v", authority)
	}
	if authority.GrantID != grantID || !strings.HasPrefix(authority.EvidenceSig, "ed25519:") || !strings.HasPrefix(authority.EvidenceHash, "sha256:") {
		t.Fatalf("use authority block malformed: %+v", authority)
	}

	// checkpoint + verify: the bundle has a broker-role grant and a resource-role use, each verifying
	// under its OWN role key set (R2). The use record's authority is verified (re-derivable evidence
	// signed by the resource key); the grant still verifies; the bundle is clean.
	if c, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); c != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", c, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"ok":true`) {
		t.Fatalf("grant+use bundle should verify clean: %s", report)
	}
	if !strings.Contains(report, `"records_proven":2`) {
		t.Fatalf("both the grant and the use should be integrity-proven: %s", report)
	}
	if !strings.Contains(report, `"grant_verified":1`) {
		t.Fatalf("the grant should still verify under the broker role: %s", report)
	}
	// the use record must classify to the resource role AND have its authority VERIFIED under the
	// (distinct) resource key — not merely be integrity-proven (R2 role separation, end to end).
	assertUseAuthorityVerified(t, report, u.UseID)
}

// assertUseAuthorityVerified parses the verify report and confirms the use record (by record_id) has
// broker_role "resource" and authority "verified".
func assertUseAuthorityVerified(t *testing.T, report, useID string) {
	t.Helper()
	var rep struct {
		RecordTrust []struct {
			RecordID   string `json:"record_id"`
			Authority  string `json:"authority"`
			BrokerRole string `json:"broker_role"`
		} `json:"record_trust"`
	}
	if err := json.Unmarshal([]byte(report), &rep); err != nil {
		t.Fatalf("decode report: %v\n%s", err, report)
	}
	for _, rt := range rep.RecordTrust {
		if rt.RecordID == useID {
			if rt.BrokerRole != "resource" || rt.Authority != "verified" {
				t.Fatalf("use record role/authority = %q/%q, want resource/verified", rt.BrokerRole, rt.Authority)
			}
			return
		}
	}
	t.Fatalf("use record %q not found in report", useID)
}

// TestTwoPhaseUseProducesValidRecords (ADR 0004 D5/D5.2): the resource records a use_intent BEFORE the side
// effect (POST /v2/use-intent) and a use_outcome AFTER (POST /v2/use-outcome). This asserts the PRODUCER
// emits structurally-correct two-phase records — the right kinds, and the RESOURCE-SIGNED use_outcome
// payload binding intent_ref + intent_hash + grant_id (the security-critical join + before-act ordering) —
// and that the bundle verifies (all three records integrity-proven + authority-verified under their role
// keys). The intent<->outcome MATCHING semantics need a verifiable anchor (the StubTSA token is not
// crypto-valid), so they are exercised exhaustively in the Rust adversarial suite, not here.
func TestTwoPhaseUseProducesValidRecords(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")

	// phase 1: use_intent
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent failed (%d): %s", code, resp)
	}
	var intent struct {
		UseID  string                     `json:"use_id"`
		Record map[string]json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal([]byte(resp), &intent); err != nil {
		t.Fatalf("decode use-intent: %v\n%s", err, resp)
	}
	var intentHash string
	json.Unmarshal(intent.Record["content_hash"], &intentHash)
	var iext struct {
		Broker struct {
			Kind        string `json:"kind"`
			UseEvidence struct {
				Kind string `json:"kind"`
			} `json:"use_evidence"`
		} `json:"broker"`
	}
	json.Unmarshal(intent.Record["extensions"], &iext)
	if iext.Broker.Kind != "use_intent" || iext.Broker.UseEvidence.Kind != "use_intent" {
		t.Fatalf("phase-1 kind = %q / use_evidence.kind = %q, want use_intent/use_intent", iext.Broker.Kind, iext.Broker.UseEvidence.Kind)
	}

	// phase 2: use_outcome
	ob, _ := json.Marshal(map[string]any{
		"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1",
		"intent_record_id": intent.UseID, "status": "ok",
	})
	code, oresp := do(t, h, "POST", "/v2/use-outcome", string(ob))
	if code != http.StatusCreated {
		t.Fatalf("use-outcome failed (%d): %s", code, oresp)
	}
	var outcome struct {
		OutcomeID string                     `json:"outcome_id"`
		Record    map[string]json.RawMessage `json:"record"`
	}
	json.Unmarshal([]byte(oresp), &outcome)
	// the SIGNED use_outcome payload binds the join + the before-act ordering to the resource signature.
	var oext struct {
		Broker struct {
			Kind       string `json:"kind"`
			UseOutcome struct {
				Kind       string `json:"kind"`
				GrantID    string `json:"grant_id"`
				IntentRef  string `json:"intent_ref"`
				IntentHash string `json:"intent_hash"`
			} `json:"use_outcome"`
		} `json:"broker"`
	}
	json.Unmarshal(outcome.Record["extensions"], &oext)
	if oext.Broker.Kind != "use_outcome" || oext.Broker.UseOutcome.Kind != "use_outcome" {
		t.Fatalf("phase-2 kind wrong: %+v", oext.Broker)
	}
	if oext.Broker.UseOutcome.IntentRef != intent.UseID {
		t.Fatalf("signed intent_ref = %q, want the intent record_id %q", oext.Broker.UseOutcome.IntentRef, intent.UseID)
	}
	if oext.Broker.UseOutcome.IntentHash != intentHash || intentHash == "" {
		t.Fatalf("signed intent_hash = %q, want the intent content_hash %q (the before-act binding)", oext.Broker.UseOutcome.IntentHash, intentHash)
	}
	if oext.Broker.UseOutcome.GrantID != grantID {
		t.Fatalf("signed grant_id = %q, want %q", oext.Broker.UseOutcome.GrantID, grantID)
	}

	if c, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); c != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", c, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"ok":true`) {
		t.Fatalf("two-phase bundle should verify clean: %s", report)
	}
	if !strings.Contains(report, `"records_proven":3`) {
		t.Fatalf("grant + intent + outcome must all be integrity-proven: %s", report)
	}
	assertUseAuthorityVerified(t, report, intent.UseID)
	assertUseAuthorityVerified(t, report, outcome.OutcomeID)
}

// TestUseOutcomeRejectsNonIntent (D5.2): /v2/use-outcome must reject an intent_record_id that is not a
// use_intent (e.g. an unknown record), so an outcome cannot be minted for a non-existent intent.
func TestUseOutcomeRejectsNonIntent(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	mkGrant(t, h, ak, "idem-grant")
	ob, _ := json.Marshal(map[string]any{
		"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1",
		"intent_record_id": "use-does-not-exist", "status": "ok",
	})
	code, resp := do(t, h, "POST", "/v2/use-outcome", string(ob))
	if code != http.StatusBadRequest {
		t.Fatalf("a use-outcome for an unknown intent must be 400, got %d: %s", code, resp)
	}
}

// TestTwoPhaseOutcomeLinksIntentDespiteInterveningRecord (adversarial review/finder D5.2): the outcome must link to its
// intent even if a record is appended in the same session BETWEEN the two phases (which drops the intent out
// of session heads). The producer FORCES the intent content_hash into the outcome's causal_prev_hashes.
func TestTwoPhaseOutcomeLinksIntentDespiteInterveningRecord(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent failed (%d): %s", code, resp)
	}
	var intent struct {
		UseID  string                     `json:"use_id"`
		Record map[string]json.RawMessage `json:"record"`
	}
	json.Unmarshal([]byte(resp), &intent)
	var intentHash string
	json.Unmarshal(intent.Record["content_hash"], &intentHash)

	// an intervening generic record in the SAME session links to (and so removes) the intent from heads.
	if c, r := do(t, h, "POST", "/v2/records", `{"idempotency_key":"mid","project_id":"p1","session_id":"s1","event_type":"decision","status":"ok","action":"interleave"}`); c != http.StatusCreated {
		t.Fatalf("intervening record: %d %s", c, r)
	}

	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	code, oresp := do(t, h, "POST", "/v2/use-outcome", string(ob))
	if code != http.StatusCreated {
		t.Fatalf("use-outcome failed (%d): %s", code, oresp)
	}
	var outcome struct {
		Record map[string]json.RawMessage `json:"record"`
	}
	json.Unmarshal([]byte(oresp), &outcome)
	var prev []string
	json.Unmarshal(outcome.Record["causal_prev_hashes"], &prev)
	found := false
	for _, p := range prev {
		if p == intentHash {
			found = true
		}
	}
	if !found {
		t.Fatalf("the outcome's causal_prev_hashes %v must include the intent content_hash %q despite the intervening record", prev, intentHash)
	}
}

// TestGenericRecordRejectsReservedIDPrefix (adversarial review D5.2): a generic /v2/records caller must not pre-seed a
// "use-"/"outcome-" record_id — that would let a later gateway retry short-circuit past PoP validation.
func TestGenericRecordRejectsReservedIDPrefix(t *testing.T) {
	h := newBrokerResourceServer(t)
	for _, rid := range []string{"use-spoof", "outcome-spoof"} {
		body := `{"project_id":"p1","session_id":"s1","event_type":"decision","status":"ok","action":"x","record_id":"` + rid + `"}`
		if code, resp := do(t, h, "POST", "/v2/records", body); code != http.StatusBadRequest {
			t.Fatalf("a generic record with reserved record_id %q must be 400, got %d: %s", rid, code, resp)
		}
	}
}

func TestUseIsIdempotentOnRetry(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	body := useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")
	// first use seals the receipt and consumes the single-use credential
	code, resp1 := do(t, h, "POST", "/v2/use", body)
	if code != http.StatusCreated {
		t.Fatalf("first use failed (%d): %s", code, resp1)
	}
	// a lost-response retry (SAME idempotency key + nonce) must return the ORIGINAL receipt, NOT fail
	// by re-consuming the now-spent credential.
	code, resp2 := do(t, h, "POST", "/v2/use", body)
	if code != http.StatusCreated {
		t.Fatalf("idempotent retry should succeed (%d): %s", code, resp2)
	}
	if !strings.Contains(resp2, `"idempotent":true`) {
		t.Fatalf("retry should be marked idempotent: %s", resp2)
	}
	var u1, u2 struct {
		UseID  string          `json:"use_id"`
		Record json.RawMessage `json:"record"`
	}
	json.Unmarshal([]byte(resp1), &u1)
	json.Unmarshal([]byte(resp2), &u2)
	if u1.UseID != u2.UseID || string(u1.Record) != string(u2.Record) {
		t.Fatalf("retry returned a different receipt:\n  first: %s\n  retry: %s", resp1, resp2)
	}
}

// TestUseIdemKeyReuseWithDifferentOperationConflicts (adversarial review convergence): reusing a successful /v2/use
// idempotency key with a DIFFERENT operation (here different params -> different use_sig + params commitment)
// must be a 409, NOT a 201 that echoes the old receipt while SKIPPING the credential-consuming ValidateUse —
// which would "authorize" an operation the gateway never validated, with a receipt for the wrong operation.
func TestUseIdemKeyReuseWithDifferentOperationConflicts(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-reuse", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("first use failed (%d): %s", code, resp)
	}
	// SAME idem key, DIFFERENT params (even with the same nonce) -> different use_sig + params commitment -> 409.
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-reuse", cap, grantID, ak, "SELECT 2", "nonce-1")); code != http.StatusConflict {
		t.Fatalf("reusing the idem key with a different operation must be 409, got %d: %s", code, resp)
	}
	// the EXACT original request still replays idempotently (the exact-match tightening must not break honest retries).
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-reuse", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated || !strings.Contains(resp, `"idempotent":true`) {
		t.Fatalf("the exact original use must still replay idempotently, got %d: %s", code, resp)
	}
}

// TestUseOutcomeIdemKeyReuseWithDifferentStatusConflicts (adversarial review convergence): the use-outcome path has the
// same shape — reusing a use-outcome idem key with a DIFFERENT status (or intent) must be a 409, not a 201
// echoing an unrelated outcome.
func TestUseOutcomeIdemKeyReuseWithDifferentStatusConflicts(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	code, ir := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent failed (%d): %s", code, ir)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(ir), &intent)
	outcome := func(idem, status string) (int, string) {
		ob, _ := json.Marshal(map[string]any{
			"idempotency_key": idem, "project_id": "p1", "session_id": "s1",
			"intent_record_id": intent.UseID, "status": status,
		})
		return do(t, h, "POST", "/v2/use-outcome", string(ob))
	}
	if code, r := outcome("idem-outcome", "ok"); code != http.StatusCreated {
		t.Fatalf("first outcome failed (%d): %s", code, r)
	}
	// SAME outcome idem key, DIFFERENT status -> 409.
	if code, r := outcome("idem-outcome", "error"); code != http.StatusConflict {
		t.Fatalf("reusing the outcome idem key with a different status must be 409, got %d: %s", code, r)
	}
	// the EXACT original outcome still replays idempotently.
	if code, r := outcome("idem-outcome", "ok"); code != http.StatusCreated {
		t.Fatalf("the exact original outcome must still replay idempotently, got %d: %s", code, r)
	}
}

// TestUsePreseededGenericIdemConflicts (adversarial review D5.2 round-2, HIGH): a generic /v2/records row already
// occupying the use's idempotency key (with a different, random record_id the old session-scan-by-useID
// missed) must make /v2/use a 409 conflict — NOT a 201 that re-consumed the credential in ValidateUse and
// then silently collapsed the seal onto the foreign row in PutRecord (an action with no persisted receipt).
// The credential must survive the conflict (the 409 is raised BEFORE ValidateUse).
func TestUsePreseededGenericIdemConflicts(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")

	// pre-seed a generic record under the SAME idempotency key the use will use (random record_id).
	if c, r := do(t, h, "POST", "/v2/records", `{"idempotency_key":"shared-key","project_id":"p1","session_id":"s1","event_type":"decision","status":"ok","action":"squat"}`); c != http.StatusCreated {
		t.Fatalf("preseed generic record: %d %s", c, r)
	}
	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "shared-key", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusConflict {
		t.Fatalf("a use whose idempotency_key is already bound to a generic record must be 409, got %d: %s", code, resp)
	}
	// the credential/nonce must be intact: a fresh use (new key, SAME nonce) still validates and seals,
	// proving ValidateUse never ran during the conflict (no burned nonce, no action-without-receipt).
	code, resp = do(t, h, "POST", "/v2/use", useBody(t, "clean-key", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("the credential must survive the conflict — a clean retry should seal a receipt, got %d: %s", code, resp)
	}
}

// TestUsePhasesDoNotShareIdemKey (adversarial review D5.2 round-2, MEDIUM): /v2/use and /v2/use-intent derive the same
// deterministic record_id from (project, idempotency_key), so reusing one key across the two phases must
// 409 — NOT silently return the use_intent as if it satisfied a one-phase /v2/use (skipping validation).
func TestUsePhasesDoNotShareIdemKey(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	// phase-1 intent under "shared-key" consumes the credential and records kind=use_intent.
	if c, r := do(t, h, "POST", "/v2/use-intent", useBody(t, "shared-key", cap, grantID, ak, "SELECT 1", "nonce-1")); c != http.StatusCreated {
		t.Fatalf("use-intent failed (%d): %s", c, r)
	}
	// a /v2/use reusing that key produces the same useID but kind=use; the kind mismatch must 409, not
	// return the use_intent record short-circuiting PoP validation.
	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "shared-key", cap, grantID, ak, "SELECT 1", "nonce-2"))
	if code != http.StatusConflict {
		t.Fatalf("reusing a use_intent's idempotency_key for /v2/use must be 409 (kind mismatch), got %d: %s", code, resp)
	}
}

// TestUseOutcomePreseededGenericIdemConflicts (adversarial review D5.2 round-2): the same guard covers /v2/use-outcome —
// a generic row squatting the outcome's idempotency key must 409, not collapse the outcome onto it.
func TestUseOutcomePreseededGenericIdemConflicts(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent failed (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(resp), &intent)
	// squat the outcome's idempotency key with a generic record.
	if c, r := do(t, h, "POST", "/v2/records", `{"idempotency_key":"out-key","project_id":"p1","session_id":"s1","event_type":"decision","status":"ok","action":"squat"}`); c != http.StatusCreated {
		t.Fatalf("preseed generic record: %d %s", c, r)
	}
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "out-key", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	if c, r := do(t, h, "POST", "/v2/use-outcome", string(ob)); c != http.StatusConflict {
		t.Fatalf("a use-outcome whose idempotency_key is already bound to a generic record must be 409, got %d: %s", c, r)
	}
}

func TestUseRejectsForgedPoP(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak, thief := grantAgentKey(), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	// a thief with the token but not the cnf key signs the PoP — the resource rejects it (no receipt).
	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, thief, "SELECT 1", "n"))
	if code != http.StatusBadRequest || !strings.Contains(resp, "PoP failed") {
		t.Fatalf("forged PoP should be a 400 PoP failure, got %d: %s", code, resp)
	}
}

func TestUseDoubleSpendRejected(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	// first use succeeds
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use-1", cap, grantID, ak, "SELECT 1", "n1")); code != http.StatusCreated {
		t.Fatalf("first use should succeed, got %d: %s", code, resp)
	}
	// second use of the single-use credential (fresh nonce, new idempotency key) is a double-spend
	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use-2", cap, grantID, ak, "SELECT 1", "n2"))
	if code != http.StatusBadRequest || !strings.Contains(resp, "double-spend") {
		t.Fatalf("single-use double-spend should be a 400, got %d: %s", code, resp)
	}
}

func TestUseDisabledWithoutResource(t *testing.T) {
	h := newBrokerServer(t) // broker only, no resource gateway
	code, resp := do(t, h, "POST", "/v2/use", `{"project_id":"p1","session_id":"s1"}`)
	if code != http.StatusNotImplemented {
		t.Fatalf("use without a resource gateway should be 501, got %d: %s", code, resp)
	}
}
