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

// TestGenericIngestCannotForgeDenialEvidence (Codex C2): a denial is sealed by the server signing key like
// every record, so the verifier cannot tell a broker-produced denial from a generic-forged one — the
// reservation must live at ingest. A generic /v2/records caller must NOT be able to forge B11 denial
// evidence via the event_type, the extensions.broker_denial payload, or a reserved denial- record_id.
func TestGenericIngestCannotForgeDenialEvidence(t *testing.T) {
	h := newBrokerServer(t)
	cases := []string{
		`{"idempotency_key":"i1","project_id":"p1","session_id":"s1","event_type":"credential_grant_denied","status":"denied","action":"x"}`,
		`{"idempotency_key":"i2","project_id":"p1","session_id":"s1","event_type":"decision","status":"ok","action":"x","extensions":{"broker_denial":{"kind":"grant_denied"}}}`,
		`{"idempotency_key":"i3","project_id":"p1","session_id":"s1","event_type":"decision","status":"ok","action":"x","record_id":"denial-spoof"}`,
		// squat the broker's "denial:"-prefixed idempotency-key namespace: pre-seeding a benign record under a
		// denial's deterministic key would make the later denied grant's PutRecord collapse onto it and silently
		// suppress the B11 evidence (Codex C2b). The prefix is reserved at ingest.
		`{"idempotency_key":"denial:spoof","project_id":"p1","session_id":"s1","event_type":"decision","status":"ok","action":"x"}`,
	}
	for i, body := range cases {
		if code, r := do(t, h, "POST", "/v2/records", body); code != http.StatusBadRequest {
			t.Fatalf("case %d: generic ingest must reject a forged denial marker, got %d: %s", i, code, r)
		}
	}
}

// TestVaryingProbeFieldsLogDistinctDenials (Codex C3): the denial id derives from the FULL requested probe
// identity, not the idempotency key — so two probes reusing one idem key + scope + reason but differing in
// another requested field (here the agent key) are logged as TWO distinct denials, not collapsed to one.
func TestVaryingProbeFieldsLogDistinctDenials(t *testing.T) {
	h := denyLogServer(t)
	ak1 := grantAgentKey()
	seed2 := make([]byte, ed25519.SeedSize)
	seed2[0] = 7
	ak2 := ed25519.NewKeyFromSeed(seed2) // a DIFFERENT agent key (a field the old idem|scope|reason id ignored)
	if code, r := do(t, h, "POST", "/v2/grants", grantBody("idem-probe", "iam:reset", ak1, ak1)); code != http.StatusBadRequest {
		t.Fatalf("probe 1 should be 400, got %d: %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/grants", grantBody("idem-probe", "iam:reset", ak2, ak2)); code != http.StatusBadRequest {
		t.Fatalf("probe 2 should be 400, got %d: %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"denied_grants":2`) {
		t.Fatalf("two probes differing in the agent key must log 2 distinct denials (not collapse): %s", report)
	}
}

// TestDenialIdResistsDelimiterInjection (Codex C3b): the denial id encodes the probe tuple as a JSON array,
// so a caller embedding the U+001F delimiter in a field cannot collide two DISTINCT probes into one id. The
// two probes below join-collide under a raw \x1f separator (action="a",resource="b\x1fX" vs
// action="a\x1fb",resource="X") but must still log as TWO distinct denials.
func TestDenialIdResistsDelimiterInjection(t *testing.T) {
	h := denyLogServer(t)
	ak := grantAgentKey()
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	post := func(action, resource string) {
		req := broker.Request{AgentID: "agent-1", Action: action, Resource: resource, Scope: "iam:reset", AgentPubKey: pub}
		sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge()))
		body, _ := json.Marshal(map[string]any{
			"idempotency_key": "idem-x", "project_id": "p1", "session_id": "s1",
			"agent_id": "agent-1", "action": action, "resource": resource,
			"scope": "iam:reset", "agent_pubkey": pub, "agent_sig": sig, "ttl_seconds": 60,
		})
		if code, r := do(t, h, "POST", "/v2/grants", string(body)); code != http.StatusBadRequest {
			t.Fatalf("forbidden scope should be 400, got %d: %s", code, r)
		}
	}
	post("a", "b\x1fX")
	post("a\x1fb", "X")
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"denied_grants":2`) {
		t.Fatalf("two probes that join-collide under a raw \\x1f separator must still log 2 distinct denials: %s", report)
	}
}

// customGrant posts a grant with explicit session/scope/ttl and a valid PoP (the PoP challenge covers
// agent_id/action/resource/scope/agent_pubkey, NOT session_id or ttl, so those vary freely under one sig).
// It asserts the request is rejected (400) — i.e. it produces a denial.
func customGrant(t *testing.T, h http.Handler, ak ed25519.PrivateKey, idem, session, scope string, ttl int) {
	t.Helper()
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	req := broker.Request{AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: scope, AgentPubKey: pub}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge()))
	body, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": "p1", "session_id": session,
		"agent_id": "agent-1", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": scope, "agent_pubkey": pub, "agent_sig": sig, "ttl_seconds": ttl,
	})
	if code, r := do(t, h, "POST", "/v2/grants", string(body)); code != http.StatusBadRequest {
		t.Fatalf("denied grant should be 400, got %d: %s", code, r)
	}
}

// TestDenialIdIncludesSessionAndTTL (Codex C3c): the denial id covers the FULL request, so varying any
// distinguishing field — here session_id (forbidden-scope probes) and ttl_seconds (over-cap TTL probes),
// both under a fixed idempotency key + otherwise-identical tuple — logs DISTINCT denials rather than
// collapsing onto the first. Old subset-based id ignored session_id and ttl_seconds → would log only 2.
func TestDenialIdIncludesSessionAndTTL(t *testing.T) {
	h := denyLogServer(t)
	ak := grantAgentKey()
	customGrant(t, h, ak, "idem-x", "s1", "iam:reset", 60)     // forbidden_scope, session s1
	customGrant(t, h, ak, "idem-x", "s2", "iam:reset", 60)     // forbidden_scope, session s2 (was collapsed)
	customGrant(t, h, ak, "idem-y", "s3", "read:orders", 99999) // ttl_exceeded, ttl 99999
	customGrant(t, h, ak, "idem-y", "s3", "read:orders", 88888) // ttl_exceeded, ttl 88888 (was collapsed)
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"denied_grants":4`) {
		t.Fatalf("varying session_id and ttl_seconds must each produce a distinct denial (want 4): %s", report)
	}
}

// TestBrokerEndpointsRejectReservedDenialIdem (Codex C2c): the "denial:" idempotency-key namespace must be
// reserved at EVERY caller-supplied entry point, not only generic/OTel ingest. A valid grant/use/outcome
// pre-seeded under denial:<computed denialID> would otherwise collapse the later denial and silently
// suppress the B11 evidence. Each broker endpoint rejects the prefix before any other processing.
func TestBrokerEndpointsRejectReservedDenialIdem(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	// /v2/grants with a valid PoP but a reserved-prefix idem — rejected before validation.
	if code, r := do(t, h, "POST", "/v2/grants", grantBody("denial:squat", "read:orders", ak, ak)); code != http.StatusBadRequest || !strings.Contains(r, "reserved") {
		t.Fatalf("/v2/grants must reject a denial:-prefixed idempotency_key, got %d: %s", code, r)
	}
	// /v2/use(+intent)/use-outcome check the prefix right after idem resolution, before capability/intent
	// validation, so a minimal body reaches the guard.
	minUse := `{"idempotency_key":"denial:squat","project_id":"p1","session_id":"s1"}`
	for _, ep := range []string{"/v2/use", "/v2/use-intent"} {
		if code, r := do(t, h, "POST", ep, minUse); code != http.StatusBadRequest || !strings.Contains(r, "reserved") {
			t.Fatalf("%s must reject a denial:-prefixed idempotency_key, got %d: %s", ep, code, r)
		}
	}
	minOut := `{"idempotency_key":"denial:squat","project_id":"p1","session_id":"s1","intent_record_id":"use-x"}`
	if code, r := do(t, h, "POST", "/v2/use-outcome", minOut); code != http.StatusBadRequest || !strings.Contains(r, "reserved") {
		t.Fatalf("/v2/use-outcome must reject a denial:-prefixed idempotency_key, got %d: %s", code, r)
	}
}

// squatStore simulates a row PRE-DATING the "denial:" namespace reservation: it injects a foreign record
// under the first "denial:"-prefixed PutRecord and returns it as the collapse (created=false), the way an
// upgrade/rolling deploy could leave a caller-seeded row occupying a denial's computed key.
type squatStore struct {
	store.Store
	squatted bool
}

func (s *squatStore) PutRecord(projectID, idemKey string, rec store.Record) (store.Record, bool, error) {
	if !s.squatted && strings.HasPrefix(idemKey, "denial:") {
		s.squatted = true
		foreign := store.Record{JSON: `{"record_id":"foreign-squat","event_type":"decision"}`, ContentHash: "sha256:" + strings.Repeat("f", 64), SessionID: rec.SessionID}
		_, _, _ = s.Store.PutRecord(projectID, idemKey, foreign)
		return foreign, false, nil
	}
	return s.Store.PutRecord(projectID, idemKey, rec)
}

// TestDenialRecoversFromPreSeededReservedKey (Codex C2d): if a FOREIGN row already occupies a denial's
// reserved "denial:" key (a row pre-dating the hardening, which the entry-point guards can't retract), the
// denial must be RECOVERED under a fresh collision-proof key — never silently suppressed by the collapse.
func TestDenialRecoversFromPreSeededReservedKey(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	ss := &squatStore{Store: store.NewMem()}
	h := api.New(c, ss, "k0").WithBroker(brokerIssuingKey()).WithDeniedGrantLog().Routes()
	ak := grantAgentKey()
	if code, r := do(t, h, "POST", "/v2/grants", grantBody("idem-deny", "iam:reset", ak, ak)); code != http.StatusBadRequest {
		t.Fatalf("forbidden scope should be 400, got %d: %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"denied_grants":1`) {
		t.Fatalf("a denial whose reserved key was pre-seeded with a foreign row must be RECOVERED, not suppressed (denied_grants:1): %s", report)
	}
}

// denialRecordID extracts the record_id of the credential_grant_denied record in an export bundle.
func denialRecordID(t *testing.T, exportJSON string) string {
	t.Helper()
	var bundle struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal([]byte(exportJSON), &bundle); err != nil {
		t.Fatalf("parse export: %v", err)
	}
	for _, r := range bundle.Records {
		var rec struct {
			RecordID  string `json:"record_id"`
			EventType string `json:"event_type"`
		}
		json.Unmarshal(r, &rec)
		if rec.EventType == "credential_grant_denied" {
			return rec.RecordID
		}
	}
	t.Fatalf("no denial record in export: %s", exportJSON)
	return ""
}

// TestDenialIdIsServerSecret (Codex C2e, root fix): the denial id mixes a server secret (a deterministic
// signature under the broker private key), so a caller cannot precompute denial:<denialID> to pre-seed/forge
// a row under it. Two deployments that differ ONLY in broker key produce DIFFERENT denial ids for the SAME
// denied request — proving the id is not publicly computable.
func TestDenialIdIsServerSecret(t *testing.T) {
	mk := func(brokerKey ed25519.PrivateKey) http.Handler {
		c, err := core.New(seed)
		if err != nil {
			t.Fatalf("core: %v", err)
		}
		return api.New(c, store.NewMem(), "k0").WithBroker(brokerKey).WithDeniedGrantLog().Routes()
	}
	ak := grantAgentKey()
	bk2Seed := make([]byte, ed25519.SeedSize)
	bk2Seed[0] = 0x33
	post := func(h http.Handler) string {
		if code, r := do(t, h, "POST", "/v2/grants", grantBody("idem-deny", "iam:reset", ak, ak)); code != http.StatusBadRequest {
			t.Fatalf("forbidden scope should be 400, got %d: %s", code, r)
		}
		_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
		return denialRecordID(t, exp)
	}
	idA := post(mk(brokerIssuingKey()))
	idB := post(mk(ed25519.NewKeyFromSeed(bk2Seed)))
	if idA == idB {
		t.Fatalf("denial id must depend on the server secret (broker key); both deployments produced %q", idA)
	}
}

// TestPoPFailureDistinctSignaturesLogDistinctDenials (Codex C2f): agent_sig stays in the denial identity, so
// two pop_failure attempts for the SAME operation but with DISTINCT failing signatures are logged as two
// distinct denials (each a distinct failed proof) — a PoP brute-force leaves one record per attempt, not one
// collapsed record. (forbidden_scope retries still dedup: their valid sig is deterministic.)
func TestPoPFailureDistinctSignaturesLogDistinctDenials(t *testing.T) {
	h := denyLogServer(t)
	ak := grantAgentKey()
	thief1 := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // all-zero seed
	s2 := make([]byte, ed25519.SeedSize)
	s2[0] = 0x55
	thief2 := ed25519.NewKeyFromSeed(s2) // a DIFFERENT wrong key -> a distinct failing signature
	// same operation + agent_pubkey (ak), two distinct invalid signatures -> two distinct failed proofs.
	if code, _ := do(t, h, "POST", "/v2/grants", grantBody("idem-pop", "read:orders", ak, thief1)); code != http.StatusBadRequest {
		t.Fatalf("bad PoP should be 400")
	}
	if code, _ := do(t, h, "POST", "/v2/grants", grantBody("idem-pop", "read:orders", ak, thief2)); code != http.StatusBadRequest {
		t.Fatalf("bad PoP should be 400")
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"denied_grants":2`) {
		t.Fatalf("two pop_failure attempts with distinct signatures must log 2 distinct denials: %s", report)
	}
}

// TestDenialIdCanonicalizesBase64 (Codex pass-8 medium): the broker's base64 decode is non-strict, so the
// SAME agent_pubkey bytes under canonical vs non-canonical spellings must collapse to ONE denial — else a
// caller inflates denied_grants without a distinct key. Two forbidden-scope probes, same key bytes, differing
// only in the pubkey's base64 padding bit, must log a single denial.
func TestDenialIdCanonicalizesBase64(t *testing.T) {
	h := denyLogServer(t)
	ak := grantAgentKey()
	pub := ak.Public().(ed25519.PublicKey)
	canon := base64.RawURLEncoding.EncodeToString(pub)
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	idx := strings.IndexByte(alpha, canon[len(canon)-1])
	nonCanon := canon[:len(canon)-1] + string(alpha[idx^1]) // same 32 bytes, non-canonical padding bit
	if nonCanon == canon {
		t.Fatal("failed to construct a non-canonical encoding")
	}
	post := func(pubB64 string) {
		req := broker.Request{AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: "iam:reset", AgentPubKey: pubB64}
		sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge()))
		body, _ := json.Marshal(map[string]any{
			"idempotency_key": "idem-x", "project_id": "p1", "session_id": "s1",
			"agent_id": "agent-1", "action": "db.query:orders-ro", "resource": "orders-db",
			"scope": "iam:reset", "agent_pubkey": pubB64, "agent_sig": sig, "ttl_seconds": 60,
		})
		if code, r := do(t, h, "POST", "/v2/grants", string(body)); code != http.StatusBadRequest {
			t.Fatalf("forbidden scope should be 400, got %d: %s", code, r)
		}
	}
	post(canon)
	post(nonCanon)
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"denied_grants":1`) {
		t.Fatalf("the same pubkey under canonical + non-canonical base64 must collapse to ONE denial: %s", report)
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
