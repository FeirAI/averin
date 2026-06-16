package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

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

func TestGrantDescriptorDisclosesUnderCredentialDomain(t *testing.T) {
	// ADR 0004 D1: the grant's credential descriptor commits under the dedicated `credential` domain
	// (not the overloaded `input`), and the offline verifier opens the disclosure against
	// credential_commit.
	h := newBrokerServer(t)
	ak := grantAgentKey()
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, ak)); code != http.StatusCreated {
		t.Fatalf("grant failed (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, resp)
	}
	code, exp := do(t, h, "GET", "/v2/export?project=p1&mode=selective_disclosure", "")
	if code != http.StatusOK {
		t.Fatalf("export (%d): %s", code, exp)
	}
	if !strings.Contains(exp, `"field":"credential"`) {
		t.Fatalf("the grant descriptor should disclose under the credential domain: %s", exp)
	}
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	report := c.VerifyBundle(exp)
	if !strings.Contains(report, `"ok":true`) {
		t.Fatalf("disclosing grant bundle should verify ok: %s", report)
	}
	if !strings.Contains(report, `"disclosures_total":1`) || !strings.Contains(report, `"disclosures_verified":1`) {
		t.Fatalf("the credential disclosure should open against credential_commit: %s", report)
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

// TestCheckpointAnchorsBrokerGrantHead proves the producer side of D6: each grant carries a gapless
// broker_seq in its signed evidence, and a checkpoint anchors a broker_grant_head whose cumulative_root
// re-derives from the issued grant log (so the offline verifier can detect suppression).
func TestCheckpointAnchorsBrokerGrantHead(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	type gi struct {
		hash string
		seq  int64
	}
	var grants []gi
	for _, idem := range []string{"idem-1", "idem-2"} {
		code, resp := do(t, h, "POST", "/v2/grants", grantBody(idem, "read:orders", ak, ak))
		if code != http.StatusCreated {
			t.Fatalf("grant %s failed (%d): %s", idem, code, resp)
		}
		var out struct {
			Record struct {
				ContentHash string `json:"content_hash"`
				Extensions  struct {
					Broker struct {
						GrantEvidence struct {
							BrokerSeq int64 `json:"broker_seq"`
						} `json:"grant_evidence"`
					} `json:"broker"`
				} `json:"extensions"`
			} `json:"record"`
		}
		if err := json.Unmarshal([]byte(resp), &out); err != nil {
			t.Fatalf("decode grant: %v\n%s", err, resp)
		}
		grants = append(grants, gi{out.Record.ContentHash, out.Record.Extensions.Broker.GrantEvidence.BrokerSeq})
	}
	if grants[0].seq != 1 || grants[1].seq != 2 {
		t.Fatalf("broker_seq = %d,%d; want gapless 1,2", grants[0].seq, grants[1].seq)
	}

	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint failed (%d): %s", code, resp)
	}
	code, exp := do(t, h, "GET", "/v2/export?project=p1&mode=proof_only", "")
	if code != http.StatusOK {
		t.Fatalf("export (%d): %s", code, exp)
	}
	var bundle struct {
		Checkpoints []struct {
			BrokerGrantHead struct {
				MaxSeq         int64  `json:"max_seq"`
				PriorHeadHash  string `json:"prior_head_hash"`
				CumulativeRoot string `json:"cumulative_root"`
			} `json:"broker_grant_head"`
		} `json:"checkpoints"`
	}
	if err := json.Unmarshal([]byte(exp), &bundle); err != nil {
		t.Fatalf("decode export: %v\n%s", err, exp)
	}
	if len(bundle.Checkpoints) == 0 {
		t.Fatalf("no checkpoints in export: %s", exp)
	}
	head := bundle.Checkpoints[len(bundle.Checkpoints)-1].BrokerGrantHead
	if head.MaxSeq != 2 {
		t.Fatalf("broker_grant_head.max_seq = %d, want 2", head.MaxSeq)
	}
	want := broker.GrantHeadRoot([]broker.GrantSeqHash{
		{Seq: grants[0].seq, ContentHash: grants[0].hash},
		{Seq: grants[1].seq, ContentHash: grants[1].hash},
	})
	if head.CumulativeRoot != want {
		t.Fatalf("cumulative_root = %s, want %s (re-derived from the grant log)", head.CumulativeRoot, want)
	}
	if head.PriorHeadHash != broker.EmptyGrantHeadRoot() {
		t.Fatalf("first checkpoint prior_head_hash should be the empty-log root, got %s", head.PriorHeadHash)
	}
}

// TestGrantRetryDoesNotBurnBrokerSeq proves the D6 fix: an idempotent grant retry must NOT allocate a
// new broker_seq (the record already exists), so a replay can never leave an unrecorded seq that
// manufactures a false transparency gap. The same mechanism covers a pre-D6 legacy-grant retry.
func TestGrantRetryDoesNotBurnBrokerSeq(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	seqOf := func(idem string) int64 {
		code, resp := do(t, h, "POST", "/v2/grants", grantBody(idem, "read:orders", ak, ak))
		if code != http.StatusCreated {
			t.Fatalf("grant %s (%d): %s", idem, code, resp)
		}
		var out struct {
			Record struct {
				Extensions struct {
					Broker struct {
						GrantEvidence struct {
							BrokerSeq int64 `json:"broker_seq"`
						} `json:"grant_evidence"`
					} `json:"broker"`
				} `json:"extensions"`
			} `json:"record"`
		}
		if err := json.Unmarshal([]byte(resp), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out.Record.Extensions.Broker.GrantEvidence.BrokerSeq
	}
	if s := seqOf("idem-1"); s != 1 {
		t.Fatalf("first grant seq = %d, want 1", s)
	}
	// retry the SAME idem -> returns the original record (seq 1), no new allocation
	if s := seqOf("idem-1"); s != 1 {
		t.Fatalf("retry seq = %d, want idempotent 1", s)
	}
	// a genuinely new grant must be seq 2 (NOT 3) — proving the retry did not burn seq 2
	if s := seqOf("idem-2"); s != 2 {
		t.Fatalf("second grant seq = %d, want gapless 2 (retry must not burn a seq)", s)
	}
}

// TestGrantResponseExpiryMatchesCapability proves the response expires_at is derived from the grant's
// signed evidence (matching the capability the agent holds) on BOTH create and idempotent retry — never
// a fresh request-time value that could outlast the original capability on a replay.
func TestGrantResponseExpiryMatchesCapability(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	parse := func(resp string) (expiresAt, capability string) {
		var out struct {
			ExpiresAt  string `json:"expires_at"`
			Capability string `json:"capability"`
		}
		if err := json.Unmarshal([]byte(resp), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out.ExpiresAt, out.Capability
	}
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("grant (%d): %s", code, resp)
	}
	expiresAt1, cap1 := parse(resp)
	claims, err := broker.VerifyCapability(cap1, brokerIssuingKey().Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("verify capability: %v", err)
	}
	want := time.Unix(claims.Exp, 0).UTC().Format("2006-01-02T15:04:05.000Z")
	if expiresAt1 != want {
		t.Fatalf("create expires_at %q != capability exp %q", expiresAt1, want)
	}
	// idempotent retry must return the SAME (original) expiry, not a fresh now()-based one
	code, resp2 := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("retry (%d): %s", code, resp2)
	}
	expiresAt2, _ := parse(resp2)
	if expiresAt2 != expiresAt1 {
		t.Fatalf("retry expires_at %q != original %q (must match the stored grant)", expiresAt2, expiresAt1)
	}
}

// TestGrantRetryWithInvalidSigDoesNotLeakCapability proves the D6 fix: an idempotent-key reuse with an
// invalid agent_sig (a caller that cannot prove possession of the agent key) is rejected by validation
// BEFORE the no-allocation retry shortcut, so it can never retrieve the stored capability.
func TestGrantRetryWithInvalidSigDoesNotLeakCapability(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, ak)); code != http.StatusCreated {
		t.Fatalf("seed grant (%d): %s", code, resp)
	}
	// an attacker knows idem-1 but signs the challenge with a DIFFERENT key (no possession of ak)
	attacker := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, attacker))
	if code != http.StatusBadRequest {
		t.Fatalf("a retry with an invalid agent_sig must be 400, got %d: %s", code, resp)
	}
	if strings.Contains(resp, "capability") {
		t.Fatalf("a rejected retry must not leak a capability: %s", resp)
	}
}

// TestGrantIdempotencyConflictRejected proves a reused idempotency key carrying a DIFFERENT grant request
// (a different agent key) is rejected with 409 and leaks no capability — only a byte-identical retry of
// the original request collapses to the stored grant (ADR 0004 D6 auth-boundary).
func TestGrantIdempotencyConflictRejected(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, ak)); code != http.StatusCreated {
		t.Fatalf("seed grant (%d): %s", code, resp)
	}
	// a DIFFERENT but validly-signed request (different agent key) reuses idem-1 -> 409, no capability
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, ed25519.SeedSize))
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", other, other))
	if code != http.StatusConflict {
		t.Fatalf("idem reuse with a different request must be 409, got %d: %s", code, resp)
	}
	if strings.Contains(resp, "capability") {
		t.Fatalf("a conflicting retry must not leak a capability: %s", resp)
	}
	// the byte-identical original request is a legitimate idempotent retry -> 201
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, ak)); code != http.StatusCreated {
		t.Fatalf("a legitimate identical retry must succeed, got %d: %s", code, resp)
	}
}

// ambiguousCommitStore simulates a store whose PutRecord COMMITS the record but returns an error (e.g. a
// Postgres tx.Commit ack lost after the server-side commit), to prove the broker_seq is NOT released for a
// grant that is actually durable (which would let a later grant reuse the number — ADR 0004 D6).
type ambiguousCommitStore struct {
	store.Store
	failNextCreate bool
}

func (a *ambiguousCommitStore) PutRecord(p, k string, rec store.Record) (store.Record, bool, error) {
	stored, created, err := a.Store.PutRecord(p, k, rec)
	if a.failNextCreate && created {
		a.failNextCreate = false
		return stored, created, errors.New("simulated ambiguous commit (the record IS durable)")
	}
	return stored, created, err
}

func TestGrantAmbiguousCommitDoesNotReleaseSeq(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	st := &ambiguousCommitStore{Store: store.NewMem(), failNextCreate: true}
	h := api.New(c, st, "k0").WithBroker(brokerIssuingKey()).Routes()
	ak := grantAgentKey()
	// first grant hits the ambiguous commit; the handler re-reads, finds the durable record, keeps seq 1.
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-1", "read:orders", ak, ak)); code != http.StatusCreated {
		t.Fatalf("ambiguous-commit grant should still succeed (record is durable), got %d: %s", code, resp)
	}
	// a second grant must get seq 2 — NOT reuse seq 1 (which would duplicate broker_seq and poison the head)
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-2", "read:orders", ak, ak))
	if code != http.StatusCreated {
		t.Fatalf("second grant (%d): %s", code, resp)
	}
	var out struct {
		Record struct {
			Extensions struct {
				Broker struct {
					GrantEvidence struct {
						BrokerSeq int64 `json:"broker_seq"`
					} `json:"grant_evidence"`
				} `json:"broker"`
			} `json:"extensions"`
		} `json:"record"`
	}
	if e := json.Unmarshal([]byte(resp), &out); e != nil {
		t.Fatalf("decode: %v", e)
	}
	if out.Record.Extensions.Broker.GrantEvidence.BrokerSeq != 2 {
		t.Fatalf("second grant broker_seq = %d, want 2 (seq 1 must NOT be released/reused after an ambiguous commit)", out.Record.Extensions.Broker.GrantEvidence.BrokerSeq)
	}
}

// TestGrantIdempotencyConflictOnShapingFields proves a reused idem key with a DIFFERENT scope_class or TTL
// (fields that change capability semantics: single_use, exp) is a 409 — not a collapse onto a
// semantically-different stored capability (ADR 0004 D6; Codex hardening).
func TestGrantIdempotencyConflictOnShapingFields(t *testing.T) {
	h := newBrokerServer(t)
	ak := grantAgentKey()
	// the agent_sig is over agent_id/action/resource/scope/agent_pubkey — NOT ttl or scope_class — so a
	// valid sig can be reused while changing those grant-shaping fields.
	bodyWith := func(idem string, ttl int, scopeClass string) string {
		pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
		sr := broker.Request{AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: "read:orders", AgentPubKey: pub}
		sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, sr.Challenge()))
		m := map[string]any{
			"idempotency_key": idem, "project_id": "p1", "session_id": "s1",
			"agent_id": "agent-1", "action": "db.query:orders-ro", "resource": "orders-db",
			"scope": "read:orders", "agent_pubkey": pub, "agent_sig": sig, "ttl_seconds": ttl,
		}
		if scopeClass != "" {
			m["scope_class"] = scopeClass
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	// seed a default single_operation grant, ttl 60
	if code, resp := do(t, h, "POST", "/v2/grants", bodyWith("idem-a", 60, "")); code != http.StatusCreated {
		t.Fatalf("seed (%d): %s", code, resp)
	}
	// same idem, different TTL -> 409
	if code, resp := do(t, h, "POST", "/v2/grants", bodyWith("idem-a", 120, "")); code != http.StatusConflict {
		t.Fatalf("a different TTL under the same idem must be 409, got %d: %s", code, resp)
	}
	// same idem, different scope_class (session_grant) -> 409
	if code, resp := do(t, h, "POST", "/v2/grants", bodyWith("idem-a", 60, "session_grant")); code != http.StatusConflict {
		t.Fatalf("a different scope_class under the same idem must be 409, got %d: %s", code, resp)
	}
	// the byte-identical original still collapses cleanly
	if code, resp := do(t, h, "POST", "/v2/grants", bodyWith("idem-a", 60, "")); code != http.StatusCreated {
		t.Fatalf("identical retry must succeed, got %d: %s", code, resp)
	}
}
