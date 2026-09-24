package resourceshim

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/goldenvec"
)

func keyFromByte(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func testNonce(t *testing.T, nonce string) NonceClaim {
	t.Helper()
	c, err := NewNonceClaim("p1", testResource, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testJTI(t *testing.T, key string) JTIClaim {
	t.Helper()
	c, err := NewJTIClaim(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const (
	testAction   = "db.query:orders-ro"
	testResource = "orders-db"
	testGrantID  = "grant-xyz"
	testParams   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

// mintCap builds a valid single-use capability (grant_id == grantID) for agent on resource.
func mintCap(t *testing.T, issuing, agent ed25519.PrivateKey, grantID, action, resource string, ttl time.Duration, now time.Time) string {
	t.Helper()
	agentPub := agent.Public().(ed25519.PublicKey)
	req := broker.Request{
		PoPVersion:       2,
		ProjectID:        "p1",
		IdempotencyKey:   grantID,
		SessionID:        "s1",
		IssuedAt:         now.Unix(),
		RequestExpiresAt: now.Add(broker.MaxRequestAge).Unix(),
		AgentID:          "agent-1",
		Action:           action,
		Resource:         resource,
		Scope:            "read:orders",
		AgentPubKey:      b64(agentPub),
		Principal:        "svc",
		TTL:              ttl,
	}
	req.AgentSig = b64(ed25519.Sign(agent, req.Challenge()))
	p, err := broker.Prepare(req, grantID, func() (int64, error) { return 1, nil }, now, issuing)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return p.Capability
}

// defaultCap mints a capability with the default test grant_id/action/resource.
func defaultCap(t *testing.T, issuing, agent ed25519.PrivateKey, ttl time.Duration, now time.Time) string {
	return mintCap(t, issuing, agent, testGrantID, testAction, testResource, ttl, now)
}

// signUse produces a valid use_sig: the agent signs the fully-bound PoP challenge with its cnf key.
func signUse(t *testing.T, agent ed25519.PrivateKey, token, grantID, resource, action, paramsCommit, nonce string) string {
	t.Helper()
	binding, err := CredentialBinding(token)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	ch := UsePoPChallenge(grantID, resource, action, paramsCommit, binding, nonce)
	return b64(ed25519.Sign(agent, ch))
}

// signDefault signs a use for the default test grant_id/resource/action.
func signDefault(t *testing.T, agent ed25519.PrivateKey, token, paramsCommit, nonce string) string {
	return signUse(t, agent, token, testGrantID, testResource, testAction, paramsCommit, nonce)
}

func resignTimes(t *testing.T, signing ed25519.PrivateKey, token string, fields map[string]int64) string {
	t.Helper()
	encoded, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatal("malformed fixture capability")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor map[string]json.RawMessage
	if err := json.Unmarshal(payload, &descriptor); err != nil {
		t.Fatal(err)
	}
	for key, value := range fields {
		descriptor[key], _ = json.Marshal(value)
	}
	payload, err = json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	encoded = b64(payload)
	return encoded + "." + b64(ed25519.Sign(signing, []byte(encoded)))
}

func TestAcceptedCapabilityLifetimeBoundsBeforeLedger(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	base := defaultCap(t, issuing, agent, time.Hour, now)
	iat := now.Unix()
	for _, tc := range []struct {
		name   string
		fields map[string]int64
	}{
		{"overlong", map[string]int64{"exp": iat + 3601}},
		{"zero lifetime", map[string]int64{"exp": iat}},
		{"max signed integer", map[string]int64{"iat": math.MaxInt64 - 1, "nbf": math.MaxInt64 - 1, "exp": math.MaxInt64}},
		{"min signed integer", map[string]int64{"iat": math.MinInt64, "nbf": math.MinInt64, "exp": math.MaxInt64}},
		{"nbf before issue", map[string]int64{"nbf": iat - 1}},
		{"nbf at expiry", map[string]int64{"nbf": iat + 3600}},
		{"future issue", map[string]int64{"iat": iat + 31, "nbf": iat + 31, "exp": iat + 91}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := NewMemLedger()
			token := resignTimes(t, issuing, base, tc.fields)
			shim := New(issuing.Public().(ed25519.PublicKey), testResource, ledger).WithProject("p1")
			_, err := shim.ValidateUse(token, signDefault(t, agent, token, testParams, "not-burned"),
				Op{Action: testAction, ParamsCommitment: testParams}, "not-burned", now)
			if err == nil {
				t.Fatal("invalid lifetime accepted")
			}
			if err := ledger.ConsumeNonce(testNonce(t, "not-burned")); err != nil {
				t.Fatalf("rejected capability burned nonce: %v", err)
			}
		})
	}
}

func TestMemLedgerNonceScopeTupleDoesNotAlias(t *testing.T) {
	ledger := NewMemLedger()
	a, _ := NewNonceClaim("a\x00b", "c", "n")
	b, _ := NewNonceClaim("a", "b\x00c", "n")
	if err := ledger.ConsumeNonce(a); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ConsumeNonce(b); err != nil {
		t.Fatalf("distinct tuple aliased: %v", err)
	}
	ledger.ReleaseNonce(a)
	c, _ := NewNonceClaim("a", "b\x00c", "n")
	if err := ledger.ConsumeNonce(c); !errors.Is(err, ErrConsumed) {
		t.Fatalf("release crossed tuple boundary: %v", err)
	}
}

func TestValidUseProducesCanonicalEvidence(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	useSig := signDefault(t, agent, token, testParams, "nonce-1")

	ev, err := sh.ValidateUse(token, useSig, Op{Action: testAction, ParamsCommitment: testParams}, "nonce-1", now)
	if err != nil {
		t.Fatalf("valid use rejected: %v", err)
	}
	if ev.Kind != "use" || ev.GrantID != testGrantID || ev.JTI != testGrantID {
		t.Fatalf("use_evidence identity wrong: %+v", ev)
	}
	if ev.Action != testAction || ev.ResourceID != testResource || ev.Nonce != "nonce-1" {
		t.Fatalf("use_evidence binding wrong: %+v", ev)
	}
	if ev.CnfKid != broker.KeyID(agent.Public().(ed25519.PublicKey)) {
		t.Fatalf("cnf_kid not bound to the agent cnf key: %s", ev.CnfKid)
	}
	if !strings.HasPrefix(ev.PopChallengeHash, "sha256:") || len(ev.PopChallengeHash) != len("sha256:")+64 {
		t.Fatalf("pop_challenge_hash shape: %s", ev.PopChallengeHash)
	}
	if !strings.HasPrefix(ev.LedgerCommitment, "sha256:") || len(ev.LedgerCommitment) != len("sha256:")+64 {
		t.Fatalf("ledger_commitment shape: %s", ev.LedgerCommitment)
	}
	if ev.UsedAt != now.Unix() {
		t.Fatalf("used_at = %d, want %d", ev.UsedAt, now.Unix())
	}
}

func TestSignedCapabilityProjectCheckedBeforeLedgerOrRevocation(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	ledger := NewMemLedger()
	revocationCalled := false
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, ledger).WithProject("p2").
		WithRevocationCheck(func(string) bool { revocationCalled = true; return false })
	_, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n"),
		Op{Action: testAction, ParamsCommitment: testParams}, "n", now)
	if err == nil || !strings.Contains(err.Error(), "project") {
		t.Fatalf("wrong-project token accepted: %v", err)
	}
	if revocationCalled {
		t.Fatal("revocation read preceded project validation")
	}
	if err := ledger.ConsumeNonce(testNonce(t, "n")); err != nil {
		t.Fatalf("wrong-project token consumed nonce: %v", err)
	}
}

func TestV2CapabilityMissingProjectRejectedBeforeLedger(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	payloadB64, _, _ := strings.Cut(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor map[string]any
	if err := json.Unmarshal(payload, &descriptor); err != nil {
		t.Fatal(err)
	}
	delete(descriptor, "project_id")
	payload, err = json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	encoded := b64(payload)
	token = encoded + "." + b64(ed25519.Sign(issuing, []byte(encoded)))
	ledger := NewMemLedger()
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, ledger).WithProject("p1")
	_, err = sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n"),
		Op{Action: testAction, ParamsCommitment: testParams}, "n", now)
	if err == nil || !strings.Contains(err.Error(), "project") {
		t.Fatalf("missing v2 project accepted: %v", err)
	}
	if err := ledger.ConsumeNonce(testNonce(t, "n")); err != nil {
		t.Fatalf("missing-project token consumed nonce: %v", err)
	}
}

func TestRevocationReadFailurePrecedesLedger(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	ledger := NewMemLedger()
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, ledger).WithProject("p1").
		WithRevocationCheckErr(func(string) (bool, error) { return false, errors.New("database unavailable") })
	_, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n"),
		Op{Action: testAction, ParamsCommitment: testParams}, "n", now)
	if !errors.Is(err, ErrRevocationCheck) {
		t.Fatalf("revocation read error = %v", err)
	}
	if err := ledger.ConsumeNonce(testNonce(t, "n")); err != nil {
		t.Fatalf("revocation failure consumed nonce: %v", err)
	}
}

func TestLegacyCapabilityNeedsAuthoritativeProjectLookup(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	req := broker.Request{AgentID: "agent-1", Action: testAction, Resource: testResource, Scope: "read:orders",
		AgentPubKey: b64(agent.Public().(ed25519.PublicKey)), TTL: time.Hour}
	req.AgentSig = b64(ed25519.Sign(agent, req.Challenge()))
	p, err := broker.Prepare(req, testGrantID, func() (int64, error) { return 1, nil }, now, issuing)
	if err != nil {
		t.Fatal(err)
	}
	token := p.Capability
	for _, project := range []string{"p1", "p2"} {
		sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject(project)
		_, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n"),
			Op{Action: testAction, ParamsCommitment: testParams}, "n", now)
		if err == nil || !strings.Contains(err.Error(), "legacy capability project") {
			t.Fatalf("legacy capability used under %s without sealed lookup: %v", project, err)
		}
	}
}

func TestExpiredCredentialRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Minute, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	useSig := signDefault(t, agent, token, testParams, "n")
	// validate two minutes later — past exp
	_, err := sh.ValidateUse(token, useSig, Op{Action: testAction, ParamsCommitment: testParams}, "n", now.Add(2*time.Minute))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired credential should be rejected, got: %v", err)
	}
}

func TestActionSubstitutionRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	// agent honestly signs for the granted action, but the resource is asked to perform a DIFFERENT op
	useSig := signDefault(t, agent, token, testParams, "n")
	_, err := sh.ValidateUse(token, useSig, Op{Action: "db.delete:everything", ParamsCommitment: testParams}, "n", now)
	if err == nil || !strings.Contains(err.Error(), "authorized action") {
		t.Fatalf("action substitution should be rejected, got: %v", err)
	}
}

func TestWrongResourceRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	// a DIFFERENT resource presents the capability (aud mismatch)
	sh := New(issuing.Public().(ed25519.PublicKey), "payments-db", NewMemLedger()).WithProject("p1")
	useSig := signUse(t, agent, token, testGrantID, "payments-db", testAction, testParams, "n")
	_, err := sh.ValidateUse(token, useSig, Op{Action: testAction, ParamsCommitment: testParams}, "n", now)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("wrong-resource use should be rejected, got: %v", err)
	}
}

func TestTokenTheftFailsPoP(t *testing.T) {
	issuing, agent, thief := keyFromByte(1), keyFromByte(2), keyFromByte(9)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	// a thief holding the token but NOT the cnf key signs the PoP with their own key
	stolenSig := signDefault(t, thief, token, testParams, "n")
	_, err := sh.ValidateUse(token, stolenSig, Op{Action: testAction, ParamsCommitment: testParams}, "n", now)
	if err == nil || !strings.Contains(err.Error(), "PoP failed") {
		t.Fatalf("token theft (no cnf key) should fail PoP, got: %v", err)
	}
}

func TestParamsBindingRejectsMismatch(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	// agent signs over one params commitment, but the resource is invoked with DIFFERENT params
	useSig := signDefault(t, agent, token, testParams, "n")
	otherParams := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	_, err := sh.ValidateUse(token, useSig, Op{Action: testAction, ParamsCommitment: otherParams}, "n", now)
	if err == nil || !strings.Contains(err.Error(), "PoP failed") {
		t.Fatalf("params mismatch should fail PoP (challenge binds params), got: %v", err)
	}
}

func TestReplayedUseSigRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	useSig := signDefault(t, agent, token, testParams, "nonce-replay")
	op := Op{Action: testAction, ParamsCommitment: testParams}
	if _, err := sh.ValidateUse(token, useSig, op, "nonce-replay", now); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	// replay the exact (nonce, use_sig) — the nonce ledger rejects it
	_, err := sh.ValidateUse(token, useSig, op, "nonce-replay", now)
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replayed use_sig should be rejected by the nonce ledger, got: %v", err)
	}
}

func TestSingleUseDoubleSpendRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	op := Op{Action: testAction, ParamsCommitment: testParams}
	// first use: fresh nonce
	if _, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n1"), op, "n1", now); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	// second use of the SAME single-use credential with a DIFFERENT fresh nonce + valid PoP — the jti
	// ledger rejects the double-spend (a nonce-only check would have missed this).
	_, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n2"), op, "n2", now)
	if err == nil || !strings.Contains(err.Error(), "double-spend") {
		t.Fatalf("single-use double-spend should be rejected by the jti ledger, got: %v", err)
	}
}

// TestRevokedGrantRejectedBeforeConsume (M5): with a revocation check wired, a use of a revoked grant is
// rejected with ErrRevoked BEFORE anything is consumed — neither the nonce nor the single-use jti is burned — and
// a grant NOT in the revoked set is unaffected.
func TestRevokedGrantRejectedBeforeConsume(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	ledger := NewMemLedger()
	revoked := map[string]bool{testGrantID: true}
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, ledger).WithProject("p1").
		WithRevocationCheck(func(g string) bool { return revoked[g] })
	op := Op{Action: testAction, ParamsCommitment: testParams}
	_, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n1"), op, "n1", now)
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("a revoked grant's use must be rejected with ErrRevoked, got: %v", err)
	}
	if err := ledger.ConsumeNonce(testNonce(t, "n1")); err != nil {
		t.Fatalf("a revoked use must not consume the nonce: %v", err)
	}
	if err := ledger.ConsumeJTI(testJTI(t, testGrantID)); err != nil {
		t.Fatalf("a revoked use must not consume the jti: %v", err)
	}
	// CONTROL: another grant (not revoked) still validates.
	other := mintCap(t, issuing, agent, "grant-ok", testAction, testResource, time.Hour, now)
	if _, err := sh.ValidateUse(other, signUse(t, agent, other, "grant-ok", testResource, testAction, testParams, "n2"), op, "n2", now); err != nil {
		t.Fatalf("a non-revoked grant must still validate: %v", err)
	}
}

// TestDoubleSpendReleasesNonce (adversarial review convergence): a use that consumes the nonce and then fails at
// ConsumeJTI (double-spend) produces no receipt, so it must RELEASE the just-consumed nonce — leaving the
// consume-before-act ledger consistent. Without the release the nonce is permanently burned.
func TestDoubleSpendReleasesNonce(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	ledger := NewMemLedger()
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, ledger).WithProject("p1")
	op := Op{Action: testAction, ParamsCommitment: testParams}
	if _, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n1"), op, "n1", now); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	// the double-spend (fresh nonce n2) fails at ConsumeJTI...
	if _, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n2"), op, "n2", now); err == nil {
		t.Fatal("double-spend should be rejected")
	}
	// ...and n2 must be free again — the failed use released it (else ConsumeNonce would report it consumed).
	if err := ledger.ConsumeNonce(testNonce(t, "n2")); err != nil {
		t.Fatalf("the double-spend's nonce must be released, not burned: %v", err)
	}
}

func TestTamperedTokenRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	// flip a character in the payload — the issuing-key signature no longer verifies
	tampered := "A" + token[1:]
	useSig := signDefault(t, agent, token, testParams, "n")
	_, err := sh.ValidateUse(tampered, useSig, Op{Action: testAction, ParamsCommitment: testParams}, "n", now)
	if err == nil {
		t.Fatalf("a tampered capability token must be rejected")
	}
}

func TestEmptyNonceRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	useSig := signDefault(t, agent, token, testParams, "")
	_, err := sh.ValidateUse(token, useSig, Op{Action: testAction, ParamsCommitment: testParams}, "", now)
	if err == nil || !strings.Contains(err.Error(), "nonce is required") {
		t.Fatalf("empty nonce should be rejected, got: %v", err)
	}
}

func TestNotYetValidRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	useSig := signDefault(t, agent, token, testParams, "n")
	// Within the accepted issuance skew, nbf must still gate use; the skew
	// bounds issuance, it does not widen the capability's validity window.
	_, err := sh.ValidateUse(token, useSig, Op{Action: testAction, ParamsCommitment: testParams}, "n", now.Add(-15*time.Second))
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("a not-yet-valid (nbf in the future) credential should be rejected, got: %v", err)
	}
}

func TestMalformedUseSigRejected(t *testing.T) {
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	op := Op{Action: testAction, ParamsCommitment: testParams}
	// not valid base64url, and a valid-base64-but-wrong-length signature, both fail closed
	for _, bad := range []string{"!!!not base64!!!", b64([]byte("too short"))} {
		if _, err := sh.ValidateUse(token, bad, op, "n", now); err == nil || !strings.Contains(err.Error(), "use_sig") {
			t.Fatalf("malformed use_sig %q should be rejected, got: %v", bad, err)
		}
	}
}

func TestMalformedTokenRejected(t *testing.T) {
	issuing := keyFromByte(1)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	// a token with no "." separator is structurally invalid
	if _, err := sh.ValidateUse("nodothere", b64(make([]byte, ed25519.SignatureSize)), Op{Action: testAction, ParamsCommitment: testParams}, "n", now); err == nil {
		t.Fatalf("a malformed capability token (no separator) must be rejected")
	}
}

func TestFailedValidationDoesNotConsumeCredential(t *testing.T) {
	// Consume-before-act ordering: a FAILED validation (here a PoP failure) must NOT consume the jti
	// or nonce, so a subsequent LEGITIMATE use with the same credential still succeeds. If a failed
	// attempt burned the credential, an attacker could grief a victim by spamming bad PoPs.
	issuing, agent, thief := keyFromByte(1), keyFromByte(2), keyFromByte(9)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	token := defaultCap(t, issuing, agent, time.Hour, now)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	op := Op{Action: testAction, ParamsCommitment: testParams}
	// a failed PoP (thief's key) with nonce "n"
	if _, err := sh.ValidateUse(token, signDefault(t, thief, token, testParams, "n"), op, "n", now); err == nil {
		t.Fatalf("thief PoP should have failed")
	}
	// the legitimate holder uses the SAME jti and SAME nonce "n" — it must still succeed, proving the
	// failed attempt consumed neither.
	if _, err := sh.ValidateUse(token, signDefault(t, agent, token, testParams, "n"), op, "n", now); err != nil {
		t.Fatalf("a failed validation must not consume the credential; legit use failed: %v", err)
	}
}

func TestNonceUniqueAcrossDifferentCredentials(t *testing.T) {
	// The nonce ledger is global: the same nonce reused across DIFFERENT credentials (different jti) is
	// rejected, independent of the per-jti single-use check.
	issuing, agent := keyFromByte(1), keyFromByte(2)
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	sh := New(issuing.Public().(ed25519.PublicKey), testResource, NewMemLedger()).WithProject("p1")
	tokenA := mintCap(t, issuing, agent, "grant-a", testAction, testResource, time.Hour, now)
	tokenB := mintCap(t, issuing, agent, "grant-b", testAction, testResource, time.Hour, now)
	op := Op{Action: testAction, ParamsCommitment: testParams}
	sigA := signUse(t, agent, tokenA, "grant-a", testResource, testAction, testParams, "shared-nonce")
	if _, err := sh.ValidateUse(tokenA, sigA, op, "shared-nonce", now); err != nil {
		t.Fatalf("first use of credential A should succeed: %v", err)
	}
	sigB := signUse(t, agent, tokenB, "grant-b", testResource, testAction, testParams, "shared-nonce")
	_, err := sh.ValidateUse(tokenB, sigB, op, "shared-nonce", now)
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("the same nonce reused on a different credential must be rejected, got: %v", err)
	}
}

func TestLedgerCommitmentGoldenVector(t *testing.T) {
	// Cross-language pinned vectors from the SHARED file (spec/golden-vectors/broker-preimages.json),
	// also loaded by core/tests/adversarial.rs — MUST equal Rust verify::ledger_commitment. If this
	// drifts, the offline verifier's D3 ledger_commitment re-derivation rejects real receipts.
	v, err := goldenvec.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.LedgerCommitment) == 0 {
		t.Fatal("shared vector: ledger_commitment section is empty")
	}
	for _, c := range v.LedgerCommitment {
		if got := ledgerCommitment(c.JTI, c.Nonce, c.UsedAt); got != c.Expect {
			t.Fatalf("ledger_commitment drifted from the shared vector: got %s want %s", got, c.Expect)
		}
	}
}

func TestUsePoPChallengeAndKeyIDGoldenVectors(t *testing.T) {
	// Cross-language pinned vectors from the SHARED file — MUST equal Rust verify::use_pop_challenge +
	// verify::cnf_kid (ADR 0004 D2). The multibyte case checks byte-length prefixing matches Rust. If
	// these drift, the offline verifier's PoP re-verification rejects genuine receipts.
	v, err := goldenvec.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.UsePoPChallenge) == 0 || len(v.CnfKid) == 0 {
		t.Fatal("shared vector: use_pop_challenge / cnf_kid section is empty")
	}
	for _, c := range v.UsePoPChallenge {
		got := hex.EncodeToString(usePoPChallenge(c.GrantID, c.ResourceID, c.Action, c.ParamsCommitment, c.CredentialBinding, c.Nonce))
		if got != c.ExpectHex {
			t.Fatalf("usePoPChallenge case %q drifted from the shared vector: %s", c.Name, got)
		}
	}
	for _, c := range v.CnfKid {
		seed, err := hex.DecodeString(c.SeedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("bad seed_hex %q", c.SeedHex)
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if got := broker.KeyID(pub); got != c.Expect {
			t.Fatalf("KeyID drifted from the shared vector: %s", got)
		}
	}
}
