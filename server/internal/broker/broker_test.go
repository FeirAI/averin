package broker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// deterministic keys for reproducible tests.
func issuingKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
}
func agentKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signed builds a request and proves possession of the cnf key (AgentSig over the challenge).
func signed(r Request, ak ed25519.PrivateKey) Request {
	r.AgentPubKey = b64(ak.Public().(ed25519.PublicKey))
	r.AgentSig = b64(ed25519.Sign(ak, r.Challenge()))
	return r
}

func validRequest() Request {
	return signed(Request{
		AgentID:   "agent-7",
		Action:    "db.query:orders-ro",
		Resource:  "orders-db",
		Scope:     "read:orders",
		Principal: "policy/orders",
		TTL:       60 * time.Second,
	}, agentKey())
}

func TestClassifyScope(t *testing.T) {
	if c, err := ClassifyScope("read:orders", ""); err != nil || c != ScopeSingleOperation {
		t.Fatalf("read:orders => %v, %v; want single_operation", c, err)
	}
	for _, bad := range []string{"read:*", "iam:PassRole", "sts:AssumeRole", "admin:reset", "x:delegate", "credentials:create"} {
		if _, err := ClassifyScope(bad, ScopeSingleOperation); err == nil {
			t.Fatalf("scope %q should be forbidden for single_operation", bad)
		}
	}
	// benign read-only scopes whose NAME contains a sensitive word are NOT flagged (delimiter-anchored)
	for _, ok := range []string{"read:admin-dashboard", "read:webhook-logs", "read:credentials-expiry", "read:workflow-templates"} {
		if _, err := ClassifyScope(ok, ScopeSingleOperation); err != nil {
			t.Fatalf("benign scope %q should be allowed: %v", ok, err)
		}
	}
	// session/batch are explicit Tier-A coarsenings, allowed even for a broad scope
	if c, err := ClassifyScope("read:*", ScopeSession); err != nil || c != ScopeSession {
		t.Fatalf("session_grant should be allowed: %v, %v", c, err)
	}
	if _, err := ClassifyScope("x", "weird_class"); err == nil {
		t.Fatal("unknown scope_class should error")
	}
}

func TestRequestValidate(t *testing.T) {
	if err := validRequest().Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	// missing required fields, bad key, over-long TTL -> error
	for name, mut := range map[string]func(*Request){
		"no agent":     func(r *Request) { r.AgentID = "" },
		"no action":    func(r *Request) { r.Action = "" },
		"no resource":  func(r *Request) { r.Resource = "" },
		"no scope":     func(r *Request) { r.Scope = "" },
		"zero ttl":     func(r *Request) { r.TTL = 0 },
		"ttl too long": func(r *Request) { r.TTL = 2 * time.Hour },
		"bad pubkey":   func(r *Request) { r.AgentPubKey = "not-a-key" },
		"short pubkey": func(r *Request) { r.AgentPubKey = b64([]byte("too-short")) },
		"tampered sig": func(r *Request) { r.AgentSig = b64(bytes.Repeat([]byte{0}, ed25519.SignatureSize)) },
		"missing sig":  func(r *Request) { r.AgentSig = "" },
	} {
		r := validRequest()
		mut(&r)
		if err := r.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func TestProofOfPossessionBlocksVictimKeyBinding(t *testing.T) {
	// An attacker tries to bind a VICTIM's public key (which is public) but signs with its OWN key.
	victim := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	attacker := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	r := Request{AgentID: "attacker", Action: "a", Resource: "r", Scope: "read:x", TTL: time.Minute}
	r.AgentPubKey = b64(victim.Public().(ed25519.PublicKey)) // victim's pubkey
	r.AgentSig = b64(ed25519.Sign(attacker, r.Challenge()))  // attacker's sig
	if err := r.Validate(); err == nil {
		t.Fatal("binding a key the requester does not control must fail proof-of-possession")
	}
}

func TestPrepareDeterministicAndBound(t *testing.T) {
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	p, err := Prepare(validRequest(), "grant-abc", func() (int64, error) { return 1, nil }, now, issuingKey())
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if p.Descriptor["jti"] != "grant-abc" {
		t.Fatalf("jti = %v, want grant-abc", p.Descriptor["jti"])
	}
	if p.Descriptor["cnf"] != b64(agentKey().Public().(ed25519.PublicKey)) {
		t.Fatalf("cnf not bound to the agent pubkey")
	}
	if p.Descriptor["act"] != "db.query:orders-ro" {
		t.Fatalf("descriptor must bind the action, got %v", p.Descriptor["act"])
	}
	if p.Descriptor["single_use"] != true {
		t.Fatalf("a single_operation grant must be single_use")
	}
	// kid is derived from the issuing key, not caller-supplied
	if p.Descriptor["kid"] != KeyID(issuingKey().Public().(ed25519.PublicKey)) {
		t.Fatalf("kid not derived from the issuing key: %v", p.Descriptor["kid"])
	}
	if p.Descriptor["exp"].(int64)-p.Descriptor["iat"].(int64) != 60 {
		t.Fatalf("exp-iat = %v, want 60", p.Descriptor["exp"].(int64)-p.Descriptor["iat"].(int64))
	}
	// the canonical grant_evidence (ADR 0003) binds the match fields + the credential binding
	if p.Evidence["kind"] != "grant" {
		t.Fatalf("grant_evidence.kind must be \"grant\", got %v", p.Evidence["kind"])
	}
	if p.Evidence["action"] != "db.query:orders-ro" {
		t.Fatalf("evidence must bind the action, got %v", p.Evidence["action"])
	}
	if p.Evidence["resource_id"] != validRequest().Resource {
		t.Fatalf("evidence must carry resource_id, got %v", p.Evidence["resource_id"])
	}
	if p.Evidence["cnf_kid"] != KeyID(agentKey().Public().(ed25519.PublicKey)) {
		t.Fatalf("evidence cnf_kid not bound to the agent key, got %v", p.Evidence["cnf_kid"])
	}
	// times are unix-second integers (RCP integers), not millis strings
	if p.Evidence["exp"].(int64)-p.Evidence["issued_at"].(int64) != 60 {
		t.Fatalf("exp-issued_at = %v, want 60", p.Evidence["exp"].(int64)-p.Evidence["issued_at"].(int64))
	}
	if p.Evidence["credential_binding"] != p.CredentialBinding {
		t.Fatalf("evidence does not commit the credential binding")
	}
	// D6: the gapless grant-transparency sequence is bound into the signed grant_evidence.
	if p.Evidence["broker_seq"] != int64(1) {
		t.Fatalf("evidence must carry broker_seq=1 (D6), got %v", p.Evidence["broker_seq"])
	}
	if !strings.HasPrefix(p.CredentialBinding, "sha256:") {
		t.Fatalf("credential binding not sha256")
	}
	// deterministic: identical inputs -> identical artifacts. (evidence_hash is derived from
	// Evidence by the cgo-capable api layer via RCP; Evidence itself being deterministic suffices.)
	p2, _ := Prepare(validRequest(), "grant-abc", func() (int64, error) { return 1, nil }, now, issuingKey())
	if p.CredentialBinding != p2.CredentialBinding || p.Capability != p2.Capability {
		t.Fatalf("Prepare is not deterministic")
	}
}

func TestPrepareDoesNotAllocateSeqOnValidationFailure(t *testing.T) {
	// A rejected grant must NOT consume a broker_seq — else an unauthenticated caller passing only the
	// minimal gate could spam validation failures and manufacture false-suppression gaps (ADR 0004 D6).
	// The allocator callback must be invoked ONLY after the request fully validates.
	allocCalled := false
	alloc := func() (int64, error) { allocCalled = true; return 1, nil }

	// forbidden scope for single_operation -> ClassifyScope rejects (after req.Validate passes).
	r := validRequest()
	r.Scope = "iam:PassRole"
	r = signed(r, agentKey()) // re-sign: the challenge binds the scope
	if _, err := Prepare(r, "g", alloc, time.Now().UTC(), issuingKey()); err == nil {
		t.Fatal("a forbidden scope must be rejected")
	}
	if allocCalled {
		t.Fatal("broker_seq must NOT be allocated for a forbidden-scope rejection (false-suppression gap)")
	}

	// tampered signature -> req.Validate fails before any allocation.
	bad := validRequest()
	bad.AgentSig = b64(bytes.Repeat([]byte{0}, ed25519.SignatureSize))
	allocCalled = false
	if _, err := Prepare(bad, "g", alloc, time.Now().UTC(), issuingKey()); err == nil {
		t.Fatal("a tampered PoP signature must be rejected")
	}
	if allocCalled {
		t.Fatal("broker_seq must NOT be allocated when the PoP signature is invalid")
	}
}

func TestSessionGrantIsNotSingleUse(t *testing.T) {
	r := validRequest()
	r.Scope = "read:*"
	r.ScopeClass = ScopeSession
	r = signed(r, agentKey()) // re-sign (scope changed -> challenge changed)
	p, err := Prepare(r, "g", func() (int64, error) { return 1, nil }, time.Now().UTC(), issuingKey())
	if err != nil {
		t.Fatalf("prepare session grant: %v", err)
	}
	if p.ScopeClass != ScopeSession {
		t.Fatalf("scope_class = %v, want session_grant", p.ScopeClass)
	}
	if p.Descriptor["single_use"] != false {
		t.Fatalf("a session/batch coarsening must NOT assert single_use")
	}
}

func TestCapabilityRoundTripAndTamper(t *testing.T) {
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	p, _ := Prepare(validRequest(), "grant-abc", func() (int64, error) { return 1, nil }, now, issuingKey())
	pub := issuingKey().Public().(ed25519.PublicKey)

	claims, err := VerifyCapability(p.Capability, pub)
	if err != nil {
		t.Fatalf("capability should verify under the issuing key: %v", err)
	}
	if claims.Jti != "grant-abc" || claims.Act != "db.query:orders-ro" {
		t.Fatalf("verified claims = %+v", claims)
	}
	if claims.Exp <= claims.Iat { // typed int64, no float64 footgun
		t.Fatalf("exp must be after iat")
	}
	// the capability payload equals the committed descriptor bytes (binding is exact)
	enc, _, _ := strings.Cut(p.Capability, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(enc)
	if !bytes.Equal(payload, p.DescriptorBytes) {
		t.Fatalf("capability payload != committed descriptor bytes")
	}
	// tampered token or wrong key fails
	if _, err := VerifyCapability(p.Capability+"x", pub); err == nil {
		t.Fatal("tampered capability must not verify")
	}
	wrongPub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := VerifyCapability(p.Capability, wrongPub); err == nil {
		t.Fatal("capability must not verify under a different issuing key")
	}
	if _, err := VerifyCapability("nodot", pub); err == nil {
		t.Fatal("malformed token must error")
	}
}

func TestForbiddenScopeBlocksPrepare(t *testing.T) {
	r := validRequest()
	r.Scope = "iam:*"
	r = signed(r, agentKey())
	if _, err := Prepare(r, "g", func() (int64, error) { return 1, nil }, time.Now().UTC(), issuingKey()); err == nil {
		t.Fatal("Prepare must reject a forbidden single_operation scope")
	}
}

func TestPrepareCanonicalizesAgentPubkey(t *testing.T) {
	// Go's base64 decode is non-strict (accepts non-canonical), but the Rust offline verifier rejects
	// non-canonical base64url (ADR 0004 D2). Prepare must canonicalize the descriptor cnf so a genuine
	// receipt doesn't false-fail PoP re-verification.
	ak := agentKey()
	pub := ak.Public().(ed25519.PublicKey)
	canon := base64.RawURLEncoding.EncodeToString(pub)
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	idx := strings.IndexByte(alpha, canon[len(canon)-1])
	nonCanon := canon[:len(canon)-1] + string(alpha[idx^1]) // same 32 bytes, non-canonical padding bit
	if nonCanon == canon {
		t.Fatal("failed to construct a non-canonical encoding")
	}
	r := Request{AgentID: "a", Action: "x", Resource: "r", Scope: "read:x", AgentPubKey: nonCanon, TTL: time.Minute}
	r.AgentSig = b64(ed25519.Sign(ak, r.Challenge()))
	p, err := Prepare(r, "g", func() (int64, error) { return 1, nil }, time.Now().UTC(), issuingKey())
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if p.Descriptor["cnf"] != canon {
		t.Fatalf("descriptor cnf not canonicalized: got %v, want %s", p.Descriptor["cnf"], canon)
	}
	// and the grant_evidence cnf_kid is derived from the canonical key bytes (stable either way)
	if p.Evidence["cnf_kid"] != KeyID(pub) {
		t.Fatalf("cnf_kid drift: %v", p.Evidence["cnf_kid"])
	}
}
