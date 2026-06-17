package core

import (
	"strings"
	"testing"
)

const seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestPubKeyAndBadSeed(t *testing.T) {
	c, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.PubKey(), "ed25519pub:") {
		t.Fatalf("bad pubkey: %s", c.PubKey())
	}
	if _, err := New("nothex"); err == nil {
		t.Fatal("expected error for bad seed")
	}
}

// TestNewSeedIsLowercaseOnly documents the asymmetry behind the F13 startup hardening: the core's seed
// decoder (Rust hashx::hex32) is lowercase-only and REJECTS an uppercase seed, whereas the broker seed
// is decoded by Go's case-insensitive hex.DecodeString. That is precisely why main.go's broker/resource
// disjointness check derives pubkeys (and compares those) rather than the raw seed-hex strings — an
// uppercase broker seed + a lowercase resource seed for the SAME key would otherwise slip a string compare.
func TestNewSeedIsLowercaseOnly(t *testing.T) {
	lower := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if _, err := New(lower); err != nil {
		t.Fatalf("a lowercase seed must be accepted: %v", err)
	}
	if _, err := New(strings.ToUpper(lower)); err == nil {
		t.Fatal("an uppercase seed must be rejected (the core requires lowercase hex)")
	}
}

func TestVerifyBundleRejectsInteriorNUL(t *testing.T) {
	c, _ := New(seed)
	// A C string is NUL-terminated, so an interior 0x00 would truncate the bundle at the FFI boundary
	// and could be reported "ok" over only the prefix before it. The cgo wrapper rejects it fail-closed.
	got := c.VerifyBundle("{\"records\":[]}\x00{\"decoy\":\"x\"}PADDING")
	if !strings.Contains(got, `"ok":false`) {
		t.Fatalf("interior NUL must fail closed: %s", got)
	}
	if !strings.Contains(got, "NUL byte") {
		t.Fatalf("expected a NUL-byte rejection message: %s", got)
	}
	if got2 := c.VerifyBundleWith("{\"records\":[]}\x00junk", "{}"); !strings.Contains(got2, `"ok":false`) {
		t.Fatalf("VerifyBundleWith interior NUL must fail closed: %s", got2)
	}
}

func TestSealRecordThroughFFI(t *testing.T) {
	c, _ := New(seed)
	body := `{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2","action":"x"}`
	sealed, err := c.SealRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sealed, `"content_hash":"sha256:`) || !strings.Contains(sealed, `"sig":"ed25519:`) {
		t.Fatalf("not sealed: %s", sealed)
	}
	if _, err := c.SealRecord("{not json"); err == nil {
		t.Fatal("expected seal error on bad body")
	}
}

func TestCanonicalize(t *testing.T) {
	c, _ := New(seed)
	if got := c.RcpCanonicalize(`{"b":1,"a":2}`); got != `{"a":2,"b":1}` {
		t.Fatalf("canon: %s", got)
	}
	if got := c.RcpCanonicalize(`{"a":1.5}`); !strings.HasPrefix(got, "ERROR:") {
		t.Fatalf("expected float rejection: %s", got)
	}
}

func TestRcpEvidenceHash(t *testing.T) {
	c, _ := New(seed)
	// key order doesn't matter (canonical) — the verifier re-derives the same hash regardless.
	a, err := c.RcpEvidenceHash(`{"b":1,"a":2}`)
	if err != nil {
		t.Fatalf("evidence hash: %v", err)
	}
	b, err := c.RcpEvidenceHash(`{"a":2,"b":1}`)
	if err != nil {
		t.Fatalf("evidence hash: %v", err)
	}
	if a != b {
		t.Fatalf("evidence hash must be key-order independent: %s != %s", a, b)
	}
	if !strings.HasPrefix(a, "sha256:") || len(a) != len("sha256:")+64 {
		t.Fatalf("evidence hash shape: %s", a)
	}
	// a parse error fails closed (surfaced as an error), never a silent empty hash.
	if _, err := c.RcpEvidenceHash(`{"a":1.5}`); err == nil {
		t.Fatalf("expected float to be a fail-closed error")
	}
}

func TestCommitmentRoundTripThroughFFI(t *testing.T) {
	c, _ := New(seed)

	nonce, err := c.RandomNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if len(nonce) != 64 {
		t.Fatalf("nonce should be 64 hex chars, got %d: %q", len(nonce), nonce)
	}

	value := []byte("SELECT balance FROM accounts WHERE id=42")
	commitment, err := c.Commit("input", value, nonce)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !strings.HasPrefix(commitment, "sha256:") {
		t.Fatalf("commitment should be sha256:..., got %q", commitment)
	}

	// The disclosed (value, nonce) opens the commitment...
	ok, err := c.VerifyCommitment(commitment, "input", value, nonce)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v; want true", ok, err)
	}
	// ...but a different value, domain, or nonce does not (binding holds).
	if ok, _ := c.VerifyCommitment(commitment, "input", []byte("tampered"), nonce); ok {
		t.Fatal("wrong value verified true")
	}
	if ok, _ := c.VerifyCommitment(commitment, "output", value, nonce); ok {
		t.Fatal("wrong domain verified true")
	}
	other, _ := c.RandomNonce()
	if ok, _ := c.VerifyCommitment(commitment, "input", value, other); ok {
		t.Fatal("wrong nonce verified true")
	}
}

func TestSignEvidence(t *testing.T) {
	c, _ := New(seed)
	eh := "sha256:" + strings.Repeat("ab", 32) // a well-formed sha256:<64 lowercase hex>
	sig, err := c.SignEvidence("gateway_enforced", "proj-1", "rec-1", eh)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.HasPrefix(sig, "ed25519:") {
		t.Fatalf("evidence sig should be ed25519:..., got %q", sig)
	}
	// malformed evidence_hash, empty record_id, and empty project_id are rejected (verify_authority would too)
	if _, err := c.SignEvidence("gateway_enforced", "proj-1", "rec-1", "not-a-hash"); err == nil {
		t.Fatal("expected error for malformed evidence_hash")
	}
	if _, err := c.SignEvidence("gateway_enforced", "proj-1", "", eh); err == nil {
		t.Fatal("expected error for empty record_id")
	}
	if _, err := c.SignEvidence("gateway_enforced", "", "rec-1", eh); err == nil {
		t.Fatal("expected error for empty project_id")
	}
}

func TestCommitRejectsBadInput(t *testing.T) {
	c, _ := New(seed)
	nonce, _ := c.RandomNonce()
	if _, err := c.Commit("bogus-domain", []byte("x"), nonce); err == nil {
		t.Fatal("expected error for bad domain")
	}
	if _, err := c.Commit("input", []byte("x"), "short-nonce"); err == nil {
		t.Fatal("expected error for bad nonce")
	}
}
