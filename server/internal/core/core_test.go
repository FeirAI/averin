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
