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
