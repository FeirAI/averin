package scrub

import (
	"strings"
	"testing"
)

func TestRedactsCommonSecrets(t *testing.T) {
	cases := []struct {
		in   string
		kind string
	}{
		{"my key is sk-abcdefghijklmnop1234 ok", "openai"},
		{"Authorization: Bearer abcdefghij1234567890", "bearer"},
		{"AKIAIOSFODNN7EXAMPLE here", "aws-akid"},
		{"ghp_aBcDeFgHiJkLmNoPqRsT12345 token", "github"},
	}
	for _, c := range cases {
		out := Redact(c.in)
		if strings.Contains(out, "sk-abc") || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
			t.Fatalf("secret leaked: %s", out)
		}
		if !strings.Contains(out, "[REDACTED:"+c.kind+"]") {
			t.Fatalf("expected %s marker, got: %s", c.kind, out)
		}
	}
}

func TestKeepsNormalText(t *testing.T) {
	in := "the agent read 12 rows from the orders table"
	if Redact(in) != in {
		t.Fatalf("redacted benign text: %s", Redact(in))
	}
}

func TestHasSecret(t *testing.T) {
	if !HasSecret("token sk-abcdefghijklmnop1234") {
		t.Fatal("should detect secret")
	}
	if HasSecret("nothing to see here") {
		t.Fatal("false positive")
	}
}
