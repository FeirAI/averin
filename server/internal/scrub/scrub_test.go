package scrub

import (
	"strings"
	"testing"
)

func TestRedactsCommonSecrets(t *testing.T) {
	cases := []struct {
		secret string
		kind   string
	}{
		{"sk-abcdefghijklmnop1234", "openai"},
		{"sk-ant-abcdefghijklmnop1234", "anthropic"},
		{"AKIAIOSFODNN7EXAMPLE", "aws-akid"},
		{"ghp_aBcDeFgHiJkLmNoPqRsT12345", "github"},
		{"github_pat_aBcDeFgHiJkLmNoPqRsT12345", "github"},
		{"AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", "google"},
		{"sk_live_abcdefghijklmnop1234", "stripe"},
		{"hf_abcdefghijklmnop1234", "huggingface"},
		{"eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NQ.SflKxwRJSMeKKF2QT4", "jwt"},
		{"Bearer abcdefghij1234567890", "bearer"},
	}
	for _, c := range cases {
		in := "context " + c.secret + " more"
		out := Redact(in)
		if strings.Contains(out, c.secret) {
			t.Fatalf("secret %q leaked: %s", c.secret, out)
		}
		if !strings.Contains(out, "[REDACTED:"+c.kind+"]") {
			t.Fatalf("expected %s marker for %q, got: %s", c.kind, c.secret, out)
		}
	}
}

func TestRedactsPemAndGenericKeyValue(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqh\nkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----"
	if out := Redact(pem); strings.Contains(out, "MIIEvQ") {
		t.Fatalf("PEM body leaked: %s", out)
	}
	for _, kv := range []string{`"api_key":"sup3rsecretvalue123"`, `password = hunter2hunter2`, `access_token: abcdef123456`} {
		out := Redact(kv)
		if strings.Contains(out, "sup3rsecret") || strings.Contains(out, "hunter2hunter2") || strings.Contains(out, "abcdef123456") {
			t.Fatalf("kv secret leaked: %s", out)
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
