package taxonomy_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/taxonomy"
)

func testKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{fill}), 32)))
}

func pubOf(k ed25519.PrivateKey) string {
	return "ed25519pub:" + base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

func signed(t *testing.T, k ed25519.PrivateKey, version int64) (hc *core.Core, js, digest string) {
	t.Helper()
	hc, err := core.New(strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	js, digest, _, err = taxonomy.Sign(hc, k, version, 0, 4102444800,
		[]taxonomy.Entry{{ResourceID: "r", Action: "a.one"}, {ResourceID: "r", Action: "a.two"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return hc, js, digest
}

func TestVerifyAcceptsValidArtifact(t *testing.T) {
	k := testKey('t')
	c, js, digest := signed(t, k, 8)
	if err := taxonomy.Verify(c, []byte(js), []string{pubOf(k)}, digest, 8); err != nil {
		t.Fatalf("valid artifact refused: %v", err)
	}
}

func TestVerifyRefusesWrongPins(t *testing.T) {
	k := testKey('t')
	c, js, digest := signed(t, k, 8)
	bad := "sha256:" + strings.Repeat("0", 64)
	cases := map[string]error{
		"digest":  taxonomy.Verify(c, []byte(js), []string{pubOf(k)}, bad, 8),
		"version": taxonomy.Verify(c, []byte(js), []string{pubOf(k)}, digest, 9),
		"pubkey":  taxonomy.Verify(c, []byte(js), []string{pubOf(testKey('u'))}, digest, 8),
		"nokeys":  taxonomy.Verify(c, []byte(js), nil, digest, 8),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("wrong %s pin accepted", name)
		}
	}
}

func TestVerifyRefusesTamperedActionList(t *testing.T) {
	k := testKey('t')
	c, js, digest := signed(t, k, 8)
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	acts := m["single_operation_actions"].([]any)
	m["single_operation_actions"] = acts[:1] // drop one action, keep the signature
	b, _ := json.Marshal(m)
	if err := taxonomy.Verify(c, b, []string{pubOf(k)}, digest, 8); err == nil {
		t.Fatal("artifact with a removed action accepted under the original digest pin")
	}
}

func TestVerifyRefusesUnsignedEditWithRepinnedDigest(t *testing.T) {
	// An attacker who adds an action AND re-pins the new digest still has no valid signature.
	k := testKey('t')
	c, js, _ := signed(t, k, 8)
	var m map[string]any
	_ = json.Unmarshal([]byte(js), &m)
	m["single_operation_actions"] = append(m["single_operation_actions"].([]any),
		map[string]any{"action": "change_payout_details", "resource_id": "r"})
	body := map[string]any{}
	for k2, v := range m {
		if k2 != "sig" {
			body[k2] = v
		}
	}
	bb, _ := json.Marshal(body)
	newDigest, err := c.RcpEvidenceHash(string(bb))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m)
	if err := taxonomy.Verify(c, b, []string{pubOf(k)}, newDigest, 8); err == nil {
		t.Fatal("unsigned edit with a matching re-pinned digest accepted")
	}
}

func TestVerifyRefusesMissingSigAndWrongKind(t *testing.T) {
	k := testKey('t')
	c, js, digest := signed(t, k, 8)
	var m map[string]any
	_ = json.Unmarshal([]byte(js), &m)
	delete(m, "sig")
	b, _ := json.Marshal(m)
	if err := taxonomy.Verify(c, b, []string{pubOf(k)}, digest, 8); err == nil {
		t.Fatal("unsigned artifact accepted")
	}
	if err := taxonomy.Verify(c, []byte("not json"), []string{pubOf(k)}, digest, 8); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestVerifyErrorNeverEchoesKeyMaterial(t *testing.T) {
	k := testKey('t')
	c, js, digest := signed(t, k, 8)
	other := testKey('u')
	err := taxonomy.Verify(c, []byte(js), []string{pubOf(other)}, digest, 8)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), pubOf(other)[len("ed25519pub:"):]) || strings.Contains(err.Error(), pubOf(k)[len("ed25519pub:"):]) {
		t.Fatalf("error echoes a public key: %v", err)
	}
}

// rawVariants returns tampered raw bytes a Go json.Unmarshal+re-marshal would normalize away but the
// Rust RCP parser (the real verifier) rejects.
func TestVerifyRefusesWhatTheRcpParserRefuses(t *testing.T) {
	k := testKey('t')
	c, js, digest := signed(t, k, 8)
	evil := `"single_operation_actions":[{"action":"evil.drop","resource_id":"r"}],`
	cases := map[string]string{
		"evil-first duplicate key": strings.Replace(js, `{`, `{`+evil, 1),
		"duplicate kind":           strings.Replace(js, `{`, `{"kind":"operation_taxonomy",`, 1),
		"trailing bracket":         js + "]",
		"trailing brace":           js + "}",
		"trailing value":           js + ` {}`,
		"lone surrogate":           strings.Replace(js, `"r"`, `"\ud800"`, 1),
		"float":                    strings.Replace(js, `"version":8`, `"version":8.0`, 1),
	}
	for name, art := range cases {
		if art == js {
			t.Fatalf("%s: test did not alter the artifact", name)
		}
		if err := taxonomy.Verify(c, []byte(art), []string{pubOf(k)}, digest, 8); err == nil {
			t.Errorf("%s: tampered artifact accepted", name)
		}
	}
	if err := taxonomy.Verify(c, append([]byte(js), 0), []string{pubOf(k)}, digest, 8); err == nil {
		t.Error("NUL-suffixed artifact accepted")
	}
	if err := taxonomy.Verify(c, []byte(strings.Replace(js, `"r"`, "\"\xff\"", 1)), []string{pubOf(k)}, digest, 8); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

func TestVerifyRefusesMalformedStructure(t *testing.T) {
	k := testKey('t')
	c, js, _ := signed(t, k, 8)
	mut := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal([]byte(js), &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := map[string]func(m map[string]any){
		"entry not object":     func(m map[string]any) { m["single_operation_actions"] = []any{"x"} },
		"entry missing action": func(m map[string]any) { m["single_operation_actions"] = []any{map[string]any{"resource_id": "r"}} },
		"escalating bad": func(m map[string]any) {
			m["escalating_actions"] = []any{map[string]any{"action": 1, "resource_id": "r"}}
		},
		"effective_from str":  func(m map[string]any) { m["effective_from"] = "0" },
		"effective_until nil": func(m map[string]any) { delete(m, "effective_until") },
	}
	for name, f := range cases {
		b := mut(f)
		// Re-sign-free: pins are irrelevant, the structural check must trip before or regardless of them.
		var mm map[string]any
		_ = json.Unmarshal(b, &mm)
		delete(mm, "sig")
		bb, _ := json.Marshal(mm)
		d, err := c.RcpEvidenceHash(string(bb))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = taxonomy.Verify(c, b, []string{pubOf(k)}, d, 8)
		if err == nil || !strings.Contains(err.Error(), "structure") {
			t.Errorf("%s: want a structure error, got %v", name, err)
		}
	}
}
