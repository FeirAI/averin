package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSeedHexFromOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taxonomy-seed")
	want := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadSeedHex("", path)
	if err != nil {
		t.Fatalf("loadSeedHex: %v", err)
	}
	if got != want {
		t.Fatalf("seed mismatch")
	}
}

func TestLoadSeedHexRejectsGroupReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taxonomy-seed")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSeedHex("", path); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("want owner-only refusal, got %v", err)
	}
}

func TestLoadSeedHexRequiresExactlyOneSource(t *testing.T) {
	if _, err := loadSeedHex("", ""); err == nil {
		t.Fatal("want missing-source refusal")
	}
	if _, err := loadSeedHex(strings.Repeat("a", 64), "seed-file"); err == nil {
		t.Fatal("want conflicting-source refusal")
	}
}

func writeTestArtifact(t *testing.T) (file, pub, digest string) {
	t.Helper()
	dir := t.TempDir()
	seed := strings.Repeat("ab", 32)
	kf := filepath.Join(dir, "seed")
	if err := os.WriteFile(kf, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(dir, "tax.json")
	var out, errb strings.Builder
	code := run([]string{"--key-file", kf, "--version", "8", "--from", "0", "--until", "4102444800", "--out", file,
		"--single", "r=a.one", "--single", "r=a.two"}, &out, &errb)
	if code != 0 {
		t.Fatalf("sign failed: %s", errb.String())
	}
	for _, l := range strings.Split(errb.String(), "\n") {
		if strings.Contains(l, "taxonomy_digest") {
			digest = strings.TrimSpace(strings.SplitN(l, "=", 2)[1])
		}
		if strings.Contains(l, "taxonomy_keys") {
			pub = strings.Trim(strings.TrimSpace(strings.SplitN(l, "=", 2)[1]), `[]"`)
		}
	}
	if digest == "" || pub == "" {
		t.Fatalf("could not read pins from %q", errb.String())
	}
	return file, pub, digest
}

func TestVerifyModeAcceptsValidArtifact(t *testing.T) {
	f, pub, digest := writeTestArtifact(t)
	var out, errb strings.Builder
	if code := run([]string{"--verify", "--file", f, "--pubkey", pub, "--digest", digest, "--version", "8"}, &out, &errb); code != 0 {
		t.Fatalf("want 0, got %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "taxonomy verify: OK") {
		t.Fatalf("no OK line: %q", out.String())
	}
	if strings.Contains(out.String()+errb.String(), strings.TrimPrefix(pub, "ed25519pub:")) {
		t.Fatal("verify printed key material")
	}
}

func TestVerifyModeRefusesMismatches(t *testing.T) {
	f, pub, digest := writeTestArtifact(t)
	raw, _ := os.ReadFile(f)
	tampered := filepath.Join(t.TempDir(), "t.json")
	_ = os.WriteFile(tampered, []byte(strings.Replace(string(raw), "a.two", "a.evil", 1)), 0o644)
	cases := map[string][]string{
		"wrong digest":  {"--file", f, "--pubkey", pub, "--digest", "sha256:" + strings.Repeat("0", 64), "--version", "8"},
		"wrong version": {"--file", f, "--pubkey", pub, "--digest", digest, "--version", "9"},
		"wrong pubkey":  {"--file", f, "--pubkey", "ed25519pub:" + strings.Repeat("A", 43), "--digest", digest, "--version", "8"},
		"tampered":      {"--file", tampered, "--pubkey", pub, "--digest", digest, "--version", "8"},
		"missing file":  {"--file", filepath.Join(t.TempDir(), "nope"), "--pubkey", pub, "--digest", digest, "--version", "8"},
		"no pubkey":     {"--file", f, "--digest", digest, "--version", "8"},
		"no digest":     {"--file", f, "--pubkey", pub, "--version", "8"},
		"no version":    {"--file", f, "--pubkey", pub, "--digest", digest},
	}
	for name, args := range cases {
		var out, errb strings.Builder
		code := run(append([]string{"--verify"}, args...), &out, &errb)
		if code == 0 {
			t.Errorf("%s: accepted", name)
		}
		if strings.Contains(out.String(), "taxonomy verify: OK") {
			t.Errorf("%s: printed OK", name)
		}
		if strings.Contains(out.String()+errb.String(), strings.TrimPrefix(pub, "ed25519pub:")) {
			t.Errorf("%s: printed key material", name)
		}
	}
}
