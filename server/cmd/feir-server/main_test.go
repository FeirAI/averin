package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feir-dev/feir/server/internal/core"
)

// TestRevocationPubKeyEncodingMatchesCore pins the cross-language format contract the R2 guard relies
// on: the revocation block compares a MANUALLY-built rvPubKey ("ed25519pub:"+RawURLEncoding(pub))
// against core.PubKey() (derived by the Rust core). If those encodings ever diverged, the comparison
// would silently always be unequal — a DEAD guard. This asserts they are byte-identical for a known
// seed, independent of the cgo binary-build test.
func TestRevocationPubKeyEncodingMatchesCore(t *testing.T) {
	seed := strings.Repeat("ab", 32) // 64 hex chars = a 32-byte Ed25519 seed
	raw, err := hex.DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	manual := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(
		ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey))
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	if c.PubKey() != manual {
		t.Fatalf("manual rvPubKey encoding must equal core.PubKey(): %q vs %q", manual, c.PubKey())
	}
}

// TestSecretEnvOrFile_HappyPaths covers the non-fatal resolutions of the
// env-or-file seed reader: inline-only, file-only (trimmed), and neither-set.
func TestSecretEnvOrFile_HappyPaths(t *testing.T) {
	const name = "FEIR_TEST_SEED_HAPPY"

	// neither set → empty (the caller decides whether empty is fatal).
	t.Setenv(name, "")
	t.Setenv(name+"_FILE", "")
	if got := secretEnvOrFile(name); got != "" {
		t.Errorf("neither set: got %q want empty", got)
	}

	// inline only → returned verbatim.
	t.Setenv(name, "deadbeef")
	if got := secretEnvOrFile(name); got != "deadbeef" {
		t.Errorf("inline only: got %q want %q", got, "deadbeef")
	}

	// file only → contents trimmed (mounted secrets carry a trailing newline).
	t.Setenv(name, "")
	path := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(path, []byte("  cafebabe\n"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	t.Setenv(name+"_FILE", path)
	if got := secretEnvOrFile(name); got != "cafebabe" {
		t.Errorf("file only: got %q want %q", got, "cafebabe")
	}
}

// TestSecretEnvOrFile_Fatal proves the fail-loud paths (both forms set; a _FILE path
// that does not exist) call log.Fatal. Each runs in a re-exec'd child of this test
// binary and asserts a non-zero exit (log.Fatal => os.Exit(1)).
func TestSecretEnvOrFile_Fatal(t *testing.T) {
	const name = "FEIR_TEST_SEED_FATAL"

	// The child branch: scenario selected by FEIR_TEST_FATAL_CASE.
	switch os.Getenv("FEIR_TEST_FATAL_CASE") {
	case "both":
		_ = secretEnvOrFile(name) // both name and name_FILE set by the parent => fatal
		return
	case "missing":
		_ = secretEnvOrFile(name) // name_FILE points at a non-existent path => fatal
		return
	}

	cases := []struct {
		scenario string
		env      []string
	}{
		{"both", []string{name + "=inline", name + "_FILE=/some/path"}},
		{"missing", []string{name + "_FILE=/nonexistent/feir/seed/path"}},
	}
	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestSecretEnvOrFile_Fatal")
			cmd.Env = append(os.Environ(), "FEIR_TEST_FATAL_CASE="+tc.scenario)
			cmd.Env = append(cmd.Env, tc.env...)
			err := cmd.Run()
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.Success() {
				t.Fatalf("scenario %q: expected non-zero exit from log.Fatal, got %v", tc.scenario, err)
			}
		})
	}
}

// TestRevocationR2Disjoint_UnderFileMountedSeeds proves the R2 role-separation guard still FATALS when
// the broker/resource seed it must be disjoint from is supplied via its <NAME>_FILE form. The pre-#40
// guard compared FEIR_REVOCATION_SEED against raw os.Getenv("FEIR_BROKER_ISSUING_SEED") /
// os.Getenv("FEIR_RESOURCE_SEED"); once those seeds moved to secretEnvOrFile, a file-mounted seed read
// as "" and the disjointness fatal was silently skipped. This builds + runs the real binary so it
// exercises main()'s actual seed resolution + the derived-pubkey comparison. (It would PASS-incorrectly
// — no fatal — on the pre-fix code.)
func TestRevocationR2Disjoint_UnderFileMountedSeeds(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the cgo binary; skipped under -short")
	}
	// Distinct valid 32-byte (64-hex) Ed25519 seeds.
	seedSigning := strings.Repeat("a1", 32)
	seedShared := strings.Repeat("b2", 32) // mounted via _FILE AND set inline as the revocation seed → collision
	seedBroker := strings.Repeat("c3", 32)

	dir := t.TempDir()
	bin := filepath.Join(dir, "feir-server-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("could not build feir-server (cgo toolchain unavailable?): %v\n%s", err, out)
	}
	sharedFile := filepath.Join(dir, "shared.seed")
	if err := os.WriteFile(sharedFile, []byte(seedShared+"\n"), 0o600); err != nil {
		t.Fatalf("write shared seed: %v", err)
	}

	cases := []struct {
		name string
		env  []string
	}{
		{
			// broker seed file-mounted == inline revocation seed → R2 fatal.
			name: "broker-via-file",
			env: []string{
				"FEIR_SIGNING_SEED=" + seedSigning,
				"FEIR_BROKER_ISSUING_SEED_FILE=" + sharedFile,
				"FEIR_REVOCATION_SEED=" + seedShared,
			},
		},
		{
			// resource seed file-mounted == inline revocation seed → R2 fatal (broker enabled separately).
			name: "resource-via-file",
			env: []string{
				"FEIR_SIGNING_SEED=" + seedSigning,
				"FEIR_BROKER_ISSUING_SEED=" + seedBroker,
				"FEIR_RESOURCE_SEED_FILE=" + sharedFile,
				"FEIR_RESOURCE_ID=res-test",
				"FEIR_REVOCATION_SEED=" + seedShared,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bin)
			// Minimal env: avoid inheriting any real seeds; bind nowhere (it fatals before listening).
			cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, tc.env...)
			out, err := cmd.CombinedOutput()
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.Success() {
				t.Fatalf("%s: expected the R2 guard to fatal (non-zero exit), got err=%v\noutput:\n%s", tc.name, err, out)
			}
			if !strings.Contains(string(out), "R2 role separation") {
				t.Fatalf("%s: exited non-zero but not via the R2 guard; output:\n%s", tc.name, out)
			}
		})
	}
}
