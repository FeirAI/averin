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

	// whitespace-only inline is returned RAW (NOT silently trimmed to "" — that would disable an
	// optional role); the caller's hex decoder then fails loud on the garbage.
	t.Setenv(name+"_FILE", "")
	t.Setenv(name, "   ")
	if got := secretEnvOrFile(name); got == "" {
		t.Error("whitespace-only inline must not resolve to empty (would silently disable an optional seed)")
	}
}

// TestSecretEnvOrFile_Fatal proves every fail-loud path of the reader calls log.Fatal: both forms set,
// a missing _FILE path, a set-but-blank _FILE, inline + a whitespace _FILE (still ambiguous), a
// _FILE that is not a regular file (a directory/FIFO/device), and a _FILE over the size cap. Each runs
// in a re-exec'd child of this test binary and asserts a non-zero exit (log.Fatal => os.Exit(1)).
func TestSecretEnvOrFile_Fatal(t *testing.T) {
	const name = "FEIR_TEST_SEED_FATAL"

	// Child branch: any configured scenario triggers the (fatal) read.
	if os.Getenv("FEIR_TEST_FATAL_CASE") != "" {
		_ = secretEnvOrFile(name)
		return
	}

	dir := t.TempDir() // a directory is not a regular file
	bigPath := filepath.Join(dir, "big")
	if err := os.WriteFile(bigPath, make([]byte, maxSeedFileBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized: %v", err)
	}

	cases := []struct {
		scenario string
		env      []string
	}{
		{"both", []string{name + "=inline", name + "_FILE=/some/path"}},
		{"missing", []string{name + "_FILE=/nonexistent/feir/seed/path"}},
		{"blank_file", []string{name + "_FILE=   "}},                       // set-but-blank _FILE must not fall back
		{"both_via_ws_file", []string{name + "=abcd", name + "_FILE=   "}}, // inline + whitespace _FILE is still both-set
		{"nonregular", []string{name + "_FILE=" + dir}},                    // a directory is not a regular file
		{"oversize", []string{name + "_FILE=" + bigPath}},                  // over the seed-file cap
	}
	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestSecretEnvOrFile_Fatal")
			cmd.Env = append(os.Environ(), "FEIR_TEST_FATAL_CASE="+tc.scenario)
			cmd.Env = append(cmd.Env, tc.env...)
			out, err := cmd.CombinedOutput()
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.Success() {
				t.Fatalf("scenario %q: expected non-zero exit from log.Fatal, got %v\n%s", tc.scenario, err, out)
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

// TestRequireProdSecrets_FailsClosed proves the FEIR_REQUIRE_PROD_SECRETS gate refuses to start when a
// prod-mandatory secret is empty/absent (empty FEIR_API_KEYS => unauthenticated API; empty
// FEIR_DATABASE_URL => volatile in-memory store). Builds + runs the real binary (the gate is in main()).
func TestRequireProdSecrets_FailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the cgo binary; skipped under -short")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "feir-server-rps")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Skipf("could not build feir-server (cgo toolchain?): %v\n%s", err, out)
	}
	seed := strings.Repeat("a1", 32)
	cases := []struct {
		name string
		env  []string
	}{
		{"missing api keys", []string{"FEIR_REQUIRE_PROD_SECRETS=1", "FEIR_SIGNING_SEED=" + seed, "FEIR_DATABASE_URL=postgres://x"}},
		{"missing db url", []string{"FEIR_REQUIRE_PROD_SECRETS=1", "FEIR_SIGNING_SEED=" + seed, "FEIR_API_KEYS=proj:tok"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bin)
			cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, tc.env...)
			out, err := cmd.CombinedOutput()
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.Success() {
				t.Fatalf("%s: expected fail-closed exit, got %v\n%s", tc.name, err, out)
			}
			if !strings.Contains(string(out), "FEIR_REQUIRE_PROD_SECRETS") {
				t.Fatalf("%s: exited non-zero but not via the gate:\n%s", tc.name, out)
			}
		})
	}
}
