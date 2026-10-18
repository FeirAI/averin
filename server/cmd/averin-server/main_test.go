package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/core"
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
	const name = "AVERIN_TEST_SEED_HAPPY"

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
	const name = "AVERIN_TEST_SEED_FATAL"

	// Child branch: any configured scenario triggers the (fatal) read.
	if os.Getenv("AVERIN_TEST_FATAL_CASE") != "" {
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
		{"missing", []string{name + "_FILE=/nonexistent/averin/seed/path"}},
		{"blank_file", []string{name + "_FILE=   "}},                       // set-but-blank _FILE must not fall back
		{"both_via_ws_file", []string{name + "=abcd", name + "_FILE=   "}}, // inline + whitespace _FILE is still both-set
		{"nonregular", []string{name + "_FILE=" + dir}},                    // a directory is not a regular file
		{"oversize", []string{name + "_FILE=" + bigPath}},                  // over the seed-file cap
	}
	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			env := append(os.Environ(), "AVERIN_TEST_FATAL_CASE="+tc.scenario)
			env = append(env, tc.env...)
			startServerExpectRefusal(t, os.Args[0], []string{"-test.run=TestSecretEnvOrFile_Fatal"}, env)
		})
	}
}

// TestRevocationR2Disjoint_UnderFileMountedSeeds proves the R2 role-separation guard still FATALS when
// the broker/resource seed it must be disjoint from is supplied via its <NAME>_FILE form. The pre-#40
// guard compared AVERIN_REVOCATION_SEED against raw os.Getenv("AVERIN_BROKER_ISSUING_SEED") /
// os.Getenv("AVERIN_RESOURCE_SEED"); once those seeds moved to secretEnvOrFile, a file-mounted seed read
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
	bin := filepath.Join(dir, "averin-server-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("could not build averin-server (cgo toolchain unavailable?): %v\n%s", err, out)
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
				"AVERIN_DEV_MODE=1",
				"AVERIN_SIGNING_SEED=" + seedSigning,
				"AVERIN_BROKER_ISSUING_SEED_FILE=" + sharedFile,
				"AVERIN_REVOCATION_SEED=" + seedShared,
			},
		},
		{
			// resource seed file-mounted == inline revocation seed → R2 fatal (broker enabled separately).
			name: "resource-via-file",
			env: []string{
				"AVERIN_DEV_MODE=1",
				"AVERIN_SIGNING_SEED=" + seedSigning,
				"AVERIN_BROKER_ISSUING_SEED=" + seedBroker,
				"AVERIN_RESOURCE_SEED_FILE=" + sharedFile,
				"AVERIN_RESOURCE_ID=res-test",
				"AVERIN_REVOCATION_SEED=" + seedShared,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Minimal env: avoid inheriting any real seeds; bind nowhere (it fatals before listening).
			out := startServerExpectRefusal(t, bin, nil, append([]string{"PATH=" + os.Getenv("PATH")}, tc.env...))
			if !strings.Contains(out, "R2 role separation") {
				t.Fatalf("%s: exited non-zero but not via the R2 guard; output:\n%s", tc.name, out)
			}
		})
	}
}

// TestRequireProdSecrets_FailsClosed proves the AVERIN_REQUIRE_PROD_SECRETS gate refuses to start when a
// prod-mandatory secret is empty/absent (empty AVERIN_API_KEYS => unauthenticated API; empty
// AVERIN_DATABASE_URL => volatile in-memory store). Builds + runs the real binary (the gate is in main()).
func TestRequireProdSecrets_FailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the cgo binary; skipped under -short")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "averin-server-rps")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Skipf("could not build averin-server (cgo toolchain?): %v\n%s", err, out)
	}
	seed := strings.Repeat("a1", 32)
	cases := []struct {
		name string
		env  []string
	}{
		{"missing api keys", []string{"AVERIN_REQUIRE_PROD_SECRETS=1", "AVERIN_SIGNING_SEED=" + seed, "AVERIN_DATABASE_URL=postgres://x"}},
		{"missing db url", []string{"AVERIN_REQUIRE_PROD_SECRETS=1", "AVERIN_SIGNING_SEED=" + seed, "AVERIN_API_KEYS=proj:tok"}},
		{"dev signing seed", []string{"AVERIN_REQUIRE_PROD_SECRETS=1", "AVERIN_API_KEYS=proj:tok", "AVERIN_DATABASE_URL=postgres://x", "AVERIN_SIGNING_SEED=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := startServerExpectRefusal(t, bin, nil, append([]string{"PATH=" + os.Getenv("PATH")}, tc.env...))
			if !strings.Contains(out, "AVERIN_REQUIRE_PROD_SECRETS") {
				t.Fatalf("%s: exited non-zero but not via the gate:\n%s", tc.name, out)
			}
		})
	}
}

// TestIsDevSigningSeed pins the detector the AVERIN_REQUIRE_PROD_SECRETS gate uses to reject the
// well-known, globally-published dev seed (core_test.go:8) — pure, fast, no cgo/re-exec needed.
func TestIsDevSigningSeed(t *testing.T) {
	cases := []struct {
		name string
		seed string
		want bool
	}{
		{"dev seed lowercase", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", true},
		{"dev seed uppercased", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", true},
		{"dev seed with whitespace + trailing newline", "  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n", true},
		{"fresh distinct seed", strings.Repeat("a1", 32), false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDevSigningSeed(tc.seed); got != tc.want {
				t.Fatalf("isDevSigningSeed(%q) = %v, want %v", tc.seed, got, tc.want)
			}
		})
	}
}

// TestPosture_LiveProcessReportsItsStartupGuards builds and runs the real binary (the wiring is in
// main()) and reads GET /v2/posture from the live process: the keyed deployment says so, the
// build stamps flow through, and the dev signing seed is reported as the violation it is.
func TestPosture_LiveProcessReportsItsStartupGuards(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the cgo binary; skipped under -short")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "averin-server-posture")
	if out, err := exec.Command("go", "build", "-ldflags", "-X main.coreRustc=rustc-test-stamp", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Skipf("could not build averin-server (cgo toolchain?): %v\n%s", err, out)
	}
	run := func(t *testing.T, seed string, extraEnv ...string) map[string]any {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close()
		env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "AVERIN_ADDR=" + addr,
			"AVERIN_DEV_MODE=1", "AVERIN_SIGNING_SEED=" + seed, "AVERIN_API_KEYS=proj:tok"}
		env = append(env, extraEnv...)
		startServerProc(t, bin, env)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/v2/posture?project=proj", nil)
			req.Header.Set("Authorization", "Bearer tok")
			if resp, err := http.DefaultClient.Do(req); err == nil {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("posture: status %d", resp.StatusCode)
				}
				var b map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
					t.Fatal(err)
				}
				return b
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("averin-server never answered /v2/posture")
		return nil
	}
	b := run(t, strings.Repeat("a1", 32), "AVERIN_REGION= eu-central-1 ")
	if b["region"] != "eu-central-1" || b["schema_version"] != float64(0) || b["runtime_role_verified"] != false {
		t.Fatalf("region, schema version and runtime-role fields: %v", b)
	}
	if b["dev_mode"] != true {
		t.Fatalf("this process was started with AVERIN_DEV_MODE=1 and must report dev_mode=true: %v", b)
	}
	// Dev mode turns approver binding off by default; the live process must report what it runs with.
	if v, ok := b["require_approver_binding"]; !ok || v != false {
		t.Fatalf("dev mode defaults approver binding off and must report require_approver_binding=false: %v", b)
	}
	if v, ok := b["approver_binding_since"]; !ok || v != nil {
		t.Fatalf("no cutover set, so approver_binding_since must be present and null: %v", b)
	}
	if b["api_keys_configured"] != true || b["signing_seed_is_dev"] != false || b["durable_store"] != false || b["require_prod_secrets"] != false {
		t.Fatalf("fresh seed, keyed, in-memory: %v", b)
	}
	// FEI-40: the live process reports the keyed fingerprint of the API key it accepts, never the key.
	mac := hmac.New(sha256.New, []byte("tok"))
	mac.Write([]byte("feir-secret-alignment/v1:averin-api-key"))
	wantFP := hex.EncodeToString(mac.Sum(nil)[:16])
	if sf, _ := b["secret_fingerprints"].(map[string]any); sf == nil || fmt.Sprint(sf["averin-api-key"]) != "["+wantFP+"]" {
		t.Fatalf("live process must report the fingerprint of AVERIN_API_KEYS' token (%s): %v", wantFP, b["secret_fingerprints"])
	}
	if raw, _ := json.Marshal(b); strings.Contains(string(raw), `"tok"`) {
		t.Fatalf("the live report carries the API key: %s", raw)
	}
	build := b["build"].(map[string]any)
	if build["core_rustc"] != "rustc-test-stamp" || build["go_version"] == "" {
		t.Fatalf("build stamps did not reach the report: %v", build)
	}
	b = run(t, strings.Repeat("a1", 32), "AVERIN_REQUIRE_APPROVER_BINDING=1", "AVERIN_APPROVER_BINDING_SINCE=2026-10-01T00:00:00.000Z")
	if b["require_approver_binding"] != true || b["approver_binding_since"] != "2026-10-01T00:00:00.000Z" {
		t.Fatalf("explicit approver binding and cutover must be reported: %v", b)
	}
	b = run(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if b["signing_seed_is_dev"] != true {
		t.Fatalf("the dev seed must be reported: %v", b)
	}
	if b["region"] != "" {
		t.Fatalf("an undeclared region must be reported empty: %v", b)
	}
}

// An invalid AVERIN_REGION stops startup instead of being reported as a region nobody meant.
func TestRegion_InvalidValueRefusesStart(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the cgo binary; skipped under -short")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "averin-server-region")
	// This test binary already links the cgo staticlib, so a failing build is a real failure here,
	// not a reason to skip (a skip would be a green result for a test that never ran).
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("could not build averin-server: %v\n%s", err, out)
	}
	// A server that wrongly ignores AVERIN_REGION starts and listens; the helper bounds the wait,
	// kills it, and fails the test instead of leaving it running.
	out := startServerExpectRefusal(t, bin, nil, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "AVERIN_ADDR=127.0.0.1:0",
		"AVERIN_DEV_MODE=1", "AVERIN_SIGNING_SEED=" + strings.Repeat("a1", 32), "AVERIN_REGION=EU West"})
	if !strings.Contains(out, "AVERIN_REGION") {
		t.Fatalf("the refusal must name AVERIN_REGION\n%s", out)
	}
}
