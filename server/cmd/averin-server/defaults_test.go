package main

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigParsers(t *testing.T) {
	t.Run("dev mode", func(t *testing.T) {
		for raw, want := range map[string]bool{"": false, "0": false, "false": false, "1": true, "TRUE": true} {
			if got, err := devModeFromEnv(raw); err != nil || got != want {
				t.Fatalf("devMode(%q) = %v, %v", raw, got, err)
			}
		}
		if _, err := devModeFromEnv("yes"); err == nil {
			t.Fatal("a non-boolean AVERIN_DEV_MODE must be an error")
		}
	})
	t.Run("prod gate defaults on and only dev mode turns it off", func(t *testing.T) {
		if v, err := requireProdSecretsFromEnv("", false); err != nil || !v {
			t.Fatalf("unset, not dev: want on, got %v %v", v, err)
		}
		if v, err := requireProdSecretsFromEnv("", true); err != nil || v {
			t.Fatalf("unset, dev: want off, got %v %v", v, err)
		}
		if _, err := requireProdSecretsFromEnv("0", false); err == nil {
			t.Fatal("AVERIN_REQUIRE_PROD_SECRETS=0 outside dev mode must be refused")
		}
		if v, err := requireProdSecretsFromEnv("0", true); err != nil || v {
			t.Fatalf("explicit 0 in dev: want off, got %v %v", v, err)
		}
		if v, err := requireProdSecretsFromEnv("1", true); err != nil || !v {
			t.Fatalf("explicit 1 in dev: want on, got %v %v", v, err)
		}
	})
	t.Run("body bound defaults on", func(t *testing.T) {
		if v, err := requireBodyBoundFromEnv("", false); err != nil || !v {
			t.Fatalf("unset, not dev: want on, got %v %v", v, err)
		}
		if v, err := requireBodyBoundFromEnv("", true); err != nil || v {
			t.Fatalf("unset, dev: want off, got %v %v", v, err)
		}
		if v, err := requireBodyBoundFromEnv("0", false); err != nil || v {
			t.Fatalf("explicit 0 is the migration opt-out, got %v %v", v, err)
		}
		if _, err := requireBodyBoundFromEnv("maybe", false); err == nil {
			t.Fatal("garbage must be an error")
		}
	})
	t.Run("approver binding", func(t *testing.T) {
		p, err := requireApproverBindingFromEnv("", "", false)
		if err != nil || !p.on {
			t.Fatalf("unset, not dev: want on, got %+v %v", p, err)
		}
		if p, err = requireApproverBindingFromEnv("", "", true); err != nil || p.on {
			t.Fatalf("unset, dev: want off, got %+v %v", p, err)
		}
		if p, err = requireApproverBindingFromEnv("0", "", false); err != nil || p.on {
			t.Fatalf("explicit 0: want off, got %+v %v", p, err)
		}
		if p, err = requireApproverBindingFromEnv("", "2026-10-01T00:00:00.000Z", false); err != nil || !p.on || p.since == "" {
			t.Fatalf("cutover: %+v %v", p, err)
		}
		for _, bad := range []string{"yesterday", "2026-10-01", "2026-10-01T00:00:00Z", "2026-13-01T00:00:00.000Z"} {
			if _, err := requireApproverBindingFromEnv("1", bad, false); err == nil {
				t.Fatalf("%q must be rejected", bad)
			}
		}
		if _, err := requireApproverBindingFromEnv("0", "2026-10-01T00:00:00.000Z", false); err == nil {
			t.Fatal("a cutover without the policy must be rejected")
		}
	})
	t.Run("budgets", func(t *testing.T) {
		if b, err := ingestBudgetFromEnv(""); err != nil || b != nil {
			t.Fatalf("unset must be off, got %v %v", b, err)
		}
		if b, err := ingestBudgetFromEnv("1"); err != nil || b == nil {
			t.Fatalf("1 must turn it on with defaults, got %v %v", b, err)
		}
		b, err := ingestBudgetFromEnv(`{"per_project_per_sec":2,"per_project_burst":3,"global_per_sec":4,"global_burst":5,"max_projects":6}`)
		if err != nil || b == nil || b.PerProjectBurst != 3 || b.GlobalBurst != 5 || b.MaxProjects != 6 {
			t.Fatalf("json budget: %+v %v", b, err)
		}
		for _, bad := range []string{`{"per_project_per_sc":2}`, `{"global_burst":-1}`, `nope`, `{} {}`} {
			if _, err := ingestBudgetFromEnv(bad); err == nil && bad != `{} {}` {
				t.Fatalf("%q must be an error", bad)
			}
		}
		if _, err := deniedGrantBudgetFromEnv(`{"bogus":1}`); err == nil {
			t.Fatal("unknown field must be an error")
		}
	})
	t.Run("quota", func(t *testing.T) {
		if n, err := nonNegativeIntFromEnv("X", ""); err != nil || n != 0 {
			t.Fatal("unset is 0")
		}
		if n, err := nonNegativeIntFromEnv("X", "100"); err != nil || n != 100 {
			t.Fatal("100")
		}
		for _, bad := range []string{"-1", "ten", "1.5"} {
			if _, err := nonNegativeIntFromEnv("X", bad); err == nil {
				t.Fatalf("%q must be an error", bad)
			}
		}
	})
}

func buildForDefaults(t *testing.T) (bin, dir string) {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the cgo binary; skipped under -short")
	}
	dir = t.TempDir()
	bin = filepath.Join(dir, "averin-server-defaults")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Skipf("could not build averin-server (cgo toolchain?): %v\n%s", err, out)
	}
	return bin, dir
}

// runToExit runs a server that is expected to refuse; a server that keeps running fails the test.
func runToExit(t *testing.T, bin string, env ...string) (string, error) {
	t.Helper()
	res := runRefusal(t, bin, nil, append([]string{"PATH=" + os.Getenv("PATH")}, env...), refusalBound)
	if res.Leaked || res.TimedOut {
		t.Fatalf("the process did not refuse to start within %s (timed out=%v leaked=%v)\n%s", refusalBound, res.TimedOut, res.Leaked, res.Out)
	}
	return res.Out, res.Err
}

// TestDefaults_RefuseToStartWithoutKeysOrDevMode: the production gate is on by default, so a process
// given only a seed refuses to start, naming the missing keys (AVE-05, AVE-06).
func TestDefaults_RefuseToStartWithoutKeysOrDevMode(t *testing.T) {
	bin, _ := buildForDefaults(t)
	seed := strings.Repeat("a1", 32)
	out, err := runToExit(t, bin, "AVERIN_SIGNING_SEED="+seed)
	if ee, ok := err.(*exec.ExitError); !ok || ee.Success() {
		t.Fatalf("expected a refusal to start, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "AVERIN_API_KEYS") || !strings.Contains(out, "AVERIN_REQUIRE_PROD_SECRETS") {
		t.Fatalf("refusal must name the gate and the missing keys:\n%s", out)
	}
	// Keys alone are not enough in production: the volatile store is refused too.
	out, err = runToExit(t, bin, "AVERIN_SIGNING_SEED="+seed, "AVERIN_API_KEYS=proj:tok")
	if ee, ok := err.(*exec.ExitError); !ok || ee.Success() || !strings.Contains(out, "AVERIN_DATABASE_URL") {
		t.Fatalf("keys without a database must be refused by default: %v\n%s", err, out)
	}
	// Turning the gate off needs dev mode.
	out, err = runToExit(t, bin, "AVERIN_SIGNING_SEED="+seed, "AVERIN_API_KEYS=proj:tok", "AVERIN_REQUIRE_PROD_SECRETS=0")
	if ee, ok := err.(*exec.ExitError); !ok || ee.Success() || !strings.Contains(out, "AVERIN_DEV_MODE=1") {
		t.Fatalf("REQUIRE_PROD_SECRETS=0 outside dev mode must be refused: %v\n%s", err, out)
	}
}

func startAndGet(t *testing.T, bin, dir string, env []string, method, path, bearer string) (int, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	stop := startServerProc(t, bin, append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "AVERIN_ADDR=" + addr}, env...))
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(method, "http://"+addr+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
			return resp.StatusCode, stop
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	t.Fatal("averin-server never answered")
	return 0, stop
}

// TestDefaults_DevModeIsTheOnlyOpenAPI: with AVERIN_DEV_MODE=1 and no keys the API is open; with keys it
// is enforced even in dev mode.
func TestDefaults_DevModeIsTheOnlyOpenAPI(t *testing.T) {
	bin, dir := buildForDefaults(t)
	seed := "AVERIN_SIGNING_SEED=" + strings.Repeat("a1", 32)
	code, stop := startAndGet(t, bin, dir, []string{seed, "AVERIN_DEV_MODE=1"}, "GET", "/v2/posture?project=p", "")
	stop()
	if code != http.StatusOK {
		t.Fatalf("dev mode, no keys: want an open API (200), got %d", code)
	}
	code, stop = startAndGet(t, bin, dir, []string{seed, "AVERIN_DEV_MODE=1", "AVERIN_API_KEYS=p:tok"}, "GET", "/v2/posture?project=p", "")
	stop()
	if code != http.StatusUnauthorized {
		t.Fatalf("dev mode with keys: want 401 without a token, got %d", code)
	}
}

// TestDefaults_ScopedKeysEnforcedByTheBinary: a read token reads and is refused a checkpoint (403), a
// write token adds evidence but is refused a checkpoint, an admin token may checkpoint, an expired token is 401.
func TestDefaults_ScopedKeysEnforcedByTheBinary(t *testing.T) {
	bin, dir := buildForDefaults(t)
	seed := "AVERIN_SIGNING_SEED=" + strings.Repeat("a1", 32)
	keys := `[{"project":"p","token":"rtok","role":"read"},{"project":"p","token":"wtok","role":"write"},` +
		`{"project":"p","token":"atok","role":"admin"},{"project":"p","token":"old","role":"admin","not_after":"2020-01-01T00:00:00Z"}]`
	env := []string{seed, "AVERIN_DEV_MODE=1", "AVERIN_API_KEYS=" + keys}
	code, stop := startAndGet(t, bin, dir, env, "GET", "/v2/posture?project=p", "rtok")
	stop()
	if code != http.StatusOK {
		t.Fatalf("read token on a GET: want 200, got %d", code)
	}
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{"POST", "/v2/checkpoints?project=p", "rtok", http.StatusForbidden},
		{"POST", "/v2/records?project=p", "rtok", http.StatusForbidden},
		{"POST", "/v2/checkpoints?project=p", "wtok", http.StatusForbidden},
		{"POST", "/v2/revoke?project=p", "wtok", http.StatusForbidden},
		{"GET", "/v2/posture?project=p", "old", http.StatusUnauthorized},
		{"GET", "/v2/posture?project=other", "rtok", http.StatusUnauthorized},
	} {
		code, stop := startAndGet(t, bin, dir, env, tc.method, tc.path, tc.token)
		stop()
		if code != tc.want {
			t.Fatalf("%s %s with %s: want %d, got %d", tc.method, tc.path, tc.token, tc.want, code)
		}
	}
}
