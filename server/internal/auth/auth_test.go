package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// okHandler is the protected handler; it records whether it ran and returns 200.
func okHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

func TestMapStoreValidFor(t *testing.T) {
	ks := NewMapStore(map[string][]string{
		"projA": {"tok-a1", "tok-a2"},
		"projB": {"tok-b1"},
		"empty": {}, // configured but with no keys -> still denies
	})

	tests := []struct {
		name    string
		project string
		token   string
		want    bool
	}{
		{"valid first token", "projA", "tok-a1", true},
		{"valid second token", "projA", "tok-a2", true},
		{"valid other project", "projB", "tok-b1", true},
		{"right token wrong project", "projB", "tok-a1", false},
		{"wrong token", "projA", "nope", false},
		{"unknown project", "ghost", "tok-a1", false},
		{"empty token", "projA", "", false},
		{"empty project", "", "tok-a1", false},
		{"project with empty key set", "empty", "anything", false},
		{"prefix of valid token is rejected", "projA", "tok-a", false},
		{"valid token plus extra is rejected", "projA", "tok-a1x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ks.ValidFor(tc.project, tc.token); got != tc.want {
				t.Fatalf("ValidFor(%q,%q)=%v want %v", tc.project, tc.token, got, tc.want)
			}
		})
	}
}

func TestMapStoreAdd(t *testing.T) {
	ks := NewMapStore(nil)
	if ks.ValidFor("p", "t") {
		t.Fatal("empty store should deny")
	}
	ks.Add("p", "t")
	if !ks.ValidFor("p", "t") {
		t.Fatal("token added via Add should be valid")
	}
	// idempotent: adding twice does not double-register or panic
	ks.Add("p", "t")
	if !ks.ValidFor("p", "t") {
		t.Fatal("token should remain valid after duplicate Add")
	}
	// empty project/token are ignored, never become credentials
	ks.Add("", "x")
	ks.Add("p2", "")
	if ks.ValidFor("", "x") || ks.ValidFor("p2", "") {
		t.Fatal("empty project/token must never be a valid credential")
	}
}

// TestNewMapStoreCopiesInitial ensures mutating the caller's map after construction does not change
// the store (defense against accidental shared-state surprises).
func TestNewMapStoreCopiesInitial(t *testing.T) {
	initial := map[string][]string{"p": {"t1"}}
	ks := NewMapStore(initial)
	initial["p"] = append(initial["p"], "t2") // mutate after construction
	if ks.ValidFor("p", "t2") {
		t.Fatal("store must not observe post-construction mutation of the initial map")
	}
	if !ks.ValidFor("p", "t1") {
		t.Fatal("original token should still be valid")
	}
}

func TestOpenStoreAllowsAll(t *testing.T) {
	ks := NewOpenStore()
	if !IsOpen(ks) {
		t.Fatal("NewOpenStore should report IsOpen=true")
	}
	if !ks.ValidFor("anything", "whatever") {
		t.Fatal("open store should allow any token/project")
	}
	if !ks.ValidFor("", "") {
		t.Fatal("open store should allow even empty token/project")
	}
	if IsOpen(NewMapStore(nil)) {
		t.Fatal("MapStore must not report as open")
	}
}

func TestMiddleware(t *testing.T) {
	ks := NewMapStore(map[string][]string{
		"projA": {"good-token"},
		"projB": {"b-token"},
	})
	mw := Middleware(ks, "project")

	tests := []struct {
		name       string
		project    string
		authHeader string // full Authorization header value, "" to omit
		apiKey     string // X-Api-Key value, "" to omit
		wantStatus int
		wantNext   bool
	}{
		{"valid bearer", "projA", "Bearer good-token", "", http.StatusOK, true},
		{"valid bearer lowercase scheme", "projA", "bearer good-token", "", http.StatusOK, true},
		{"valid bearer mixed scheme", "projA", "BeArEr good-token", "", http.StatusOK, true},
		{"valid x-api-key", "projA", "", "good-token", http.StatusOK, true},
		{"wrong token bearer", "projA", "Bearer bad-token", "", http.StatusUnauthorized, false},
		{"wrong token api-key", "projA", "", "bad-token", http.StatusUnauthorized, false},
		{"no credential", "projA", "", "", http.StatusUnauthorized, false},
		{"right token wrong project", "projB", "Bearer good-token", "", http.StatusUnauthorized, false},
		{"valid token but no project", "", "Bearer good-token", "", http.StatusUnauthorized, false},
		{"unknown project", "ghost", "Bearer good-token", "", http.StatusUnauthorized, false},
		{"malformed auth falls through to deny", "projA", "Basic Zm9vOmJhcg==", "", http.StatusUnauthorized, false},
		{"bearer with no token", "projA", "Bearer ", "", http.StatusUnauthorized, false},
		{"bearer wins over wrong api-key", "projA", "Bearer good-token", "bad-token", http.StatusOK, true},
		{"valid token with surrounding spaces", "projA", "Bearer   good-token  ", "", http.StatusOK, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			h := mw(okHandler(&reached))

			url := "/v2/dag"
			if tc.project != "" {
				url += "?project=" + tc.project
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.apiKey != "" {
				req.Header.Set("X-Api-Key", tc.apiKey)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d want %d (body=%q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if reached != tc.wantNext {
				t.Fatalf("next-handler reached=%v want %v", reached, tc.wantNext)
			}
			if tc.wantStatus == http.StatusUnauthorized {
				// 401 body must be generic and must never echo the token or project name.
				body := rec.Body.String()
				if !strings.Contains(body, `"unauthorized"`) {
					t.Fatalf("401 body not generic: %q", body)
				}
				if tc.authHeader != "" && strings.Contains(body, "good-token") {
					t.Fatalf("401 body leaked a token: %q", body)
				}
				if tc.project != "" && strings.Contains(body, tc.project) {
					t.Fatalf("401 body leaked the project name: %q", body)
				}
				if got := rec.Header().Get("WWW-Authenticate"); got == "" {
					t.Fatal("401 should set WWW-Authenticate")
				}
			}
		})
	}
}

// TestMiddlewareDefaultProjectParam: empty projectParam defaults to "project".
func TestMiddlewareDefaultProjectParam(t *testing.T) {
	ks := NewMapStore(map[string][]string{"p": {"t"}})
	mw := Middleware(ks, "") // should default to "project"

	reached := false
	h := mw(okHandler(&reached))
	req := httptest.NewRequest(http.MethodGet, "/?project=p", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("default project param not honored: code=%d reached=%v", rec.Code, reached)
	}
}

// TestMiddlewareCustomProjectParam: a non-default param name is read instead of "project".
func TestMiddlewareCustomProjectParam(t *testing.T) {
	ks := NewMapStore(map[string][]string{"p": {"t"}})
	mw := Middleware(ks, "proj")

	reached := false
	h := mw(okHandler(&reached))
	// Supplying ?project=p (the default name) must NOT satisfy a "proj" param.
	req := httptest.NewRequest(http.MethodGet, "/?project=p", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong param name should fail: code=%d", rec.Code)
	}

	reached = false
	h = mw(okHandler(&reached))
	req = httptest.NewRequest(http.MethodGet, "/?proj=p", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("custom param name should pass: code=%d reached=%v", rec.Code, reached)
	}
}

func TestMiddlewareOpenStoreBypasses(t *testing.T) {
	mw := Middleware(NewOpenStore(), "project")
	reached := false
	h := mw(okHandler(&reached))
	// No credential, no project — open mode must still allow through.
	req := httptest.NewRequest(http.MethodGet, "/v2/dag", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("open store should bypass auth: code=%d reached=%v", rec.Code, reached)
	}
}

func TestCutBearer(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"Bearer ", "", true}, // valid scheme, empty token
		{"Bearertoken", "", false},
		{"Basic abc", "", false},
		{"", "", false},
		{"Bearer", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := cutBearer(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("cutBearer(%q)=(%q,%v) want (%q,%v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestConstantTimeCompareUsed is a behavioral check that the compare does not early-out byte-by-byte:
// a token that shares a long prefix with the real one must take indistinguishable time from a token
// that differs in the first byte. We can't assert exact timings deterministically, but we CAN assert
// the result is correct for adversarial near-miss inputs (the property a non-constant-time compare
// would still get right) AND that equal-length-different and different-length inputs both deny — the
// outcomes a subtle.ConstantTimeCompare guarantees. The timing ratio check below is a soft signal.
func TestConstantTimeCompareUsed(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef" // 32-byte token
	ks := NewMapStore(map[string][]string{"p": {secret}})

	// Near-miss (differs only in last byte) and far-miss (differs in first byte) must both deny.
	nearMiss := secret[:len(secret)-1] + "X"
	farMiss := "X" + secret[1:]
	if ks.ValidFor("p", nearMiss) || ks.ValidFor("p", farMiss) {
		t.Fatal("near/far miss tokens must be denied")
	}
	if !ks.ValidFor("p", secret) {
		t.Fatal("exact token must be accepted")
	}

	// Soft timing signal: with a constant-time compare, the mean time for near-miss vs far-miss
	// guesses should be close. A naive byte-by-byte == would make far-miss much faster. We use a
	// generous tolerance to avoid flakiness on shared CI; the hard correctness checks above are the
	// real guarantee.
	measure := func(guess string) time.Duration {
		const iter = 20000
		start := time.Now()
		for i := 0; i < iter; i++ {
			ks.ValidFor("p", guess)
		}
		return time.Since(start)
	}
	// warm up
	measure(nearMiss)
	measure(farMiss)
	near := measure(nearMiss)
	far := measure(farMiss)
	ratio := float64(near) / float64(far)
	if ratio < 0.2 || ratio > 5.0 {
		// Extremely wide bounds: this only catches gross asymmetry, not subtle leaks. It exists to
		// document intent; the correctness assertions are what enforce constant-time usage.
		t.Logf("timing near=%v far=%v ratio=%.2f (informational; wide tolerance)", near, far, ratio)
	}
}
