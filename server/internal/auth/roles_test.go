package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, raw string) *MapStore {
	t.Helper()
	ks, _, err := ParseKeysConfig(raw)
	if err != nil {
		t.Fatalf("ParseKeysConfig: %v", err)
	}
	return ks
}

func TestRoleOrdering(t *testing.T) {
	if !RoleAdmin.Allows(RoleWrite) || !RoleAdmin.Allows(RoleRead) || !RoleWrite.Allows(RoleRead) {
		t.Fatal("higher roles include lower ones")
	}
	if RoleRead.Allows(RoleWrite) || RoleWrite.Allows(RoleAdmin) || RoleRead.Allows(RoleAdmin) {
		t.Fatal("lower roles must not include higher ones")
	}
	if Role(0).Allows(RoleRead) || Role(99).Allows(RoleRead) {
		t.Fatal("a zero or unknown role allows nothing")
	}
	for _, bad := range []string{"", "Admin", "root", "reader", " read"} {
		if _, ok := ParseRole(bad); ok {
			t.Fatalf("ParseRole(%q) must fail", bad)
		}
	}
}

func TestParseKeysConfigLegacyIsAdminNoExpiry(t *testing.T) {
	ks, n, err := ParseKeysConfig("p:t1,t2;q:t3")
	if err != nil || n != 2 {
		t.Fatalf("legacy parse: n=%d err=%v", n, err)
	}
	far := time.Now().Add(100 * 365 * 24 * time.Hour)
	if r, ok := ks.RoleFor("p", "t2", far); !ok || r != RoleAdmin {
		t.Fatalf("legacy token must be admin with no expiry, got %v %v", r, ok)
	}
}

func TestParseKeysConfigJSONRolesAndExpiry(t *testing.T) {
	ks := mustParse(t, `[{"project":"p","token":"r","role":"read","not_after":"2030-01-01T00:00:00Z"},{"project":"p","token":"w","role":"write"}]`)
	now := time.Date(2029, 12, 31, 23, 59, 59, 0, time.UTC)
	if r, ok := ks.RoleFor("p", "r", now); !ok || r != RoleRead {
		t.Fatalf("read token: %v %v", r, ok)
	}
	if r, ok := ks.RoleFor("p", "w", now.AddDate(50, 0, 0)); !ok || r != RoleWrite {
		t.Fatalf("a token without not_after never expires: %v %v", r, ok)
	}
	if _, ok := ks.RoleFor("p", "r", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); ok {
		t.Fatal("the expiry instant itself is expired")
	}
	if _, ok := ks.RoleFor("q", "r", now); ok {
		t.Fatal("a token is valid only for its own project")
	}
	if _, ok := ks.RoleFor("p", "", now); ok {
		t.Fatal("empty token")
	}
	ks.WithClock(func() time.Time { return time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC) })
	if ks.ValidFor("p", "r") {
		t.Fatal("ValidFor must honor expiry")
	}
	if !ks.ValidFor("p", "w") {
		t.Fatal("non-expiring token stays valid")
	}
}

func TestParseKeysConfigSHA256Token(t *testing.T) {
	d := sha256.Sum256([]byte("secret-token"))
	ks := mustParse(t, `[{"project":"p","token_sha256":"`+hex.EncodeToString(d[:])+`","role":"write"}]`)
	if r, ok := ks.RoleFor("p", "secret-token", time.Now()); !ok || r != RoleWrite {
		t.Fatalf("digest-configured token must match its preimage: %v %v", r, ok)
	}
	if _, ok := ks.RoleFor("p", hex.EncodeToString(d[:]), time.Now()); ok {
		t.Fatal("the digest itself must not authenticate")
	}
}

func TestParseKeysConfigRejectsBadInput(t *testing.T) {
	empty := sha256.Sum256(nil)
	cases := map[string]string{
		"empty array":      `[]`,
		"unknown role":     `[{"project":"p","token":"t","role":"root"}]`,
		"missing role":     `[{"project":"p","token":"t"}]`,
		"missing token":    `[{"project":"p","role":"read"}]`,
		"both token forms": `[{"project":"p","token":"t","token_sha256":"` + strings.Repeat("0", 64) + `","role":"read"}]`,
		"bad digest":       `[{"project":"p","token_sha256":"abc","role":"read"}]`,
		"empty-token hash": `[{"project":"p","token_sha256":"` + hex.EncodeToString(empty[:]) + `","role":"read"}]`,
		"bad expiry":       `[{"project":"p","token":"t","role":"read","not_after":"tomorrow"}]`,
		"missing project":  `[{"token":"t","role":"read"}]`,
		"unknown field":    `[{"project":"p","token":"t","role":"read","roles":"admin"}]`,
		"duplicate":        `[{"project":"p","token":"t","role":"read"},{"project":"p","token":"t","role":"admin"}]`,
		"trailing data":    `[{"project":"p","token":"t","role":"read"}] x`,
		"spaced token":     `[{"project":"p","token":" t","role":"read"}]`,
	}
	for name, raw := range cases {
		if _, _, err := ParseKeysConfig(raw); err == nil {
			t.Errorf("%s: must be rejected", name)
		} else if strings.Contains(err.Error(), `"t"`) {
			t.Errorf("%s: error must not echo the token: %v", name, err)
		}
	}
}

func TestMiddlewareRolesStatusCodes(t *testing.T) {
	ks := mustParse(t, `[{"project":"p","token":"r","role":"read"},{"project":"p","token":"a","role":"admin"},{"project":"p","token":"old","role":"admin","not_after":"2020-01-01T00:00:00Z"}]`)
	need := func(r *http.Request) Role {
		if r.Method == http.MethodGet {
			return RoleRead
		}
		return RoleAdmin
	}
	h := MiddlewareRoles(ks, "project", need)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, tc := range []struct {
		method, project, token string
		want                   int
	}{
		{"GET", "p", "r", 204},
		{"POST", "p", "r", 403},
		{"POST", "p", "a", 204},
		{"GET", "p", "old", 401},
		{"GET", "p", "", 401},
		{"GET", "q", "r", 401},
		{"GET", "p", "nope", 401},
	} {
		req := httptest.NewRequest(tc.method, "/v2/x?project="+tc.project, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s project=%s token=%q: want %d got %d", tc.method, tc.project, tc.token, tc.want, rec.Code)
		}
		if rec.Code == 403 && strings.Contains(rec.Body.String(), "p") && strings.Contains(rec.Body.String(), "token") {
			t.Errorf("403 body must be generic: %s", rec.Body.String())
		}
	}
}

func TestLegacyMiddlewareStillTreatsEveryTokenAsAdmin(t *testing.T) {
	ks, _ := ParseKeys("p:tok")
	h := Middleware(ks, "project")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest("POST", "/v2/revoke?project=p", nil)
	req.Header.Set("X-Api-Key", "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("legacy token must keep admin: %d", rec.Code)
	}
}

func TestDenyAll(t *testing.T) {
	called := false
	h := DenyAll(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest("GET", "/v2/records?project=p", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("DenyAll must 401 and never call next: called=%v code=%d", called, rec.Code)
	}
}

func TestContainsTokenCountsExpiredTokens(t *testing.T) {
	ks := mustParse(t, `[{"project":"p","token":"old","role":"read","not_after":"2020-01-01T00:00:00Z"}]`)
	if !ks.ContainsToken("old") {
		t.Fatal("an expired token must still block reuse as a recovery credential")
	}
}
