package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

func doAs(h http.Handler, method, path, token, body string) int {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestAuth_NoTokenConfiguredRefusesEveryRequest (AVE-05): a server given no auth store refuses every /v2
// request, for any method and any (even bogus) credential. Only the probes stay up.
func TestAuth_NoTokenConfiguredRefusesEveryRequest(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(c, store.NewMem(), "k0").Routes() // no WithAuth
	for _, tc := range []struct{ method, path string }{
		{"GET", "/v2/records?project=p"}, {"POST", "/v2/records?project=p"}, {"GET", "/v2/verify?project=p"},
		{"GET", "/v2/export?project=p"}, {"POST", "/v2/checkpoints?project=p"}, {"GET", "/v2/posture?project=p"},
		{"GET", "/v2/usage?project=p"}, {"POST", "/v2/revoke?project=p"}, {"GET", "/v2/unknown"},
	} {
		for _, tok := range []string{"", "anything"} {
			if code := doAs(h, tc.method, tc.path, tok, `{}`); code != http.StatusUnauthorized {
				t.Fatalf("%s %s token=%q: want 401, got %d", tc.method, tc.path, tok, code)
			}
		}
	}
	if code := doAs(h, "GET", "/healthz", "", ""); code != http.StatusOK {
		t.Fatalf("healthz must stay reachable, got %d", code)
	}
}

func scopedServer(t *testing.T, now func() time.Time) http.Handler {
	t.Helper()
	ks, _, err := auth.ParseKeysConfig(`[
	  {"project":"p","token":"rtok","role":"read"},
	  {"project":"p","token":"wtok","role":"write"},
	  {"project":"p","token":"atok","role":"admin"},
	  {"project":"p","token":"soon","role":"admin","not_after":"2027-06-01T00:00:00Z"},
	  {"project":"q","token":"qtok","role":"admin"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if now != nil {
		ks.WithClock(now)
	}
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	return api.New(c, store.NewMem(), "k0").WithAuth(ks).Routes()
}

const recBody = `{"idempotency_key":"i1","project_id":"p","session_id":"s1","action":"a"}`

// TestAuth_ScopedTokensPerRoute (AVE-05): read reads, write adds evidence, admin revokes and checkpoints;
// a role never reaches above its level; a token never reaches another project.
func TestAuth_ScopedTokensPerRoute(t *testing.T) {
	h := scopedServer(t, nil)
	type tc struct {
		name, method, path, token, body string
		want                            int
	}
	cases := []tc{
		{"read GET records", "GET", "/v2/records?project=p", "rtok", "", 200},
		{"read GET verify", "GET", "/v2/verify?project=p", "rtok", "", 200},
		{"read GET export", "GET", "/v2/export?project=p", "rtok", "", 200},
		{"read GET usage", "GET", "/v2/usage?project=p", "rtok", "", 200},
		{"read POST records", "POST", "/v2/records?project=p", "rtok", recBody, 403},
		{"read POST checkpoints", "POST", "/v2/checkpoints?project=p", "rtok", "", 403},
		{"read POST revoke", "POST", "/v2/revoke?project=p", "rtok", `{}`, 403},
		{"write POST records", "POST", "/v2/records?project=p", "wtok", recBody, 201},
		{"write GET records", "GET", "/v2/records?project=p", "wtok", "", 200},
		{"write POST checkpoints", "POST", "/v2/checkpoints?project=p", "wtok", "", 403},
		{"write POST revoke", "POST", "/v2/revoke?project=p", "wtok", `{}`, 403},
		{"write POST unknown path", "POST", "/v2/records/extra?project=p", "wtok", recBody, 403},
		{"write DELETE records", "DELETE", "/v2/records?project=p", "wtok", "", 403},
		{"admin POST checkpoints", "POST", "/v2/checkpoints?project=p", "atok", "", 201},
		{"admin POST records", "POST", "/v2/records?project=p", "atok", `{"idempotency_key":"i2","project_id":"p","session_id":"s1","action":"a"}`, 201},
		{"other project token", "GET", "/v2/records?project=p", "qtok", "", 401},
		{"no token", "GET", "/v2/records?project=p", "", "", 401},
		{"wrong token", "GET", "/v2/records?project=p", "bad", "", 401},
	}
	for _, c := range cases {
		if got := doAs(h, c.method, c.path, c.token, c.body); got != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, got)
		}
	}
}

// TestAuth_TokenExpires (AVE-05): the same token works before its not_after and is refused at and after it.
func TestAuth_TokenExpires(t *testing.T) {
	clock := time.Date(2027, 5, 31, 23, 59, 0, 0, time.UTC)
	h := scopedServer(t, func() time.Time { return clock })
	if got := doAs(h, "GET", "/v2/records?project=p", "soon", ""); got != 200 {
		t.Fatalf("before expiry: want 200, got %d", got)
	}
	clock = time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	if got := doAs(h, "GET", "/v2/records?project=p", "soon", ""); got != 401 {
		t.Fatalf("at expiry: want 401, got %d", got)
	}
	if got := doAs(h, "POST", "/v2/checkpoints?project=p", "soon", ""); got != 401 {
		t.Fatalf("an expired admin token must not checkpoint: got %d", got)
	}
}
