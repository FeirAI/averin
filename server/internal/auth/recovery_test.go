package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoveryAuthorization(t *testing.T) {
	rs, n, err := ParseRecoveryKeys(`[{"project_id":"p1","actor_id":"operator-1","token":"recovery-secret"},{"project_id":"p2","actor_id":"operator-2","token":"other-secret"}]`)
	if err != nil || n != 2 {
		t.Fatalf("parse: count=%d err=%v", n, err)
	}
	for _, tc := range []struct {
		name, project, token, actor string
	}{
		{"operator", "p1", "recovery-secret", "operator-1"},
		{"other project", "p2", "other-secret", "operator-2"},
		{"writer", "p1", "writer-secret", ""},
		{"wrong project", "p2", "recovery-secret", ""},
		{"absent", "p1", "", ""},
		{"unknown project", "unknown", "recovery-secret", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actor, ok := rs.ActorFor(tc.project, tc.token)
			if actor != tc.actor || ok != (tc.actor != "") {
				t.Fatalf("ActorFor returned actor=%q ok=%v", actor, ok)
			}
		})
	}
	h := RecoveryMiddleware(rs)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := RecoveryActor(r.Context())
		if !ok || actor != "operator-1" {
			t.Fatalf("missing authenticated actor: %q %v", actor, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		path, token string
		status      int
	}{
		{"/void?project=p1", "recovery-secret", http.StatusNoContent},
		{"/void?project=p1", "writer-secret", http.StatusForbidden},
		{"/void?project=p2", "recovery-secret", http.StatusForbidden},
		{"/void", "recovery-secret", http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodPost, tc.path, nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s %q: got %d want %d", tc.path, tc.token, w.Code, tc.status)
		}
		if w.Code == http.StatusForbidden && (strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "p1")) {
			t.Fatal("denial disclosed credential or project")
		}
	}
}

func TestRecoveryConfigFailsClosed(t *testing.T) {
	for _, raw := range []string{
		`[{"project_id":"p1","actor_id":"a","token":"x"},{"project_id":"p2","actor_id":"b","token":"x"}]`,
		`[{"project_id":"p1","actor_id":"","token":"x"}]`,
		`[{"project_id":"p1","actor_id":"a","token":""}]`,
		`[{"project_id":"p1","actor_id":"a","token":"x","role":"admin"}]`,
		`{"project_id":"p1","actor_id":"a","token":"x"}`,
		`[] garbage`,
	} {
		if _, _, err := ParseRecoveryKeys(raw); err == nil {
			t.Fatalf("accepted invalid recovery config: %s", raw)
		}
	}
	rs, n, err := ParseRecoveryKeys("")
	if err != nil || n != 0 {
		t.Fatalf("empty config: count=%d err=%v", n, err)
	}
	if _, ok := rs.ActorFor("p1", "anything"); ok {
		t.Fatal("absent recovery configuration granted access")
	}
	writers := NewMapStore(map[string][]string{"different-project": {"shared-token"}})
	if _, _, err := ParseRecoveryKeys(`[{"project_id":"p1","actor_id":"operator","token":"shared-token"}]`, writers); err == nil {
		t.Fatal("a recovery token shared with an ordinary writer on another project was accepted")
	}
}
