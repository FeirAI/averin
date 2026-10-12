package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
)

func postureReq(h http.Handler, project, bearer string) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodGet, "/v2/posture?project="+project, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// On a keyed deployment the report needs the project's bearer; with it, it reports the guards the
// process was started with.
func TestPosture_KeyedDeploymentReportsItsGuardsAndRefusesAnonymous(t *testing.T) {
	h := newServer(t).
		WithAuth(auth.NewMapStore(map[string][]string{"p1": {"s3cret"}})).
		WithPosture(api.Posture{RequireProdSecrets: true, DurableStore: true, CoreRustc: "rustc 1.99.0 (test)"}).
		Routes()
	if code, _ := postureReq(h, "p1", ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d, want 401", code)
	}
	if code, _ := postureReq(h, "p1", "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer: %d, want 401", code)
	}
	code, b := postureReq(h, "p1", "s3cret")
	if code != http.StatusOK {
		t.Fatalf("keyed: %d, want 200", code)
	}
	if b["plane"] != "averin" || b["schema"] != float64(api.PostureSchema) {
		t.Fatalf("plane/schema = %v/%v", b["plane"], b["schema"])
	}
	for k, want := range map[string]bool{
		"require_prod_secrets": true, "api_keys_configured": true, "durable_store": true,
		"signing_seed_is_dev": false, "require_pinned_authority": true, "require_body_bound_authority": false,
	} {
		if b[k] != want {
			t.Errorf("%s = %v, want %v", k, b[k], want)
		}
	}
	build := b["build"].(map[string]any)
	if build["go_version"] != runtime.Version() || build["core_rustc"] != "rustc 1.99.0 (test)" {
		t.Errorf("build = %v", build)
	}
}

// An unauthenticated deployment answers, and says so: api_keys_configured=false is the violation the
// verifier reports. A server nobody wired a posture into claims no guard.
func TestPosture_OpenDeploymentReportsNoKeysAndNoGuards(t *testing.T) {
	for name, h := range map[string]http.Handler{
		"no auth store": newServer(t).Routes(),
		"explicit open": newServer(t).WithAuth(auth.NewOpenStore()).Routes(),
	} {
		code, b := postureReq(h, "p1", "")
		if code != http.StatusOK {
			t.Fatalf("%s: %d, want 200", name, code)
		}
		for _, k := range []string{"require_prod_secrets", "api_keys_configured", "durable_store", "signing_seed_is_dev"} {
			if b[k] != false {
				t.Errorf("%s: %s = %v, want false", name, k, b[k])
			}
		}
	}
}

func TestPosture_ReportsTheAuthorityPinSwitches(t *testing.T) {
	h := newServer(t).WithRequirePinnedAuthority(false).WithRequireBodyBoundAuthority(true).Routes()
	_, b := postureReq(h, "p1", "")
	if b["require_pinned_authority"] != false || b["require_body_bound_authority"] != true {
		t.Fatalf("pin switches = %v / %v", b["require_pinned_authority"], b["require_body_bound_authority"])
	}
}
