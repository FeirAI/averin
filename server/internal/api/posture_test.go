package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
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
	if b["dev_mode"] != false {
		t.Errorf("dev_mode = %v, want false for a process started without AVERIN_DEV_MODE", b["dev_mode"])
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

// AVE-06: a process started in dev mode says so, and a handler nobody wired a posture into claims no dev
// mode either (the verifier then fails the missing guards, not a silent absence).
func TestPosture_ReportsDevMode(t *testing.T) {
	h := newServer(t).WithPosture(api.Posture{DevMode: true}).WithAuth(auth.NewOpenStore()).Routes()
	_, b := postureReq(h, "p1", "")
	if b["dev_mode"] != true {
		t.Fatalf("dev_mode = %v, want true", b["dev_mode"])
	}
	_, b = postureReq(newServer(t).WithAuth(auth.NewOpenStore()).Routes(), "p1", "")
	if b["dev_mode"] != false {
		t.Fatalf("an unwired posture reports dev_mode = %v, want false", b["dev_mode"])
	}
}

func TestPosture_ReportsTheAuthorityPinSwitches(t *testing.T) {
	h := newServer(t).WithRequirePinnedAuthority(false).WithRequireBodyBoundAuthority(true).Routes()
	_, b := postureReq(h, "p1", "")
	if b["require_pinned_authority"] != false || b["require_body_bound_authority"] != true {
		t.Fatalf("pin switches = %v / %v", b["require_pinned_authority"], b["require_body_bound_authority"])
	}
}

// The region label, the schema version and whether the runtime role was verified at startup are
// reported as given; a server nobody wired a posture into claims none of them.
func TestPosture_ReportsRegionSchemaVersionAndRuntimeRole(t *testing.T) {
	h := newServer(t).WithPosture(api.Posture{Region: "eu-central-1", SchemaVersion: 7, RuntimeRoleVerified: true}).Routes()
	_, b := postureReq(h, "p1", "")
	if b["region"] != "eu-central-1" || b["schema_version"] != float64(7) || b["runtime_role_verified"] != true {
		t.Fatalf("posture = %v", b)
	}
	_, z := postureReq(newServer(t).Routes(), "p1", "")
	if z["region"] != "" || z["schema_version"] != float64(0) || z["runtime_role_verified"] != false {
		t.Fatalf("a server with no posture claims region/schema/role: %v", z)
	}
}

func TestParseRegion(t *testing.T) {
	for _, c := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false}, {"  ", "", false}, {"eu-central-1", "eu-central-1", false}, {" eu-west-1 ", "eu-west-1", false},
		{"EU-west-1", "", true}, {"1eu", "", true}, {"-eu", "", true}, {"eu west", "", true}, {"eu_west", "", true},
		{strings.Repeat("a", api.MaxRegionLen), strings.Repeat("a", api.MaxRegionLen), false},
		{strings.Repeat("a", api.MaxRegionLen+1), "", true},
	} {
		got, err := api.ParseRegion(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("ParseRegion(%q) = %q, %v; want %q, err=%v", c.in, got, err, c.want, c.wantErr)
		}
	}
}

// Approver binding (AVE-10) is reported with its cutover, so a deploy-time verifier sees an explicit
// AVERIN_REQUIRE_APPROVER_BINDING=0 and a far-future AVERIN_APPROVER_BINDING_SINCE.
func TestPosture_ReportsApproverBinding(t *testing.T) {
	_, b := postureReq(newServer(t).WithRequireApproverBinding(true, "").Routes(), "p1", "")
	if b["require_approver_binding"] != true {
		t.Fatalf("require_approver_binding = %v, want true", b["require_approver_binding"])
	}
	if v, ok := b["approver_binding_since"]; !ok || v != nil {
		t.Fatalf("approver_binding_since = %v (present=%v), want null", v, ok)
	}
	_, b = postureReq(newServer(t).WithRequireApproverBinding(true, "2026-10-01T00:00:00.000Z").Routes(), "p1", "")
	if b["approver_binding_since"] != "2026-10-01T00:00:00.000Z" {
		t.Fatalf("approver_binding_since = %v", b["approver_binding_since"])
	}
	_, b = postureReq(newServer(t).WithRequireApproverBinding(false, "").Routes(), "p1", "")
	if b["require_approver_binding"] != false {
		t.Fatalf("require_approver_binding = %v, want false", b["require_approver_binding"])
	}
}
