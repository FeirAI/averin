package api_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

// FEI-40: a keyed deployment reports a keyed fingerprint of every API key it accepts, per
// relationship "averin-api-key", so the verifier can check the key each calling plane sends is one
// averin accepts. The expected values are computed here independently (HMAC-SHA256 keyed by the
// token over the fixed label), and the report never contains a token.
func TestPosture_ReportsFingerprintsOfEveryAcceptedAPIKeyAndNeverTheKey(t *testing.T) {
	fp := func(secret string) string {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte("feir-secret-alignment/v1:averin-api-key"))
		return hex.EncodeToString(m.Sum(nil)[:16])
	}
	h := newServer(t).
		WithAuth(auth.NewMapStore(map[string][]string{"p1": {"tok-one", "tok-two"}, "p2": {"tok-three", "tok-one"}})).
		Routes()
	req := httptest.NewRequest(http.MethodGet, "/v2/posture?project=p1", nil)
	req.Header.Set("Authorization", "Bearer tok-one")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("keyed: %d", rec.Code)
	}
	var b struct {
		SecretFingerprints map[string][]string `json:"secret_fingerprints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	got := b.SecretFingerprints["averin-api-key"]
	want := map[string]bool{fp("tok-one"): true, fp("tok-two"): true, fp("tok-three"): true}
	if len(got) != len(want) {
		t.Fatalf("fingerprints = %v, want the %d distinct accepted keys", got, len(want))
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected fingerprint %s", g)
		}
	}
	for _, tok := range []string{"tok-one", "tok-two", "tok-three"} {
		if strings.Contains(rec.Body.String(), tok) {
			t.Fatalf("the posture report must never carry an API key (%q found)", tok)
		}
	}
}

// An open or unkeyed deployment accepts no key by value: it reports no fingerprint (an empty object,
// not a fingerprint of nothing), which the verifier reads as "nothing to compare".
func TestPosture_OpenDeploymentReportsNoFingerprints(t *testing.T) {
	for name, h := range map[string]http.Handler{
		"no auth store": newServer(t).Routes(),
		"explicit open": newServer(t).WithAuth(auth.NewOpenStore()).Routes(),
	} {
		_, b := postureReq(h, "p1", "")
		sf, ok := b["secret_fingerprints"].(map[string]any)
		if !ok || len(sf) != 0 {
			t.Errorf("%s: secret_fingerprints = %v, want an empty object", name, b["secret_fingerprints"])
		}
	}
}
