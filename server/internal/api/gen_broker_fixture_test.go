package api_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/feir-dev/feir/server/internal/core"
)

// TestGenerateBrokerFixture regenerates spec/fixtures/bundle-broker-valid.json — a REAL Go-produced
// Tier-A/B broker bundle (a gateway_enforced grant + a two-phase use, test-anchored) together with the
// verify `opts` that pin the broker/resource/tsa recording keys. It is the broker-path fixture the
// WASM/JS offline verifier test (verifier/test/broker.test.js) loads, so the browser build's
// verification of the credential-broker surface is exercised against a real producer bundle — not only
// natively in Rust. Skipped in normal runs; regenerate deterministically with:
//
//	FEIR_GEN_BROKER_FIXTURE=1 go test ./internal/api -run TestGenerateBrokerFixture
func TestGenerateBrokerFixture(t *testing.T) {
	if os.Getenv("FEIR_GEN_BROKER_FIXTURE") == "" {
		t.Skip("set FEIR_GEN_BROKER_FIXTURE=1 to regenerate spec/fixtures/bundle-broker-valid.json")
	}
	h := newBrokerResourceServer(t)
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")

	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(resp), &intent)
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	if code, oresp := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, oresp)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	opts := map[string]any{
		"broker_authority_keys":   []string{c.PubKey()},
		"resource_authority_keys": []string{rc.PubKey()},
		"tsa_keys":                []string{tsaPubEncoded(tsa)},
	}
	optsJSON, _ := json.Marshal(opts)

	// Refuse to write a fixture that doesn't verify clean with the pinned roles.
	rep := c.VerifyBundleWith(anchored, string(optsJSON))
	if !strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, `"uses_matched":1`) {
		t.Fatalf("refusing to write a broker fixture that does not verify clean: %s", rep)
	}

	wrapper := map[string]any{
		"_comment": "Real Go-produced Tier-A/B broker bundle (gateway_enforced grant + two-phase use, " +
			"test-anchored). The WASM/JS offline-verifier broker-path test (verifier/test/broker.test.js) " +
			"verifies `bundle` via feir_verify_bundle_with(bundle, opts), pinning the broker/resource/tsa " +
			"keys in `opts`. Regenerate: FEIR_GEN_BROKER_FIXTURE=1 go test ./internal/api -run TestGenerateBrokerFixture.",
		"opts":   opts,
		"bundle": json.RawMessage(anchored),
	}
	out, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	_, self, _, _ := runtime.Caller(0)
	// self = <repo>/server/internal/api/gen_broker_fixture_test.go -> repo root is three dirs up.
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	path := filepath.Join(root, "spec", "fixtures", "bundle-broker-valid.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(out))
}
