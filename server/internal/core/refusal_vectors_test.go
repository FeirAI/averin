package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// cross-impl-refusal-vector: the FFI (cgo) target replays the same rows as the native Rust test
// (core/tests/gateway_refusal.rs) and the WASM test (verifier/test/gateway-refusal.test.js). The vectors are
// signed by TEST-ONLY keys (spec/test-keys.json).
func TestGatewayRefusalVectorsCgo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "fixtures", "gateway-refusal-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name                 string         `json:"name"`
		BundleJSON           string         `json:"bundle_json"`
		OptsJSON             string         `json:"opts_json"`
		ExpectedOK           bool           `json:"expected_ok"`
		ExpectedRefusals     int            `json:"expected_gateway_refusals"`
		ExpectedAttempts     int            `json:"expected_gateway_refusal_attempts"`
		ExpectedByClass      map[string]int `json:"expected_gateway_refusals_by_class"`
		ExpectedRefusalIssue bool           `json:"expected_refusal_issue"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("expected 4 rows, got %d", len(rows))
	}
	c, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		var rep struct {
			OK       bool           `json:"ok"`
			Refusals int            `json:"gateway_refusals"`
			Attempts int            `json:"gateway_refusal_attempts"`
			ByClass  map[string]int `json:"gateway_refusals_by_class"`
			Issues   []string       `json:"issues"`
		}
		if err := json.Unmarshal([]byte(c.VerifyBundleWith(row.BundleJSON, row.OptsJSON)), &rep); err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		hasIssue := false
		for _, i := range rep.Issues {
			if len(i) >= 15 && i[:15] == "gateway refusal" {
				hasIssue = true
			}
		}
		if rep.OK != row.ExpectedOK || rep.Refusals != row.ExpectedRefusals || rep.Attempts != row.ExpectedAttempts ||
			!reflect.DeepEqual(rep.ByClass, row.ExpectedByClass) || hasIssue != row.ExpectedRefusalIssue {
			t.Fatalf("%s: cgo report diverged from the native vector: %+v", row.Name, rep)
		}
	}
}
