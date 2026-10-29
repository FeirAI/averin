package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// feir-ops#16: the FFI (cgo) target replays the same rows as the native Rust test
// (core/tests/canonical_shape.rs) and the WASM test (verifier/test/canonical-shape.test.js). The bundles are
// signed by a TEST-ONLY seed-0 key, the key of spec/fixtures/bundle-valid.json.
func TestCanonicalShapeVectorsCgo(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "fixtures", "canonical-shape-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name       string `json:"name"`
		BundleJSON string `json:"bundle_json"`
		OptsJSON   string `json:"opts_json"`
		OK         bool   `json:"expected_ok"`
		Proven     int    `json:"expected_records_proven"`
		Verified   int    `json:"expected_checkpoints_verified"`
		Reason     string `json:"expected_reason"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 20 {
		t.Fatalf("expected 20 rows, got %d", len(rows))
	}
	c, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		out := c.VerifyBundleWith(row.BundleJSON, row.OptsJSON)
		var rep struct {
			OK       bool `json:"ok"`
			Proven   int  `json:"records_proven"`
			Verified int  `json:"checkpoints_verified"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("%s: %v", row.Name, err)
		}
		if rep.OK != row.OK || rep.Proven != row.Proven || rep.Verified != row.Verified || !strings.Contains(out, row.Reason) {
			t.Fatalf("%s: cgo report diverged from the native vector: %s", row.Name, out)
		}
	}
}
