package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The closed vocabularies live in three places (core/src/refusal.rs, this package, vectors/refusal-classes.v1.json).
// The server copy must equal the spec file; core has the same pin in core/tests/gateway_refusal.rs.
func TestRefusalVocabularyMatchesSpec(t *testing.T) {
	raw, err := os.ReadFile("../../../vectors/refusal-classes.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Classes     []string `json:"reason_classes"`
		EntryPoints []string `json:"entry_points"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(refusalReasonClasses, ","), strings.Join(spec.Classes, ","); got != want {
		t.Fatalf("server classes %s != spec %s", got, want)
	}
	if got, want := strings.Join(refusalEntryPoints, ","), strings.Join(spec.EntryPoints, ","); got != want {
		t.Fatalf("server entry points %s != spec %s", got, want)
	}
}
