package secretfp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type vectorFile struct {
	LabelPrefix string `json:"label_prefix"`
	Cases       []struct {
		Name         string `json:"name"`
		Secret       string `json:"secret"`
		Relationship string `json:"relationship"`
		Fingerprint  string `json:"fingerprint"`
	} `json:"cases"`
}

// The fingerprint reproduces every golden vector from the independent Python reference.
func TestFingerprintMatchesTheGoldenVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "vectors", "secret-fingerprint.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.LabelPrefix != labelPrefix {
		t.Fatalf("label prefix %q, vectors say %q", labelPrefix, v.LabelPrefix)
	}
	if len(v.Cases) < 8 {
		t.Fatalf("only %d vectors", len(v.Cases))
	}
	for _, c := range v.Cases {
		if got := Fingerprint(c.Secret, c.Relationship); got != c.Fingerprint {
			t.Errorf("%s: fingerprint = %s, want %s", c.Name, got, c.Fingerprint)
		}
	}
}

func TestFingerprintShapeAndRelationshipSeparation(t *testing.T) {
	a := Fingerprint("s", "leria-outbox")
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(a) {
		t.Fatalf("fingerprint %q is not 32 lowercase hex characters", a)
	}
	if a == Fingerprint("s", "vultrino-outbox-poll") {
		t.Fatal("one secret must have a different fingerprint per relationship")
	}
	if a == Fingerprint("s2", "leria-outbox") {
		t.Fatal("different secrets must have different fingerprints")
	}
	if strings.Contains(a, "s") && a == "s" {
		t.Fatal("never the secret")
	}
	if Fingerprint("", "leria-outbox") != "" {
		t.Fatal("an empty secret has no fingerprint")
	}
}

func TestFingerprintsKeepOrderDropEmptyAndDuplicates(t *testing.T) {
	got := Fingerprints([]string{"b", "", "a", "b"}, "leria-outbox")
	want := []string{Fingerprint("b", "leria-outbox"), Fingerprint("a", "leria-outbox")}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
	if Fingerprints(nil, "x") != nil || Fingerprints([]string{""}, "x") != nil {
		t.Fatal("nothing to fingerprint must be nil")
	}
}
