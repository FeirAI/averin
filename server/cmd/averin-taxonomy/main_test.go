package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSeedHexFromOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taxonomy-seed")
	want := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadSeedHex("", path)
	if err != nil {
		t.Fatalf("loadSeedHex: %v", err)
	}
	if got != want {
		t.Fatalf("seed mismatch")
	}
}

func TestLoadSeedHexRejectsGroupReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taxonomy-seed")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSeedHex("", path); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("want owner-only refusal, got %v", err)
	}
}

func TestLoadSeedHexRequiresExactlyOneSource(t *testing.T) {
	if _, err := loadSeedHex("", ""); err == nil {
		t.Fatal("want missing-source refusal")
	}
	if _, err := loadSeedHex(strings.Repeat("a", 64), "seed-file"); err == nil {
		t.Fatal("want conflicting-source refusal")
	}
}
