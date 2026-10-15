package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI writes the two files the server reads, and the server's own loader accepts them.
func TestKeyrotateWritesFilesTheLineageAccepts(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "keyrotate")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	oldS := filepath.Join(dir, "old.seed")
	newS := filepath.Join(dir, "new.seed")
	os.WriteFile(oldS, []byte(strings.Repeat("ab", 32)+"\n"), 0o600)
	os.WriteFile(newS, []byte(strings.Repeat("cd", 32)+"\n"), 0o600)
	rot, ret := filepath.Join(dir, "rotations.json"), filepath.Join(dir, "retired.json")
	run := func(args ...string) (string, error) {
		out, err := exec.Command(bin, args...).CombinedOutput()
		return string(out), err
	}
	out, err := run("--reason", "scheduled", "--rotated-at", "2026-07-01T00:00:00.000Z",
		"--old-id", "k0", "--old-epoch", "0", "--old-seed-file", oldS,
		"--new-id", "k1", "--new-epoch", "1", "--new-seed-file", newS,
		"--rotations-file", rot, "--retired-file", ret)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var stmts []map[string]any
	var retired []map[string]any
	b, _ := os.ReadFile(rot)
	if err := json.Unmarshal(b, &stmts); err != nil || len(stmts) != 1 || stmts[0]["sig_old"] == nil {
		t.Fatalf("rotations file: %v %s", err, b)
	}
	b, _ = os.ReadFile(ret)
	if err := json.Unmarshal(b, &retired); err != nil || len(retired) != 1 || retired[0]["key_status"] != "retired" {
		t.Fatalf("retired file: %v %s", err, b)
	}
	// a scheduled rotation without the old seed, and a world-readable seed, are refused
	if _, err := run("--reason", "scheduled", "--rotated-at", "2026-07-01T00:00:00.000Z", "--old-id", "k0",
		"--old-public-key", "ed25519pub:AAAA", "--new-id", "k1", "--new-seed-file", newS,
		"--rotations-file", rot, "--retired-file", ret); err == nil {
		t.Fatal("scheduled rotation without the old seed must fail")
	}
	os.Chmod(newS, 0o644)
	if _, err := run("--reason", "compromise", "--rotated-at", "2026-07-01T00:00:00.000Z", "--old-id", "k0",
		"--old-public-key", "ed25519pub:AAAA", "--new-id", "k1", "--new-seed-file", newS,
		"--rotations-file", rot, "--retired-file", ret); err == nil {
		t.Fatal("a group-readable seed file must be refused")
	}
}
