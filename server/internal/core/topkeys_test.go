package core

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

// TestAllowedTopKeysParity pins the Go mirror against ALLOWED_TOP_KEYS in core/src/record.rs.
func TestAllowedTopKeysParity(t *testing.T) {
	src, err := os.ReadFile("../../../core/src/record.rs")
	if err != nil {
		t.Fatal(err)
	}
	blk := regexp.MustCompile(`(?s)pub const ALLOWED_TOP_KEYS: &\[&str\] = &\[(.*?)\];`).FindSubmatch(src)
	if blk == nil {
		t.Fatal("ALLOWED_TOP_KEYS not found in core/src/record.rs")
	}
	var want []string
	for _, m := range regexp.MustCompile(`(?m)^\s*"([a-z_]+)",`).FindAllSubmatch(blk[1], -1) {
		want = append(want, string(m[1]))
	}
	var got []string
	for k := range AllowedTopKeys {
		got = append(got, k)
	}
	sort.Strings(want)
	sort.Strings(got)
	if len(want) == 0 || len(want) != len(got) {
		t.Fatalf("mirror drift: rust %v go %v", want, got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("mirror drift at %d: rust %q go %q", i, want[i], got[i])
		}
	}
}
