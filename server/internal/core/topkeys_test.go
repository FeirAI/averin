package core

import (
	"os"
	"reflect"
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

// rustList reads one `pub const NAME: &[&str] = &[...]` list from core/src/record.rs, in source order.
func rustList(t *testing.T, name string) []string {
	t.Helper()
	src, err := os.ReadFile("../../../core/src/record.rs")
	if err != nil {
		t.Fatal(err)
	}
	blk := regexp.MustCompile(`(?s)pub const ` + name + `: &\[&str\] = &\[(.*?)\];`).FindSubmatch(src)
	if blk == nil {
		t.Fatalf("%s not found in core/src/record.rs", name)
	}
	var out []string
	for _, m := range regexp.MustCompile(`"([a-z_]+)"`).FindAllSubmatch(blk[1], -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// TestNestedKeysParity pins every nested closed-member-set mirror against its Rust list.
func TestNestedKeysParity(t *testing.T) {
	for name, got := range map[string][]string{
		"ALLOWED_AUTHORITY_KEYS":           AllowedAuthorityKeys,
		"ALLOWED_POLICY_SNAPSHOT_REF_KEYS": AllowedPolicySnapshotRefKeys,
		"ALLOWED_CONTENT_KEYS":             AllowedContentKeys,
		"ALLOWED_TOKENS_KEYS":              AllowedTokensKeys,
		"ALLOWED_COMMIT_KEYS":              AllowedCommitKeys,
		"COMMIT_FIELDS":                    CommitFields,
	} {
		want := rustList(t, name)
		if len(want) == 0 || !reflect.DeepEqual(want, got) {
			t.Fatalf("mirror drift for %s: rust %v go %v", name, want, got)
		}
	}
}

func TestUnknownNestedMember(t *testing.T) {
	ok := map[string]any{
		"authority":         map[string]any{"source": "x", "policy_snapshot_ref": map[string]any{"uri": "u"}},
		"tokens":            map[string]any{"in": 1.0, "out": 2.0},
		"content":           map[string]any{"uri": "u"},
		"input_commit":      map[string]any{"alg": "a"},
		"extensions":        map[string]any{"anything": map[string]any{"goes": true}},
		"credential_commit": "not an object",
	}
	if got := UnknownNestedMember(ok); got != "" {
		t.Fatalf("conforming record refused: %q", got)
	}
	for _, c := range []struct{ path, want string }{
		{"authority", "authority.bogus"},
		{"policy_snapshot_ref", "authority.policy_snapshot_ref.bogus"},
		{"content", "content.bogus"},
		{"tokens", "tokens.bogus"},
		{"input_commit", "input_commit.bogus"},
		{"output_commit", "output_commit.bogus"},
		{"rationale_commit", "rationale_commit.bogus"},
		{"credential_commit", "credential_commit.bogus"},
	} {
		rec := map[string]any{}
		switch c.path {
		case "policy_snapshot_ref":
			rec["authority"] = map[string]any{"policy_snapshot_ref": map[string]any{"bogus": 1.0}}
		default:
			rec[c.path] = map[string]any{"bogus": 1.0}
		}
		if got := UnknownNestedMember(rec); got != c.want {
			t.Fatalf("%s: got %q want %q", c.path, got, c.want)
		}
	}
}
