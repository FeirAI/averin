package broker

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// revocationV2Vector is the shared Go/Rust contract for the plan 009 revocation tree
// (spec/golden-vectors/revocation-v2.json). Set AVERIN_WRITE_REVOCATION_V2_VECTOR=1 to regenerate.
func revocationV2Vector(t *testing.T) map[string]any {
	t.Helper()
	keyCases := []any{}
	for _, g := range []string{"grant-1", "é-grant", "Ω-grant-🔑"} {
		keyCases = append(keyCases, map[string]any{
			"grant_id": g, "preimage_hex": hex.EncodeToString(RevocationKeyV2Preimage(g)),
			"key_hex": hex.EncodeToString(func() []byte { k := RevocationKeyV2(g); return k[:] }()),
		})
	}
	stateCases := []any{}
	for _, c := range []struct {
		mode   string
		cutoff int64
	}{{"total", 0}, {"prospective", 7}, {"prospective", 1 << 40}, {"sentinel", 0}} {
		d := RevocationStateV2(c.mode, c.cutoff)
		stateCases = append(stateCases, map[string]any{
			"mode": c.mode, "cutoff": c.cutoff,
			"preimage_hex": hex.EncodeToString(RevocationStateV2Preimage(c.mode, c.cutoff)), "digest_hex": hex.EncodeToString(d[:]),
		})
	}
	key, state := RevocationKeyV2("grant-1"), RevocationStateV2("prospective", 7)
	entry := RevocationEntryV2(key, state)
	entries := []RevocationStateEntry{{"grant-1", "prospective", 7}, {"grant-2", "total", 0}, {"é-grant", "prospective", 3}}
	tree, err := BuildRevocationTreeV2(entries)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"description": "Plan 009 v2 revocation tree: key, committed state and entry preimages, root and proofs. Checked by server/internal/broker and core/tests/golden.rs.",
		"key_cases":   keyCases,
		"state_cases": stateCases,
		"entry_case": map[string]any{
			"key_hex": hex.EncodeToString(key[:]), "state_hex": hex.EncodeToString(state[:]),
			"preimage_hex": hex.EncodeToString(RevocationEntryV2Preimage(key, state)), "entry_hex": hex.EncodeToString(entry[:]),
		},
		"tree": map[string]any{
			"entries":         []any{map[string]any{"grant_id": "grant-1", "mode": "prospective", "cutoff_order": 7}, map[string]any{"grant_id": "grant-2", "mode": "total"}, map[string]any{"grant_id": "é-grant", "mode": "prospective", "cutoff_order": 3}},
			"root":            tree.RootHex(),
			"leaf_count":      tree.LeafCount(),
			"membership":      tree.Proof("grant-1"),
			"nonmembership":   tree.Proof("grant-3"),
			"nonmember_grant": "grant-3",
		},
	}
}

func TestRevocationV2GoldenVector(t *testing.T) {
	got, err := json.MarshalIndent(revocationV2Vector(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "..", "spec", "golden-vectors", "revocation-v2.json")
	if os.Getenv("AVERIN_WRITE_REVOCATION_V2_VECTOR") == "1" {
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("Go v2 revocation tree drifted from the shared vector:\n%s", got)
	}
}

func TestRevocationTreeV2RejectsMalformedEntries(t *testing.T) {
	for _, bad := range [][]RevocationStateEntry{
		{{"g", "total", 3}},
		{{"g", "prospective", 0}},
		{{"g", "sometimes", 0}},
		{{"g", "total", 0}, {"g", "prospective", 2}},
		{{"", "total", 0}},
	} {
		if _, err := BuildRevocationTreeV2(bad); err == nil {
			t.Fatalf("malformed entries accepted: %+v", bad)
		}
	}
}
