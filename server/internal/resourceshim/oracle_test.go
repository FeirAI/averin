package resourceshim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Check the ledger producer against each Lean-generated ledger preimage, not
// only the one shared broker golden vector.
func TestLedgerCommitmentMatchesLeanOracleVariations(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	type field struct {
		S   *string `json:"s"`
		U64 *int64  `json:"u64"`
	}
	type inRow struct {
		Family string  `json:"family"`
		Fields []field `json:"fields"`
	}
	type outRow struct {
		Family string `json:"family"`
		Hex    string `json:"hex"`
	}
	var inputs struct {
		Families []inRow `json:"families"`
		Variants []inRow `json:"preimage_variants"`
	}
	var expected struct {
		Families []outRow `json:"families"`
		Variants []outRow `json:"preimage_variants"`
	}
	load := func(name string, dst any) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, "formal", "oracle", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	load("inputs.json", &inputs)
	load("expected.json", &expected)
	count := 0
	check := func(ins []inRow, outs []outRow) {
		t.Helper()
		if len(ins) != len(outs) {
			t.Fatal("oracle row count mismatch")
		}
		for i, row := range ins {
			if row.Family != "use ledger" {
				continue
			}
			if row.Family != outs[i].Family {
				t.Fatal("oracle family mismatch")
			}
			pre, err := hex.DecodeString(outs[i].Hex)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(pre)
			got := strings.TrimPrefix(ledgerCommitment(*row.Fields[0].S, *row.Fields[1].S, *row.Fields[2].U64), "sha256:")
			if got != hex.EncodeToString(sum[:]) {
				t.Errorf("ledger row %d: got %s want %x", i, got, sum)
			}
			count++
		}
	}
	check(inputs.Families, expected.Families)
	check(inputs.Variants, expected.Variants)
	if count < 4 {
		t.Fatalf("ledger corpus missing field mutations: %d", count)
	}
}
