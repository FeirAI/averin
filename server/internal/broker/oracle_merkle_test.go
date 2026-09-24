package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The private producer functions are the ones BuildRevocationTree uses. Pin
// their hashes to the Lean model's distinct 0x00 leaf and 0x01 node bytes.
func TestRevocationMerkleHashInputsMatchLeanOracle(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	type inRow struct {
		Kind  string `json:"kind"`
		Left  string `json:"left"`
		Right string `json:"right"`
	}
	type outRow struct {
		Kind string `json:"kind"`
		Hex  string `json:"hex"`
	}
	var inputs struct {
		Merkle []inRow `json:"merkle"`
	}
	var expected struct {
		Merkle []outRow `json:"merkle"`
	}
	read := func(name string, dst any) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, "formal", "oracle", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	read("inputs.json", &inputs)
	read("expected.json", &expected)
	if len(inputs.Merkle) < 3 || len(inputs.Merkle) != len(expected.Merkle) {
		t.Fatal("Merkle corpus incomplete")
	}
	for i, row := range inputs.Merkle {
		if row.Kind != expected.Merkle[i].Kind {
			t.Fatal("Merkle kind mismatch")
		}
		leftBytes, err := hex.DecodeString(row.Left)
		if err != nil || len(leftBytes) != 32 {
			t.Fatal("invalid left leaf")
		}
		var left [32]byte
		copy(left[:], leftBytes)
		var got [32]byte
		switch row.Kind {
		case "leaf":
			got = merkleLeafHash(left)
		case "node":
			rightBytes, err := hex.DecodeString(row.Right)
			if err != nil || len(rightBytes) != 32 {
				t.Fatal("invalid right leaf")
			}
			var right [32]byte
			copy(right[:], rightBytes)
			got = merkleNodeHash(left, right)
		default:
			t.Fatalf("unknown Merkle kind %q", row.Kind)
		}
		pre, err := hex.DecodeString(expected.Merkle[i].Hex)
		if err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256(pre)
		if got != want {
			t.Errorf("%s row %d: Go hash %x != Lean-preimage hash %x", row.Kind, i, got, want)
		}
	}
}
