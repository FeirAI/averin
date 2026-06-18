package broker

import (
	"encoding/hex"
	"testing"

	"github.com/feir-dev/feir/server/internal/goldenvec"
)

func TestRevocationLeafAndMerkleRootGoldenVector(t *testing.T) {
	// Cross-language pinned vectors from the SHARED file — MUST equal Rust verify::revocation_leaf and
	// verify::revocation_merkle_root. Drift in the leaf preimage OR the tree fold (0x00/0x01 separation,
	// sentinels, odd-promote, sort order) fails here AND in Rust against the same one file (ADR 0005 M5).
	v, err := goldenvec.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.RevocationLeaf) == 0 || len(v.RevocationMerkleRoot) == 0 {
		t.Fatal("shared vector: revocation_leaf / revocation_merkle_root section is empty")
	}
	for _, c := range v.RevocationLeaf {
		l := RevocationLeaf(c.GrantID)
		if got := hex.EncodeToString(l[:]); got != c.ExpectHex {
			t.Errorf("revocation_leaf case %q drifted: got %s want %s", c.Name, got, c.ExpectHex)
		}
	}
	for _, c := range v.RevocationMerkleRoot {
		if got := BuildRevocationTree(c.Revoked).RootHex(); got != c.Expect {
			t.Errorf("revocation_merkle_root case %q drifted: got %s want %s", c.Name, got, c.Expect)
		}
	}
}
