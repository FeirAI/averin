package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
)

// revocationLeafTag domain-separates a revocation leaf hash (ADR 0005 M5 Merkle-non-disclosure) from every other
// preimage. A leaf VALUE binds a grant_id; the tree's leaves are the SORTED set of these, sentinel-bracketed.
const revocationLeafTag = "averin.broker.revocation.leaf.v1"

// RevocationLeaf = sha256( LP4(tag) ‖ LP4(grant_id) ): the 32-byte leaf VALUE for a (possibly) revoked grant_id,
// byte-identical to the Rust verifier's revocation_leaf. The tree leaves are the SORTED set of these, bracketed
// by the MIN (0x00*32) / MAX (0xff*32) sentinels so every queried id has a strictly-bracketing consecutive pair.
func RevocationLeaf(grantID string) [32]byte {
	h := sha256.New()
	lp4 := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	lp4(revocationLeafTag)
	lp4(grantID)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// merkleLeafHash = sha256( 0x00 ‖ v ); merkleNodeHash = sha256( 0x01 ‖ l ‖ r ) — RFC6962 domain separation,
// byte-identical to the Rust verifier (a leaf can never be reinterpreted as an interior node).
func merkleLeafHash(v [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(v[:])
	var o [32]byte
	copy(o[:], h.Sum(nil))
	return o
}

func merkleNodeHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var o [32]byte
	copy(o[:], h.Sum(nil))
	return o
}

// RevocationTree is a sorted, sentinel-bracketed Merkle tree over a revoked grant set (ADR 0005 M5). It produces
// the signed root + the per-grant (non-)membership proofs the offline verifier checks.
type RevocationTree struct {
	leaves [][32]byte   // sorted leaf VALUES (incl. the MIN/MAX sentinels)
	levels [][][32]byte // levels[0] = leaf hashes, ascending to levels[last] = [root]
}

// BuildRevocationTree builds the tree over the SORTED, sentinel-bracketed leaves for `revoked` (deduping is the
// caller's responsibility; duplicate grant_ids fold to one leaf via the sort being stable on equal values).
func BuildRevocationTree(revoked []string) *RevocationTree {
	hs := make([][32]byte, 0, len(revoked))
	for _, g := range revoked {
		hs = append(hs, RevocationLeaf(g))
	}
	sort.Slice(hs, func(i, j int) bool { return bytes.Compare(hs[i][:], hs[j][:]) < 0 })
	leaves := make([][32]byte, 0, len(hs)+2)
	leaves = append(leaves, [32]byte{}) // MIN sentinel
	leaves = append(leaves, hs...)
	var max [32]byte
	for i := range max {
		max[i] = 0xff
	}
	leaves = append(leaves, max) // MAX sentinel

	level := make([][32]byte, len(leaves))
	for i, v := range leaves {
		level[i] = merkleLeafHash(v)
	}
	levels := [][][32]byte{append([][32]byte(nil), level...)}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); {
			if i+1 < len(level) {
				next = append(next, merkleNodeHash(level[i], level[i+1]))
				i += 2
			} else {
				next = append(next, level[i]) // promote the last (odd) node
				i++
			}
		}
		levels = append(levels, append([][32]byte(nil), next...))
		level = next
	}
	return &RevocationTree{leaves: leaves, levels: levels}
}

// RootHex returns the Merkle root as "sha256:<hex>" (what SignRevocationMerkleRoot commits to).
func (t *RevocationTree) RootHex() string {
	r := t.levels[len(t.levels)-1][0]
	return "sha256:" + hex.EncodeToString(r[:])
}

// LeafCount is the tree's leaf count (incl. the 2 sentinels); covered by the signed root.
func (t *RevocationTree) LeafCount() int { return len(t.leaves) }

func (t *RevocationTree) auditPath(index int) []any {
	var path []any
	idx := index
	for _, level := range t.levels {
		if len(level) <= 1 {
			break
		}
		last := len(level) - 1
		if idx%2 == 1 {
			path = append(path, hex.EncodeToString(level[idx-1][:]))
		} else if idx < last {
			path = append(path, hex.EncodeToString(level[idx+1][:]))
		}
		idx /= 2
	}
	if path == nil {
		path = []any{}
	}
	return path
}

// NonMembershipProof builds a proof that grantID is NOT in the revoked set (two consecutive leaves strictly
// bracketing its leaf). Returns nil if grantID IS revoked (no such bracket exists) — the caller must then issue
// a MembershipProof instead (or the use is blocked).
func (t *RevocationTree) NonMembershipProof(grantID string) map[string]any {
	q := RevocationLeaf(grantID)
	for k := 0; k+1 < len(t.leaves); k++ {
		if bytes.Compare(t.leaves[k][:], q[:]) < 0 && bytes.Compare(q[:], t.leaves[k+1][:]) < 0 {
			return map[string]any{
				"type":     "nonmembership",
				"lo":       hex.EncodeToString(t.leaves[k][:]),
				"hi":       hex.EncodeToString(t.leaves[k+1][:]),
				"lo_index": k,
				"hi_index": k + 1,
				"lo_path":  t.auditPath(k),
				"hi_path":  t.auditPath(k + 1),
			}
		}
	}
	return nil
}

// MembershipProof builds a proof that grantID IS in the revoked set. Returns nil if grantID is not revoked.
func (t *RevocationTree) MembershipProof(grantID string) map[string]any {
	q := RevocationLeaf(grantID)
	for k := range t.leaves {
		if t.leaves[k] == q {
			return map[string]any{"type": "membership", "index": k, "path": t.auditPath(k)}
		}
	}
	return nil
}
