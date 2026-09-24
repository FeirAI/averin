package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

// Plan 009 v2 revocation tree. Leaves are sorted by a grant key and commit the grant's revocation
// mode and cutoff, so a membership proof authenticates the cutoff and a stripped or altered cutoff
// no longer re-derives the signed root. Byte-identical to the Rust verifier's
// revocation_key_v2 / revocation_state_digest_v2 / revocation_entry_v2 (shared golden vector).
const (
	revocationKeyV2Tag   = "averin.broker.revocation.key.v2"
	revocationStateV2Tag = "averin.broker.revocation.state.v2"
	revocationEntryV2Tag = "averin.broker.revocation.entry.v2"
)

func lp4Write(buf *bytes.Buffer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	buf.Write(n[:])
	buf.Write(b)
}

// RevocationKeyV2Preimage = LP4(tag) ‖ LP4(grant_id).
func RevocationKeyV2Preimage(grantID string) []byte {
	var b bytes.Buffer
	lp4Write(&b, []byte(revocationKeyV2Tag))
	lp4Write(&b, []byte(grantID))
	return b.Bytes()
}

// RevocationKeyV2 is the sort key of a grant's leaf.
func RevocationKeyV2(grantID string) [32]byte { return sha256.Sum256(RevocationKeyV2Preimage(grantID)) }

// RevocationStateV2Preimage = LP4(tag) ‖ LP4(mode) ‖ BE8(cutoff): mode "total" (cutoff 0),
// "prospective" (cutoff >= 1) or "sentinel" (cutoff 0).
func RevocationStateV2Preimage(mode string, cutoff int64) []byte {
	var b bytes.Buffer
	lp4Write(&b, []byte(revocationStateV2Tag))
	lp4Write(&b, []byte(mode))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(cutoff))
	b.Write(n[:])
	return b.Bytes()
}

func RevocationStateV2(mode string, cutoff int64) [32]byte {
	return sha256.Sum256(RevocationStateV2Preimage(mode, cutoff))
}

// RevocationEntryV2Preimage = LP4(tag) ‖ key ‖ state_digest; its SHA-256 is the 32-byte leaf value
// folded by the RFC6962 tree (merkleLeafHash / merkleNodeHash, shared with v1).
func RevocationEntryV2Preimage(key, state [32]byte) []byte {
	var b bytes.Buffer
	lp4Write(&b, []byte(revocationEntryV2Tag))
	b.Write(key[:])
	b.Write(state[:])
	return b.Bytes()
}

func RevocationEntryV2(key, state [32]byte) [32]byte {
	return sha256.Sum256(RevocationEntryV2Preimage(key, state))
}

// RevocationStateEntry is one grant's committed revocation.
type RevocationStateEntry struct {
	GrantID     string
	Mode        string // "total" | "prospective"
	CutoffOrder int64  // prospective only
}

// RevocationTreeV2 is the sorted, sentinel-bracketed v2 tree.
type RevocationTreeV2 struct {
	keys    [][32]byte
	states  [][32]byte
	entries map[[32]byte]RevocationStateEntry
	tree    RevocationTree // the RFC6962 levels over the entry values
}

// BuildRevocationTreeV2 builds the v2 tree. Entries must name distinct grants with a valid mode;
// a prospective cutoff must be >= 1 and a total entry must carry no cutoff.
func BuildRevocationTreeV2(entries []RevocationStateEntry) (*RevocationTreeV2, error) {
	type pair struct {
		key, state [32]byte
		entry      RevocationStateEntry
	}
	pairs := make([]pair, 0, len(entries))
	seen := map[string]bool{}
	for _, e := range entries {
		if e.GrantID == "" || seen[e.GrantID] {
			return nil, fmt.Errorf("revocation tree v2: empty or duplicate grant %q", e.GrantID)
		}
		seen[e.GrantID] = true
		switch {
		case e.Mode == "total" && e.CutoffOrder == 0:
		case e.Mode == "prospective" && e.CutoffOrder >= 1:
		default:
			return nil, fmt.Errorf("revocation tree v2: invalid state for %q", e.GrantID)
		}
		pairs = append(pairs, pair{RevocationKeyV2(e.GrantID), RevocationStateV2(e.Mode, e.CutoffOrder), e})
	}
	sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].key[:], pairs[j].key[:]) < 0 })
	sentinel := RevocationStateV2("sentinel", 0)
	var max [32]byte
	for i := range max {
		max[i] = 0xff
	}
	t := &RevocationTreeV2{entries: map[[32]byte]RevocationStateEntry{}}
	t.keys = append(t.keys, [32]byte{})
	t.states = append(t.states, sentinel)
	for _, p := range pairs {
		t.keys = append(t.keys, p.key)
		t.states = append(t.states, p.state)
		t.entries[p.key] = p.entry
	}
	t.keys = append(t.keys, max)
	t.states = append(t.states, sentinel)
	values := make([][32]byte, len(t.keys))
	for i := range t.keys {
		values[i] = RevocationEntryV2(t.keys[i], t.states[i])
	}
	level := make([][32]byte, len(values))
	for i, v := range values {
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
				next = append(next, level[i])
				i++
			}
		}
		levels = append(levels, append([][32]byte(nil), next...))
		level = next
	}
	t.tree = RevocationTree{leaves: values, levels: levels}
	return t, nil
}

func (t *RevocationTreeV2) RootHex() string { return t.tree.RootHex() }
func (t *RevocationTreeV2) LeafCount() int  { return t.tree.LeafCount() }

// Proof returns the grant's v2 proof: a membership proof carrying its clear mode and cutoff, or a
// non-membership proof revealing only the neighbours' keys and opaque state digests.
func (t *RevocationTreeV2) Proof(grantID string) map[string]any {
	q := RevocationKeyV2(grantID)
	for k := range t.keys {
		if t.keys[k] == q {
			e := t.entries[q]
			p := map[string]any{"type": "membership", "index": k, "path": t.tree.auditPath(k), "mode": e.Mode}
			if e.Mode == "prospective" {
				p["cutoff_order"] = e.CutoffOrder
			}
			return p
		}
	}
	side := func(k int) map[string]any {
		return map[string]any{"key": hex.EncodeToString(t.keys[k][:]), "state_digest": hex.EncodeToString(t.states[k][:])}
	}
	for k := 0; k+1 < len(t.keys); k++ {
		if bytes.Compare(t.keys[k][:], q[:]) < 0 && bytes.Compare(q[:], t.keys[k+1][:]) < 0 {
			return map[string]any{
				"type": "nonmembership", "lo": side(k), "hi": side(k + 1),
				"lo_index": k, "hi_index": k + 1,
				"lo_path": t.tree.auditPath(k), "hi_path": t.tree.auditPath(k + 1),
			}
		}
	}
	return nil
}
