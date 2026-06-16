package broker

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// grantHeadTag domain-separates the cumulative grant-transparency hash chain (ADR 0004 D6 / MF2).
const grantHeadTag = "feir.broker.grant_head.v1"

// GrantSeqHash is one entry in the grant log: a broker_seq and the grant record's content_hash.
type GrantSeqHash struct {
	Seq         int64
	ContentHash string // sha256:<hex>
}

// GrantHeadRoot is the cumulative grant-transparency root (ADR 0004 D6 / MF2): a hash-CHAIN that folds
// (broker_seq, grant content_hash) pairs in ASCENDING broker_seq order. It is byte-identical to Rust
// feir_decision_core::verify::grant_head_root (pinned by a shared golden vector), so the offline
// verifier re-derives the cumulative_root an anchored checkpoint's broker_grant_head carries — and a
// dropped, renumbered, or forked grant fails the re-derivation.
//
//	acc_0 = sha256( LP4(tag) )
//	acc_i = sha256( LP4(tag) ‖ acc_{i-1}(32 raw bytes) ‖ BE8(seq_i) ‖ LP4(content_hash_i) )
//
// LP4 is a 4-byte big-endian length prefix; BE8 an 8-byte big-endian int. The caller MUST pass the
// pairs already sorted by broker_seq (the producer folds in issue order). The empty log has a
// well-defined non-zero seed root, so "no grants" is distinguishable from a forged/zero root.
func GrantHeadRoot(grants []GrantSeqHash) string {
	lp4 := func(buf, b []byte) []byte {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		return append(append(buf, n[:]...), b...)
	}
	seed := sha256.Sum256(lp4(nil, []byte(grantHeadTag)))
	acc := seed[:]
	for _, g := range grants {
		buf := lp4(nil, []byte(grantHeadTag))
		buf = append(buf, acc...)
		var s [8]byte
		binary.BigEndian.PutUint64(s[:], uint64(g.Seq))
		buf = append(buf, s[:]...)
		buf = lp4(buf, []byte(g.ContentHash))
		sum := sha256.Sum256(buf)
		acc = sum[:]
	}
	return "sha256:" + hex.EncodeToString(acc)
}
