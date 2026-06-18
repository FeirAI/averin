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
// feir_decision_core::verify::grant_head_root (pinned by the SHARED golden vector
// spec/golden-vectors/broker-preimages.json, loaded by both languages' tests), so the offline
// verifier re-derives the cumulative_root an anchored checkpoint's broker_grant_head carries — and a
// dropped, renumbered, or forked grant fails the re-derivation.
//
//	acc_0 = sha256( LP4(tag) )
//	acc_i = sha256( LP4(tag) ‖ acc_{i-1}(32 raw bytes) ‖ BE8(seq_i) ‖ LP4(content_hash_i) )
//
// LP4 is a 4-byte big-endian length prefix; BE8 an 8-byte big-endian int. The caller MUST pass the
// pairs already sorted by broker_seq (the producer folds in issue order). The empty log has a
// well-defined non-zero seed root, so "no grants" is distinguishable from a forged/zero root.
// BrokerGrantHead is the head a checkpoint anchors (ADR 0004 D6 / MF2): the cumulative_root over the
// grant log [1..max_seq], the max_seq, and prior_head_hash linking to the PREVIOUS checkpoint's
// cumulative_root (the empty-log root when there is no prior checkpoint). Because the head lives inside
// the signed, fork-detected, anchored checkpoint, the broker cannot equivocate on the grant log without
// a detectable fork/anchor mismatch. `grants` MUST be sorted by broker_seq.
func BrokerGrantHead(grants []GrantSeqHash, priorHeadHash string) map[string]any {
	var maxSeq int64
	for _, g := range grants {
		if g.Seq > maxSeq {
			maxSeq = g.Seq
		}
	}
	return map[string]any{
		"max_seq":         maxSeq,
		"prior_head_hash": priorHeadHash,
		"cumulative_root": GrantHeadRoot(grants),
	}
}

// EmptyGrantHeadRoot is the cumulative_root of an empty grant log — the prior_head_hash a project's
// FIRST checkpoint uses (no previous head to chain to).
func EmptyGrantHeadRoot() string { return GrantHeadRoot(nil) }

// BrokerGrantHeads is the FEDERATED head a checkpoint anchors (ADR 0005 M4): a MAP `{broker_id:
// BrokerGrantHead(...)}` — the per-`broker_id` generalization of the single `broker_grant_head`. Each broker's
// entry folds ONLY that broker's grant log (its own gapless [1..n_b] broker_seq prefix) and chains to that
// broker's OWN previous head via `prior[broker_id]` (the empty-log root when the broker has no prior checkpoint).
// The offline verifier re-derives each broker's cumulative_root independently, so a gap in broker A's sequence is
// detected in A's partition and can never be masked by broker B's interleaved grants. Each `perBroker` slice MUST
// be sorted by broker_seq.
func BrokerGrantHeads(perBroker map[string][]GrantSeqHash, prior map[string]string) map[string]any {
	heads := make(map[string]any, len(perBroker))
	for brokerID, grants := range perBroker {
		p, ok := prior[brokerID]
		if !ok {
			p = EmptyGrantHeadRoot()
		}
		heads[brokerID] = BrokerGrantHead(grants, p)
	}
	return heads
}

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
