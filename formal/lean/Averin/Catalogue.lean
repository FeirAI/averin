import Averin.Preimage

/-!
# The rest of the preimage catalogue

`Averin.Preimage` covers the LP-framed families. This module covers every *other* byte string
averin hashes or signs, and proves each one distinguishable from the framed families and from
each other:

| Family | Source | Shape |
|---|---|---|
| grant PoP challenge | `server/internal/broker/broker.go` `Request.Challenge` | canonical JSON object, first byte `{` (signed by the agent key) |
| denial salt | `server/internal/api/server.go` (`averin.denial.salt.v1`) | fixed ASCII string (signed by the broker key) |
| `cnf_kid` input | `core/src/verify.rs::cnf_kid` | raw 32-byte Ed25519 public key |
| credential binding | `verify.rs` D6.4 (`sha256(descriptor)`) | canonical JSON descriptor, first byte `{` |
| server record ids | `server.go::uuidV5Shaped` | `namespace ‖ 0x00 ‖ project ‖ 0x00 ‖ idem` |
| Merkle leaf / node | `verify.rs::merkle_leaf_hash` / `merkle_node_hash` | `0x00 ‖ v(32)` / `0x01 ‖ l(32) ‖ r(32)` |

RFC 3161 tokens are verified, never produced, and are out of scope (`check-refinement.py` allowlists
them).

The headline results:

* `merkle_leaf_ne_framed`, `merkle_node_ne_framed`: Merkle preimages never equal any framed
  hash-family preimage. The leaf and the framed families both start with byte `0`; they are
  separated by length (leaf = 33, every framed family ≥ 34 or exactly 31).
* `raw_key_ne_framed`, `raw_key_ne_merkle`: a 32-byte `cnf_kid` input is never a framed or Merkle
  preimage.
* `pop_ne_digest`, `pop_ne_framed`, `salt_ne_digest`, `salt_ne_framed`: the agent-signed JSON
  challenge and the broker-signed salt can never be confused with a framed signed message or a raw
  32-byte challenge digest (they are also disjuncts of `Seal.HonestSigner`).
* `nul_join_inj` / `server_id_inj`: server ids are injective in `(namespace, project, idem)`
  **provided none of them contains a NUL byte**; `server_id_nul_collision` exhibits the collision
  when a project may contain NUL. The server rejects NUL in `project_id`, `idempotency_key` and
  `record_id` for exactly this reason.
-/

namespace Averin.Catalogue

open Averin Averin.Preimage

/-! ## Lengths of framed families -/

/-- Least encoded length of a schema: 4 per `LP` field, `n` per fixed field. -/
def fieldMinLen : Field → Nat
  | .framed => 4
  | .fixed n => n

def minLen : List Field → Nat
  | [] => 0
  | f :: fs => fieldMinLen f + minLen fs

theorem encodeFields_length_min : ∀ (fs : List Field) (vs : List Bytes) (t : Bytes),
    Averin.Admits fs vs → minLen fs + t.length ≤ (encodeFields fs vs t).length
  | [], [], t, _ => by simp [minLen, encodeFields]
  | [], _ :: _, _, h => by simp [Averin.Admits] at h
  | _ :: _, [], _, h => by simp [Averin.Admits] at h
  | f :: fs, v :: vs, t, h => by
    simp only [Averin.Admits] at h
    have ih := encodeFields_length_min fs vs t h.2
    simp only [encodeFields, List.length_append, minLen]
    cases f with
    | framed => simp [Field.encode, fieldMinLen, lp]; omega
    | fixed n =>
      simp only [Field.admits] at h
      simp [Field.encode, fieldMinLen, h.1]; omega

theorem msg_length_min (F : Family) (vs : List Bytes) (t : Bytes) (h : F.Admits vs) :
    4 + (ascii F.tag).length + minLen F.schema ≤ (F.msg vs t).length := by
  have := encodeFields_length_min F.schema vs (if F.tailed then t else []) h
  simp only [Family.msg, encodeFields, Field.encode, lp, List.length_append, be32_length]
  omega

/-- Every fixed-schema framed hash family (all but the body hashes, the commitment and the
grant-head seed, which are handled separately) is at least 34 bytes. -/
theorem framed_long : ∀ F ∈ [usePop, cosig, delegationHop, introspection, federation,
    ledger, grantHeadStep, revocationLeaf],
    34 ≤ 4 + (ascii F.tag).length + minLen F.schema := by
  decide

/-- The hiding commitment carries a 32-byte nonce (`commit.rs` rejects any other length). -/
theorem commitment_long (vs : List Bytes) (t : Bytes) (h : commitment.Admits vs)
    (hn : ∃ d n v, vs = [d, n, v] ∧ n.length = 32) : 34 ≤ (commitment.msg vs t).length := by
  obtain ⟨d, n, v, rfl, hn⟩ := hn
  simp only [Family.msg, commitment, encodeFields, Field.encode, lp, List.length_append,
    be32_length]
  rw [hn]; simp; omega

/-- Record/checkpoint body-hash preimages: the verifier pins `canon_version = "rcp-1"` and the
canonical body is a JSON object (at least `{}`). -/
theorem body_hash_long (F : Family) (hF : F ∈ [recordHash, checkpointHash]) (t : Bytes)
    (ht : 2 ≤ t.length) : 34 ≤ (F.msg [ascii "rcp-1"] t).length := by
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hF
  rcases hF with rfl | rfl <;>
  · simp only [Family.msg, recordHash, checkpointHash, encodeFields, Field.encode, lp,
      List.length_append, be32_length, if_true]
    have : (ascii "rcp-1").length = 5 := by decide
    have h2 : 24 ≤ (ascii "flightrecorder.record.v2").length := by decide
    have h3 : 24 ≤ (ascii "flightrecorder.checkpoint.v2").length := by decide
    omega

theorem grantHeadSeed_length (t : Bytes) : (grantHeadSeed.msg [] t).length = 31 := by
  simp only [Family.msg, grantHeadSeed, encodeFields, Field.encode, lp, List.length_append,
    be32_length, Bool.false_eq_true, if_false, List.length_nil]
  decide

/-- A framed hash-family preimage, with the verifier's own shape constraints. -/
def FramedHashInput (m : Bytes) : Prop :=
  (∃ F ∈ [usePop, cosig, delegationHop, introspection, federation, ledger, grantHeadStep,
      revocationLeaf], ∃ vs t, F.Admits vs ∧ m = F.msg vs t) ∨
  (∃ F ∈ [recordHash, checkpointHash], ∃ t, 2 ≤ t.length ∧ m = F.msg [ascii "rcp-1"] t) ∨
  (∃ vs t, commitment.Admits vs ∧ (∃ d n v, vs = [d, n, v] ∧ n.length = 32) ∧
      m = commitment.msg vs t) ∨
  (∃ t, m = grantHeadSeed.msg [] t)

theorem framed_hash_length (m : Bytes) (h : FramedHashInput m) : 34 ≤ m.length ∨ m.length = 31 := by
  rcases h with ⟨F, hF, vs, t, ha, rfl⟩ | ⟨F, hF, t, ht, rfl⟩ | ⟨vs, t, ha, hn, rfl⟩ | ⟨t, rfl⟩
  · exact Or.inl (Nat.le_trans (framed_long F hF) (msg_length_min F vs t ha))
  · exact Or.inl (body_hash_long F hF t ht)
  · exact Or.inl (commitment_long vs t ha hn)
  · exact Or.inr (grantHeadSeed_length t)

/-! ## Merkle, raw keys -/

theorem merkle_leaf_ne_framed (v : Bytes) (hv : v.length = 32) (m : Bytes)
    (hm : FramedHashInput m) : merkleLeaf v ≠ m := by
  intro h
  have := framed_hash_length m hm
  rw [← h] at this
  simp [merkleLeaf, hv] at this

theorem framed_head (m : Bytes) (hm : FramedHashInput m) : m.head? = some 0 := by
  have hs : ∀ F ∈ [usePop, cosig, delegationHop, introspection, federation, ledger,
      grantHeadStep, revocationLeaf], (ascii F.tag).length < 256 := by
    decide
  have hs' : ∀ F ∈ [recordHash, checkpointHash], (ascii F.tag).length < 256 := by decide
  rcases hm with ⟨F, hF, vs, t, _, rfl⟩ | ⟨F, hF, t, _, rfl⟩ | ⟨vs, t, _, _, rfl⟩ | ⟨t, rfl⟩
  · exact framed_head_zero F (hs F hF) vs t
  · exact framed_head_zero F (hs' F hF) _ t
  · exact framed_head_zero commitment (by decide) vs t
  · exact framed_head_zero grantHeadSeed (by decide) [] t

theorem merkle_node_ne_framed (l r : Bytes) (m : Bytes) (hm : FramedHashInput m) :
    merkleNode l r ≠ m := by
  intro h
  have := framed_head m hm
  rw [← h] at this
  simp [merkleNode] at this

/-- `cnf_kid` hashes the raw 32-byte key: never a framed (≥ 34 or = 31) or Merkle (33/65) preimage. -/
theorem raw_key_ne_framed (k : Bytes) (hk : k.length = 32) (m : Bytes) (hm : FramedHashInput m) :
    k ≠ m := by
  intro h
  have := framed_hash_length m hm
  rw [← h, hk] at this
  omega

theorem raw_key_ne_merkle (k v l r : Bytes) (hk : k.length = 32) (hv : v.length = 32)
    (hl : l.length = 32) (hr : r.length = 32) : k ≠ merkleLeaf v ∧ k ≠ merkleNode l r := by
  refine ⟨fun h => ?_, fun h => ?_⟩
  · have := congrArg List.length h; simp [merkleLeaf, hk, hv] at this
  · have := congrArg List.length h; simp [merkleNode, hk, hl, hr] at this

/-! ## Signed non-framed messages -/

/-- The broker grant PoP challenge as the Go producer builds it: a JSON object (first byte `{`)
that always carries the 43-character base64url agent key, so it is longer than 43 bytes. -/
def ValidatedPop (m : Bytes) : Prop := m.head? = some 123 ∧ 43 < m.length

theorem pop_ne_digest (m : Bytes) (h : ValidatedPop m) : m.length ≠ 32 := by
  have := h.2; omega

theorem pop_ne_framed (m : Bytes) (h : ValidatedPop m) (F : Family)
    (hshort : (ascii F.tag).length < 256) (vs : List Bytes) (t : Bytes) : m ≠ F.msg vs t := by
  intro he
  have h1 := h.1
  rw [he, framed_head_zero F hshort vs t] at h1
  simp at h1

def denialSalt : Bytes := ascii "averin.denial.salt.v1"

theorem salt_ne_digest : denialSalt.length ≠ 32 := by decide

theorem salt_ne_framed (F : Family) (hshort : (ascii F.tag).length < 256) (vs : List Bytes)
    (t : Bytes) : denialSalt ≠ F.msg vs t := by
  intro he
  have h := framed_head_zero F hshort vs t
  rw [← he] at h
  simp [denialSalt, ascii] at h

theorem salt_ne_pop (m : Bytes) (h : ValidatedPop m) : denialSalt ≠ m := by
  intro he
  have h1 := h.1
  rw [← he] at h1
  simp [denialSalt, ascii] at h1

/-! ## Output formats never collide -/

/-- `cnf_kid` renders as `ed25519-…` and every digest comparison uses `sha256:…`, so a key id can
never be mistaken for a content hash, credential binding or commitment (and vice versa). -/
theorem kid_prefix_ne_digest_prefix (a b : Bytes) :
    ascii "ed25519-" ++ a ≠ ascii "sha256:" ++ b := by
  intro h
  have := congrArg List.head? h
  simp [ascii] at this

/-! ## Server id derivations (`uuidV5Shaped`) -/

/-- `a ‖ 0x00 ‖ r` splits uniquely at the first NUL when `a` has none. -/
theorem nul_join_inj : ∀ {a b r s : Bytes}, 0 ∉ a → 0 ∉ b →
    a ++ 0 :: r = b ++ 0 :: s → a = b ∧ r = s
  | [], [], _, _, _, _, h => by simpa using h
  | [], y :: b, _, _, _, hb, h => by
    simp only [List.nil_append, List.cons_append, List.cons.injEq] at h
    exact absurd (h.1 ▸ List.mem_cons_self) hb
  | x :: a, [], _, _, ha, _, h => by
    simp only [List.nil_append, List.cons_append, List.cons.injEq] at h
    exact absurd (h.1 ▸ List.mem_cons_self) ha
  | x :: a, y :: b, r, s, ha, hb, h => by
    simp only [List.cons_append, List.cons.injEq] at h
    have := nul_join_inj (fun hm => ha (List.mem_cons_of_mem _ hm))
      (fun hm => hb (List.mem_cons_of_mem _ hm)) h.2
    exact ⟨by rw [h.1, this.1], this.2⟩

def serverIdInput (ns project idem : Bytes) : Bytes := ns ++ 0 :: (project ++ 0 :: idem)

/-- **Server ids are injective** in `(namespace, project, idem)` when namespace and project are
NUL-free (the namespaces are ASCII literals; the server rejects NUL in `project_id`). -/
theorem server_id_inj {ns ns' p p' i i' : Bytes} (hns : 0 ∉ ns) (hns' : 0 ∉ ns') (hp : 0 ∉ p)
    (hp' : 0 ∉ p') (h : serverIdInput ns p i = serverIdInput ns' p' i') :
    ns = ns' ∧ p = p' ∧ i = i' := by
  obtain ⟨h1, h2⟩ := nul_join_inj hns hns' h
  obtain ⟨h3, h4⟩ := nul_join_inj hp hp' h2
  exact ⟨h1, h3, h4⟩

/-- Without the NUL restriction the derivation collides across projects. -/
theorem server_id_nul_collision :
    ∃ ns p i p' i', p ≠ p' ∧ serverIdInput ns p i = serverIdInput ns p' i' :=
  ⟨[1], [97], [98, 0, 99], [97, 0, 98], [99], by decide, by decide⟩

theorem namespaces_nul_free : ∀ ns ∈ ["averin.grant.id.v1", "averin.use.id.v1",
    "averin.denial.id.v1", "averin.use_outcome.id.v1", "averin.introspection.id.v1"],
    0 ∉ ascii ns := by decide

theorem namespaces_distinct : (["averin.grant.id.v1", "averin.use.id.v1", "averin.denial.id.v1",
    "averin.use_outcome.id.v1", "averin.introspection.id.v1"].map ascii).Pairwise (· ≠ ·) := by
  decide

end Averin.Catalogue
