import Averin.Preimage

/-!
# The rest of the preimage catalogue

`Averin.Preimage` covers the LP-framed families. This module covers every *other* message an averin
signing key signs, and every other preimage the verifier recomputes, and proves each one
distinguishable from the framed families and from each other:

| Family | Source | Shape |
|---|---|---|
| grant PoP challenge | `server/internal/broker/broker.go` `Request.Challenge` | canonical JSON object, first byte `{` (signed by the agent key) |
| denial salt | `server/internal/api/server.go` (`averin.denial.salt.v1`) | fixed ASCII string (signed by the broker key) |
| capability token | `server/internal/broker/broker.go::mint` | `base64url(descriptor)` text, first byte `e` (signed by the broker key) |
| `cnf_kid` input | `core/src/verify.rs::cnf_kid` | raw 32-byte Ed25519 public key |
| credential binding | `verify.rs` D6.4 (`sha256(descriptor)`) | canonical JSON descriptor, first byte `{` |
| server record ids | `server.go::uuidV5Shaped` | `namespace ‖ 0x00 ‖ project ‖ 0x00 ‖ idem` |
| Merkle leaf / node | `verify.rs::merkle_leaf_hash` / `merkle_node_hash` | `0x00 ‖ v(32)` / `0x01 ‖ l(32) ‖ r(32)` |

RFC 3161 tokens are verified, never produced, and are out of scope (`check-refinement.py` allowlists
them).

**Not catalogued (untagged plain SHA-256, no signature over them).** The server also hashes bytes
with no domain tag: the RFC 3161 imprint `sha256(checkpoint_hash string)` (`server.go`
`anchorCheckpoint`, a format fixed by the TSA protocol), content addresses (`content.go::Digest`),
the witness fork-detection id (`witness.go::canonHash`), idempotency digests of request bodies
(`server.go`, OTel ingest), the bearer-token comparison (`auth.go`), the denial-budget map key and
the self-verify cache key. None of these is signed, and each is compared only against a digest of
the same kind, so they rely on SHA-256 collision resistance alone and have no cross-family
confusion to rule out. They are listed here so the scope is explicit; `check-refinement.py` sees
only tagged preimages, by construction.

The headline results:

* `merkle_leaf_ne_framed`, `merkle_node_ne_framed`: Merkle preimages never equal any framed
  hash-family preimage. The leaf and the framed families both start with byte `0`; they are
  separated by length (leaf = 33, every framed family ≥ 34 or exactly 31).
* `raw_key_ne_framed`, `raw_key_ne_merkle`: a 32-byte `cnf_kid` input is never a framed or Merkle
  preimage.
* `pop_ne_digest`, `pop_ne_framed`, `salt_ne_digest`, `salt_ne_framed`: the agent-signed JSON
  challenge and the broker-signed salt can never be confused with a framed signed message or a raw
  32-byte challenge digest (they are also disjuncts of `Seal.HonestSigner`).
* `capability_head`, `capability_ne_framed`, `capability_ne_pop`, `capability_ne_salt`: the
  broker-signed capability-token text (`base64url` of a JSON descriptor) starts with `e`, so it is
  never a framed message, a PoP challenge or the salt, and `Seal.HonestSigner` admits it.
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

/-- RFC 4648 §5 base64url alphabet. -/
def b64Alphabet : Bytes :=
  ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def b64Sym (i : Nat) : Nat := b64Alphabet.getD i 0

/-- Unpadded base64url (`base64.RawURLEncoding`), 3 bytes to 4 symbols. -/
def b64url : Bytes → Bytes
  | a :: b :: c :: rest =>
      [b64Sym (a / 4), b64Sym (a % 4 * 16 + b / 16), b64Sym (b % 16 * 4 + c / 64), b64Sym (c % 64)] ++
        b64url rest
  | [a, b] => [b64Sym (a / 4), b64Sym (a % 4 * 16 + b / 16), b64Sym (b % 16 * 4)]
  | [a] => [b64Sym (a / 4), b64Sym (a % 4 * 16)]
  | [] => []

/-- `broker.go::mint`: the broker key signs `base64url(descriptor)` (the token text before `.`),
where the descriptor is canonical JSON. -/
def capabilityMsg (descriptor : Bytes) : Bytes := b64url descriptor

/-- A capability-token message over a JSON descriptor starts with `e` (`'{' = 0x7B`, whose top six
bits are 30, and `b64Alphabet[30] = 'e'`). -/
theorem capability_head (d : Bytes) (h : d.head? = some 123) :
    (capabilityMsg d).head? = some 101 := by
  match d, h with
  | 123 :: _ :: _ :: _, _ => rfl
  | [123, _], _ => rfl
  | [123], _ => rfl

theorem capability_ne_framed (d : Bytes) (h : d.head? = some 123) (F : Family)
    (hshort : (ascii F.tag).length < 256) (vs : List Bytes) (t : Bytes) :
    capabilityMsg d ≠ F.msg vs t := by
  intro he
  have h1 := capability_head d h
  rw [he, framed_head_zero F hshort vs t] at h1
  simp at h1

/-- The capability text is admitted by `Seal.HonestSigner`'s unframed disjunct. -/
theorem capability_head_ne_zero (d : Bytes) (h : d.head? = some 123) :
    (capabilityMsg d).head? ≠ some 0 := by
  rw [capability_head d h]; simp

theorem capability_ne_pop (d m : Bytes) (h : d.head? = some 123) (hm : ValidatedPop m) :
    capabilityMsg d ≠ m := by
  intro he
  have h1 := hm.1
  rw [← he, capability_head d h] at h1
  simp at h1

theorem capability_ne_salt (d : Bytes) (h : d.head? = some 123) : capabilityMsg d ≠ denialSalt := by
  intro he
  have h1 := capability_head d h
  rw [he] at h1
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

def serverIdNamespaces : List String :=
  ["averin.grant.id.v1", "averin.use.id.v1", "averin.denial.id.v1", "averin.use_outcome.id.v1",
   "averin.introspection.id.v1"]

theorem namespaces_nul_free : ∀ ns ∈ serverIdNamespaces, 0 ∉ ascii ns := by decide

theorem namespaces_distinct : (serverIdNamespaces.map ascii).Pairwise (· ≠ ·) := by decide

/-! ## The complete tag inventory

`catalogueTags` lists every domain string that is not the leading `LP` tag of a `Preimage.Family`:
the grant PoP challenge's `"tag"` field (inside its JSON), the grant-void tombstone's evidence
`domain` (inside a canonical-JSON evidence payload, first byte `{`, so `json_disjoint_from_framed`
separates it from every framed family), the denial-salt message, and the server id namespaces.
`formal/check-refinement.py` fails unless every `averin.*.vN` literal in `core/src` and
`server/internal` is a `Family` tag or appears here. -/
def catalogueTags : List String :=
  ["averin.broker.pop.v1", "averin.broker.grant_void.v1", "averin.denial.salt.v1"] ++
    serverIdNamespaces

/-- No catalogue domain string reuses a framed-family tag, and they are pairwise distinct. -/
theorem catalogue_tags_fresh :
    (catalogueTags.map ascii).Pairwise (· ≠ ·) ∧
    ∀ t ∈ catalogueTags, ∀ F ∈ signedFamilies ++ hashFamilies ++ [grantHeadSeed],
      ascii t ≠ ascii F.tag := by
  decide

end Averin.Catalogue
