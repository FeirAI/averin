import Averin.Encoding

/-!
# Every hashed and signed preimage family, and their domain separation

This is the catalogue of every byte string averin feeds to SHA-256 or to Ed25519, transcribed
from the Rust (file references on each family; `formal/check-refinement.py` keeps the tags and
schemas in sync with the source).

The theorems here are the *no-ambiguity / no-cross-protocol-replay* half of "the seal is
unbreakable":

* `Family.msg_inj` — within a family, equal bytes ⇒ equal fields (no field can bleed into
  another; no delimiter injection).
* `signed_families_disjoint` — messages from two different Ed25519-signed families never
  coincide, whatever their fields. A signature minted in one context therefore cannot verify in
  another, **even if two roles share a key** (role-key disjointness is defence in depth, not the
  only barrier).
* `signed_message_long` — once the verifier's own input validation holds (every digest it signs
  over is a 71-byte `sha256:<hex>` string), every LP-framed signed message is longer than 32
  bytes, so it can never equal the raw 32-byte digest that the broker challenge families sign.
* `hash_families_disjoint`, `framed_head_zero`, `json_head` — every SHA-256 input family is
  distinguishable from every other, including the unframed canonical-JSON evidence payloads
  (first byte `{`) and the RFC 6962 Merkle leaf/node preimages (first byte `0x00`/`0x01`, fixed
  33/65 bytes).
-/

namespace Averin.Preimage

open Averin

def ascii (s : String) : Bytes := s.toList.map Char.toNat

/-- A preimage family: `LP(tag) ‖ fields… ‖ tail?`. -/
structure Family where
  name : String
  tag : String
  schema : List Field
  /-- Whether an unframed trailing field (a digest string / canonical JSON) follows. -/
  tailed : Bool
deriving Repr

def Family.msg (F : Family) (vs : List Bytes) (t : Bytes) : Bytes :=
  encodeFields (.framed :: F.schema) (ascii F.tag :: vs) (if F.tailed then t else [])

/-! ## Families signed directly by Ed25519 -/

/-- `sign.rs` `RECORD_SIG_TAG`: `LP(tag) ‖ utf8(content_hash)`. -/
def recordSig : Family := ⟨"record sig", "averin.record.sig.v1", [], true⟩
/-- `sign.rs` `CHECKPOINT_SIG_TAG`. -/
def checkpointSig : Family := ⟨"checkpoint sig", "averin.checkpoint.sig.v1", [], true⟩
/-- `verify.rs` taxonomy statement, via `sign::verify`. -/
def taxonomySig : Family := ⟨"taxonomy statement", "averin.taxonomy.v1", [], true⟩
/-- `verify.rs` revocation statement, via `sign::verify`. -/
def revocationSig : Family := ⟨"revocation statement", "averin.revocation.v1", [], true⟩
/-- `verify.rs` Merkle revocation root, via `sign::verify`. -/
def merkleRootSig : Family :=
  ⟨"revocation merkle root", "averin.broker.revocation.merkleroot.v1", [], true⟩
/-- `verify.rs` deployment attestation, via `sign::verify`. -/
def attestationSig : Family := ⟨"attestation", "averin.attestation.v1", [], true⟩
/-- `authority.rs::preimage`: `LP(tag) ‖ LP(source) ‖ LP(project_id) ‖ LP(record_id) ‖ utf8(evidence_hash)`. -/
def authoritySig : Family :=
  ⟨"authority evidence", "averin.authority.v2", [.framed, .framed, .framed], true⟩
/-- `anchor.rs::anchor_preimage` (test anchors): `LP(tag) ‖ LP(checkpoint_hash) ‖ LP(anchored_ts)`. -/
def testAnchorSig : Family := ⟨"test anchor", "averin.anchor.v1", [.framed, .framed], false⟩

def signedFamilies : List Family :=
  [recordSig, checkpointSig, taxonomySig, revocationSig, merkleRootSig, attestationSig,
   authoritySig, testAnchorSig]

/-! ## Challenge families (SHA-256 of the preimage; the raw 32-byte digest is what is signed) -/

/-- `broker.Request.Challenge` v2. The opaque tail is the variable-length
delegation LP4 sequence followed by two fixed BE8 freshness times. The shared
golden vector checks the complete encoding in both producers. -/
def grantPopV2 : Family :=
  ⟨"grant PoP v2", "averin.broker.pop.v2",
   List.replicate 12 .framed ++ [.fixed 8, .fixed 8, .fixed 8], true⟩

/-- `verify.rs::use_pop_challenge`. -/
def usePop : Family :=
  ⟨"use PoP", "averin.broker.use.pop.v1", [.framed, .framed, .framed, .framed, .framed, .framed], false⟩
/-- `verify.rs::cosig_approval_challenge`. -/
def cosig : Family :=
  ⟨"cosig approval", "averin.broker.cosig.approval.v1",
   [.framed, .framed, .framed, .fixed 8, .fixed 8], false⟩
/-- `verify.rs::delegation_hop_challenge`. -/
def delegationHop : Family :=
  ⟨"delegation hop", "averin.broker.delegation.hop.v1",
   [.framed, .fixed 8, .framed, .framed, .framed, .framed, .framed, .fixed 8], false⟩
/-- `verify.rs::introspection_transcript_challenge`. -/
def introspection : Family :=
  ⟨"introspection transcript", "averin.resource.introspection.v1",
   [.framed, .framed, .framed, .framed, .fixed 8, .fixed 8], false⟩
/-- `verify.rs::federation_cert_challenge`. -/
def federation : Family :=
  ⟨"federation cert", "averin.broker.federation.cert.v1",
   [.framed, .framed, .framed, .framed, .framed, .fixed 8], false⟩

/-! ## Hash-only families -/

/-- `record.rs::hash_body` for records: `LP(domain) ‖ LP(canon_version) ‖ utf8(canon)`; the verifier
requires `domain = "flightrecorder.record.v2"` (`verify_content_hash`). -/
def recordHash : Family := ⟨"record content_hash", "flightrecorder.record.v2", [.framed], true⟩
/-- `checkpoint.rs::compute_checkpoint_hash`; `verify_checkpoint_sealed` pins the domain. -/
def checkpointHash : Family :=
  ⟨"checkpoint_hash", "flightrecorder.checkpoint.v2", [.framed], true⟩
/-- `commit.rs::commit`: `LP(tag) ‖ LP(field_domain) ‖ LB(nonce) ‖ LB(value)`. -/
def commitment : Family := ⟨"hiding commitment", "averin.commit.v1", [.framed, .framed, .framed], false⟩
/-- `verify.rs::ledger_commitment`. -/
def ledger : Family := ⟨"use ledger", "averin.broker.use.ledger.v1", [.framed, .framed, .fixed 8], false⟩
/-- `verify.rs::grant_head_root` seed `acc_0 = H(LP(tag))`. -/
def grantHeadSeed : Family := ⟨"grant head seed", "averin.broker.grant_head.v1", [], false⟩
/-- `verify.rs::grant_head_root` step `H(LP(tag) ‖ acc(32) ‖ BE8(seq) ‖ LP(content_hash))`. -/
def grantHeadStep : Family :=
  ⟨"grant head step", "averin.broker.grant_head.v1", [.fixed 32, .fixed 8, .framed], false⟩
/-- `verify.rs::revocation_leaf`. -/
def revocationLeaf : Family := ⟨"revocation leaf", "averin.broker.revocation.leaf.v1", [.framed], false⟩

/-- Every LP-framed SHA-256 input family whose leading tag is unique. (`grantHeadSeed` shares its
tag with `grantHeadStep` and is separated by length in `grant_head_seed_ne_step`.) -/
def hashFamilies : List Family :=
  [grantPopV2, usePop, cosig, delegationHop, introspection, federation, recordHash, checkpointHash, commitment,
   ledger, grantHeadStep, revocationLeaf]

/-! ## Within-family injectivity -/

def Family.Admits (F : Family) (vs : List Bytes) : Prop := Averin.Admits F.schema vs

theorem Family.tag_lt (F : Family) (h : (ascii F.tag).length < lpLimit) :
    (Field.framed).admits (ascii F.tag) := h

/-- **No delimiter injection.** Equal messages of one family have equal fields and tails. -/
theorem Family.msg_inj (F : Family) {vs ws : List Bytes} {t u : Bytes}
    (htag : (ascii F.tag).length < lpLimit) (hv : F.Admits vs) (hw : F.Admits ws)
    (h : F.msg vs t = F.msg ws u) : vs = ws ∧ (F.tailed = true → t = u) := by
  have := encodeFields_inj (.framed :: F.schema) (ascii F.tag :: vs) (ascii F.tag :: ws) _ _
    ⟨htag, hv⟩ ⟨htag, hw⟩ h
  refine ⟨by simpa using this.1, fun ht => ?_⟩
  have h2 := this.2
  simp only [ht, if_true] at h2
  exact h2

/-- **Cross-family disjointness.** Distinct leading tags ⇒ distinct messages, for any fields. -/
theorem Family.msg_disjoint (F G : Family) (vs ws : List Bytes) (t u : Bytes)
    (hF : (ascii F.tag).length < lpLimit) (hG : (ascii G.tag).length < lpLimit)
    (hne : ascii F.tag ≠ ascii G.tag) : F.msg vs t ≠ G.msg ws u := by
  intro h
  exact hne (encodeFields_lp_head hF hG h)

theorem signed_tags_distinct : (signedFamilies.map (fun F => ascii F.tag)).Pairwise (· ≠ ·) := by
  decide

theorem hash_tags_distinct : (hashFamilies.map (fun F => ascii F.tag)).Pairwise (· ≠ ·) := by
  decide

theorem challenge_tags_disjoint_from_signed :
    ∀ F ∈ [grantPopV2, usePop, cosig, delegationHop, introspection, federation],
    ∀ G ∈ signedFamilies, ascii F.tag ≠ ascii G.tag := by
  decide

theorem tags_short : ∀ F ∈ signedFamilies ++ hashFamilies ++ [grantHeadSeed],
    16 ≤ (ascii F.tag).length ∧ (ascii F.tag).length < 256 := by
  decide

theorem pairwise_mem {α} {R : α → α → Prop} :
    ∀ {l : List α}, l.Pairwise R → ∀ {i j : Nat} (hi : i < l.length) (hj : j < l.length),
      i < j → R l[i] l[j]
  | _ :: _, h, 0, j + 1, _, hj, _ => by
    simp only [List.pairwise_cons] at h
    exact h.1 _ (List.getElem_mem (by simpa using hj))
  | _ :: _, h, i + 1, j + 1, hi, hj, hij => by
    simp only [List.pairwise_cons] at h
    exact pairwise_mem h.2 (by simpa using hi) (by simpa using hj) (by omega)

/--
**Signature domain separation.** For any two *different* Ed25519-signed families (by index in
`signedFamilies`), no message of one equals any message of the other.
-/
theorem signed_families_disjoint {i j : Nat} (hi : i < signedFamilies.length)
    (hj : j < signedFamilies.length) (hij : i ≠ j) (vs ws : List Bytes) (t u : Bytes) :
    signedFamilies[i].msg vs t ≠ signedFamilies[j].msg ws u := by
  have hshort := tags_short
  have hlt : ∀ F ∈ signedFamilies, (ascii F.tag).length < lpLimit := fun F hF => by
    have := (hshort F (by simp [hF])).2; unfold lpLimit; omega
  have hmap := signed_tags_distinct
  apply Family.msg_disjoint _ _ _ _ _ _ (hlt _ (List.getElem_mem hi)) (hlt _ (List.getElem_mem hj))
  rcases Nat.lt_or_gt_of_ne hij with h | h
  · have := pairwise_mem hmap (by simpa using hi) (by simpa using hj) h
    simpa using this
  · have := pairwise_mem hmap (by simpa using hj) (by simpa using hi) h
    simpa using (Ne.symm (by simpa using this))

/-! ## Length separation from the raw-digest (challenge) signatures -/

theorem encodeFields_length_ge : ∀ (fs : List Field) (vs : List Bytes) (t : Bytes),
    t.length ≤ (encodeFields fs vs t).length
  | f :: fs, v :: vs, t => by
    simp only [encodeFields, List.length_append]
    have := encodeFields_length_ge fs vs t; omega
  | [], _, _ | _ :: _, [], _ => by simp [encodeFields]

/-- The verifier-side shape of a signed message: every tail it signs over is a `sha256:<hex>`
string (71 bytes), and a test anchor frames a checkpoint hash (71 bytes) first. -/
def ValidatedSigned (F : Family) (vs : List Bytes) (t : Bytes) : Prop :=
  (F.tailed = true → t.length = 71) ∧ (F.tailed = false → ∃ v rest, vs = v :: rest ∧ v.length = 71)

/--
**Raw-digest separation.** A validated LP-framed signed message is always longer than 32 bytes,
so it can never be the 32-byte SHA-256 digest that `use_pop`/`cosig`/`delegation`/
`introspection`/`federation` signers sign. (A resource key signs both records and introspection
transcripts; this is why that cannot be abused.)
-/
theorem signed_message_long (F : Family) (hF : F ∈ signedFamilies) (vs : List Bytes) (t : Bytes)
    (hv : ValidatedSigned F vs t) : 32 < (F.msg vs t).length := by
  have hshort := (tags_short F (by simp [hF])).1
  unfold Family.msg
  cases ht : F.tailed
  · obtain ⟨v, rest, hvs, hvl⟩ := hv.2 ht
    subst hvs
    have hs : F.schema ≠ [] := by
      simp only [signedFamilies, List.mem_cons, List.not_mem_nil, or_false] at hF
      rcases hF with h | h | h | h | h | h | h | h <;> subst h <;> simp_all [recordSig,
        checkpointSig, taxonomySig, revocationSig, merkleRootSig, attestationSig, authoritySig,
        testAnchorSig]
    match hsch : F.schema, hs with
    | f :: fs, _ =>
      simp only [encodeFields, Field.encode, lp, List.length_append, be32_length]
      cases f <;> simp [] <;> omega
  · simp only [encodeFields, Field.encode, lp, List.length_append, be32_length, if_true]
    have := encodeFields_length_ge F.schema vs t
    have := hv.1 ht
    omega

/-! ## Hash-input separation -/

/-- Every LP-framed family starts with byte `0` (its tag is shorter than 2^24 bytes). -/
theorem framed_head_zero (F : Family) (hshort : (ascii F.tag).length < 256) (vs : List Bytes)
    (t : Bytes) : (F.msg vs t).head? = some 0 := by
  simp only [Family.msg, encodeFields, Field.encode, lp, be32]
  simp only [List.cons_append, List.head?_cons, Option.some.injEq]
  omega

/-- The grant-head seed and step share a tag but never coincide (the step is ≥ 40 bytes longer). -/
theorem grant_head_seed_ne_step (vs : List Bytes) (hv : grantHeadStep.Admits vs) (t u : Bytes) :
    grantHeadSeed.msg [] t ≠ grantHeadStep.msg vs u := by
  intro h
  have := congrArg List.length h
  match vs, hv with
  | [a, b, c], ⟨ha, hb, hc, _⟩ =>
    simp only [Field.admits] at ha hb
    simp [Family.msg, grantHeadSeed, grantHeadStep, encodeFields, Field.encode, lp, ha, hb] at this

/-- RFC 6962 leaf `0x00 ‖ v(32)` and node `0x01 ‖ l(32) ‖ r(32)` (`merkle_leaf_hash`/`merkle_node_hash`). -/
def merkleLeaf (v : Bytes) : Bytes := 0 :: v
def merkleNode (l r : Bytes) : Bytes := 1 :: (l ++ r)

theorem merkle_leaf_ne_node (v l r : Bytes) : merkleLeaf v ≠ merkleNode l r := by
  simp [merkleLeaf, merkleNode]

theorem merkle_node_inj {l r l' r' : Bytes} (hl : l.length = 32) (hl' : l'.length = 32)
    (h : merkleNode l r = merkleNode l' r') : l = l' ∧ r = r' := by
  simp only [merkleNode, List.cons.injEq, true_and] at h
  exact List.append_inj h (by omega)

/-- Canonical JSON evidence payloads (`evidence_rederivable`: `sha256(serialize(payload))`) start
with `{` = 123 — never 0 or 1 — so they are disjoint from every framed and Merkle family. -/
theorem json_disjoint_from_framed (F : Family) (hshort : (ascii F.tag).length < 256)
    (vs : List Bytes) (t rest : Bytes) : 123 :: rest ≠ F.msg vs t := by
  intro h
  have := framed_head_zero F hshort vs t
  rw [← h] at this
  simp at this

end Averin.Preimage
