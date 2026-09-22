import Averin.Canon
import Averin.Utf8
import Averin.Preimage

/-!
# The seal theorem

"A record that verifies under the pinned key is exactly a body the key holder sealed — unless
SHA-256 has a collision or Ed25519 has a forgery."

Cryptography is not axiomatised as injective (SHA-256 is compressing, so an injectivity axiom
would be *false* and make every theorem vacuous). Instead:

* SHA-256 is an arbitrary function `H`; every conclusion is a disjunction whose second arm is an
  explicit collision `x ≠ y ∧ H x = H y`.
* Ed25519 unforgeability is the hypothesis that every message whose signature verifies under the
  pinned key is in `Signed`, the set of messages the key holder actually signed. The honest
  signer (`HonestSigner`) signs only through `record::seal` and `checkpoint::seal_checkpoint`.
* `fmt` is `"sha256:" ‖ lowerhex(·)`; its injectivity is discharged against the real `hashx.rs`
  code by the Kani harnesses `hex_byte_roundtrip` and `hex_digit_is_canonical` (per byte, at fixed
  width).

Everything else — canonical JSON, UTF-8, LP framing, domain separation — is proved, not assumed.
-/

namespace Averin.Seal

open Averin Averin.Canon Averin.Preimage

section
variable (H : Bytes → Bytes) (fmt : Bytes → Bytes)

/-- `record.rs::compute_content_hash` of a canonical body, after `verify_content_hash` has pinned
`domain = "flightrecorder.record.v2"` and `canon_version = "rcp-1"`. -/
noncomputable def recordHashOf (body : CV) : Bytes :=
  fmt (H (recordHash.msg [ascii "rcp-1"] (utf8 (ser body))))

/-- `checkpoint.rs::compute_checkpoint_hash` (domain pinned by `verify_checkpoint_sealed`). -/
noncomputable def checkpointHashOf (body : CV) : Bytes :=
  fmt (H (checkpointHash.msg [ascii "rcp-1"] (utf8 (ser body))))

def Collision : Prop := ∃ x y, x ≠ y ∧ H x = H y

/-- The key holder's signing policy: it signs record and checkpoint seals and nothing else. -/
def HonestSigner (Signed : Bytes → Prop) (records checkpoints : List CV) : Prop :=
  ∀ m, Signed m →
    (∃ B ∈ records, m = recordSig.msg [] (recordHashOf H fmt B)) ∨
    (∃ C ∈ checkpoints, m = checkpointSig.msg [] (checkpointHashOf H fmt C))

end

theorem ascii_short (s : String) (h : (ascii s).length < 256) : (ascii s).length < lpLimit := by
  unfold lpLimit; omega

theorem rec_admits : recordHash.Admits [ascii "rcp-1"] :=
  show (ascii "rcp-1").length < lpLimit ∧ True from ⟨by decide, trivial⟩

theorem cp_admits : checkpointHash.Admits [ascii "rcp-1"] :=
  show (ascii "rcp-1").length < lpLimit ∧ True from ⟨by decide, trivial⟩

theorem nil_admits_rs : recordSig.Admits [] := show True from trivial
theorem nil_admits_cs : checkpointSig.Admits [] := show True from trivial

theorem recordHash_pre_inj {a b : CV}
    (h : recordHash.msg [ascii "rcp-1"] (utf8 (ser a)) = recordHash.msg [ascii "rcp-1"] (utf8 (ser b))) :
    a = b := by
  have := (recordHash.msg_inj (by decide) rec_admits rec_admits h).2 rfl
  exact ser_injective (utf8_inj this)

theorem checkpointHash_pre_inj {a b : CV}
    (h : checkpointHash.msg [ascii "rcp-1"] (utf8 (ser a)) =
      checkpointHash.msg [ascii "rcp-1"] (utf8 (ser b))) : a = b := by
  have := (checkpointHash.msg_inj (by decide) cp_admits cp_admits h).2 rfl
  exact ser_injective (utf8_inj this)

/-- Two record content hashes agree only for the same body, or via a SHA-256 collision. -/
theorem recordHashOf_binding (H fmt : Bytes → Bytes) (hfmt : ∀ x y, fmt x = fmt y → x = y)
    {a b : CV} (h : recordHashOf H fmt a = recordHashOf H fmt b) : a = b ∨ Collision H := by
  have hH := hfmt _ _ h
  by_cases hp : recordHash.msg [ascii "rcp-1"] (utf8 (ser a)) =
      recordHash.msg [ascii "rcp-1"] (utf8 (ser b))
  · exact Or.inl (recordHash_pre_inj hp)
  · exact Or.inr ⟨_, _, hp, hH⟩

theorem checkpointHashOf_binding (H fmt : Bytes → Bytes) (hfmt : ∀ x y, fmt x = fmt y → x = y)
    {a b : CV} (h : checkpointHashOf H fmt a = checkpointHashOf H fmt b) : a = b ∨ Collision H := by
  have hH := hfmt _ _ h
  by_cases hp : checkpointHash.msg [ascii "rcp-1"] (utf8 (ser a)) =
      checkpointHash.msg [ascii "rcp-1"] (utf8 (ser b))
  · exact Or.inl (checkpointHash_pre_inj hp)
  · exact Or.inr ⟨_, _, hp, hH⟩

/-- A record hash never equals a checkpoint hash (no record/checkpoint type confusion), except via
a SHA-256 collision: their preimages carry different pinned domains. -/
theorem record_ne_checkpoint_hash (H fmt : Bytes → Bytes) (hfmt : ∀ x y, fmt x = fmt y → x = y)
    (a b : CV) (h : recordHashOf H fmt a = checkpointHashOf H fmt b) : Collision H := by
  have hH := hfmt _ _ h
  refine ⟨_, _, ?_, hH⟩
  exact Family.msg_disjoint recordHash checkpointHash _ _ _ _ (by decide) (by decide) (by decide)

theorem recordSig_ne_checkpointSig (x y : Bytes) :
    recordSig.msg [] x ≠ checkpointSig.msg [] y :=
  signed_families_disjoint (i := 0) (j := 1) (by decide) (by decide) (by decide) [] [] x y

/--
**Record seal theorem.** If a record body's signature verifies under the pinned key (so, absent an
Ed25519 forgery, the key holder signed its message) then the body is *exactly* one the key holder
sealed — or SHA-256 has a collision. In particular no checkpoint signature can be replayed as a
record signature, and no second body can share a sealed body's signature.
-/
theorem record_seal_sound (H fmt : Bytes → Bytes) (hfmt : ∀ x y, fmt x = fmt y → x = y)
    (Signed : Bytes → Prop) (records checkpoints : List CV)
    (honest : HonestSigner H fmt Signed records checkpoints)
    (body : CV) (verified : Signed (recordSig.msg [] (recordHashOf H fmt body))) :
    body ∈ records ∨ Collision H := by
  rcases honest _ verified with ⟨B, hB, hm⟩ | ⟨C, _, hm⟩
  · have := (recordSig.msg_inj (by decide) nil_admits_rs nil_admits_rs hm).2 rfl
    rcases recordHashOf_binding H fmt hfmt this with h | h
    · exact Or.inl (h ▸ hB)
    · exact Or.inr h
  · exact absurd hm (recordSig_ne_checkpointSig _ _)

/-- **Checkpoint seal theorem** (same statement for checkpoint bodies). -/
theorem checkpoint_seal_sound (H fmt : Bytes → Bytes) (hfmt : ∀ x y, fmt x = fmt y → x = y)
    (Signed : Bytes → Prop) (records checkpoints : List CV)
    (honest : HonestSigner H fmt Signed records checkpoints)
    (body : CV) (verified : Signed (checkpointSig.msg [] (checkpointHashOf H fmt body))) :
    body ∈ checkpoints ∨ Collision H := by
  rcases honest _ verified with ⟨B, _, hm⟩ | ⟨C, hC, hm⟩
  · exact absurd hm.symm (recordSig_ne_checkpointSig _ _)
  · have := (checkpointSig.msg_inj (by decide) nil_admits_cs nil_admits_cs hm).2 rfl
    rcases checkpointHashOf_binding H fmt hfmt this with h | h
    · exact Or.inl (h ▸ hC)
    · exact Or.inr h

/-! ## Hiding commitments are binding -/

/-- `commit.rs::commit` preimage for a field domain, nonce and value. -/
def commitPre (dom nonce value : Bytes) : Bytes := commitment.msg [dom, nonce, value] []

/-- **Commitment binding.** Equal commitments open to the same `(field_domain, nonce, value)`, or
SHA-256 has a collision. (A disclosure can never open one commitment to two different values.) -/
theorem commitment_binding (H : Bytes → Bytes) {d n v d' n' v' : Bytes}
    (hd : d.length < lpLimit) (hn : n.length < lpLimit) (hv : v.length < lpLimit)
    (hd' : d'.length < lpLimit) (hn' : n'.length < lpLimit) (hv' : v'.length < lpLimit)
    (h : H (commitPre d n v) = H (commitPre d' n' v')) :
    (d = d' ∧ n = n' ∧ v = v') ∨ Collision H := by
  by_cases hp : commitPre d n v = commitPre d' n' v'
  · have := (commitment.msg_inj (vs := [d, n, v]) (ws := [d', n', v']) (by decide)
      (show _ ∧ _ ∧ _ ∧ True from ⟨hd, hn, hv, trivial⟩)
      (show _ ∧ _ ∧ _ ∧ True from ⟨hd', hn', hv', trivial⟩) hp).1
    simp only [List.cons.injEq, and_true] at this
    exact Or.inl this
  · exact Or.inr ⟨_, _, hp, h⟩

end Averin.Seal
