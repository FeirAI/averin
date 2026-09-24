import Refinement.Sign

/-!
# The seal theorems, for the production code

**Explicit binding** (`record_hash_binding`, `checkpoint_hash_binding`). If two production bodies get
the same production content hash, then they have the same `domain`, the same `canon_version` and
denote the same canonical body (`SameBody`), or the two production preimages are different byte
strings with the same SHA-256 digest — an explicit collision of the trusted primitive on the two
inputs the code actually hashed. This uses the model's framing and injectivity lemmas
(`Averin.lp_append_inj`, `Averin.utf8_inj`, `Averin.Canon.ser_injective`) on the production
preimage, and the production formatter's injectivity (`fmtP_inj`).

**The model's hypotheses, discharged for production** (`record_hash_is_model`,
`checkpoint_hash_is_model`). For a body with the pinned `domain`/`canon_version`
(`record::verify_content_hash`, `checkpoint::verify_checkpoint_sealed`), the production content hash
string is *exactly* `Seal.recordHashOf prodH fmtM m`, with `fmtM` injective (`fmtM_inj`, the `hfmt`
hypothesis) and `fmtM ∘ prodH` always 71 bytes (`prodH_len`, the `hlen` hypothesis). So the model's
`recordHashOf_binding`, `record_ne_checkpoint_hash` and `record_seal_sound` apply verbatim to
production hashes (`production_record_seal_sound`). Note that the model's `Collision H` is an
existential; for a compressing `H` it is provable outright, so the explicit form above is the
load-bearing binding statement.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core
open Averin Averin.Canon Averin.Preimage

namespace Refinement

/-! ## Explicit binding -/

/-- Two bodies commit to the same thing: same raw `domain` and `canon_version`, same denotation. -/
def SameBody (ts : List (List Nat)) (a b : canon.CanonValue) : Prop :=
  ∃ d cv m, BodyDenotes ts a d cv m ∧ BodyDenotes ts b d cv m

theorem vals_array_inj {x y : Std.Array Std.U8 32#usize} (h : vals x.val = vals y.val) : x = y := by
  apply Std.Array.ext
  exact List.map_injective_iff.mpr (fun a b hab => UScalar.eq_of_val_eq hab) h

theorem vals_lt (l : List Std.U8) : ∀ x ∈ vals l, x < 256 := by
  intro x hx
  simp only [vals, List.mem_map] at hx
  obtain ⟨b, _, rfl⟩ := hx
  have : b.val < 2 ^ 8 := by scalar_tac
  simpa using this

theorem preimageBytes_inj {d cv d' cv' : String} {m m' : CV}
    (hd : (utf8 d.toList).length < lpLimit) (hcv : (utf8 cv.toList).length < lpLimit)
    (hd' : (utf8 d'.toList).length < lpLimit) (hcv' : (utf8 cv'.toList).length < lpLimit)
    (h : preimageBytes d cv m = preimageBytes d' cv' m') : d = d' ∧ cv = cv' ∧ m = m' := by
  unfold preimageBytes at h
  rw [List.append_assoc, List.append_assoc] at h
  obtain ⟨e1, h⟩ := lp_append_inj hd hd' h
  obtain ⟨e2, e3⟩ := lp_append_inj hcv hcv' h
  refine ⟨?_, ?_, ser_injective (utf8_inj e3)⟩
  · have := utf8_inj e1; exact String.toList_inj.mp this
  · have := utf8_inj e2; exact String.toList_inj.mp this

theorem bodyDenotes_functional {ts : List (List Nat)} {v : canon.CanonValue} {d cv d' cv' : String}
    {m m' : CV} (h : BodyDenotes ts v d cv m) (h' : BodyDenotes ts v d' cv' m') :
    d = d' ∧ cv = cv' ∧ m = m' := by
  obtain ⟨members, rfl, e1, e2, _, _, qs, L, hq, hp, hs, rfl⟩ := h
  obtain ⟨members', he, e1', e2', _, _, qs', L', hq', hp', hs', rfl⟩ := h'
  simp at he; subst he
  rw [e1] at e1'; rw [e2] at e2'
  simp at e1' e2'
  refine ⟨e1', e2', ?_⟩
  have hqq := pairs_functional (fun p _ => canon_functional _ p.2 rfl) hq hq'
  subst hqq
  rw [keySorted_perm_eq (hp.trans hp'.symm) hs hs']

/-- **Explicit binding of the record content hash.** -/
theorem record_hash_binding {a b : canon.CanonValue} {s : String}
    (ha : record.record_hash a = ok (.Ok s)) (hb : record.record_hash b = ok (.Ok s)) :
    SameBody recordStrip a b ∨
    ∃ pa pb, record.record_preimage a = ok (.Ok pa) ∧ record.record_preimage b = ok (.Ok pb) ∧
      vals pa.val ≠ vals pb.val ∧
      AverinTrusted.sha256 (alloc.vec.Vec.deref pa) = AverinTrusted.sha256 (alloc.vec.Vec.deref pb) := by
  obtain ⟨pa, da, cva, ma, hpa, hda, hva, hsa⟩ := record_hash_model ha
  obtain ⟨pb, db, cvb, mb, hpb, hdb, hvb, hsb⟩ := record_hash_model hb
  have hsha : AverinTrusted.sha256 (alloc.vec.Vec.deref pa) =
      AverinTrusted.sha256 (alloc.vec.Vec.deref pb) :=
    vals_array_inj (fmtP_inj (vals_lt _) (vals_lt _) (hsa.symm.trans hsb))
  by_cases hpre : vals pa.val = vals pb.val
  · left
    obtain ⟨_, _, _, _, hd1, hcv1, _⟩ := id hda
    obtain ⟨_, _, _, _, hd2, hcv2, _⟩ := id hdb
    obtain ⟨rfl, rfl, rfl⟩ := preimageBytes_inj hd1 hcv1 hd2 hcv2 (hva.symm.trans (hpre.trans hvb))
    exact ⟨da, cva, ma, hda, hdb⟩
  · right
    exact ⟨pa, pb, hpa, hpb, hpre, hsha⟩

/-- **Explicit binding of the checkpoint hash.** -/
theorem checkpoint_hash_binding {a b : canon.CanonValue} {s : String}
    (ha : checkpoint.checkpoint_hash a = ok (.Ok s)) (hb : checkpoint.checkpoint_hash b = ok (.Ok s)) :
    SameBody checkpointStrip a b ∨
    ∃ pa pb, checkpoint.checkpoint_preimage a = ok (.Ok pa) ∧
      checkpoint.checkpoint_preimage b = ok (.Ok pb) ∧ vals pa.val ≠ vals pb.val ∧
      AverinTrusted.sha256 (alloc.vec.Vec.deref pa) = AverinTrusted.sha256 (alloc.vec.Vec.deref pb) := by
  obtain ⟨pa, da, cva, ma, hpa, hda, hva, hsa⟩ := checkpoint_hash_model ha
  obtain ⟨pb, db, cvb, mb, hpb, hdb, hvb, hsb⟩ := checkpoint_hash_model hb
  have hsha : AverinTrusted.sha256 (alloc.vec.Vec.deref pa) =
      AverinTrusted.sha256 (alloc.vec.Vec.deref pb) :=
    vals_array_inj (fmtP_inj (vals_lt _) (vals_lt _) (hsa.symm.trans hsb))
  by_cases hpre : vals pa.val = vals pb.val
  · left
    obtain ⟨_, _, _, _, hd1, hcv1, _⟩ := id hda
    obtain ⟨_, _, _, _, hd2, hcv2, _⟩ := id hdb
    obtain ⟨rfl, rfl, rfl⟩ := preimageBytes_inj hd1 hcv1 hd2 hcv2 (hva.symm.trans (hpre.trans hvb))
    exact ⟨da, cva, ma, hda, hdb⟩
  · right
    exact ⟨pa, pb, hpa, hpb, hpre, hsha⟩

/-! ## The model's seal statements, instantiated with the production functions -/

/-- The production SHA-256 on byte strings, extended to all `Bytes` for the model's `H`
(out-of-range inputs, which the code never hashes, map to the digest of the empty slice). -/
noncomputable def prodH (x : Bytes) : Bytes :=
  if h : (∀ b ∈ x, b < 256) ∧ x.length ≤ Usize.max then
    vals (AverinTrusted.sha256 (Slice.from (x.map (fun b => (⟨BitVec.ofNat 8 b⟩ : Std.U8)))
      (by simpa using h.2))).val
  else vals (AverinTrusted.sha256 (Slice.from [] (by simp))).val

theorem prodH_prod (pre : alloc.vec.Vec Std.U8) :
    prodH (vals pre.val) = vals (AverinTrusted.sha256 (alloc.vec.Vec.deref pre)).val := by
  unfold prodH
  rw [dif_pos ⟨vals_lt _, by simp⟩]
  congr 3
  apply Slice.ext
  simp only [Slice.from_val, alloc.vec.Vec.deref, vals, List.map_map]
  conv => rhs; rw [← List.map_id pre.val]
  apply List.map_congr_left
  intro x _
  simp only [Function.comp_apply, id_eq]
  apply UScalar.eq_of_val_eq
  have hx : x.val < 256 := by scalar_tac
  show (BitVec.ofNat 8 x.val).toNat = x.val
  rw [BitVec.toNat_ofNat]
  exact Nat.mod_eq_of_lt hx

theorem prodH_bytes (x : Bytes) : (prodH x).length = 32 ∧ ∀ b ∈ prodH x, b < 256 := by
  unfold prodH
  split <;> exact ⟨by simp, vals_lt _⟩

/-- `hlen` of `Seal.record_seal_sound`, discharged: every formatted digest is 71 bytes. -/
theorem prodH_len : ∀ x, (fmtM (prodH x)).length = 71 := by
  intro x
  obtain ⟨hl, hb⟩ := prodH_bytes x
  unfold fmtM
  rw [if_pos hb]
  simp [fmtP, List.length_flatMap, hl]

/-- The pinned record profile (`verify_content_hash`): `domain = RECORD_DOMAIN`, `canon_version =
CANON_VERSION`, stated through the extracted constants. -/
def RecordPinned (d cv : String) : Prop :=
  utf8 d.toList = vals (strSlice record.RECORD_DOMAIN).val ∧
    utf8 cv.toList = vals (strSlice record.CANON_VERSION).val

def CheckpointPinned (d cv : String) : Prop :=
  utf8 d.toList = vals (strSlice checkpoint.CHECKPOINT_DOMAIN).val ∧
    utf8 cv.toList = vals (strSlice checkpoint.CHECKPOINT_CANON_VERSION).val

theorem record_constants :
    vals (strSlice record.RECORD_DOMAIN).val = ascii recordHash.tag ∧
    vals (strSlice record.CANON_VERSION).val = ascii "rcp-1" := by
  unfold record.RECORD_DOMAIN record.CANON_VERSION
  rw [lit_vals _ _ (by decide), lit_vals _ _ (by decide)]
  exact ⟨rfl, rfl⟩

theorem checkpoint_constants :
    vals (strSlice checkpoint.CHECKPOINT_DOMAIN).val = ascii checkpointHash.tag ∧
    vals (strSlice checkpoint.CHECKPOINT_CANON_VERSION).val = ascii "rcp-1" := by
  unfold checkpoint.CHECKPOINT_DOMAIN checkpoint.CHECKPOINT_CANON_VERSION
  rw [lit_vals _ _ (by decide), lit_vals _ _ (by decide)]
  exact ⟨rfl, rfl⟩

theorem family_msg1 (F : Family) (hs : F.schema = [.framed]) (ht : F.tailed = true) (v t : Bytes) :
    F.msg [v] t = lp (ascii F.tag) ++ lp v ++ t := by
  simp [Family.msg, encodeFields, Field.encode, hs, ht]

/-- **The production record preimage is the model's**: with the pinned profile, the bytes
`record::record_preimage` hashes are `recordHash.msg [ascii "rcp-1"] (utf8 (ser m))`. -/
theorem record_preimage_is_model {d cv : String} {m : CV} (hpin : RecordPinned d cv) :
    preimageBytes d cv m = recordHash.msg [ascii "rcp-1"] (utf8 (ser m)) := by
  obtain ⟨e1, e2⟩ := hpin
  rw [record_constants.1] at e1; rw [record_constants.2] at e2
  unfold preimageBytes
  rw [e1, e2, family_msg1 recordHash rfl rfl]

theorem checkpoint_preimage_is_model {d cv : String} {m : CV} (hpin : CheckpointPinned d cv) :
    preimageBytes d cv m = checkpointHash.msg [ascii "rcp-1"] (utf8 (ser m)) := by
  obtain ⟨e1, e2⟩ := hpin
  rw [checkpoint_constants.1] at e1; rw [checkpoint_constants.2] at e2
  unfold preimageBytes
  rw [e1, e2, family_msg1 checkpointHash rfl rfl]

/-- **The production content hash is the model's `recordHashOf`.** -/
theorem record_hash_is_model {body : canon.CanonValue} {s : String} {d cv : String} {m : CV}
    (h : record.record_hash body = ok (.Ok s)) (hden : BodyDenotes recordStrip body d cv m)
    (hpin : RecordPinned d cv) :
    utf8 s.toList = Seal.recordHashOf prodH fmtM m := by
  obtain ⟨pre, d', cv', m', _, hden', hv, hs⟩ := record_hash_model h
  obtain ⟨rfl, rfl, rfl⟩ := bodyDenotes_functional hden hden'
  rw [hs, Seal.recordHashOf, ← record_preimage_is_model hpin, ← hv, prodH_prod]
  unfold fmtM
  rw [if_pos (vals_lt _)]

theorem checkpoint_hash_is_model {body : canon.CanonValue} {s : String} {d cv : String} {m : CV}
    (h : checkpoint.checkpoint_hash body = ok (.Ok s))
    (hden : BodyDenotes checkpointStrip body d cv m) (hpin : CheckpointPinned d cv) :
    utf8 s.toList = Seal.checkpointHashOf prodH fmtM m := by
  obtain ⟨pre, d', cv', m', _, hden', hv, hs⟩ := checkpoint_hash_model h
  obtain ⟨rfl, rfl, rfl⟩ := bodyDenotes_functional hden hden'
  rw [hs, Seal.checkpointHashOf, ← checkpoint_preimage_is_model hpin, ← hv, prodH_prod]
  unfold fmtM
  rw [if_pos (vals_lt _)]

/-- **Model binding, applied to production hashes** (`Seal.recordHashOf_binding` with the production
`H`/`fmt`; its `hfmt` is `fmtM_inj`). -/
theorem production_record_binding_model {a b : canon.CanonValue} {s : String}
    {da cva db cvb : String} {ma mb : CV}
    (ha : record.record_hash a = ok (.Ok s)) (hb : record.record_hash b = ok (.Ok s))
    (hda : BodyDenotes recordStrip a da cva ma) (hdb : BodyDenotes recordStrip b db cvb mb)
    (hpa : RecordPinned da cva) (hpb : RecordPinned db cvb) :
    ma = mb ∨ Seal.Collision prodH :=
  Seal.recordHashOf_binding prodH fmtM fmtM_inj
    ((record_hash_is_model ha hda hpa).symm.trans (record_hash_is_model hb hdb hpb))

/-- **Seal soundness, applied to production.** If the key holder only ever signs through the
honest-signer interface of the model (`Seal.HonestSigner`, instantiated with the production hash),
and a record body's production content hash `s`, framed by the production `sign::preimage` under
`RECORD_SIG_TAG`, is a signed message, then the body's denotation is one the key holder sealed, or
SHA-256 (the model's `Collision`) collides. -/
theorem production_record_seal_sound (Signed : Bytes → Prop) (records checkpoints : List CV)
    (honest : Seal.HonestSigner prodH fmtM Signed records checkpoints)
    {body : canon.CanonValue} {s : String} {d cv : String} {m : CV}
    (h : record.record_hash body = ok (.Ok s)) (hden : BodyDenotes recordStrip body d cv m)
    (hpin : RecordPinned d cv) {ch : Str} (hch : vals (strSlice ch).val = utf8 s.toList)
    {msg : alloc.vec.Vec Std.U8}
    (hmsg : sign.preimage sign.RECORD_SIG_TAG ch = ok (some msg)) (verified : Signed (vals msg.val)) :
    m ∈ records ∨ Seal.Collision prodH := by
  have hm := ((sign_preimage_model hmsg).1 msg rfl).2
  rw [record_tag_vals, hch, record_hash_is_model h hden hpin, ← sign_msg_eq recordSig rfl rfl] at hm
  rw [hm] at verified
  exact Seal.record_seal_sound prodH fmtM fmtM_inj prodH_len Signed records checkpoints honest m
    verified

/-- **Checkpoint seal soundness, applied to production.** -/
theorem production_checkpoint_seal_sound (Signed : Bytes → Prop) (records checkpoints : List CV)
    (honest : Seal.HonestSigner prodH fmtM Signed records checkpoints)
    {body : canon.CanonValue} {s : String} {d cv : String} {m : CV}
    (h : checkpoint.checkpoint_hash body = ok (.Ok s))
    (hden : BodyDenotes checkpointStrip body d cv m) (hpin : CheckpointPinned d cv) {ch : Str}
    (hch : vals (strSlice ch).val = utf8 s.toList) {msg : alloc.vec.Vec Std.U8}
    (hmsg : sign.preimage sign.CHECKPOINT_SIG_TAG ch = ok (some msg))
    (verified : Signed (vals msg.val)) :
    m ∈ checkpoints ∨ Seal.Collision prodH := by
  have hm := ((sign_preimage_model hmsg).1 msg rfl).2
  rw [checkpoint_tag_vals, hch, checkpoint_hash_is_model h hden hpin,
    ← sign_msg_eq checkpointSig rfl rfl] at hm
  rw [hm] at verified
  exact Seal.checkpoint_seal_sound prodH fmtM fmtM_inj prodH_len Signed records checkpoints honest m
    verified

/-- A production record hash never equals a production checkpoint hash of a pinned body except
through the model's `Collision` (record/checkpoint type confusion, `Seal.record_ne_checkpoint_hash`). -/
theorem production_record_ne_checkpoint {a b : canon.CanonValue} {s : String} {da cva db cvb : String}
    {ma mb : CV} (ha : record.record_hash a = ok (.Ok s))
    (hb : checkpoint.checkpoint_hash b = ok (.Ok s))
    (hda : BodyDenotes recordStrip a da cva ma) (hdb : BodyDenotes checkpointStrip b db cvb mb)
    (hpa : RecordPinned da cva) (hpb : CheckpointPinned db cvb) : Seal.Collision prodH :=
  Seal.record_ne_checkpoint_hash prodH fmtM fmtM_inj ma mb
    ((record_hash_is_model ha hda hpa).symm.trans (checkpoint_hash_is_model hb hdb hpb))

end Refinement
