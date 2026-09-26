import Refinement.Preimage

/-!
# The signature message (`sign::preimage`)

`sign_preimage_model`: `sign::preimage(tag, ch)` returns `Some(LP(tag) ‖ ch)` or `None`, and `None`
exactly when `tag` is too long to frame — callers fail closed on it (`sign` panics, `verify`
rejects). `sign_preimage_record` / `sign_preimage_checkpoint`: for the production tag constants the
result is always `Some`, and it is the model's `recordSig.msg [] ch` / `checkpointSig.msg [] ch`.
The tag constants themselves are the extracted `sign::RECORD_SIG_TAG`/`CHECKPOINT_SIG_TAG`, so
renaming a production tag breaks these proofs.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core
open Averin Averin.Preimage

namespace Refinement

theorem sign_preimage_model {tag ch : Str} {r : Option (alloc.vec.Vec Std.U8)}
    (h : sign.preimage tag ch = ok r) :
    (∀ pre, r = some pre → (strSlice tag).val.length < lpLimit ∧
      vals pre.val = lp (vals (strSlice tag).val) ++ vals (strSlice ch).val) ∧
    (r = none → lpLimit ≤ (strSlice tag).val.length) := by
  unfold sign.preimage at h
  obtain ⟨⟨b, p⟩, hp, h⟩ := bind_eq_ok.mp h
  have hpv := lp_str_into_model hp
  cases b
  · simp at h; subst h
    exact ⟨fun _ hh => by simp at hh, fun _ => (hpv.2 rfl).1⟩
  · obtain ⟨hlen, hpv⟩ := hpv.1 rfl
    obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
    simp [core.str.Str.as_bytes] at hs
    obtain ⟨p1, hp1, h⟩ := bind_eq_ok.mp h
    simp at h; subst h
    refine ⟨fun pre hpre => ?_, fun hh => by simp at hh⟩
    simp at hpre; subst hpre
    refine ⟨hlen, ?_⟩
    rw [extend_u8_ok hp1]
    simp only [vals, List.map_append] at hpv ⊢
    rw [hpv]
    have : s = strSlice ch := by rw [← hs]; rfl
    subst this
    simp [alloc.vec.Vec.new]
    rfl

/-- `Vec::extend_from_slice` succeeds while the result fits in `usize`. -/
theorem extend_u8_eq (v : alloc.vec.Vec Std.U8) (s : Slice Std.U8)
    (hlen : v.val.length + s.val.length ≤ Usize.max) :
    ∃ w, alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v s = ok w ∧ w.val = v.val ++ s.val := by
  unfold alloc.vec.Vec.extend_from_slice
  rw [dif_pos (by simpa using hlen)]
  obtain ⟨s', hs', hss⟩ := spec_imp_exists (Slice.clone_spec (clone := core.clone.CloneU8.clone)
    (s := s) (fun x _ => rfl))
  split
  · rename_i s'' h''
    simp at h''; rw [hs'] at h''; simp at h''; subst h''; subst hss
    exact ⟨_, rfl, by simp⟩
  · rename_i h''; simp [hs'] at h''
  · rename_i h''; simp [hs'] at h''

theorem tag_frames (tag : Str) (htag : (strSlice tag).val.length < 256) (ch : Str)
    (hch : (strSlice ch).val.length + 260 ≤ Usize.max) :
    ∃ pre, sign.preimage tag ch = ok (some pre) := by
  have hmax : 4294967295 ≤ Usize.max := by
    have := System.Platform.numBits_eq
    simp only [Usize.max, Usize.numBits, UScalarTy.numBits]
    rcases this with h | h <;> rw [h] <;> decide
  unfold sign.preimage hashx.lp_str_into hashx.lp_into
  simp only [core.str.Str.as_bytes, bind_tc_ok]
  have hmx : hashx.MAX_LP_LEN = ok (UScalar.cast UScalarTy.Usize core.num.U32.MAX) := by
    unfold hashx.MAX_LP_LEN; rfl
  rw [hmx, bind_tc_ok]
  have hle : ¬ (Slice.len (strSlice tag) > UScalar.cast UScalarTy.Usize core.num.U32.MAX) := by
    intro hgt
    have hc : (UScalar.cast UScalarTy.Usize core.num.U32.MAX).val = 4294967295 := by
      rw [UScalar.cast_val_eq]
      have : (core.num.U32.MAX).val = 4294967295 := rfl
      rw [this]
      have : 4294967295 < 2 ^ UScalarTy.Usize.numBits := by
        have := System.Platform.numBits_eq
        simp only [UScalarTy.numBits]
        rcases this with h | h <;> rw [h] <;> decide
      exact Nat.mod_eq_of_lt this
    have : (Slice.len (strSlice tag)).val > 4294967295 := by rw [← hc]; scalar_tac
    simp at this
    omega
  have e1 := extend_u8_eq (alloc.vec.Vec.new Std.U8)
    (Std.Array.to_slice (core.num.U32.to_be_bytes (UScalar.cast UScalarTy.U32 (Slice.len (strSlice tag)))))
    (by simp [Std.Array.to_slice]; omega)
  obtain ⟨w1, hw1, hw1v⟩ := e1
  have e2 := extend_u8_eq w1 (strSlice tag) (by rw [hw1v]; simp [Std.Array.to_slice]; omega)
  obtain ⟨w2, hw2, hw2v⟩ := e2
  have e3 := extend_u8_eq w2 (strSlice ch) (by rw [hw2v, hw1v]; simp [Std.Array.to_slice]; omega)
  obtain ⟨w3, hw3, _⟩ := e3
  refine ⟨w3, ?_⟩
  simp only [strSlice] at hle hw1 hw2 hw3
  simp only [lift, bind_tc_ok]
  rw [if_neg hle]
  simp only [hw1, hw2, bind_tc_ok]
  have hfin : Aeneas.Std.bind (alloc.vec.Vec.extend_from_slice core.clone.CloneU8 w2 (strSlice ch))
      (fun pre1 => ok (some pre1)) = ok (some w3) := by
    simp only [strSlice] at hw3 ⊢
    rw [hw3, bind_ok]
  exact hfin

theorem record_tag_vals : vals (strSlice sign.RECORD_SIG_TAG).val = ascii recordSig.tag := by
  unfold sign.RECORD_SIG_TAG
  rw [lit_vals _ _ (by decide)]
  rfl

theorem checkpoint_tag_vals :
    vals (strSlice sign.CHECKPOINT_SIG_TAG).val = ascii checkpointSig.tag := by
  unfold sign.CHECKPOINT_SIG_TAG
  rw [lit_vals _ _ (by decide)]
  rfl

theorem sign_msg_eq (F : Family) (hs : F.schema = []) (ht : F.tailed = true) (x : Bytes) :
    F.msg [] x = lp (ascii F.tag) ++ x := by
  simp [Family.msg, encodeFields, Field.encode, hs, ht]

/-- **The record signature message.** For every content hash (up to `usize::MAX - 260` bytes),
`sign::preimage(RECORD_SIG_TAG, ch)` is `Some`, and it is `recordSig.msg [] ch`. -/
theorem sign_preimage_record (ch : Str) (hch : (strSlice ch).val.length + 260 ≤ Usize.max) :
    ∃ pre, sign.preimage sign.RECORD_SIG_TAG ch = ok (some pre) ∧
      vals pre.val = recordSig.msg [] (vals (strSlice ch).val) := by
  have hlen : (strSlice sign.RECORD_SIG_TAG).val.length < 256 := by
    have := congrArg List.length record_tag_vals; simp at this; rw [this]; decide
  obtain ⟨pre, hpre⟩ := tag_frames _ hlen ch hch
  refine ⟨pre, hpre, ?_⟩
  rw [((sign_preimage_model hpre).1 pre rfl).2, record_tag_vals,
    sign_msg_eq recordSig rfl rfl]

/-- **The checkpoint signature message.** -/
theorem sign_preimage_checkpoint (ch : Str) (hch : (strSlice ch).val.length + 260 ≤ Usize.max) :
    ∃ pre, sign.preimage sign.CHECKPOINT_SIG_TAG ch = ok (some pre) ∧
      vals pre.val = checkpointSig.msg [] (vals (strSlice ch).val) := by
  have hlen : (strSlice sign.CHECKPOINT_SIG_TAG).val.length < 256 := by
    have := congrArg List.length checkpoint_tag_vals; simp at this; rw [this]; decide
  obtain ⟨pre, hpre⟩ := tag_frames _ hlen ch hch
  refine ⟨pre, hpre, ?_⟩
  rw [((sign_preimage_model hpre).1 pre rfl).2, checkpoint_tag_vals,
    sign_msg_eq checkpointSig rfl rfl]

end Refinement
