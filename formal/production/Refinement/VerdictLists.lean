import Refinement.Escape

/-!
# The list checks of the verdict kernel

`verify::verdict::{key_pinned, seal_pinned, seals_pinned, anchors_checkpoint, anchored_at}` are
search loops over the verified seals, the pinned signer keys and the verified TSA anchors. Each
returns (total correctness: the loops terminate, no index or addition fails) the truth value of the
list predicate it searches for. `Refinement.Verdict` uses these to relate the kernel to the model.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

namespace Refinement

/-- A pinned Ed25519 key (`[u8; 32]`). -/
abbrev Key := Std.Array Std.U8 32#usize

theorem slice_index_total {α} (v : Slice α) (i : Std.Usize) (h : i.val < v.val.length) :
    Slice.index_usize v i = ok v.val[i.val] := by
  obtain ⟨x, hx, hv⟩ := spec_imp_exists (Slice.index_usize_spec v i (by simpa using h))
  rw [hx, hv]

theorem usize_succ_total (i : Std.Usize) {n : Nat} (hn : n ≤ Std.Usize.max) (h : i.val < n) :
    ∃ i2 : Std.Usize, i + 1#usize = ok i2 ∧ i2.val = i.val + 1 := by
  obtain ⟨z, hz, hv⟩ := spec_imp_exists (Usize.add_spec (x := i) (y := 1#usize) (by scalar_tac))
  exact ⟨z, hz, by simpa using hv⟩

theorem slice_len_le_max {α} (v : Slice α) : v.val.length ≤ Std.Usize.max := v.property

/-- `[u8; 32]` equality is value equality. -/
theorem array_ne_u8 (a b : Key) :
    core.array.equality.PartialEqArray.ne core.cmp.PartialEqU8 a b = ok (!decide (a = b)) := by
  -- The array and slice comparisons have the same body; the slice one has an Aeneas spec.
  have hs : core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 a b =
      core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a.to_slice b.to_slice := by
    unfold core.array.equality.PartialEqArray.eq core.slice.cmp.PartialEqSlice.eq
    simp only [Array.val_to_slice, Slice.length]
  obtain ⟨r, hr, hp⟩ := spec_imp_exists (core.slice.cmp.PartialEqSlice.eq_homo_spec
    core.cmp.PartialEqU8 a.to_slice b.to_slice (fun x y => by simp))
  have hab : a.to_slice = b.to_slice ↔ a = b := by
    rw [Slice.eq_iff, Std.Array.eq_iff, Array.val_to_slice, Array.val_to_slice]
  unfold core.array.equality.PartialEqArray.ne
  rw [hs, hr]
  cases r <;> simp_all

theorem key_pinned_loop_ok (keys : Slice (Key))
    (key : Key) :
    ∀ (n : Nat) (i : Std.Usize), keys.val.length - i.val = n → i.val ≤ keys.val.length →
    ∃ j, verify.verdict.key_pinned_loop keys key i = ok j ∧ i.val ≤ j.val ∧
      j.val ≤ keys.val.length ∧
      (∀ t (ht : t < keys.val.length), i.val ≤ t → t < j.val → keys.val[t] ≠ key) ∧
      (∀ (hj : j.val < keys.val.length), keys.val[j.val] = key) := by
  intro n
  induction n with
  | zero =>
    intro i hn hle
    refine ⟨i, ?_, le_refl _, hle, fun t _ h1 h2 => by omega, fun hj => by omega⟩
    unfold verify.verdict.key_pinned_loop
    have : ¬ i < Slice.len keys := by
      intro h; have : i.val < keys.val.length := by scalar_tac
      omega
    simp [this]
  | succ n ih =>
    intro i hn hle
    have hlt : i.val < keys.val.length := by omega
    have hlt' : i < Slice.len keys := by scalar_tac
    unfold verify.verdict.key_pinned_loop
    simp only [hlt', ↓reduceIte, slice_index_total keys i hlt, bind_tc_ok, array_ne_u8]
    by_cases he : keys.val[i.val] = key
    · rw [if_neg (by simp only [Bool.not_eq_true', decide_eq_false_iff_not, not_not]; exact he)]
      exact ⟨i, rfl, le_refl _, by omega, fun t _ h1 h2 => by omega, fun _ => he⟩
    · obtain ⟨i2, hi2, hv⟩ := usize_succ_total i (slice_len_le_max keys) hlt
      rw [if_pos (by simp only [Bool.not_eq_true', decide_eq_false_iff_not]; exact he), hi2,
        bind_tc_ok]
      obtain ⟨j, hj, r1, r2, r3, r4⟩ := ih i2 (by omega) (by omega)
      refine ⟨j, hj, by omega, r2, ?_, r4⟩
      intro t ht h1 h2
      by_cases hti : t = i.val
      · subst hti; exact he
      · exact r3 t ht (by omega) h2

/-- `key_pinned` decides membership of `key` among the pinned signer keys. -/
theorem key_pinned_ok (keys : Slice (Key))
    (key : Key) :
    verify.verdict.key_pinned keys key = ok (decide (key ∈ keys.val)) := by
  obtain ⟨j, hj, r1, r2, r3, r4⟩ := key_pinned_loop_ok keys key _ 0#usize rfl (by simp)
  unfold verify.verdict.key_pinned
  simp only [hj, bind_tc_ok, ok_eq_ok]
  by_cases hlt : j.val < keys.val.length
  · have hlt' : j < Slice.len keys := by scalar_tac
    simp only [hlt', decide_true]
    symm; simp only [decide_eq_true_eq]
    rw [← r4 hlt]; exact List.getElem_mem hlt
  · have hge : ¬ j < Slice.len keys := by scalar_tac
    simp only [hge, decide_false]
    symm; simp only [decide_eq_false_iff_not]
    intro hm
    obtain ⟨t, ht, htk⟩ := List.mem_iff_getElem.mp hm
    exact r3 t ht (by simp) (by omega) htk

/-- A string is empty exactly when it has no UTF-8 bytes (the glue's `String::is_empty`). -/
abbrev Nonempty' (s : String) : Prop := AverinGlue.stringBytes s ≠ []

theorem seal_pinned_ok (sl : verify.verdict.PinnedRecordSeal)
    (keys : Slice (Key)) :
    verify.verdict.seal_pinned sl keys =
      ok (decide (Nonempty' sl.record_hash ∧ sl.key_bytes ∈ keys.val)) := by
  unfold verify.verdict.seal_pinned
  simp only [alloc.string.String.is_empty, bind_tc_ok]
  by_cases h : AverinGlue.stringBytes sl.record_hash = []
  · simp [h]
  · simp [h, key_pinned_ok]

theorem seals_pinned_loop_ok (seals : Slice verify.verdict.PinnedRecordSeal)
    (keys : Slice (Key)) :
    ∀ (n : Nat) (i : Std.Usize), seals.val.length - i.val = n → i.val ≤ seals.val.length →
    ∃ j, verify.verdict.seals_pinned_loop seals keys i = ok j ∧ i.val ≤ j.val ∧
      j.val ≤ seals.val.length ∧
      (∀ t (ht : t < seals.val.length), i.val ≤ t → t < j.val →
        Nonempty' seals.val[t].record_hash ∧ seals.val[t].key_bytes ∈ keys.val) ∧
      (∀ (hj : j.val < seals.val.length),
        ¬ (Nonempty' seals.val[j.val].record_hash ∧ seals.val[j.val].key_bytes ∈ keys.val)) := by
  intro n
  induction n with
  | zero =>
    intro i hn hle
    refine ⟨i, ?_, le_refl _, hle, fun t _ h1 h2 => by omega, fun hj => by omega⟩
    unfold verify.verdict.seals_pinned_loop
    have : ¬ i < Slice.len seals := by
      intro h; have : i.val < seals.val.length := by scalar_tac
      omega
    simp [this]
  | succ n ih =>
    intro i hn hle
    have hlt : i.val < seals.val.length := by omega
    have hlt' : i < Slice.len seals := by scalar_tac
    unfold verify.verdict.seals_pinned_loop
    simp only [hlt', ↓reduceIte, slice_index_total seals i hlt, bind_tc_ok, seal_pinned_ok]
    by_cases hp : Nonempty' seals.val[i.val].record_hash ∧ seals.val[i.val].key_bytes ∈ keys.val
    · obtain ⟨i2, hi2, hv⟩ := usize_succ_total i (slice_len_le_max seals) hlt
      rw [if_pos (by simp only [decide_eq_true_eq]; exact hp), hi2, bind_tc_ok]
      obtain ⟨j, hj, r1, r2, r3, r4⟩ := ih i2 (by omega) (by omega)
      refine ⟨j, hj, by omega, r2, ?_, r4⟩
      intro t ht h1 h2
      by_cases hti : t = i.val
      · subst hti; exact hp
      · exact r3 t ht (by omega) h2
    · rw [if_neg (by simp only [decide_eq_true_eq]; exact hp)]
      exact ⟨i, rfl, le_refl _, by omega, fun t _ h1 h2 => by omega, fun _ => hp⟩

/-- `seals_pinned` decides that every seal names a record hash and a pinned key. -/
theorem seals_pinned_ok (seals : Slice verify.verdict.PinnedRecordSeal)
    (keys : Slice (Key)) :
    verify.verdict.seals_pinned seals keys =
      ok (decide (∀ s ∈ seals.val, Nonempty' s.record_hash ∧ s.key_bytes ∈ keys.val)) := by
  obtain ⟨j, hj, r1, r2, r3, r4⟩ := seals_pinned_loop_ok seals keys _ 0#usize rfl (by simp)
  unfold verify.verdict.seals_pinned
  simp only [hj, bind_tc_ok, ok_eq_ok]
  by_cases hlt : j.val < seals.val.length
  · have hne : ¬ j = Slice.len seals := by intro e; have := congrArg (·.val) e; simp at this; omega
    simp only [hne, decide_false]
    symm; simp only [decide_eq_false_iff_not]
    intro hall
    exact r4 hlt (hall _ (List.getElem_mem hlt))
  · have heq : j = Slice.len seals := by
      apply UScalar.eq_of_val_eq; simp; omega
    simp only [heq, decide_true]
    symm; simp only [decide_eq_true_eq]
    intro s hs
    obtain ⟨t, ht, hts⟩ := List.mem_iff_getElem.mp hs
    rw [← hts]; exact r3 t ht (by simp) (by omega)

/-- The anchor names the checkpoint `sequence`, with a checkpoint hash and a time. -/
abbrev AnchorsCheckpoint (a : verify.verdict.AnchoredCheckpoint) (sequence : Std.I64) : Prop :=
  a.sequence = sequence ∧ Nonempty' a.checkpoint_hash ∧ Nonempty' a.timestamp

theorem anchors_checkpoint_ok (a : verify.verdict.AnchoredCheckpoint) (sequence : Std.I64) :
    verify.verdict.anchors_checkpoint a sequence = ok (decide (AnchorsCheckpoint a sequence)) := by
  unfold verify.verdict.anchors_checkpoint
  simp only [alloc.string.String.is_empty, bind_tc_ok]
  by_cases hs : a.sequence = sequence <;>
  by_cases hh : AverinGlue.stringBytes a.checkpoint_hash = [] <;>
  by_cases ht : AverinGlue.stringBytes a.timestamp = [] <;>
  simp [hs, hh, ht, AnchorsCheckpoint]

theorem anchored_at_loop_ok (anchors : Slice verify.verdict.AnchoredCheckpoint)
    (sequence : Std.I64) :
    ∀ (n : Nat) (i : Std.Usize), anchors.val.length - i.val = n → i.val ≤ anchors.val.length →
    ∃ j, verify.verdict.anchored_at_loop anchors sequence i = ok j ∧ i.val ≤ j.val ∧
      j.val ≤ anchors.val.length ∧
      (∀ t (ht : t < anchors.val.length), i.val ≤ t → t < j.val →
        ¬ AnchorsCheckpoint anchors.val[t] sequence) ∧
      (∀ (hj : j.val < anchors.val.length), AnchorsCheckpoint anchors.val[j.val] sequence) := by
  intro n
  induction n with
  | zero =>
    intro i hn hle
    refine ⟨i, ?_, le_refl _, hle, fun t _ h1 h2 => by omega, fun hj => by omega⟩
    unfold verify.verdict.anchored_at_loop
    have : ¬ i < Slice.len anchors := by
      intro h; have : i.val < anchors.val.length := by scalar_tac
      omega
    simp [this]
  | succ n ih =>
    intro i hn hle
    have hlt : i.val < anchors.val.length := by omega
    have hlt' : i < Slice.len anchors := by scalar_tac
    unfold verify.verdict.anchored_at_loop
    simp only [hlt', ↓reduceIte, slice_index_total anchors i hlt, bind_tc_ok, anchors_checkpoint_ok]
    by_cases hp : AnchorsCheckpoint anchors.val[i.val] sequence
    · rw [if_pos (by simp only [decide_eq_true_eq]; exact hp)]
      exact ⟨i, rfl, le_refl _, by omega, fun t _ h1 h2 => by omega, fun _ => hp⟩
    · obtain ⟨i2, hi2, hv⟩ := usize_succ_total i (slice_len_le_max anchors) hlt
      rw [if_neg (by simp only [decide_eq_true_eq]; exact hp), hi2, bind_tc_ok]
      obtain ⟨j, hj, r1, r2, r3, r4⟩ := ih i2 (by omega) (by omega)
      refine ⟨j, hj, by omega, r2, ?_, r4⟩
      intro t ht h1 h2
      by_cases hti : t = i.val
      · subst hti; exact hp
      · exact r3 t ht (by omega) h2

/-- `anchored_at` decides that some verified anchor names the checkpoint `sequence`. -/
theorem anchored_at_ok (anchors : Slice verify.verdict.AnchoredCheckpoint) (sequence : Std.I64) :
    verify.verdict.anchored_at anchors sequence =
      ok (decide (∃ a ∈ anchors.val, AnchorsCheckpoint a sequence)) := by
  obtain ⟨j, hj, r1, r2, r3, r4⟩ := anchored_at_loop_ok anchors sequence _ 0#usize rfl (by simp)
  unfold verify.verdict.anchored_at
  simp only [hj, bind_tc_ok, ok_eq_ok]
  by_cases hlt : j.val < anchors.val.length
  · have hlt' : j < Slice.len anchors := by scalar_tac
    simp only [hlt', decide_true]
    symm; simp only [decide_eq_true_eq]
    exact ⟨_, List.getElem_mem hlt, r4 hlt⟩
  · have hge : ¬ j < Slice.len anchors := by scalar_tac
    simp only [hge, decide_false]
    symm; simp only [decide_eq_false_iff_not]
    rintro ⟨a, ha, hp⟩
    obtain ⟨t, ht, hta⟩ := List.mem_iff_getElem.mp ha
    exact r3 t ht (by simp) (by omega) (hta ▸ hp)

end Refinement
