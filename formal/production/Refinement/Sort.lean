import Refinement.Utf16

/-!
# `canon::sort_by_units` sorts

The production merge sort returns a permutation of its input positions, ordered by the key order
`keyLe` (not after, in UTF-16 code-unit order). It is Lean core's `List.merge` step by step, so the
core lemmas `merge_perm_append` and `pairwise_merge` apply.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

namespace Refinement

/-- The code units stored at position `p` (empty when `p` is out of range, which never happens). -/
def ukey (units : Slice (alloc.vec.Vec Std.U16)) (p : Std.Usize) : List Nat :=
  ((units.val[p.val]?).map (fun v => vals v.val)).getD []

/-- `p` may precede `q`: `q`'s key is not smaller. -/
def keyLe (units : Slice (alloc.vec.Vec Std.U16)) (p q : Std.Usize) : Bool :=
  !decide (ukey units q < ukey units p)

theorem keyLe_trans (units : Slice (alloc.vec.Vec Std.U16)) :
    ∀ a b c, keyLe units a b → keyLe units b c → keyLe units a c := by
  intro a b c h1 h2
  simp only [keyLe, Bool.not_eq_true', decide_eq_false_iff_not] at *
  exact List.le_trans (List.not_lt.mp h1) (List.not_lt.mp h2)

theorem keyLe_total (units : Slice (alloc.vec.Vec Std.U16)) :
    ∀ a b, keyLe units a b || keyLe units b a := by
  intro a b
  simp only [keyLe, Bool.or_eq_true, Bool.not_eq_true', decide_eq_false_iff_not]
  by_contra hc
  simp only [not_or, not_not] at hc
  exact List.lt_asymm hc.1 hc.2

theorem index_key {units : Slice (alloc.vec.Vec Std.U16)} {p : Std.Usize}
    {v : alloc.vec.Vec Std.U16} (h : Slice.index_usize units p = ok v) :
    vals (alloc.vec.Vec.deref v).val = ukey units p := by
  obtain ⟨hp, hv⟩ := slice_index_ok h
  simp [ukey, alloc.vec.Vec.deref, List.getElem?_eq_getElem hp, hv]

/-- One comparison of the merge: `units_lt` on the keys at `q` and `p` is `¬ keyLe p q`. -/
theorem cmp_ok {units : Slice (alloc.vec.Vec Std.U16)} {p q : Std.Usize}
    {vq vp : alloc.vec.Vec Std.U16} {b : Bool}
    (hq : Slice.index_usize units q = ok vq) (hp : Slice.index_usize units p = ok vp)
    (h : canon.units_lt (alloc.vec.Vec.deref vq) (alloc.vec.Vec.deref vp) = ok b) :
    b = !keyLe units p q := by
  rw [units_lt_model h, index_key hq, index_key hp]
  simp [keyLe]

theorem merge_loop_ok : ∀ (m : Nat) (units : Slice (alloc.vec.Vec Std.U16))
    (left right : Slice Std.Usize) (out r : alloc.vec.Vec Std.Usize) (i j : Std.Usize),
    (left.val.length - i.val) + (right.val.length - j.val) = m →
    i.val ≤ left.val.length → j.val ≤ right.val.length →
    canon.merge_by_units_loop units left right out i j = ok r →
    r.val = out.val ++ List.merge (left.val.drop i.val) (right.val.drop j.val) (keyLe units) := by
  intro m
  induction m with
  | zero =>
    intro units left right out r i j hm hi hj h
    have ei : i.val = left.val.length := by omega
    have ej : j.val = right.val.length := by omega
    unfold canon.merge_by_units_loop at h
    dsimp only at h
    split at h
    · rename_i hlt; have : i.val < left.val.length := by scalar_tac
      omega
    · split at h
      · rename_i hlt; have : j.val < right.val.length := by scalar_tac
        omega
      · simp at h; subst h
        simp [ei, ej]
  | succ m ih =>
    intro units left right out r i j hm hi hj h
    unfold canon.merge_by_units_loop at h
    dsimp only at h
    split at h
    · rename_i hlt
      have hlt' : i.val < left.val.length := by scalar_tac
      have dl : left.val.drop i.val = left.val[i.val] :: left.val.drop (i.val + 1) :=
        List.drop_eq_getElem_cons hlt'
      split at h
      · -- right exhausted: take from the left
        rename_i hje
        have hje' : j.val = right.val.length := by scalar_tac
        obtain ⟨x, hx, h⟩ := bind_eq_ok.mp h
        obtain ⟨_, hxv⟩ := slice_index_ok hx
        obtain ⟨o1, ho1, h⟩ := bind_eq_ok.mp h
        obtain ⟨i4, hi4, h⟩ := bind_eq_ok.mp h
        have hi4v := uadd_ok hi4; simp at hi4v
        rw [ih units left right o1 r i4 j (by omega) (by omega) hj h, push_ok ho1, dl, hi4v, hxv]
        have : right.val.drop j.val = [] := by simp; omega
        simp [this]
      · rename_i hjne
        have hjlt : j.val < right.val.length := by
          have : j.val ≠ right.val.length := by intro e; apply hjne; scalar_tac
          omega
        have dr : right.val.drop j.val = right.val[j.val] :: right.val.drop (j.val + 1) :=
          List.drop_eq_getElem_cons hjlt
        obtain ⟨y, hy, h⟩ := bind_eq_ok.mp h
        obtain ⟨_, hyv⟩ := slice_index_ok hy
        obtain ⟨vy, hvy, h⟩ := bind_eq_ok.mp h
        obtain ⟨x, hx, h⟩ := bind_eq_ok.mp h
        obtain ⟨_, hxv⟩ := slice_index_ok hx
        obtain ⟨vx, hvx, h⟩ := bind_eq_ok.mp h
        obtain ⟨b, hb, h⟩ := bind_eq_ok.mp h
        have hbv := cmp_ok hvy hvx hb
        rw [dl, dr, List.cons_merge_cons]
        split at h
        · rename_i hbt
          obtain ⟨o1, ho1, h⟩ := bind_eq_ok.mp h
          obtain ⟨j1, hj1, h⟩ := bind_eq_ok.mp h
          have hj1v := uadd_ok hj1; simp at hj1v
          rw [ih units left right o1 r i j1 (by omega) hi (by omega) h, push_ok ho1]
          have hle : keyLe units x y = false := by
            rw [hbt] at hbv; simpa using hbv.symm
          rw [← hxv, ← hyv, hle, dl, hj1v, hxv]
          simp
        · rename_i hbf
          obtain ⟨o1, ho1, h⟩ := bind_eq_ok.mp h
          obtain ⟨i1, hi1, h⟩ := bind_eq_ok.mp h
          have hi1v := uadd_ok hi1; simp at hi1v
          rw [ih units left right o1 r i1 j (by omega) (by omega) hj h, push_ok ho1]
          have hle : keyLe units x y = true := by
            have : b = false := by simpa using hbf
            rw [this] at hbv; simpa using hbv.symm
          rw [← hxv, ← hyv, hle, dr, hi1v, hyv]
          simp
    · rename_i hge
      have hge' : ¬ i.val < left.val.length := by scalar_tac
      have ei : i.val = left.val.length := by omega
      have dl : left.val.drop i.val = [] := by simp; omega
      split at h
      · rename_i hjlt
        have hjlt' : j.val < right.val.length := by scalar_tac
        have dr : right.val.drop j.val = right.val[j.val] :: right.val.drop (j.val + 1) :=
          List.drop_eq_getElem_cons hjlt'
        split at h
        · rename_i hje; exfalso; have : j.val = right.val.length := by scalar_tac
          omega
        · obtain ⟨y, hy, h⟩ := bind_eq_ok.mp h
          obtain ⟨_, hyv⟩ := slice_index_ok hy
          obtain ⟨o1, ho1, h⟩ := bind_eq_ok.mp h
          obtain ⟨j1, hj1, h⟩ := bind_eq_ok.mp h
          have hj1v := uadd_ok hj1; simp at hj1v
          rw [ih units left right o1 r i j1 (by omega) hi (by omega) h, push_ok ho1, dl, dr,
            hj1v, hyv]
          simp
      · rename_i hjge
        have : ¬ j.val < right.val.length := by scalar_tac
        omega

theorem merge_ok {units : Slice (alloc.vec.Vec Std.U16)} {left right : Slice Std.Usize}
    {r : alloc.vec.Vec Std.Usize} (h : canon.merge_by_units units left right = ok r) :
    r.val = List.merge left.val right.val (keyLe units) := by
  unfold canon.merge_by_units at h
  obtain ⟨n, _, h⟩ := bind_eq_ok.mp h
  have := merge_loop_ok _ units left right _ r 0#usize 0#usize rfl (by simp) (by simp) h
  simpa [alloc.vec.Vec.with_capacity] using this

/-- **`sort_by_units` sorts**: a permutation of the positions, in key order. -/
theorem sort_ok : ∀ (m : Nat) (units : Slice (alloc.vec.Vec Std.U16)) (pos : Slice Std.Usize)
    (r : alloc.vec.Vec Std.Usize), pos.val.length = m →
    canon.sort_by_units units pos = ok r →
    r.val.Perm pos.val ∧ r.val.Pairwise (fun a b => keyLe units a b) := by
  intro m
  induction m using Nat.strong_induction_on with
  | _ m ih =>
    intro units pos r hm h
    unfold canon.sort_by_units at h
    dsimp only at h
    split at h
    · rename_i hle
      have hle' : pos.val.length ≤ 1 := by scalar_tac
      have := spec_ok_eq (alloc.slice.Slice.to_vec_spec core.clone.CloneUsize pos
        (fun x _ => rfl)) h
      have hr : r.val = pos.val := by
        subst this; simp [alloc.vec.Vec.val]
      rw [hr]
      refine ⟨List.Perm.refl _, ?_⟩
      match hp : pos.val, hle' with
      | [], _ => simp
      | [_], _ => simp
    · rename_i hgt
      have hgt' : 1 < pos.val.length := by scalar_tac
      obtain ⟨i3, hi3, h⟩ := bind_eq_ok.mp h
      have hi3v := spec_ok_eq (Usize.div_spec (Slice.len pos) (y := 2#usize) (by decide)) hi3
      obtain ⟨mid, hmid, h⟩ := bind_eq_ok.mp h
      have hmidv := usub_ok hmid
      simp at hi3v hmidv
      obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
      rw [Slice.index_SliceIndexRangeToUsizeSliceInst] at hs
      have hsv := spec_ok_eq (core.slice.index.SliceIndexRangeToUsizeSlice.index.step_spec
        { «end» := mid } pos (by simp; omega)) hs
      obtain ⟨left, hl, h⟩ := bind_eq_ok.mp h
      obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
      rw [Slice.index_SliceIndexRangeFromUsizeSliceInst] at hs1
      have hs1v := spec_ok_eq (core.slice.index.SliceIndexRangeFromUsizeSlice.index.step_spec
        { start := mid } pos (by simp; omega)) hs1
      obtain ⟨right, hr, h⟩ := bind_eq_ok.mp h
      have hlen_s : s.val.length < m := by
        rw [hsv.1]; simp [List.slice]; omega
      have hlen_s1 : s1.val.length < m := by
        rw [hs1v.1]; simp; omega
      obtain ⟨pl, sl⟩ := ih _ hlen_s units s left rfl hl
      obtain ⟨pr, sr⟩ := ih _ hlen_s1 units s1 right rfl hr
      have hmerge := merge_ok h
      simp only [alloc.vec.Vec.deref, Slice.from_val] at hmerge
      rw [hmerge]
      refine ⟨?_, List.pairwise_merge (keyLe_trans units) (keyLe_total units) _ _ sl sr⟩
      refine (List.merge_perm_append _).trans ?_
      refine (pl.append pr).trans ?_
      rw [hsv.1, hs1v.1]
      simp [List.slice]

theorem positions_loop_ok : ∀ (m : Nat) (n p : Std.Usize) (pos r : alloc.vec.Vec Std.Usize),
    n.val - p.val = m → canon.positions_loop n pos p = ok r →
    (r.val.map (·.val)) = pos.val.map (·.val) ++ List.range' p.val (n.val - p.val) := by
  intro m
  induction m with
  | zero =>
    intro n p pos r hm h
    unfold canon.positions_loop at h
    split at h
    · rename_i hlt; have : p.val < n.val := by scalar_tac
      omega
    · simp at h; subst h; simp; omega
  | succ m ih =>
    intro n p pos r hm h
    unfold canon.positions_loop at h
    split at h
    · obtain ⟨pos1, hp1, h⟩ := bind_eq_ok.mp h
      obtain ⟨p1, hp, h⟩ := bind_eq_ok.mp h
      have hpv := uadd_ok hp; simp at hpv
      rw [ih n p1 pos1 r (by omega) h, push_ok hp1, hpv]
      have : n.val - p.val = (n.val - (p.val + 1)) + 1 := by omega
      rw [this, List.range'_succ]
      simp
    · rename_i hge; have : ¬ p.val < n.val := by scalar_tac
      omega

theorem positions_ok {n : Std.Usize} {r : alloc.vec.Vec Std.Usize}
    (h : canon.positions n = ok r) : r.val.map (·.val) = List.range n.val := by
  unfold canon.positions at h
  have := positions_loop_ok _ n 0#usize _ r rfl h
  simpa [alloc.vec.Vec.with_capacity, List.range_eq_range'] using this

end Refinement
