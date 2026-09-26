import Refinement.ParseLeaf
open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

/-!
# The duplicate-key check returns

Totality of `canon::first_repeat` (the parser's post-NFC duplicate-key check) and of what it calls:
`widen`, `positions`, `units_lt`, the merge loop and the production merge sort `sort_by_units`
(whose results stay a permutation-sized list of in-range positions).
-/

namespace Refinement.Parse

/-- Close list-length/membership side goals left by `step*`. -/
macro "vfin" : tactic => `(tactic| first
  | done
  | (simp_all [alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, alloc.vec.Vec.length, Slice.length]; done)
  | (simp_all [alloc.vec.Vec.with_capacity, alloc.vec.Vec.new, alloc.vec.Vec.length, Slice.length]; scalar_tac))

@[step]
theorem widen_loop_spec (s : Slice Std.U8) (out : alloc.vec.Vec Std.U16) (i : Std.Usize)
    (hi : i.val ≤ s.length) (hb : out.length + (s.length - i.val) ≤ Usize.max) :
    canon.widen_loop s out i ⦃ o => o.length = out.length + (s.length - i.val) ⦄ := by
  unfold canon.widen_loop
  step* <;> vfin
termination_by s.length - i.val
decreasing_by scalar_decr_tac

@[step]
theorem widen_spec (s : Slice Std.U8) : canon.widen s ⦃ o => o.length = s.length ⦄ := by
  have := s.property
  unfold canon.widen
  step* <;> vfin

@[step]
theorem positions_loop_spec (n : Std.Usize) (pos : alloc.vec.Vec Std.Usize) (p : Std.Usize)
    (hp : p.val ≤ n.val) (hlen : pos.length = p.val) (hlt : ∀ x ∈ pos.val, x.val < n.val) :
    canon.positions_loop n pos p ⦃ r => r.length = n.val ∧ ∀ x ∈ r.val, x.val < n.val ⦄ := by
  unfold canon.positions_loop
  step*
  · simp_all
  · intro x hx; simp only [pos1_post, List.mem_append, List.mem_singleton] at hx
    rcases hx with hx | rfl
    · exact hlt x hx
    · scalar_tac
termination_by n.val - p.val
decreasing_by scalar_decr_tac

@[step]
theorem positions_spec (n : Std.Usize) :
    canon.positions n ⦃ r => r.length = n.val ∧ ∀ x ∈ r.val, x.val < n.val ⦄ := by
  unfold canon.positions
  step* <;> vfin

@[step]
theorem units_lt_loop_spec (a b : Slice Std.U16) (n i : Std.Usize) (ha : n.val ≤ a.length)
    (hb : n.val ≤ b.length) (hi : i.val ≤ n.val) :
    canon.units_lt_loop a b n i ⦃ j => j.val ≤ n.val ⦄ := by
  unfold canon.units_lt_loop
  step*
termination_by n.val - i.val
decreasing_by scalar_decr_tac

@[step]
theorem units_lt_spec (a b : Slice Std.U16) : canon.units_lt a b ⦃ _ => True ⦄ := by
  unfold canon.units_lt
  by_cases h : a.len < b.len
  · simp only [h, ↓reduceIte, bind_tc_ok]; step*
  · simp only [h, ↓reduceIte, bind_tc_ok]; step*


@[simp] theorem vec_deref_val {α} (v : alloc.vec.Vec α) : (alloc.vec.Vec.deref v).val = v.val := by
  simp [alloc.vec.Vec.deref, Slice.from_val]

/-- Every position in `l` indexes `units`. -/
abbrev InRange (N : Nat) (l : List Std.Usize) : Prop := ∀ x ∈ l, x.val < N

theorem inRange_push {N : Nat} {l : List Std.Usize} {x : Std.Usize} (h : InRange N l)
    (hx : x.val < N) : InRange N (l ++ [x]) := by
  intro y hy; simp only [List.mem_append, List.mem_singleton] at hy
  rcases hy with hy | rfl
  · exact h y hy
  · exact hx

@[step]
theorem merge_loop_spec (units : Slice (alloc.vec.Vec Std.U16)) (left right : Slice Std.Usize)
    (out : alloc.vec.Vec Std.Usize) (i j : Std.Usize)
    (hl : InRange units.length left.val) (hr : InRange units.length right.val)
    (ho : InRange units.length out.val) (hi : i.val ≤ left.length) (hj : j.val ≤ right.length)
    (hb : out.length + (left.length - i.val) + (right.length - j.val) ≤ Usize.max) :
    canon.merge_by_units_loop units left right out i j ⦃ r =>
      r.length = out.length + (left.length - i.val) + (right.length - j.val) ∧
      InRange units.length r.val ⦄ := by
  unfold canon.merge_by_units_loop
  step*
  all_goals first
    | exact hl _ (by subst_vars; exact List.getElem_mem _)
    | exact hr _ (by subst_vars; exact List.getElem_mem _)
    | (rw [out1_post]; refine inRange_push ho ?_
       first
         | exact hl _ (by subst_vars; exact List.getElem_mem _)
         | exact hr _ (by subst_vars; exact List.getElem_mem _))
    | (simp only [alloc.vec.Vec.length, out1_post, List.length_append, List.length_singleton] at *
       scalar_tac)
termination_by (left.length - i.val) + (right.length - j.val)
decreasing_by all_goals scalar_decr_tac


@[step]
theorem merge_spec (units : Slice (alloc.vec.Vec Std.U16)) (left right : Slice Std.Usize)
    (hl : InRange units.length left.val) (hr : InRange units.length right.val)
    (hb : left.length + right.length ≤ Usize.max) :
    canon.merge_by_units units left right ⦃ r =>
      r.length = left.length + right.length ∧ InRange units.length r.val ⦄ := by
  unfold canon.merge_by_units
  step*
  · intro x hx; simp [alloc.vec.Vec.with_capacity] at hx
  · simp [alloc.vec.Vec.with_capacity]; scalar_tac
  · simp [alloc.vec.Vec.with_capacity] at r_post; exact ⟨r_post, r_post1⟩

@[step]
theorem sort_spec (units : Slice (alloc.vec.Vec Std.U16)) (pos : Slice Std.Usize)
    (hp : InRange units.length pos.val) :
    canon.sort_by_units units pos ⦃ r => r.length = pos.length ∧ InRange units.length r.val ⦄ := by
  have hmax := pos.property
  unfold canon.sort_by_units
  step*
  all_goals first
    | (subst pos_post; exact ⟨rfl, hp⟩)
    | (intro x hx; rw [s_post] at hx; exact hp x (List.mem_of_mem_drop (List.mem_of_mem_take hx)))
    | (intro x hx; rw [s1_post] at hx; exact hp x (List.mem_of_mem_drop hx))
    | (simp only [vec_deref_val]; assumption)
    | (simp only [vec_deref_val, Slice.length, alloc.vec.Vec.length] at *; scalar_tac)
termination_by pos.length
decreasing_by all_goals (simp only [Slice.length] at *; scalar_tac)


theorem allM_total : ∀ (l : List (Std.U16 × Std.U16)),
    ∃ r, List.allM (fun (x : Std.U16 × Std.U16) => core.cmp.PartialEqU16.eq x.1 x.2) l = ok r
  | [] => ⟨true, rfl⟩
  | x :: l => by
    obtain ⟨r, hr⟩ := allM_total l
    simp only [List.allM, liftFun2]
    by_cases h : x.1 = x.2
    · exact ⟨r, by simp [h, hr]⟩
    · exact ⟨false, by simp [h]; rfl⟩

@[step]
theorem vec_eq_u16_spec (a b : alloc.vec.Vec Std.U16) :
    alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU16 a b ⦃ _ => True ⦄ := by
  unfold alloc.vec.partial_eq.PartialEqVec.eq
  split
  · obtain ⟨r, hr⟩ := allM_total (a.val.zip b.val)
    rw [hr]; exact WP.spec.ret trivial
  · exact WP.spec.ret trivial

@[step]
theorem first_repeat_loop_spec (units : alloc.vec.Vec (alloc.vec.Vec Std.U16))
    (order : alloc.vec.Vec Std.Usize) (first n : Std.Usize)
    (ho : InRange units.length order.val) (hf : first.val ≤ units.length) (hn : 1 ≤ n.val) :
    canon.first_repeat_loop units order first n ⦃ r => r.val ≤ units.length ⦄ := by
  unfold canon.first_repeat_loop
  step*
  · exact ho _ (by subst_vars; exact List.getElem_mem _)
  · exact ho _ (by subst_vars; exact List.getElem_mem _)
  · have h3 : i3.val < units.length := ho _ (by subst_vars; exact List.getElem_mem _)
    have key : ∃ f1 : Std.Usize,
        (if b = true then (if i3 < first then ok i3 else ok first) else ok first) = ok f1 ∧
        f1.val ≤ units.length := by
      split_ifs
      · exact ⟨i3, rfl, by omega⟩
      · exact ⟨first, rfl, hf⟩
      · exact ⟨first, rfl, hf⟩
    obtain ⟨f1, hf1, hf1'⟩ := key
    rw [hf1, bind_tc_ok]
    step*
termination_by order.length - n.val
decreasing_by scalar_decr_tac

@[step]
theorem first_repeat_spec (units : alloc.vec.Vec (alloc.vec.Vec Std.U16)) :
    canon.first_repeat units ⦃ r => r.val ≤ units.length ⦄ := by
  unfold canon.first_repeat
  step*
  · intro x hx; rw [vec_deref_val] at hx; have := v_post1 x hx; simp only [vec_deref_val, Slice.length] at *; scalar_tac
  · intro x hx; have := order_post1 x hx; simp only [vec_deref_val, Slice.length] at *; scalar_tac

end Refinement.Parse
