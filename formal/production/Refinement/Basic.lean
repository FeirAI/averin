import Extracted.Funs

/-!
# Partial-correctness reasoning about the extracted code

Every theorem in `Refinement` has the shape "if the production function returns `ok r`, then `r` is
…". The Rust function either returns (and then its result is what the theorem says) or it panics or
aborts (an out-of-memory `Vec`, an arithmetic overflow, an out-of-bounds index: `fail`), which never
produces a hash, a preimage or a signature. This file collects the facts about the Aeneas standard
library primitives in that form. They are proved from the Aeneas definitions; nothing is assumed.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace Refinement

/-! ## Monadic plumbing -/

theorem bind_eq_ok {α β} {m : Result α} {k : α → Result β} {z : β} :
    Aeneas.Std.bind m k = ok z ↔ ∃ y, m = ok y ∧ k y = ok z := by
  constructor
  · intro h
    cases m using Result.cases with
    | ret y => exact ⟨y, rfl, by simpa using h⟩
    | vis e k' => simp at h
    | div => simp at h
  · rintro ⟨y, rfl, h⟩
    simpa using h

@[simp] theorem bind_tc_eq_ok {α β} {m : Result α} {k : α → Result β} {z : β} :
    (m >>= k) = ok z ↔ ∃ y, m = ok y ∧ k y = ok z :=
  bind_eq_ok

@[simp] theorem ok_eq_ok {α} {a b : α} : (ok a : Result α) = ok b ↔ a = b := by simp

@[simp] theorem fail_eq_ok {α} {e : Error} {b : α} : (fail e : Result α) = ok b ↔ False := by simp

@[simp] theorem lift_eq_ok {α} {a b : α} : (lift a : Result α) = ok b ↔ a = b := by
  simp [lift]

@[simp] theorem ite_eq_ok {α} {c : Prop} [Decidable c] {a b : Result α} {z : α} :
    (if c then a else b) = ok z ↔ (c ∧ a = ok z) ∨ (¬ c ∧ b = ok z) := by
  split <;> simp_all

@[simp] theorem massert_eq_ok {b : Prop} [Decidable b] {u : Unit} : massert b = ok u ↔ b := by
  unfold massert; split <;> simp_all

/-! ## Byte views -/

/-- The byte values of a slice/vector of `u8`, as the model's `Bytes` (`List Nat`). -/
abbrev vals {ty : UScalarTy} (l : List (UScalar ty)) : List Nat := l.map (·.val)

/-! ## Vectors -/

theorem push_ok {α} {v : alloc.vec.Vec α} {x : α} {w : alloc.vec.Vec α}
    (h : alloc.vec.Vec.push v x = ok w) : w.val = v.val ++ [x] := by
  unfold alloc.vec.Vec.push at h
  dsimp only at h
  split at h
  · simp at h; subst h; simp
  · simp at h

theorem extend_ok {α} {c : core.clone.Clone α} {v : alloc.vec.Vec α} {s : Slice α}
    {w : alloc.vec.Vec α} (hc : ∀ x, c.clone x = ok x)
    (h : alloc.vec.Vec.extend_from_slice c v s = ok w) : w.val = v.val ++ s.val := by
  unfold alloc.vec.Vec.extend_from_slice at h
  split at h
  · have ⟨s', hs', hss⟩ := spec_imp_exists (Slice.clone_spec (clone := c.clone) (s := s)
      (fun x _ => hc x))
    split at h
    · rename_i s'' h''
      simp at h''
      rw [hs'] at h''
      simp at h''
      subst h''; subst hss
      simp at h; subst h; simp
    · rename_i h''; simp [hs'] at h''
    · rename_i h''; simp [hs'] at h''
  · simp at h

@[simp] theorem cloneU8 (x : Std.U8) : core.clone.CloneU8.clone x = ok x := rfl
@[simp] theorem cloneUsize (x : Std.Usize) : core.clone.CloneUsize.clone x = ok x := rfl
@[simp] theorem cloneBool (x : Bool) : core.clone.CloneBool.clone x = ok x := rfl

theorem extend_u8_ok {v : alloc.vec.Vec Std.U8} {s : Slice Std.U8} {w : alloc.vec.Vec Std.U8}
    (h : alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v s = ok w) :
    w.val = v.val ++ s.val :=
  extend_ok (fun _ => rfl) h

theorem slice_index_ok {α} {v : Slice α} {i : Std.Usize} {x : α}
    (h : Slice.index_usize v i = ok x) : ∃ hi : i.val < v.val.length, x = v.val[i.val] := by
  unfold Slice.index_usize at h
  split at h
  · simp at h
  · rename_i y hy
    simp at h; subst h
    simp at hy
    obtain ⟨hlt, hx⟩ := List.getElem?_eq_some_iff.mp hy
    exact ⟨hlt, hx.symm⟩

theorem vec_index_ok {α} {v : alloc.vec.Vec α} {i : Std.Usize} {x : α}
    (h : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = ok x) :
    ∃ hi : i.val < v.val.length, x = v.val[i.val] := by
  rw [alloc.vec.Vec.index_slice_index] at h
  unfold alloc.vec.Vec.index_usize at h
  split at h
  · simp at h
  · rename_i y hy
    simp at h; subst h
    simp at hy
    obtain ⟨hlt, hx⟩ := List.getElem?_eq_some_iff.mp hy
    exact ⟨hlt, hx.symm⟩

theorem array_index_ok {α} {n : Std.Usize} {v : Std.Array α n} {i : Std.Usize} {x : α}
    (h : Std.Array.index_usize v i = ok x) : ∃ hi : i.val < v.val.length, x = v.val[i.val] := by
  unfold Std.Array.index_usize at h
  split at h
  · simp at h
  · rename_i y hy
    simp at h; subst h
    simp at hy
    obtain ⟨hlt, hx⟩ := List.getElem?_eq_some_iff.mp hy
    exact ⟨hlt, hx.symm⟩

/-! ## Scalars -/

theorem uadd_ok {ty} {x y z : UScalar ty} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := UScalar.add_equiv x y
  rw [h] at this
  simp at this
  exact this.2.1

theorem usub_ok {ty} {x y z : UScalar ty} (h : x - y = ok z) :
    y.val ≤ x.val ∧ z.val = x.val - y.val := by
  have := UScalar.sub_equiv x y
  rw [h] at this
  simp at this
  omega

theorem umul_ok {ty} {x y z : UScalar ty} (h : x * y = ok z) : z.val = x.val * y.val := by
  have := UScalar.mul_equiv x y
  have h' : x.mul y = ok z := h
  rw [h'] at this
  simp at this
  exact this.2.1

end Refinement
