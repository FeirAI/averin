import Refinement.Escape

/-!
# `canon::write_int` refines `Canon.serInt`

The production formatter writes `|n|` digit by digit from the right into a 20-byte buffer and
copies the used tail; `write_int_model` shows the appended bytes are `utf8 (serInt n)`.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

namespace Refinement

/-- The model's decimal digits of `n`, as bytes. -/
def decB (n : Nat) : List Nat := (Averin.Canon.digits n).map Char.toNat

theorem decB_eq (n : Nat) :
    decB n = if n < 10 then [48 + n] else decB (n / 10) ++ [48 + n % 10] := by
  unfold decB
  rw [Averin.Canon.digits]
  split
  · simp [Averin.Canon.digitChar_toNat (by omega : n < 10)]
  · simp [Averin.Canon.digitChar_toNat (by omega : n % 10 < 10)]

theorem drop_set_self {α} : ∀ (l : List α) (i : Nat), i < l.length → ∀ x : α,
    (l.set i x).drop i = x :: l.drop (i + 1)
  | [], _, h, _ => by simp at h
  | a :: l, 0, _, x => by simp
  | a :: l, i + 1, h, x => by
    simp only [List.set_cons_succ, List.drop_succ_cons]
    exact drop_set_self l i (by simpa using h) x

theorem write_int_loop_ok : ∀ (m : Nat) (u : Std.U64) (digits : Std.Array Std.U8 20#usize)
    (k k' : Std.Usize) (arr : Std.Array Std.U8 20#usize), u.val = m →
    canon.write_int_loop u digits k = ok (k', arr) →
    k'.val ≤ k.val ∧
    (vals arr.val).drop k'.val = decB u.val ++ (vals digits.val).drop k.val := by
  intro m
  induction m using Nat.strong_induction_on with
  | _ m ih =>
    intro u digits k k' arr hm h
    unfold canon.write_int_loop at h
    obtain ⟨k1, hk1, h⟩ := bind_eq_ok.mp h
    have hk1v := usub_ok hk1
    obtain ⟨i, hi, h⟩ := bind_eq_ok.mp h
    have hiv := spec_ok_eq (U64.rem_spec u (y := 10#u64) (by decide)) hi
    obtain ⟨i1, hi1, h⟩ := bind_eq_ok.mp h
    simp at hi1; subst hi1
    obtain ⟨i2, hi2, h⟩ := bind_eq_ok.mp h
    have hi2v := uadd_ok hi2
    obtain ⟨⟨x, back⟩, hix, h⟩ := bind_eq_ok.mp h
    have hix' : Std.Array.index_mut_usize digits k1 = ok (x, back) := hix
    unfold Std.Array.index_mut_usize at hix'
    obtain ⟨y, hy, hix'⟩ := bind_eq_ok.mp hix'
    obtain ⟨hk1lt, _⟩ := array_index_ok hy
    simp at hix'
    obtain ⟨_, rfl⟩ := hix'
    obtain ⟨u1, hu1, h⟩ := bind_eq_ok.mp h
    have hu1v := spec_ok_eq (U64.div_spec u (y := 10#u64) (by decide)) hu1
    have hdig : i2.val = 48 + u.val % 10 := by
      have hc : (UScalar.cast UScalarTy.U8 i).val = i.val % 2 ^ 8 := by
        rw [UScalar.cast_val_eq]; rfl
      have hi10 : i.val = u.val % 10 := by rw [hiv]; rfl
      have hilt : i.val < 10 := by rw [hi10]; exact Nat.mod_lt _ (by decide)
      rw [hi2v, hc, Nat.mod_eq_of_lt (by omega), hi10]
      rfl
    have hk1e : k1.val + 1 = k.val := by
      have := hk1v; simp at this; omega
    have hset : (vals (Std.Array.set digits k1 i2).val).drop k1.val =
        (48 + u.val % 10) :: (vals digits.val).drop k.val := by
      simp only [vals, Std.Array.set_val_eq]
      rw [← List.map_drop, drop_set_self _ _ (by simpa using hk1lt), ← hk1e]
      simp [hdig]
    have hlen : (Std.Array.set digits k1 i2).val.length = 20 := by simp
    split at h
    · rename_i hz
      simp at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨by omega, ?_⟩
      rw [hset, decB_eq]
      have : u.val < 10 := by
        have : u1.val = 0 := by scalar_tac
        simp at hu1v; omega
      simp [this]
    · rename_i hnz
      have hu1pos : u1.val ≠ 0 := by intro e; apply hnz; scalar_tac
      simp at hu1v
      have hlt : u1.val < m := by subst hm; omega
      have := ih u1.val hlt u1 _ k1 k' arr rfl h
      refine ⟨by omega, ?_⟩
      rw [this.2, hset, decB_eq u.val]
      have : ¬ u.val < 10 := by omega
      simp [this, hu1v]

theorem utf8_digits (n : Nat) : Averin.utf8 (Averin.Canon.digits n) = decB n := by
  rw [utf8_ascii, decB]
  intro c hc
  have := Averin.Canon.digits_all n c hc
  simp [Averin.Canon.isDigit] at this
  omega

theorem utf8_serInt (i : Int) : Averin.utf8 (Averin.Canon.serInt i) =
    (if i < 0 then [45] else []) ++ decB i.natAbs := by
  unfold Averin.Canon.serInt
  split
  · rw [utf8_cons, enc_ascii (by decide), utf8_digits]; simp
  · rw [utf8_digits]; simp; congr 1; omega

/-- **`write_int` refines `serInt`.** -/
theorem write_int_model {n : Std.I64} {out w : alloc.vec.Vec Std.U8}
    (h : canon.write_int n out = ok w) :
    vals w.val = vals out.val ++ Averin.utf8 (Averin.Canon.serInt n.val) := by
  unfold canon.write_int at h
  obtain ⟨⟨out1, u⟩, hu, h⟩ := bind_eq_ok.mp h
  -- `out1` and `|n|`
  have hsign : vals out1.val = vals out.val ++ (if n.val < 0 then [45] else []) ∧
      u.val = n.val.natAbs := by
    split at hu
    · rename_i hneg
      have hneg' : n.val < 0 := by scalar_tac
      obtain ⟨o2, ho2, hu⟩ := bind_eq_ok.mp hu
      obtain ⟨i, hi, hu⟩ := bind_eq_ok.mp hu
      obtain ⟨i1, hi1, hu⟩ := bind_eq_ok.mp hu
      obtain ⟨i2, hi2, hu⟩ := bind_eq_ok.mp hu
      obtain ⟨u1, hu1, hu⟩ := bind_eq_ok.mp hu
      simp at hu; obtain ⟨rfl, rfl⟩ := hu
      simp at hi2; subst hi2
      have hiv : i.val = n.val + 1 := by
        have := IScalar.add_equiv n 1#i64; rw [hi] at this; simp at this; omega
      have hi1v : i1.val = - i.val := by
        have hi1' : IScalar.neg i = ok i1 := hi1
        unfold IScalar.neg at hi1'
        have := IScalar.tryMk_eq .I64 (-i.val)
        rw [hi1'] at this; simp at this; omega
      have hu1v := uadd_ok hu1
      refine ⟨by rw [push_ok ho2]; simp [hneg'], ?_⟩
      rw [hu1v, IScalar.hcast_val_eq]
      simp [hi1v, hiv]
      have : -(n.val + 1) % 2 ^ 64 = -(n.val + 1) := Int.emod_eq_of_lt (by omega) (by scalar_tac)
      omega
    · rename_i hnn
      have hnn' : ¬ n.val < 0 := by scalar_tac
      obtain ⟨u1, hu1, hu⟩ := bind_eq_ok.mp hu
      simp at hu; obtain ⟨rfl, rfl⟩ := hu
      simp at hu1; subst hu1
      refine ⟨by simp [hnn'], ?_⟩
      rw [IScalar.hcast_val_eq]
      have : n.val % 2 ^ 64 = n.val := Int.emod_eq_of_lt (by omega) (by scalar_tac)
      simp; omega
  obtain ⟨⟨k, back⟩, hk, h⟩ := bind_eq_ok.mp h
  obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
  have hext := extend_u8_ok h
  have hloop := write_int_loop_ok _ u _ _ k back rfl hk
  rw [Std.Array.index_SliceIndexRangeFromUsizeSlice] at hs
  have hsv := spec_ok_eq (core.slice.index.SliceIndexRangeFromUsizeSlice.index.step_spec _ _
    (by simp [Std.Array.to_slice]; scalar_tac)) hs
  rw [hext, utf8_serInt, ← hsign.2]
  simp only [vals, List.map_append] at hsign ⊢
  rw [hsign.1, hsv.1]
  simp only [Std.Array.to_slice, Slice.from_val, List.map_drop]
  simp only [vals] at hloop
  rw [hloop.2]
  simp

end Refinement
