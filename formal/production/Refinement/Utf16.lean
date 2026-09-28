import Refinement.Int

/-!
# UTF-16 key order (RFC 8785 §3.2.3 / RCP §2)

`canon::utf16_units` decodes UTF-8 and re-encodes to UTF-16 code units; `canon::units_lt` is strict
lexicographic order on code units. `utf16_units_model` and `units_lt_model` show they compute the
RCP key order on the model's scalar sequences: `keyLt a b ↔ utf16Units a < utf16Units b`.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

namespace Refinement

/-- UTF-16 code units of one scalar (RFC 2781 §2.1). -/
def utf16Char (c : Char) : List Nat :=
  if c.toNat < 0x10000 then [c.toNat]
  else [0xD800 + (c.toNat - 0x10000) / 0x400, 0xDC00 + (c.toNat - 0x10000) % 0x400]

/-- UTF-16 code units of a scalar sequence. -/
def utf16Units (l : List Char) : List Nat := l.flatMap utf16Char

/-- RCP §2 member order: lexicographic on UTF-16 code units, a proper prefix first. -/
def keyLt (a b : List Char) : Prop := utf16Units a < utf16Units b

instance (a b : List Char) : Decidable (keyLt a b) := inferInstanceAs (Decidable (_ < _))

theorem cast32_val (x : Std.U8) : (UScalar.cast UScalarTy.U32 x).val = x.val := by
  rw [UScalar.cast_val_eq]
  have : x.val < 2 ^ 8 := by scalar_tac
  simp only [UScalarTy.U32_numBits_eq]
  omega

theorem cast16_val (x : Std.U32) (h : x.val < 65536) : (UScalar.cast UScalarTy.U16 x).val = x.val := by
  rw [UScalar.cast_val_eq]
  simp only [UScalarTy.U16_numBits_eq]
  omega

theorem udiv_ok32 {x z : Std.U32} {d : Std.U32} (hd : d.val ≠ 0) (h : x / d = ok z) :
    z.val = x.val / d.val := by
  have := spec_ok_eq (U32.div_spec x (y := d) hd) h
  exact this

theorem urem_ok32 {x z : Std.U32} {d : Std.U32} (hd : d.val ≠ 0) (h : x % d = ok z) :
    z.val = x.val % d.val := by
  have := spec_ok_eq (U32.rem_spec x (y := d) hd) h
  exact this

theorem vals_drop_getElem {s : Slice Std.U8} {i j : Nat} {l : List Nat}
    (hd : (vals s.val).drop i = l) (hj : j < l.length) (hij : i + j < s.val.length) :
    (s.val[i + j]).val = l[j] := by
  subst hd
  simp [vals]

/-- One decoding step: the production arithmetic recovers the scalar and its UTF-8 width. -/
theorem decode_step (c : Char) (b : Nat → Nat) (hb : ∀ j, j < (enc c).length → b j = (enc c)[j]!) :
    (if b 0 < 0x80 then (b 0, 1)
     else if b 0 < 0xE0 then ((b 0 - 0xC0) * 0x40 + (b 1 - 0x80), 2)
     else if b 0 < 0xF0 then ((b 0 - 0xE0) * 0x1000 + (b 1 - 0x80) * 0x40 + (b 2 - 0x80), 3)
     else ((b 0 - 0xF0) * 0x40000 + (b 1 - 0x80) * 0x1000 + (b 2 - 0x80) * 0x40 + (b 3 - 0x80), 4))
    = (c.toNat, (enc c).length) := by
  have hc := char_toNat_le c
  have e := enc_eq c
  split at e
  · rename_i h1
    have := hb 0 (by simp [e]); simp [e] at this
    simp [this, e]; intro; omega
  · split at e
    · rename_i h1 h2
      have b0 := hb 0 (by simp [e]); have b1 := hb 1 (by simp [e])
      simp [e] at b0 b1
      simp only [b0, b1, e]
      simp
      split_ifs <;> (refine Prod.ext ?_ ?_ <;> dsimp only <;> omega)
    · split at e
      · rename_i h1 h2 h3
        have b0 := hb 0 (by simp [e]); have b1 := hb 1 (by simp [e]); have b2 := hb 2 (by simp [e])
        simp [e] at b0 b1 b2
        simp only [b0, b1, b2, e]
        simp
        split_ifs <;> (refine Prod.ext ?_ ?_ <;> dsimp only <;> omega)
      · rename_i h1 h2 h3
        have b0 := hb 0 (by simp [e]); have b1 := hb 1 (by simp [e]); have b2 := hb 2 (by simp [e])
        have b3 := hb 3 (by simp [e])
        simp [e] at b0 b1 b2 b3
        simp only [b0, b1, b2, b3, e]
        simp
        split_ifs <;> (refine Prod.ext ?_ ?_ <;> dsimp only <;> omega)

theorem drop_getElem! {l : List Nat} {i j : Nat} (h : i + j < l.length) :
    (l.drop i)[j]! = l[i + j] := by
  rw [getElem!_pos (l.drop i) j (by simp; omega)]
  simp

/-- The `(cp, width)` block of the decoding loop, on the bytes following position `i`. -/
theorem decode_block_ok {s : Slice Std.U8} {i : Std.Usize} {b0 : Std.U8}
    {cp : Std.U32} {width : Std.Usize}
    (hi : i.val < s.val.length) (hb0 : b0 = s.val[i.val])
    (h : (if UScalar.cast UScalarTy.U32 b0 < 128#u32 then ok (UScalar.cast UScalarTy.U32 b0, 1#usize)
      else if UScalar.cast UScalarTy.U32 b0 < 224#u32 then do
        let i3 ← UScalar.cast UScalarTy.U32 b0 - 192#u32
        let i4 ← i3 * 64#u32
        let i5 ← i + 1#usize
        let i6 ← Slice.index_usize s i5
        let i7 ← lift (UScalar.cast UScalarTy.U32 i6)
        let i8 ← i7 - 128#u32
        let i9 ← i4 + i8
        ok (i9, 2#usize)
      else if UScalar.cast UScalarTy.U32 b0 < 240#u32 then do
        let i3 ← UScalar.cast UScalarTy.U32 b0 - 224#u32
        let i4 ← i3 * 4096#u32
        let i5 ← i + 1#usize
        let i6 ← Slice.index_usize s i5
        let i7 ← lift (UScalar.cast UScalarTy.U32 i6)
        let i8 ← i7 - 128#u32
        let i9 ← i8 * 64#u32
        let i10 ← i4 + i9
        let i11 ← i + 2#usize
        let i12 ← Slice.index_usize s i11
        let i13 ← lift (UScalar.cast UScalarTy.U32 i12)
        let i14 ← i13 - 128#u32
        let i15 ← i10 + i14
        ok (i15, 3#usize)
      else do
        let i3 ← UScalar.cast UScalarTy.U32 b0 - 240#u32
        let i4 ← i3 * 262144#u32
        let i5 ← i + 1#usize
        let i6 ← Slice.index_usize s i5
        let i7 ← lift (UScalar.cast UScalarTy.U32 i6)
        let i8 ← i7 - 128#u32
        let i9 ← i8 * 4096#u32
        let i10 ← i4 + i9
        let i11 ← i + 2#usize
        let i12 ← Slice.index_usize s i11
        let i13 ← lift (UScalar.cast UScalarTy.U32 i12)
        let i14 ← i13 - 128#u32
        let i15 ← i14 * 64#u32
        let i16 ← i10 + i15
        let i17 ← i + 3#usize
        let i18 ← Slice.index_usize s i17
        let i19 ← lift (UScalar.cast UScalarTy.U32 i18)
        let i20 ← i19 - 128#u32
        let i21 ← i16 + i20
        ok (i21, 4#usize)) = ok (cp, width)) :
    let B := fun j => ((vals s.val).drop i.val)[j]!
    (cp.val, width.val) =
    (if B 0 < 0x80 then (B 0, 1)
     else if B 0 < 0xE0 then ((B 0 - 0xC0) * 0x40 + (B 1 - 0x80), 2)
     else if B 0 < 0xF0 then ((B 0 - 0xE0) * 0x1000 + (B 1 - 0x80) * 0x40 + (B 2 - 0x80), 3)
     else ((B 0 - 0xF0) * 0x40000 + (B 1 - 0x80) * 0x1000 + (B 2 - 0x80) * 0x40 + (B 3 - 0x80), 4))
    := by
  intro B
  have hB0 : B 0 = b0.val := by
    simp only [B]; rw [drop_getElem! (by simpa using hi)]; simp [vals, hb0]
  have hB : ∀ (k : Std.Usize) (j : Nat) (x : Std.U8), k.val = i.val + j →
      Slice.index_usize s k = ok x → B j = x.val := by
    intro k j x hk hx
    obtain ⟨hkl, hxv⟩ := slice_index_ok hx
    simp only [B]; rw [drop_getElem! (by simp; omega)]; simp [vals, hxv, hk]
  have c0 := cast32_val b0
  rw [hB0]
  split at h
  · rename_i hlt
    simp at h; obtain ⟨rfl, rfl⟩ := h
    have : b0.val < 128 := by scalar_tac
    simp [this, c0]
  · rename_i hge1
    split at h
    · rename_i hlt2
      have g1 : ¬ b0.val < 128 := by scalar_tac
      have l2 : b0.val < 224 := by scalar_tac
      simp only [g1, l2, if_false, if_true]
      obtain ⟨i3, h3, h⟩ := bind_eq_ok.mp h; have v3 := usub_ok h3
      obtain ⟨i4, h4, h⟩ := bind_eq_ok.mp h; have v4 := umul_ok h4
      obtain ⟨i5, h5, h⟩ := bind_eq_ok.mp h; have v5 := uadd_ok h5
      obtain ⟨i6, h6, h⟩ := bind_eq_ok.mp h; have v6 := hB i5 1 i6 (by simp [v5]) h6
      obtain ⟨i7, h7, h⟩ := bind_eq_ok.mp h; simp at h7; subst h7
      obtain ⟨i8, h8, h⟩ := bind_eq_ok.mp h; have v8 := usub_ok h8
      obtain ⟨i9, h9, h⟩ := bind_eq_ok.mp h; have v9 := uadd_ok h9
      simp at h; obtain ⟨rfl, rfl⟩ := h
      simp at v3 v4 v8 v9 ⊢
      omega
    · split at h
      · rename_i hlt3
        have g1 : ¬ b0.val < 128 := by scalar_tac
        have g2 : ¬ b0.val < 224 := by scalar_tac
        have l3 : b0.val < 240 := by scalar_tac
        simp only [g1, g2, l3, if_false, if_true]
        obtain ⟨i3, h3, h⟩ := bind_eq_ok.mp h; have v3 := usub_ok h3
        obtain ⟨i4, h4, h⟩ := bind_eq_ok.mp h; have v4 := umul_ok h4
        obtain ⟨i5, h5, h⟩ := bind_eq_ok.mp h; have v5 := uadd_ok h5
        obtain ⟨i6, h6, h⟩ := bind_eq_ok.mp h; have v6 := hB i5 1 i6 (by simp [v5]) h6
        obtain ⟨i7, h7, h⟩ := bind_eq_ok.mp h; simp at h7; subst h7
        obtain ⟨i8, h8, h⟩ := bind_eq_ok.mp h; have v8 := usub_ok h8
        obtain ⟨i9, h9, h⟩ := bind_eq_ok.mp h; have v9 := umul_ok h9
        obtain ⟨i10, h10, h⟩ := bind_eq_ok.mp h; have v10 := uadd_ok h10
        obtain ⟨i11, h11, h⟩ := bind_eq_ok.mp h; have v11 := uadd_ok h11
        obtain ⟨i12, h12, h⟩ := bind_eq_ok.mp h; have v12 := hB i11 2 i12 (by simp [v11]) h12
        obtain ⟨i13, h13, h⟩ := bind_eq_ok.mp h; simp at h13; subst h13
        obtain ⟨i14, h14, h⟩ := bind_eq_ok.mp h; have v14 := usub_ok h14
        obtain ⟨i15, h15, h⟩ := bind_eq_ok.mp h; have v15 := uadd_ok h15
        simp at h; obtain ⟨rfl, rfl⟩ := h
        simp at v3 v4 v8 v9 v10 v14 v15 ⊢
        omega
      · rename_i hge3
        have g1 : ¬ b0.val < 128 := by scalar_tac
        have g2 : ¬ b0.val < 224 := by scalar_tac
        have g3 : ¬ b0.val < 240 := by scalar_tac
        simp only [g1, g2, g3, if_false]
        obtain ⟨i3, h3, h⟩ := bind_eq_ok.mp h; have v3 := usub_ok h3
        obtain ⟨i4, h4, h⟩ := bind_eq_ok.mp h; have v4 := umul_ok h4
        obtain ⟨i5, h5, h⟩ := bind_eq_ok.mp h; have v5 := uadd_ok h5
        obtain ⟨i6, h6, h⟩ := bind_eq_ok.mp h; have v6 := hB i5 1 i6 (by simp [v5]) h6
        obtain ⟨i7, h7, h⟩ := bind_eq_ok.mp h; simp at h7; subst h7
        obtain ⟨i8, h8, h⟩ := bind_eq_ok.mp h; have v8 := usub_ok h8
        obtain ⟨i9, h9, h⟩ := bind_eq_ok.mp h; have v9 := umul_ok h9
        obtain ⟨i10, h10, h⟩ := bind_eq_ok.mp h; have v10 := uadd_ok h10
        obtain ⟨i11, h11, h⟩ := bind_eq_ok.mp h; have v11 := uadd_ok h11
        obtain ⟨i12, h12, h⟩ := bind_eq_ok.mp h; have v12 := hB i11 2 i12 (by simp [v11]) h12
        obtain ⟨i13, h13, h⟩ := bind_eq_ok.mp h; simp at h13; subst h13
        obtain ⟨i14, h14, h⟩ := bind_eq_ok.mp h; have v14 := usub_ok h14
        obtain ⟨i15, h15, h⟩ := bind_eq_ok.mp h; have v15 := umul_ok h15
        obtain ⟨i16, h16, h⟩ := bind_eq_ok.mp h; have v16 := uadd_ok h16
        obtain ⟨i17, h17, h⟩ := bind_eq_ok.mp h; have v17 := uadd_ok h17
        obtain ⟨i18, h18, h⟩ := bind_eq_ok.mp h; have v18 := hB i17 3 i18 (by simp [v17]) h18
        obtain ⟨i19, h19, h⟩ := bind_eq_ok.mp h; simp at h19; subst h19
        obtain ⟨i20, h20, h⟩ := bind_eq_ok.mp h; have v20 := usub_ok h20
        obtain ⟨i21, h21, h⟩ := bind_eq_ok.mp h; have v21 := uadd_ok h21
        simp at h; obtain ⟨rfl, rfl⟩ := h
        simp at v3 v4 v8 v9 v10 v14 v15 v16 v20 v21 ⊢
        omega

theorem utf16_units_loop_ok : ∀ (cs : List Char) (s : Slice Std.U8)
    (units r : alloc.vec.Vec Std.U16) (i : Std.Usize),
    (vals s.val).drop i.val = Averin.utf8 cs →
    canon.utf16_units_loop s units i = ok r → vals r.val = vals units.val ++ utf16Units cs
  | [], s, units, r, i, hd, h => by
    unfold canon.utf16_units_loop at h
    dsimp only at h
    split at h
    · rename_i hlt
      have : i.val < s.val.length := by scalar_tac
      simp at hd; omega
    · simp at h; subst h; simp [utf16Units]
  | c :: cs, s, units, r, i, hd, h => by
    rw [utf8_cons] at hd
    have hne : 0 < (enc c).length := by
      rw [enc_eq]; split_ifs <;> simp
    have hi : i.val < s.val.length := by
      have := congrArg List.length hd; simp at this; omega
    unfold canon.utf16_units_loop at h
    dsimp only at h
    split at h
    · obtain ⟨b0, hb0, h⟩ := bind_eq_ok.mp h
      obtain ⟨hi', hb0v⟩ := slice_index_ok hb0
      obtain ⟨b0', hb0', h⟩ := bind_eq_ok.mp h
      simp at hb0'; subst hb0'
      obtain ⟨⟨cp, width⟩, hcw, h⟩ := bind_eq_ok.mp h
      have hbj : ∀ j, j < (enc c).length →
          (fun j => ((vals s.val).drop i.val)[j]!) j = (enc c)[j]! := by
        intro j hj
        simp only [hd]
        rw [getElem!_pos _ j (by simp; omega), getElem!_pos _ j hj]
        simp [List.getElem_append_left hj]
      have hblock : (cp.val, width.val) = (c.toNat, (enc c).length) :=
        Eq.trans (decode_block_ok hi hb0v hcw) (decode_step c _ hbj)
      simp only [Prod.mk.injEq] at hblock
      obtain ⟨hcp, hwidth⟩ := hblock
      obtain ⟨units1, hu1, h⟩ := bind_eq_ok.mp h
      obtain ⟨i3, hi3, h⟩ := bind_eq_ok.mp h
      have hi3v := uadd_ok hi3
      have hrest : (vals s.val).drop i3.val = Averin.utf8 cs := by
        rw [hi3v, hwidth, ← List.drop_drop, hd, List.drop_left]
      have hrec := utf16_units_loop_ok cs s units1 r i3 hrest h
      rw [hrec]
      have hc := char_toNat_le c
      -- the pushed code units
      have hpush : vals units1.val = vals units.val ++ utf16Char c := by
        split at hu1
        · rename_i hlt
          obtain ⟨x, hx, hu1⟩ := bind_eq_ok.mp hu1
          simp at hx; subst hx
          rw [push_ok hu1]
          have : cp.val < 65536 := by scalar_tac
          have hlt' : c.toNat < 65536 := hcp ▸ this
          simp [utf16Char, cast16_val _ this, hcp, hlt']
        · rename_i hge
          have hge' : ¬ cp.val < 65536 := by scalar_tac
          obtain ⟨i3', h3, hu1⟩ := bind_eq_ok.mp hu1; have v3 := usub_ok h3
          obtain ⟨i4, h4, hu1⟩ := bind_eq_ok.mp hu1
          have v4 := udiv_ok32 (by decide) h4
          obtain ⟨i5, h5, hu1⟩ := bind_eq_ok.mp hu1; have v5 := uadd_ok h5
          obtain ⟨i6, h6, hu1⟩ := bind_eq_ok.mp hu1; simp at h6; subst h6
          obtain ⟨units2, h7, hu1⟩ := bind_eq_ok.mp hu1; have v7 := push_ok h7
          obtain ⟨i7, h8, hu1⟩ := bind_eq_ok.mp hu1
          have v8 := urem_ok32 (by decide) h8
          obtain ⟨i8, h9, hu1⟩ := bind_eq_ok.mp hu1; have v9 := uadd_ok h9
          obtain ⟨i9, h10, hu1⟩ := bind_eq_ok.mp hu1; simp at h10; subst h10
          have v11 := push_ok hu1
          simp at v3 v4 v5 v8 v9
          have l5 : i5.val < 65536 := by omega
          have l8 : i8.val < 65536 := by omega
          rw [v11, v7]
          simp [utf16Char, cast16_val _ l5, cast16_val _ l8, ← hcp, hge']
          omega
      rw [hpush]
      simp [utf16Units]
    · rename_i hge
      have : ¬ i.val < s.val.length := by scalar_tac
      omega

/-- **`utf16_units` refines `utf16Units`** on the UTF-8 bytes of any scalar sequence. -/
theorem utf16_units_model {s : Slice Std.U8} {cs : List Char} {r : alloc.vec.Vec Std.U16}
    (hs : vals s.val = Averin.utf8 cs) (h : canon.utf16_units s = ok r) :
    vals r.val = utf16Units cs := by
  unfold canon.utf16_units at h
  have := utf16_units_loop_ok cs s _ r 0#usize (by simpa using hs) h
  simpa [alloc.vec.Vec.with_capacity] using this

/-- Lists that agree on their first `j` elements compare like their `j`-suffixes. -/
theorem lt_iff_drop : ∀ (a b : List Nat) (j : Nat), (∀ k, k < j → a[k]? = b[k]?) →
    j ≤ a.length → j ≤ b.length → (a < b ↔ a.drop j < b.drop j)
  | a, b, 0, _, _, _ => by simp
  | x :: a, y :: b, j + 1, h, ha, hb => by
    have hxy : x = y := by simpa using h 0 (by omega)
    subst hxy
    simp only [List.cons_lt_cons_self, List.drop_succ_cons]
    exact lt_iff_drop a b j (fun k hk => by simpa using h (k + 1) (by omega))
      (by simp at ha; omega) (by simp at hb; omega)
  | [], _, _ + 1, _, ha, _ => by simp at ha
  | _ :: _, [], _ + 1, _, _, hb => by simp at hb

theorem units_lt_loop_ok : ∀ (m : Nat) (a b : Slice Std.U16) (n i j : Std.Usize),
    n.val - i.val = m → n.val ≤ a.val.length → n.val ≤ b.val.length →
    canon.units_lt_loop a b n i = ok j →
    i.val ≤ j.val ∧ j.val ≤ max i.val n.val ∧
    (∀ k, i.val ≤ k → k < j.val → (vals a.val)[k]? = (vals b.val)[k]?) ∧
    (j.val < n.val → (vals a.val)[j.val]? ≠ (vals b.val)[j.val]?) := by
  intro m
  induction m with
  | zero =>
    intro a b n i j hm ha hb h
    unfold canon.units_lt_loop at h
    split at h
    · rename_i hlt; have : i.val < n.val := by scalar_tac
      omega
    · simp at h; subst h
      refine ⟨le_refl _, by omega, fun k h1 h2 => by omega, fun h => by omega⟩
  | succ m ih =>
    intro a b n i j hm ha hb h
    unfold canon.units_lt_loop at h
    split at h
    · rename_i hlt
      have hlt' : i.val < n.val := by scalar_tac
      obtain ⟨x, hx, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, hxv⟩ := slice_index_ok hx
      obtain ⟨y, hy, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, hyv⟩ := slice_index_ok hy
      split at h
      · rename_i hxy
        obtain ⟨i3, hi3, h⟩ := bind_eq_ok.mp h
        have hi3v := uadd_ok hi3
        simp at hi3v
        have := ih a b n i3 j (by omega) ha hb h
        obtain ⟨r1, r2, r3, r4⟩ := this
        refine ⟨by omega, by omega, ?_, r4⟩
        intro k hk1 hk2
        by_cases hki : k = i.val
        · subst hki
          simp [vals]
          rw [List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)]
          simp [← hxv, ← hyv, hxy]
        · exact r3 k (by omega) hk2
      · rename_i hxy
        simp at h; subst h
        refine ⟨le_refl _, by omega, fun k h1 h2 => by omega, fun _ => ?_⟩
        simp only [vals, List.getElem?_map]
        rw [List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)]
        simp [← hxv, ← hyv]
        intro e; apply hxy; exact UScalar.eq_of_val_eq e
    · simp at h; subst h
      refine ⟨le_refl _, by omega, fun k h1 h2 => by omega, fun h => ?_⟩
      have : ¬ i.val < n.val := by scalar_tac
      omega

/-- **`units_lt` is the RCP key order** (strict lexicographic order on code units). -/
theorem units_lt_model {a b : Slice Std.U16} {r : Bool} (h : canon.units_lt a b = ok r) :
    r = decide (vals a.val < vals b.val) := by
  unfold canon.units_lt at h
  obtain ⟨n, hn, h⟩ := bind_eq_ok.mp h
  have hnv : n.val = min a.val.length b.val.length := by
    split at hn
    · rename_i hl; simp at hn; subst hn
      have : a.val.length < b.val.length := by scalar_tac
      simp; omega
    · rename_i hl; simp at hn; subst hn
      have : ¬ a.val.length < b.val.length := by scalar_tac
      simp; omega
  obtain ⟨j, hj, h⟩ := bind_eq_ok.mp h
  obtain ⟨r1, r2, r3, r4⟩ := units_lt_loop_ok _ a b n 0#usize j rfl (by omega) (by omega) hj
  simp at r1 r2
  have hpre : ∀ k, k < j.val → (vals a.val)[k]? = (vals b.val)[k]? := fun k hk => r3 k (by simp) hk
  rw [show decide (vals a.val < vals b.val) =
      decide ((vals a.val).drop j.val < (vals b.val).drop j.val) from
    decide_eq_decide.mpr (lt_iff_drop _ _ j.val hpre (by simp; omega) (by simp; omega))]
  split at h
  · rename_i hlt
    have hlt' : j.val < n.val := by scalar_tac
    obtain ⟨x, hx, h⟩ := bind_eq_ok.mp h
    obtain ⟨hxa, hxv⟩ := slice_index_ok hx
    obtain ⟨y, hy, h⟩ := bind_eq_ok.mp h
    obtain ⟨hyb, hyv⟩ := slice_index_ok hy
    simp at h; subst h
    have hne := r4 hlt'
    have ha' : j.val < (vals a.val).length := by simp; omega
    have hb' : j.val < (vals b.val).length := by simp; omega
    apply decide_eq_decide.mpr
    rw [List.drop_eq_getElem_cons ha', List.drop_eq_getElem_cons hb', List.cons_lt_cons_iff]
    simp only [vals, List.getElem?_map, List.getElem_map] at hne ⊢
    rw [List.getElem?_eq_getElem hxa, List.getElem?_eq_getElem hyb] at hne
    simp at hne
    have hxy : x.val ≠ y.val := by rw [hxv, hyv]; exact hne
    simp only [← hxv, ← hyv, hxy, false_and, or_false]
  · rename_i hge
    have hge' : ¬ j.val < n.val := by scalar_tac
    have hjn : j.val = n.val := by omega
    simp at h; subst h
    by_cases hab : a.val.length < b.val.length
    · have e1 : (vals a.val).drop j.val = [] := by simp; omega
      have e2 : (vals b.val).drop j.val ≠ [] := by simp; omega
      rw [e1]
      obtain ⟨z, zs, hz⟩ := List.exists_cons_of_ne_nil e2
      rw [hz]
      simp [hab]
    · have e1 : (vals b.val).drop j.val = [] := by simp; omega
      rw [e1]
      simp; omega

end Refinement
