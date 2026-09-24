import Refinement.Utf8
import Averin.Canon

/-!
# `canon::escape_into` refines `Canon.serStr`

The production escaper works byte by byte on UTF-8. `escape_into_ok` states that, on the UTF-8
bytes of any scalar sequence `cs`, it appends exactly `utf8 (serStr cs)`: the model's per-scalar
escape (`Canon.escChar`) followed by UTF-8. `escByte` is only a proof device (the extracted loop
is characterised by it first, then it is shown to agree with the model).
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

namespace Refinement

/-- A lowercase hex digit's byte (`hex_digit`). -/
def hexd (n : Nat) : Nat := if n < 10 then 48 + n else 87 + n

/-- The extracted escape table, on byte values. -/
def escByte (b : Nat) : List Nat :=
  if b = 34 then [92, 34] else if b = 92 then [92, 92] else if b = 8 then [92, 98]
  else if b = 9 then [92, 116] else if b = 10 then [92, 110] else if b = 12 then [92, 102]
  else if b = 13 then [92, 114]
  else if b ≤ 31 then [92, 117, 48, 48, hexd (b / 16), hexd (b % 16)]
  else [b]

theorem spec_ok_eq {α} {m : Result α} {P : α → Prop} {y : α} (hs : spec m P) (h : m = ok y) :
    P y := by
  obtain ⟨y', h', hp⟩ := spec_imp_exists hs
  rw [h] at h'; simp at h'; subst h'; exact hp

theorem hex_digit_ok {n d : Std.U8} (hn : n.val < 16) (h : canon.hex_digit n = ok d) :
    d.val = hexd n.val := by
  unfold canon.hex_digit at h
  simp only [hexd]
  split at h
  · rename_i hlt
    have := uadd_ok h
    have : n.val < 10 := by scalar_tac
    simp [*]
  · rename_i hlt
    obtain ⟨i, hi, h⟩ := bind_eq_ok.mp h
    have h1 := usub_ok hi
    have h2 := uadd_ok h
    have : ¬ n.val < 10 := by scalar_tac
    simp only [this, if_false]
    simp at h1 h2
    omega

theorem lit_ext_ok {out w : alloc.vec.Vec Std.U8} {n : Std.Usize} {l : List Std.U8}
    {p : l.length = n.val}
    (h : (do
      let s1 ← lift (Std.Array.make n l p).to_slice
      alloc.vec.Vec.extend_from_slice core.clone.CloneU8 out s1) = ok w) :
    w.val = out.val ++ l := by
  obtain ⟨s1, hs, h⟩ := bind_eq_ok.mp h
  simp at hs; subst hs
  rw [extend_u8_ok h]
  simp [Std.Array.to_slice]

theorem escape_loop_ok : ∀ (n : Nat) (s : Slice Std.U8) (out out' : alloc.vec.Vec Std.U8)
    (i : Std.Usize), s.val.length - i.val = n →
    canon.escape_into_loop s out i = ok out' →
    vals out'.val = vals out.val ++ ((vals s.val).drop i.val).flatMap escByte := by
  intro n
  induction n with
  | zero =>
    intro s out out' i hn h
    unfold canon.escape_into_loop at h
    dsimp only at h
    split at h
    · rename_i hlt; simp at hlt; omega
    · simp at h; subst h
      have : (vals s.val).drop i.val = [] := by simp; omega
      simp [this]
  | succ n ih =>
    intro s out out' i hn h
    unfold canon.escape_into_loop at h
    dsimp only at h
    split at h
    · rename_i hlt
      obtain ⟨b, hb, h⟩ := bind_eq_ok.mp h
      obtain ⟨hi, hbv⟩ := slice_index_ok hb
      obtain ⟨out1, hm, h⟩ := bind_eq_ok.mp h
      obtain ⟨i2, hi2, h⟩ := bind_eq_ok.mp h
      have hi2v := uadd_ok hi2
      have hrec := ih s out1 out' i2 (by simp at hi2v; omega) h
      rw [hrec]
      have hdrop : (vals s.val).drop i.val = b.val :: (vals s.val).drop i2.val := by
        simp at hi2v
        rw [hi2v]
        simp only [vals]
        rw [List.drop_eq_getElem_cons (by simpa using hi)]
        simp [hbv]
      rw [hdrop, List.flatMap_cons, ← List.append_assoc]
      congr 1
      -- the per-byte step
      split at hm
      all_goals first
        | (rw [lit_ext_ok hm]; simp only [vals, List.map_append, List.map_cons, List.map_nil]; rfl)
        | skip
      rename_i hne1 hne2 hne3 hne4 hne5 hne6 hne7
      have n34 : b.val ≠ 34 := fun hv => hne1 (UScalar.eq_of_val_eq (by rw [hv]; rfl))
      have n92 : b.val ≠ 92 := fun hv => hne2 (UScalar.eq_of_val_eq (by rw [hv]; rfl))
      have n8 : b.val ≠ 8 := fun hv => hne3 (UScalar.eq_of_val_eq (by rw [hv]; rfl))
      have n9 : b.val ≠ 9 := fun hv => hne4 (UScalar.eq_of_val_eq (by rw [hv]; rfl))
      have n10 : b.val ≠ 10 := fun hv => hne5 (UScalar.eq_of_val_eq (by rw [hv]; rfl))
      have n12 : b.val ≠ 12 := fun hv => hne6 (UScalar.eq_of_val_eq (by rw [hv]; rfl))
      have n13 : b.val ≠ 13 := fun hv => hne7 (UScalar.eq_of_val_eq (by rw [hv]; rfl))
      have hb256 : b.val < 256 := by scalar_tac
      split at hm
      · split at hm
        · rename_i _ hle
          have hle' : b.val ≤ 31 := by scalar_tac
          obtain ⟨s1, hs1, hm⟩ := bind_eq_ok.mp hm
          simp at hs1; subst hs1
          obtain ⟨out2, ho2, hm⟩ := bind_eq_ok.mp hm
          have ho2v := extend_u8_ok ho2
          obtain ⟨i2', hsh, hm⟩ := bind_eq_ok.mp hm
          have hshv := spec_ok_eq (U8.ShiftRight_IScalar_spec b 4#i32 (by decide) (by decide)) hsh
          obtain ⟨i3, hd1, hm⟩ := bind_eq_ok.mp hm
          obtain ⟨out3, ho3, hm⟩ := bind_eq_ok.mp hm
          have ho3v := push_ok ho3
          obtain ⟨i4, hand, hm⟩ := bind_eq_ok.mp hm
          simp at hand; subst hand
          obtain ⟨i5, hd2, hm⟩ := bind_eq_ok.mp hm
          have ho4v := push_ok hm
          have hsh4 : i2'.val = b.val / 16 := by
            rw [hshv.1]; simp [Nat.shiftRight_eq_div_pow]
          have hand4 : (b &&& 15#u8).val = b.val % 16 := by
            simp only [UScalar.val_and]
            rw [show (15#u8 : Std.U8).val = 2 ^ 4 - 1 by rfl, Nat.and_two_pow_sub_one_eq_mod]
          have hd1v := hex_digit_ok (by rw [hsh4]; omega) hd1
          have hd2v := hex_digit_ok (by rw [hand4]; omega) hd2
          rw [ho4v, ho3v, ho2v]
          simp [Std.Array.to_slice, escByte, n34, n92, n8, n9, n10, n12, n13, hle', hd1v, hd2v,
            hsh4, hand4]
        · rename_i _ hgt
          have hgt' : ¬ b.val ≤ 31 := by scalar_tac
          rw [push_ok hm]
          simp [escByte, n34, n92, n8, n9, n10, n12, n13, hgt']
      · rename_i hlt0; exfalso; apply hlt0; scalar_tac
    · simp at h; subst h
      rename_i hge
      simp at hge
      omega

theorem escape_into_ok {s : Slice Std.U8} {out w : alloc.vec.Vec Std.U8}
    (h : canon.escape_into s out = ok w) :
    vals w.val = vals out.val ++ [34] ++ (vals s.val).flatMap escByte ++ [34] := by
  unfold canon.escape_into at h
  obtain ⟨o1, h1, h⟩ := bind_eq_ok.mp h
  obtain ⟨o2, h2, h⟩ := bind_eq_ok.mp h
  have e3 := push_ok h
  have e2 := escape_loop_ok _ s o1 o2 0#usize rfl h2
  have e1 := push_ok h1
  rw [e3]
  simp only [vals, List.map_append] at e2 ⊢
  rw [e2, e1]
  simp

set_option maxRecDepth 100000 in
/-- The escape table agrees with the model's `escChar` on every ASCII scalar (checked for all 128). -/
theorem escByte_ascii : ∀ n, n < 128 →
    escByte n = (Averin.Canon.escChar (Char.ofNat n)).flatMap enc := by
  decide

theorem escByte_enc (c : Char) : (enc c).flatMap escByte = Averin.utf8 (Averin.Canon.escChar c) := by
  rw [utf8_eq]
  by_cases hc : c.toNat < 0x80
  · rw [enc_ascii hc]
    simp only [List.flatMap_cons, List.flatMap_nil, List.append_nil]
    rw [escByte_ascii c.toNat hc, Char.ofNat_toNat]
  · have hhi := enc_high (c := c) (by omega)
    have hesc : Averin.Canon.escChar c = [c] := by
      unfold Averin.Canon.escChar
      have h1 : c ≠ '"' := by intro e; subst e; simp at hc
      have h2 : c ≠ '\\' := by intro e; subst e; simp at hc
      simp only [h1, h2, if_false]
      rw [if_neg (by omega), if_neg (by omega), if_neg (by omega), if_neg (by omega),
        if_neg (by omega), if_neg (by omega)]
    rw [hesc]
    simp only [List.flatMap_cons, List.flatMap_nil, List.append_nil]
    have : ∀ l : List Nat, (∀ b ∈ l, 0x80 ≤ b ∧ b < 0x100) → l.flatMap escByte = l := by
      intro l hl
      induction l with
      | nil => rfl
      | cons b l ih =>
        have hb := hl b (by simp)
        simp only [List.flatMap_cons]
        rw [ih (fun x hx => hl x (by simp [hx]))]
        have : escByte b = [b] := by
          unfold escByte
          split_ifs <;> simp_all; omega
        rw [this]; rfl
    exact this _ hhi

theorem escByte_utf8 : ∀ cs : List Char,
    (Averin.utf8 cs).flatMap escByte = Averin.utf8 (Averin.Canon.escStr cs)
  | [] => by simp [Averin.Canon.escStr]
  | c :: cs => by
    rw [utf8_cons, List.flatMap_append, escByte_enc, escByte_utf8 cs]
    simp only [Averin.Canon.escStr, utf8_append]

theorem utf8_serStr (cs : List Char) :
    Averin.utf8 (Averin.Canon.serStr cs) = [34] ++ Averin.utf8 (Averin.Canon.escStr cs) ++ [34] := by
  simp only [Averin.Canon.serStr, utf8_cons, utf8_append]
  simp [enc_ascii (c := '"') (by decide)]

/-- **`escape_into` refines `serStr`.** On the UTF-8 bytes of any scalar sequence, the production
escaper appends exactly the model's quoted, escaped string. -/
theorem escape_into_model {s : Slice Std.U8} {cs : List Char} {out w : alloc.vec.Vec Std.U8}
    (hs : vals s.val = Averin.utf8 cs) (h : canon.escape_into s out = ok w) :
    vals w.val = vals out.val ++ Averin.utf8 (Averin.Canon.serStr cs) := by
  rw [escape_into_ok h, hs, escByte_utf8, utf8_serStr]
  simp

end Refinement
