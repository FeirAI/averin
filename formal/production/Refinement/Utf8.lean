import Refinement.Basic
import Averin.Utf8

/-!
# UTF-8, byte by byte

`Averin.utf8` (the model's encoding of canonical text) unfolded to one arithmetic formula per
scalar, straight from Lean core's `String.utf8EncodeChar`. The extracted code works on the UTF-8
bytes of Rust strings; these lemmas connect those bytes to the model's characters.
-/

open Aeneas Aeneas.Std Result

namespace Refinement

/-- The UTF-8 bytes of one scalar, as the model's `Bytes`. -/
def enc (c : Char) : List Nat := (String.utf8EncodeChar c).map UInt8.toNat

theorem utf8_eq (l : List Char) : Averin.utf8 l = l.flatMap enc := by
  simp only [Averin.utf8, List.utf8Encode, List.toList_data_toByteArray, List.map_flatMap]
  rfl

@[simp] theorem utf8_nil : Averin.utf8 [] = [] := by simp [utf8_eq]

theorem utf8_cons (c : Char) (l : List Char) : Averin.utf8 (c :: l) = enc c ++ Averin.utf8 l := by
  simp [utf8_eq]

theorem utf8_append (a b : List Char) : Averin.utf8 (a ++ b) = Averin.utf8 a ++ Averin.utf8 b := by
  simp [utf8_eq]

theorem char_toNat_le (c : Char) : c.toNat ≤ 0x10ffff := by
  have := c.valid
  simp only [UInt32.isValidChar, Nat.isValidChar] at this
  have e : c.toNat = c.val.toNat := rfl
  omega

/-- `enc` as arithmetic on the scalar value (the four UTF-8 length classes). -/
theorem enc_eq (c : Char) : enc c =
    if c.toNat ≤ 0x7f then [c.toNat]
    else if c.toNat ≤ 0x7ff then [c.toNat / 64 % 32 + 0xc0, c.toNat % 64 + 0x80]
    else if c.toNat ≤ 0xffff then
      [c.toNat / 4096 % 16 + 0xe0, c.toNat / 64 % 64 + 0x80, c.toNat % 64 + 0x80]
    else
      [c.toNat / 262144 % 8 + 0xf0, c.toNat / 4096 % 64 + 0x80, c.toNat / 64 % 64 + 0x80,
        c.toNat % 64 + 0x80] := by
  have hc := char_toNat_le c
  have e : c.toNat = c.val.toNat := rfl
  simp only [enc, String.utf8EncodeChar, e]
  split
  · simp; omega
  · split
    · simp; omega
    · split
      · simp; omega
      · simp; omega

theorem enc_ascii {c : Char} (h : c.toNat < 0x80) : enc c = [c.toNat] := by
  rw [enc_eq]; simp; omega

theorem enc_high {c : Char} (h : 0x80 ≤ c.toNat) : ∀ b ∈ enc c, 0x80 ≤ b ∧ b < 0x100 := by
  have hc := char_toNat_le c
  rw [enc_eq]
  intro b hb
  split at hb
  · omega
  · split at hb
    · simp at hb; omega
    · split at hb
      · simp at hb; omega
      · simp at hb; omega

theorem enc_lt (c : Char) : ∀ b ∈ enc c, b < 0x100 := by
  intro b hb
  simp only [enc, List.mem_map] at hb
  obtain ⟨x, _, rfl⟩ := hb
  exact x.toNat_lt

/-- An ASCII-only list of scalars encodes to its code points. -/
theorem utf8_ascii : ∀ (l : List Char), (∀ c ∈ l, c.toNat < 0x80) →
    Averin.utf8 l = l.map Char.toNat
  | [], _ => by simp
  | c :: l, h => by
    rw [utf8_cons, enc_ascii (h c (by simp)), utf8_ascii l (fun d hd => h d (by simp [hd]))]
    simp

/-! ## Rust strings

Aeneas maps `alloc::string::String` to Lean's `String`, whose representation is its UTF-8 bytes;
`AverinGlue.stringBytes` exposes them as `u8`s (`Extracted/FunsExternal.lean`). -/

theorem stringBytes_vals (s : String) :
    vals (AverinGlue.stringBytes s) = Averin.utf8 s.toList := by
  simp only [vals, AverinGlue.stringBytes, Averin.utf8, List.map_map, String.utf8Encode_toList]
  congr 1

theorem stringSlice_ok {s : String} {sl : Slice Std.U8} (h : AverinGlue.stringSlice s = ok sl) :
    vals sl.val = Averin.utf8 s.toList := by
  unfold AverinGlue.stringSlice at h
  split at h
  · simp at h; subst h; simp [stringBytes_vals]
  · simp at h

theorem byteArray_toList_loop (bs : ByteArray) : ∀ (i : Nat) (r : List UInt8), i ≤ bs.size →
    ByteArray.toList.loop bs i r = r.reverse ++ bs.data.toList.drop i := by
  intro i r hi
  fun_induction ByteArray.toList.loop bs i r with
  | case1 i r h ih =>
    rw [ih (by omega)]
    have hi' : i < bs.data.toList.length := by simpa using h
    rw [List.drop_eq_getElem_cons hi']
    have : bs.get! i = bs.data.toList[i] := by
      simp only [ByteArray.get!, Array.getElem!_eq_getD, Array.getD]
      rw [dif_pos (by simpa using h)]; simp
    simp [this]
  | case2 i r h =>
    have : bs.data.toList.drop i = [] := by
      apply List.drop_eq_nil_of_le
      simp only [Array.length_toList]
      simp only [ByteArray.size] at h
      omega
    rw [this]; simp

theorem byteArray_toList (bs : ByteArray) : bs.toList = bs.data.toList := by
  simp [ByteArray.toList, byteArray_toList_loop bs 0 [] (by omega)]

/-- The bytes of a string literal in the extracted code (`toStr`) are its UTF-8 encoding. -/
theorem toStr_vals (s : String) (h) : vals (Aeneas.Std.toStr s h).val = Averin.utf8 s.toList := by
  simp only [Aeneas.Std.toStr, Slice.from_val, vals, List.map_map, Averin.utf8,
    String.utf8Encode_toList, byteArray_toList]
  apply List.map_congr_left; intro x _; rfl

end Refinement
