import Refinement.Canonical
import Averin.Encoding

/-!
# LP framing and the digest string

* `lp_into_model`: `hashx::lp_into` appends exactly the model's `LP(b) = uint32_be(|b|) ‖ b`
  (`Averin.lp`), and refuses (`false`, nothing appended) only when `|b| ≥ 2^32`.
* `sha256_prefixed_model`: `hashx::sha256_prefixed` returns the string whose UTF-8 bytes are
  `fmtP (SHA-256 data)`, `"sha256:" ‖ lowercase hex`.
* `fmtP_inj`: that formatting is injective on byte strings — the `hfmt` hypothesis of the model's
  `Seal.recordHashOf_binding`, discharged for the production formatter (`fmtM_inj` for all inputs).
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

namespace Refinement

theorem be_bytes (x : Std.U32) : (x.bv.toBEBytes).map BitVec.toNat =
    [x.bv.toNat / 16777216 % 256, x.bv.toNat / 65536 % 256, x.bv.toNat / 256 % 256,
      x.bv.toNat % 256] := by
  have hx : x.bv.toNat < 2^32 := x.bv.isLt
  simp only [BitVec.toBEBytes]
  rw [BitVec.toLEBytes, BitVec.toLEBytes, BitVec.toLEBytes, BitVec.toLEBytes, BitVec.toLEBytes]
  simp [BitVec.toNat_setWidth, BitVec.toNat_ushiftRight]
  omega

/-- **LP framing.** -/
theorem lp_into_model {out w : alloc.vec.Vec Std.U8} {b : Slice Std.U8} {flag : Bool}
    (h : hashx.lp_into out b = ok (flag, w)) :
    (flag = true → b.val.length < Averin.lpLimit ∧ vals w.val = vals out.val ++ Averin.lp (vals b.val)) ∧
    (flag = false → Averin.lpLimit ≤ b.val.length ∧ w = out) := by
  unfold hashx.lp_into at h
  obtain ⟨mx, hmx, h⟩ := bind_eq_ok.mp h
  have hmxv : mx.val = 4294967295 := by
    unfold hashx.MAX_LP_LEN at hmx
    simp at hmx; subst hmx
    rw [UScalar.cast_val_eq]
    have : (core.num.U32.MAX).val = 4294967295 := by rfl
    rw [this]
    have : 4294967295 < 2 ^ UScalarTy.Usize.numBits := by
      have := System.Platform.numBits_eq
      simp only [UScalarTy.numBits]
      rcases this with h | h <;> rw [h] <;> decide
    exact Nat.mod_eq_of_lt this
  split at h
  · rename_i hgt
    have hgt' : 4294967295 < b.val.length := by rw [← hmxv]; scalar_tac
    simp at h; obtain ⟨rfl, rfl⟩ := h
    refine ⟨by simp, fun _ => ⟨by simp [Averin.lpLimit]; omega, rfl⟩⟩
  · rename_i hle
    have hle' : b.val.length ≤ 4294967295 := by rw [← hmxv]; scalar_tac
    obtain ⟨i3, hi3, h⟩ := bind_eq_ok.mp h
    simp at hi3; subst hi3
    obtain ⟨a, ha, h⟩ := bind_eq_ok.mp h
    simp at ha; subst ha
    obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
    simp at hs; subst hs
    obtain ⟨o1, ho1, h⟩ := bind_eq_ok.mp h
    obtain ⟨o2, ho2, h⟩ := bind_eq_ok.mp h
    simp at h; obtain ⟨rfl, rfl⟩ := h
    refine ⟨fun _ => ⟨by simp [Averin.lpLimit]; omega, ?_⟩, by simp⟩
    rw [extend_u8_ok ho2, extend_u8_ok ho1]
    have hcast : (UScalar.cast UScalarTy.U32 (Slice.len b)).bv.toNat = b.val.length := by
      show (UScalar.cast UScalarTy.U32 (Slice.len b)).val = _
      rw [UScalar.cast_val_eq, Slice.len_val, UScalarTy.U32_numBits_eq]
      exact Nat.mod_eq_of_lt (by simp only [Slice.length]; omega)
    have hbe := be_bytes (UScalar.cast UScalarTy.U32 (Slice.len b))
    rw [hcast] at hbe
    simp only [vals, List.map_append, Averin.lp, Averin.be32]
    simp only [Std.Array.to_slice, Slice.from_val, core.num.U32.to_be_bytes, Std.Array.from_val,
      List.map_map]
    have : (List.map (UScalar.val ∘ @UScalar.mk UScalarTy.U8)
        (UScalar.cast UScalarTy.U32 (Slice.len b)).bv.toBEBytes) =
        List.map BitVec.toNat (UScalar.cast UScalarTy.U32 (Slice.len b)).bv.toBEBytes := by
      apply List.map_congr_left; intro x _; rfl
    rw [this, hbe]
    simp

theorem lp_str_into_model {out w : alloc.vec.Vec Std.U8} {s : Str} {flag : Bool}
    (h : hashx.lp_str_into out s = ok (flag, w)) :
    (flag = true → (strSlice s).val.length < Averin.lpLimit ∧
      vals w.val = vals out.val ++ Averin.lp (vals (strSlice s).val)) ∧
    (flag = false → Averin.lpLimit ≤ (strSlice s).val.length ∧ w = out) := by
  unfold hashx.lp_str_into at h
  obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
  simp [core.str.Str.as_bytes] at hs1
  have e : strSlice s = s1 := hs1
  rw [e]
  exact lp_into_model h

/-! ## The digest string -/

/-- `"sha256:" ‖ lowercase hex`, on byte values (the model's `fmt` for production digests). -/
def fmtP (d : List Nat) : List Nat :=
  [115, 104, 97, 50, 53, 54, 58] ++ d.flatMap (fun x => [hexd (x / 16), hexd (x % 16)])

theorem hexd_inj {a b : Nat} (ha : a < 16) (hb : b < 16) (h : hexd a = hexd b) : a = b := by
  unfold hexd at h; split_ifs at h <;> omega

theorem hexd_lt (a : Nat) (ha : a < 16) : hexd a < 256 := by unfold hexd; split_ifs <;> omega

theorem hexPairs_inj : ∀ {d e : List Nat}, (∀ x ∈ d, x < 256) → (∀ x ∈ e, x < 256) →
    d.flatMap (fun x => [hexd (x / 16), hexd (x % 16)]) =
      e.flatMap (fun x => [hexd (x / 16), hexd (x % 16)]) → d = e
  | [], [], _, _, _ => rfl
  | [], _ :: _, _, _, h => by simp at h
  | _ :: _, [], _, _, h => by simp at h
  | x :: d, y :: e, hd, he, h => by
    simp only [List.flatMap_cons, List.cons_append, List.nil_append, List.cons.injEq] at h
    have hx := hd x (by simp)
    have hy := he y (by simp)
    have h1 := hexd_inj (by omega) (by omega) h.1
    have h2 := hexd_inj (by omega) (by omega) h.2.1
    have hxy : x = y := by omega
    rw [hxy, hexPairs_inj (fun z hz => hd z (by simp [hz])) (fun z hz => he z (by simp [hz])) h.2.2]

/-- **The production digest formatting is injective** (on byte strings). -/
theorem fmtP_inj {d e : List Nat} (hd : ∀ x ∈ d, x < 256) (he : ∀ x ∈ e, x < 256)
    (h : fmtP d = fmtP e) : d = e := by
  simp only [fmtP, List.cons_append, List.cons.injEq, List.nil_append, true_and] at h
  exact hexPairs_inj hd he h

/-- `fmtP` extended to all `Bytes` (for instantiating the model's `fmt`): out-of-range inputs, which
no digest ever is, are tagged by a leading `256` and cannot collide with a digest string. -/
def fmtM (d : List Nat) : List Nat :=
  if ∀ x ∈ d, x < 256 then fmtP d else 256 :: d

/-- **`hfmt` of `Seal.recordHashOf_binding`, discharged**: `fmtM` is injective on all inputs. -/
theorem fmtM_inj : ∀ x y, fmtM x = fmtM y → x = y := by
  intro x y h
  unfold fmtM at h
  split_ifs at h with hx hy hy
  · exact fmtP_inj hx hy h
  · simp [fmtP] at h
  · simp [fmtP] at h
  · simpa using h

/-- `hashx::HEX`'s contents. -/
def hexTable : List Std.U8 := [48#u8, 49#u8, 50#u8, 51#u8, 52#u8, 53#u8, 54#u8, 55#u8,
  56#u8, 57#u8, 97#u8, 98#u8, 99#u8, 100#u8, 101#u8, 102#u8]

theorem hexTable_spec : ∀ k (hk : k < 16), (hexTable[k]'(by simp [hexTable]; omega)).val = hexd k := by
  decide

theorem hex_loop_ok : ∀ (m : Nat) (b : Slice Std.U8) (out w : alloc.vec.Vec Std.U8) (i : Std.Usize),
    b.val.length - i.val = m → hashx.hex_lower_into_loop b out i = ok w →
    vals w.val = vals out.val ++
      ((vals b.val).drop i.val).flatMap (fun x => [hexd (x / 16), hexd (x % 16)]) := by
  intro m
  induction m with
  | zero =>
    intro b out w i hm h
    unfold hashx.hex_lower_into_loop at h
    dsimp only at h
    split at h
    · rename_i hlt; have : i.val < b.val.length := by scalar_tac
      omega
    · simp at h; subst h
      have : (vals b.val).drop i.val = [] := by simp; omega
      simp [this]
  | succ m ih =>
    intro b out w i hm h
    unfold hashx.hex_lower_into_loop at h
    dsimp only at h
    split at h
    · rename_i hlt
      have hi : i.val < b.val.length := by scalar_tac
      obtain ⟨x, hx, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, hxv⟩ := slice_index_ok hx
      obtain ⟨i3, hi3, h⟩ := bind_eq_ok.mp h
      have hi3v := spec_ok_eq (U8.ShiftRight_IScalar_spec x 4#i32 (by decide) (by decide)) hi3
      obtain ⟨i4, hi4, h⟩ := bind_eq_ok.mp h
      simp at hi4; subst hi4
      obtain ⟨d1, hd1, h⟩ := bind_eq_ok.mp h
      obtain ⟨hd1l, hd1v⟩ := array_index_ok hd1
      obtain ⟨o1, ho1, h⟩ := bind_eq_ok.mp h
      obtain ⟨i6, hi6, h⟩ := bind_eq_ok.mp h
      simp at hi6; subst hi6
      obtain ⟨i7, hi7, h⟩ := bind_eq_ok.mp h
      simp at hi7; subst hi7
      obtain ⟨d2, hd2, h⟩ := bind_eq_ok.mp h
      obtain ⟨hd2l, hd2v⟩ := array_index_ok hd2
      obtain ⟨o2, ho2, h⟩ := bind_eq_ok.mp h
      obtain ⟨i9, hi9, h⟩ := bind_eq_ok.mp h
      have hi9v := uadd_ok hi9; simp at hi9v
      rw [ih b o2 w i9 (by omega) h, push_ok ho2, push_ok ho1, hi9v]
      have hx16 : i3.val = x.val / 16 := by rw [hi3v.1]; simp [Nat.shiftRight_eq_div_pow]
      have hand : (x &&& 15#u8).val = x.val % 16 := by
        simp only [UScalar.val_and]
        rw [show (15#u8 : Std.U8).val = 2 ^ 4 - 1 by rfl, Nat.and_two_pow_sub_one_eq_mod]
      have hxl : x.val < 256 := by scalar_tac
      have hHEX : ∀ k (hk : k < 16) (hk' : k < hashx.HEX.val.length),
          (hashx.HEX.val[k]'hk').val = hexd k := by
        intro k hk hk'
        have hv : hashx.HEX.val = hexTable := by unfold hashx.HEX hexTable; simp
        rw [List.getElem_of_eq hv]
        exact hexTable_spec k hk
      have e1 : d1.val = hexd (x.val / 16) := by
        rw [hd1v]
        have hk : (UScalar.cast UScalarTy.Usize i3).val = x.val / 16 := by
          have : x.val / 16 < 2 ^ UScalarTy.Usize.numBits := by
            have := System.Platform.numBits_eq
            simp only [UScalarTy.numBits]
            rcases this with h | h <;> rw [h] <;> omega
          rw [UScalar.cast_val_eq, hx16, Nat.mod_eq_of_lt this]
        simp only [hk]
        exact hHEX _ (by omega) _
      have e2 : d2.val = hexd (x.val % 16) := by
        rw [hd2v]
        have hk : (UScalar.cast UScalarTy.Usize (x &&& 15#u8)).val = x.val % 16 := by
          have : x.val % 16 < 2 ^ UScalarTy.Usize.numBits := by
            have := System.Platform.numBits_eq
            simp only [UScalarTy.numBits]
            rcases this with h | h <;> rw [h] <;> omega
          rw [UScalar.cast_val_eq, hand, Nat.mod_eq_of_lt this]
        simp only [hk]
        exact hHEX _ (by omega) _
      have hi' : i.val < (vals b.val).length := by simpa using hi
      rw [List.drop_eq_getElem_cons hi']
      simp [vals, e1, e2, hxv]
    · rename_i hge; have : ¬ i.val < b.val.length := by scalar_tac
      omega

theorem ascii_string_ok {v : alloc.vec.Vec Std.U8} {s : String}
    (h : hashx.ascii_string v = ok s) : Averin.utf8 s.toList = vals v.val := by
  unfold hashx.ascii_string at h
  obtain ⟨r, hr, h⟩ := bind_eq_ok.mp h
  unfold alloc.string.String.from_utf8 at hr
  split at hr
  · rename_i s' hs'
    simp at hr; subst hr
    simp at h; subst h
    simp only [String.fromUTF8?] at hs'
    split at hs'
    · simp at hs'; subst hs'
      simp only [Averin.utf8, String.utf8Encode_toList]
      simp [String.fromUTF8, AverinGlue.uint8OfU8, vals]
    · simp at hs'
  · simp at hr; subst hr
    simp at h

/-- **The digest string.** -/
theorem sha256_prefixed_model {data : Slice Std.U8} {s : String}
    (h : hashx.sha256_prefixed data = ok s) :
    Averin.utf8 s.toList = fmtP (vals (AverinTrusted.sha256 data).val) := by
  unfold hashx.sha256_prefixed at h
  obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
  simp at hs1; subst hs1
  obtain ⟨s2, hs2, h⟩ := bind_eq_ok.mp h
  obtain ⟨a, ha, h⟩ := bind_eq_ok.mp h
  simp [hashx.sha256] at ha; subst ha
  obtain ⟨s3, hs3, h⟩ := bind_eq_ok.mp h
  simp at hs3; subst hs3
  obtain ⟨s4, hs4, h⟩ := bind_eq_ok.mp h
  rw [ascii_string_ok h]
  have := hex_loop_ok _ _ s2 s4 0#usize rfl hs4
  simp only [show (0#usize : Std.Usize).val = 0 from rfl, List.drop_zero] at this
  rw [this, extend_u8_ok hs2]
  simp [fmtP, vals, Std.Array.to_slice, alloc.vec.Vec.with_capacity]

end Refinement
