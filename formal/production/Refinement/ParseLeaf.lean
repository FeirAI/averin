import Refinement.Sort
import Refinement.VerdictLists
open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

/-!
# The parser's leaf functions return

Total specifications (`f args ⦃ r => P r ⦄`: returns `ok r` with `P r`) of the extracted parser's
non-recursive helpers and loops: whitespace, literals, numbers (with the checked i64 magnitude
accumulation), `\u` escapes, UTF-8 scalar validation, UTF-16 and UTF-8 encoding, the strict UTF-16
decoder and `parse_string`. Loops terminate by `termination_by` on the bytes left. String lengths
use the weight `W` (UTF-8 bytes each UTF-16 unit decodes to), bounded by the input consumed.
See "Parser panic-freedom" in `formal/production/README.md`.
-/

namespace Refinement.Parse

@[step]
theorem is_ws_spec (b : Std.U8) : canon.is_ws b ⦃ _ => True ⦄ := by
  unfold canon.is_ws; step*

@[step]
theorem is_digit_spec (b : Std.U8) : canon.is_digit b ⦃ r => r = true → 48 ≤ b.val ∧ b.val ≤ 57 ⦄ := by
  unfold canon.is_digit; step*

@[step]
theorem skip_ws_loop_spec (s : Slice Std.U8) (i : Std.Usize) (h : i.val ≤ s.length) :
    canon.skip_ws_loop s i ⦃ j => i.val ≤ j.val ∧ j.val ≤ s.length ⦄ := by
  unfold canon.skip_ws_loop
  step*
termination_by s.length - i.val
decreasing_by scalar_decr_tac

@[step]
theorem skip_ws_spec (s : Slice Std.U8) (i : Std.Usize) (h : i.val ≤ s.length) :
    canon.skip_ws s i ⦃ j => i.val ≤ j.val ∧ j.val ≤ s.length ⦄ := by
  unfold canon.skip_ws; step*

@[step]
theorem at_spec (s : Slice Std.U8) (i : Std.Usize) (b : Std.U8) :
    canon.at s i b ⦃ r => r = true → ∃ h : i.val < s.length, s.val[i.val] = b ⦄ := by
  unfold canon.at; step*

@[step]
theorem expect_spec (s : Slice Std.U8) (i : Std.Usize) (b : Std.U8) :
    canon.expect s i b ⦃ r => ∀ j, r = .Ok j → j.val = i.val + 1 ∧ j.val ≤ s.length ⦄ := by
  unfold canon.expect; step*


/-- What every parse function guarantees: an `Ok` result ends strictly after `i`, within `s`. -/
def Adv {α} (s : Slice Std.U8) (i : Std.Usize) :
    core.result.Result (α × Std.Usize) canon.ParseError → Prop
  | .Ok (_, j) => i.val < j.val ∧ j.val ≤ s.length
  | .Err _ => True

/-- Close an `Adv` goal: `Err` is trivial, `Ok` is arithmetic. -/
macro "adv" : tactic => `(tactic| (simp only [Adv]; try scalar_tac))

@[step]
theorem parse_literal_loop_spec (s : Slice Std.U8) (i : Std.Usize) (kw : Slice Std.U8)
    (k : Std.Usize) (hk : k.val ≤ kw.length) (h : i.val + kw.length ≤ s.length) :
    canon.parse_literal_loop s i kw k ⦃ k' => k'.val ≤ kw.length ⦄ := by
  unfold canon.parse_literal_loop
  step*
termination_by kw.length - k.val
decreasing_by scalar_decr_tac

@[step]
theorem parse_literal_spec (s : Slice Std.U8) (i : Std.Usize) (kw : Slice Std.U8)
    (err : canon.ErrorKind) (v : canon.CanonValue) (hi : i.val ≤ s.length) (hkw : 0 < kw.length) :
    canon.parse_literal s i kw err v ⦃ r => Adv s i r ⦄ := by
  unfold canon.parse_literal
  step* <;> adv

@[step]
theorem parse_number_loop_spec (s : Slice Std.U8) (i : Std.Usize) (h : i.val ≤ s.length) :
    canon.parse_number_loop s i ⦃ j => i.val ≤ j.val ∧ j.val ≤ s.length ∧
      ∀ k (hk : k < s.length), i.val ≤ k → k < j.val → 48 ≤ (s.val[k]'hk).val ⦄ := by
  unfold canon.parse_number_loop
  step*
termination_by s.length - i.val
decreasing_by scalar_decr_tac


@[step]
theorem decimal_i64_loop_spec (s : Slice Std.U8) (hiI : Std.Usize) (limit mag : Std.U64)
    (in_range : Bool) (k : Std.Usize) (hto : hiI.val ≤ s.length)
    (hd : ∀ j (hj : j < s.length), k.val ≤ j → j < hiI.val → 48 ≤ (s.val[j]'hj).val)
    (hlim : 256 ≤ limit.val) (hmag : mag.val ≤ limit.val) :
    canon.decimal_i64_loop s hiI limit mag in_range k ⦃ (m, _) => m.val ≤ limit.val ⦄ := by
  unfold canon.decimal_i64_loop
  step*
  rename_i i3 _ _
  by_cases hm : mag > i3
  · simp only [hm, if_true, bind_tc_ok]
    step*
  · simp only [hm, if_false]
    step*
termination_by hiI.val - k.val
decreasing_by all_goals (have : k.val < hiI.val := by scalar_tac
                         simp at *; omega)

@[step]
theorem decimal_i64_spec (s : Slice Std.U8) (fr hiI : Std.Usize) (negative : Bool)
    (hto : hiI.val ≤ s.length)
    (hd : ∀ j (hj : j < s.length), fr.val ≤ j → j < hiI.val → 48 ≤ (s.val[j]'hj).val) :
    canon.decimal_i64 s fr hiI negative ⦃ _ => True ⦄ := by
  unfold canon.decimal_i64
  split <;> step*
  rename_i hne
  have hv : mag.val ≠ 9223372036854775808 := fun h => hne (UScalar.eq_of_val_eq (by simp [h]))
  subst i_post
  rw [UScalar.hcast_val_eq]
  simp only [IScalar.min, Int.bmod]
  split <;> simp <;> omega

@[step]
theorem parse_number_spec (s : Slice Std.U8) (i : Std.Usize) (hi : i.val < s.length) :
    canon.parse_number s i ⦃ r => Adv s i r ⦄ := by
  unfold canon.parse_number
  step*
  by_cases hn : negative = true
  · simp only [hn, if_true]
    step* <;> adv
  · simp only [hn, if_false, Bool.false_eq_true, bind_tc_ok]
    step* <;> adv


@[step]
theorem short_escape_spec (e : Std.U8) : canon.short_escape e ⦃ _ => True ⦄ := by
  unfold canon.short_escape; split <;> simp

@[step]
theorem hex_value_spec (c : Std.U8) : canon.hex_value c ⦃ d => d.val ≤ 16 ⦄ := by
  unfold canon.hex_value; step*

@[step]
theorem parse_hex4_spec (s : Slice Std.U8) (i : Std.Usize) (hi : i.val ≤ s.length) :
    canon.parse_hex4 s i ⦃ r => ∀ u j, r = .Ok (u, j) → j.val = i.val + 4 ∧ j.val ≤ s.length ⦄ := by
  unfold canon.parse_hex4; step*

@[step]
theorem is_continuation_spec (b : Std.U8) :
    canon.is_continuation b ⦃ r => r = true → 128 ≤ b.val ∧ b.val ≤ 191 ⦄ := by
  unfold canon.is_continuation; step*

/-- UTF-8 bytes needed to re-encode the UTF-16 units of scalar `c` (`push_utf16` then `push_utf8`). -/
def wc (c : Nat) : Nat := if c < 0x80 then 1 else if c < 0x800 then 2 else if c < 0x10000 then 3 else 4

set_option maxHeartbeats 2000000 in
@[step]
theorem utf8_scalar_spec (s : Slice Std.U8) (i len : Std.Usize) (h : i.val + len.val ≤ s.length)
    (hlen : 1 ≤ len.val ∧ len.val ≤ 4)
    (hlead : ∀ hi : i.val < s.length,
      (len.val = 1 → (s.val[i.val]'hi).val < 0x80) ∧
      (len.val = 2 → 0xC0 ≤ (s.val[i.val]'hi).val ∧ (s.val[i.val]'hi).val < 0xE0) ∧
      (len.val = 3 → 0xE0 ≤ (s.val[i.val]'hi).val ∧ (s.val[i.val]'hi).val < 0xF0) ∧
      (len.val = 4 → 0xF0 ≤ (s.val[i.val]'hi).val ∧ (s.val[i.val]'hi).val < 0xF8)) :
    canon.utf8_scalar s i len ⦃ o => ∀ c, o = some c →
      c.val < 0x110000 ∧ (c.val < 0xD800 ∨ 0xE000 ≤ c.val) ∧ wc c.val ≤ len.val ⦄ := by
  have hi : i.val < s.length := by omega
  obtain ⟨h1, h2, h3, h4⟩ := hlead hi
  unfold canon.utf8_scalar
  step*
  all_goals first
    | (intro c hc; simp only [Option.some.injEq] at hc; subst hc
       simp only [wc]; simp_all only [UScalar.cast_val_eq]; split_ifs <;> scalar_tac)
    | skip
  all_goals (
    by_cases e0 : b0 = 224#u32 <;> by_cases e1 : b0 = 240#u32 <;>
      by_cases e2 : b0 = 237#u32 <;> by_cases e3 : b0 = 244#u32 <;>
      simp (config := {decide := true}) only [e0, e1, e2, e3, bind_tc_ok, ↓reduceIte] <;> step* <;>
      (intro c hc; simp only [Option.some.injEq] at hc; subst hc
       simp only [wc]; simp_all only [UScalar.cast_val_eq]; split_ifs <;> scalar_tac))


@[step]
theorem next_utf8_char_spec (s : Slice Std.U8) (i : Std.Usize) (hi : i.val < s.length) :
    canon.next_utf8_char s i ⦃ r => ∀ c l, r = .Ok (c, l) →
      1 ≤ l.val ∧ i.val + l.val ≤ s.length ∧ c.val < 0x110000 ∧ wc c.val ≤ l.val ⦄ := by
  unfold canon.next_utf8_char
  step*
  all_goals (intros; simp_all [Nat.shiftRight_eq_div_pow, UScalar.eq_equiv, UScalar.lt_equiv] <;> omega)

/-- UTF-8 bytes that decoding a UTF-16 unit produces (a surrogate is half of a 4-byte scalar). -/
def w (u : Nat) : Nat :=
  if u < 0x80 then 1 else if u < 0x800 then 2 else if 0xD800 ≤ u ∧ u < 0xE000 then 2 else 3

/-- The UTF-8 size of a unit sequence; at least its length. -/
def W (l : List Std.U16) : Nat := (l.map (fun u => w u.val)).sum

theorem W_append (a b : List Std.U16) : W (a ++ b) = W a + W b := by simp [W]

theorem W_push (l : List Std.U16) (u : Std.U16) : W (l ++ [u]) = W l + w u.val := by
  simp [W]

theorem length_le_W (l : List Std.U16) : l.length ≤ W l := by
  induction l with
  | nil => simp [W]
  | cons u l ih =>
    have : 1 ≤ w u.val := by unfold w; split_ifs <;> omega
    simp only [W, List.map_cons, List.sum_cons, List.length_cons] at *; omega

@[step]
theorem push_utf16_spec (units : alloc.vec.Vec Std.U16) (c : Std.U32) (hc : c.val < 0x110000)
    (hb : units.length + wc c.val ≤ Usize.max) :
    canon.push_utf16 units c ⦃ u' => W u'.val ≤ W units.val + wc c.val ⦄ := by
  have h1 : 1 ≤ wc c.val := by unfold wc; split_ifs <;> omega
  have h4 : 65536 ≤ c.val → wc c.val = 4 := by intro h; unfold wc; split_ifs <;> omega
  have hbmp : c.val < 65536 → w c.val ≤ wc c.val := by intro h; unfold w wc; split_ifs <;> omega
  unfold canon.push_utf16
  split
  · have hlt : c.val < 65536 := by scalar_tac
    have hcv : (UScalar.cast UScalarTy.U16 c).val = c.val := cast16_val c hlt
    step*
    rw [u'_post, W_push, i_post, hcv]
    have := hbmp hlt; omega
  · have hge : 65536 ≤ c.val := by scalar_tac
    have := h4 hge
    step*
    · simp only [units1_post, List.length_append, List.length_cons, List.length_nil]
      have : units.length = units.val.length := rfl
      omega
    · have c2 : (UScalar.cast UScalarTy.U16 i2).val = i2.val := cast16_val i2 (by omega)
      have c5 : (UScalar.cast UScalarTy.U16 i5).val = i5.val := cast16_val i5 (by omega)
      rw [u'_post, W_push, units1_post, W_push, i3_post, i6_post, c2, c5]
      unfold w; split_ifs <;> omega

@[step]
theorem push_utf8_spec (out : alloc.vec.Vec Std.U8) (c : Std.U32)
    (hb : out.length + wc c.val ≤ Usize.max) :
    canon.push_utf8 out c ⦃ o => o.length = out.length + wc c.val ⦄ := by
  have h1 : c.val < 128 → wc c.val = 1 := by intro h; simp [wc, h]
  have h2 : 128 ≤ c.val → c.val < 2048 → wc c.val = 2 := by intro h h'; unfold wc; split_ifs <;> omega
  have h3 : 2048 ≤ c.val → c.val < 65536 → wc c.val = 3 := by
    intro h h'; unfold wc; split_ifs <;> omega
  have h4 : 65536 ≤ c.val → wc c.val = 4 := by intro h; unfold wc; split_ifs <;> omega
  unfold canon.push_utf8
  step* <;> simp_all <;> omega


theorem W_drop (l : List Std.U16) (i : Nat) (hi : i < l.length) :
    W (l.drop i) = w (l[i]'hi).val + W (l.drop (i + 1)) := by
  unfold W; rw [List.drop_eq_getElem_cons hi, List.map_cons, List.sum_cons]

theorem w_bmp {u : Nat} (h : u < 0xD800 ∨ (0xE000 ≤ u ∧ u < 0x10000)) : wc u = w u := by
  unfold wc w; split_ifs <;> omega

theorem pair_W (l : List Std.U16) (i : Nat) (h : i + 1 < l.length)
    (hu : 0xD800 ≤ (l[i]'(by omega)).val ∧ (l[i]'(by omega)).val ≤ 0xDBFF)
    (hl : 0xDC00 ≤ (l[i + 1]'h).val ∧ (l[i + 1]'h).val ≤ 0xDFFF) :
    W (l.drop i) = 4 + W (l.drop (i + 2)) := by
  rw [W_drop l i (by omega), W_drop l (i + 1) h]
  have e1 : w (l[i]'(by omega)).val = 2 := by unfold w; split_ifs <;> omega
  have e2 : w (l[i + 1]'h).val = 2 := by unfold w; split_ifs <;> omega
  have e3 : i + 1 + 1 = i + 2 := by omega
  rw [e1, e2, e3]; omega

theorem cast32_of16 (x : Std.U16) : (UScalar.cast UScalarTy.U32 x).val = x.val := by simp

@[step]
theorem decode_loop_spec (units : Slice Std.U16) (out : alloc.vec.Vec Std.U8)
    (fault : canon.ErrorKind) (ok1 : Bool) (i : Std.Usize) (Wt : Nat)
    (hi : i.val ≤ units.length) (hinv : out.length + W (units.val.drop i.val) ≤ Wt)
    (hWt : Wt ≤ Usize.max) :
    canon.decode_utf16_strict_loop units out fault ok1 i ⦃ (o, _, _) => o.length ≤ Wt ⦄ := by
  unfold canon.decode_utf16_strict_loop
  step*
  all_goals first
    | (have hi0 : i3.val < units.val.length := by scalar_tac
       have hi1 : i.val + 1 < units.val.length := by omega
       have cu : (units.val[i.val]'(by omega)).val = u.val := by rw [u_post, cast32_of16, i2_post]
       have cl : (units.val[i.val + 1]'hi1).val = lo.val := by
         rw [lo_post, cast32_of16, i5_post]; simp only [i3_post]
       clear u_post i2_post lo_post i5_post
       have hW := pair_W units.val i.val hi1 (by rw [cu]; scalar_tac) (by rw [cl]; scalar_tac)
       have hwc : wc i10.val = 4 := by unfold wc; split_ifs <;> scalar_tac
       simp only [Slice.length] at *
       scalar_tac)
    | (have hlt : i.val < units.val.length := by scalar_tac
       have cu : (units.val[i.val]'hlt).val = u.val := by rw [u_post, cast32_of16, i2_post]
       clear u_post i2_post
       have hW := W_drop units.val i.val hlt
       have hwc : wc u.val = w u.val := w_bmp (by scalar_tac)
       rw [cu] at hW
       simp only [Slice.length] at *
       scalar_tac)
termination_by 2 * (units.length - i.val) + (if ok1 then 1 else 0)
decreasing_by all_goals (simp_wf; scalar_tac)


/-- The glue's `String::from_utf8` returns (always) and keeps the bytes. -/
@[step]
theorem from_utf8_spec (v : alloc.vec.Vec Std.U8) :
    alloc.string.String.from_utf8 v ⦃ r => ∀ t, r = .Ok t →
      (AverinGlue.stringBytes t).length = v.length ⦄ := by
  unfold alloc.string.String.from_utf8
  split
  · rename_i t h
    simp only [String.fromUTF8?] at h
    split at h
    · simp only [Option.some.injEq] at h; subst h
      simp [AverinGlue.stringBytes, String.fromUTF8]
      exact (by simp : ((List.map AverinGlue.uint8OfU8 v.val).toArray).size = v.val.length)
    · simp at h
  · simp

@[step]
theorem decode_spec (units : Slice Std.U16) (hW : W units.val ≤ Usize.max) :
    canon.decode_utf16_strict units ⦃ r => ∀ t, r = .Ok t →
      (AverinGlue.stringBytes t).length ≤ Usize.max ⦄ := by
  unfold canon.decode_utf16_strict
  step*
  -- the capacity (`3 * len` under the `len <= usize::MAX / 3` guard) is computed without overflow
  have hcap : ∃ c : Std.Usize,
      (if units.len ≤ i1 then 3#usize * units.len else ok units.len) = ok c := by
    split_ifs with h
    · obtain ⟨c, hc, _⟩ := spec_imp_exists (Usize.mul_spec (x := 3#usize) (y := units.len)
        (by simp only [Usize.max] at *; scalar_tac))
      exact ⟨c, hc⟩
    · exact ⟨_, rfl⟩
  obtain ⟨c, hc⟩ := hcap
  rw [hc, bind_tc_ok]
  step*
  simp [alloc.vec.Vec.with_capacity]


theorem w_le3 (u : Nat) : w u ≤ 3 := by unfold w; split_ifs <;> omega

@[step]
theorem parse_string_loop_spec (s : Slice Std.U8) (i : Std.Usize) (units : alloc.vec.Vec Std.U16)
    (fault : Option canon.ParseError) (op : Bool) (hi : i.val ≤ s.length)
    (hW : W units.val ≤ i.val) :
    canon.parse_string_loop s i units fault op ⦃ (j, u', _) =>
      i.val ≤ j.val ∧ j.val ≤ s.length ∧ W u'.val ≤ j.val ⦄ := by
  have hl := length_le_W units.val
  unfold canon.parse_string_loop
  step*
  any_goals (rename_i p hp; obtain ⟨a, b⟩ := p; have hab := r_post _ _ hp)
  all_goals try step*
  all_goals (rw [units1_post, W_push])
  · have := w_le3 a.val; scalar_tac
  · have : w u.val = 1 := by unfold w; split_ifs <;> scalar_tac
    scalar_tac
termination_by 2 * (s.length - i.val) + (if op then 1 else 0)
decreasing_by all_goals (simp_wf; split_ifs; scalar_tac)


@[step]
theorem deref_spec (t : String) (h : (AverinGlue.stringBytes t).length ≤ Usize.max) :
    alloc.string.String.Insts.CoreOpsDerefDerefStr.deref t ⦃ _ => True ⦄ := by
  simp only [alloc.string.String.Insts.CoreOpsDerefDerefStr.deref, AverinGlue.stringSlice, h,
    dif_pos]
  exact WP.spec.ret trivial

@[step]
theorem nfc_spec (x : Str) : canon.nfc x ⦃ r => r = AverinTrusted.nfc x ⦄ := by
  simp [canon.nfc]

/-- What `parse_string` returns: an NFC output (a value of the trusted primitive) ending after `i`. -/
def StrOk (s : Slice Std.U8) (i : Std.Usize) :
    core.result.Result (String × Std.Usize) canon.ParseError → Prop
  | .Ok (t, j) => i.val < j.val ∧ j.val ≤ s.length ∧ ∃ x, t = AverinTrusted.nfc x
  | .Err _ => True

@[step]
theorem parse_string_spec (s : Slice Std.U8) (i : Std.Usize) :
    canon.parse_string s i ⦃ r => StrOk s i r ⦄ := by
  unfold canon.parse_string
  step as ⟨r, hr⟩
  cases r with
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, StrOk]
  | Ok j =>
    obtain ⟨hj1, hj2⟩ := hr j rfl
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step*
    · simp [W, alloc.vec.Vec.new]
    · have hs := s.property
      show W (alloc.vec.Vec.deref units).val ≤ Usize.max
      simp only [alloc.vec.Vec.deref, Slice.from_val]
      simp only [Slice.length] at *; omega
    all_goals first
      | (simp only [StrOk]; done)
      | (simp only [StrOk]; exact ⟨by scalar_tac, by scalar_tac, _, by assumption⟩)

end Refinement.Parse
