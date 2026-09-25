import Refinement.Sort
open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

namespace Refinement.ParseTest

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
    core.result.Result (α × Std.Usize) canon.ParseFault → Prop
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
    (err : canon.ParseError) (v : canon.CanonValue) (hi : i.val ≤ s.length) (hkw : 0 < kw.length) :
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
decreasing_by all_goals (simp_wf; have : k.val < hiI.val := by scalar_tac
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
  unfold canon.hex_value; step* <;> scalar_tac

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
      simp (config := {decide := true}) only [e0, e1, e2, e3, if_true, if_false, bind_tc_ok, ↓reduceIte] <;> step* <;>
      (intro c hc; simp only [Option.some.injEq] at hc; subst hc
       simp only [wc]; simp_all only [UScalar.cast_val_eq]; split_ifs <;> scalar_tac))


end Refinement.ParseTest
