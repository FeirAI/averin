import Refinement.ParseSort
open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

/-!
# The production RCP parser returns for every input

`parse_document_total`: the extracted `canon::parse_document` (the body of
`CanonValue::parse_typed`) evaluates to `ok` for every input byte string, under `NfcFits`.
The mutually recursive `parse_value`/`parse_array`/`parse_object` and their loops are proved
together by well-founded recursion on `4 * (bytes left) + rank` (`parse_decreasing`).
-/

namespace Refinement.Parse

/-- Rust's `String` invariant for the values the trusted NFC primitive returns: a `String` fits in
memory, so its byte length is at most `usize::MAX`. (The glue maps a Rust `String` to an unbounded
Lean `String`; this hypothesis restores the bound for NFC outputs, the only strings whose bytes the
parser reads.) -/
def NfcFits : Prop := ∀ x, (AverinGlue.stringBytes (AverinTrusted.nfc x)).length ≤ Usize.max

@[step]
theorem string_as_bytes_spec (t : String) (h : (AverinGlue.stringBytes t).length ≤ Usize.max) :
    alloc.string.String.as_bytes t ⦃ _ => True ⦄ := by
  simp only [alloc.string.String.as_bytes, AverinGlue.stringSlice, h, dif_pos]
  exact WP.spec.ret trivial

@[step]
theorem string_clone_spec (t : String) :
    alloc.string.String.Insts.CoreCloneClone.clone t ⦃ t' => t' = t ⦄ := by
  simp [alloc.string.String.Insts.CoreCloneClone.clone]

@[simp] theorem max_depth_val : canon.MAX_DEPTH.val = 256 := by
  simp [canon.MAX_DEPTH]

/-- The key/unit/offset bookkeeping of the object loop. -/
def ObjInv (i : Nat) (members : alloc.vec.Vec (String × canon.CanonValue))
    (units : alloc.vec.Vec (alloc.vec.Vec Std.U16)) (starts : alloc.vec.Vec Std.Usize)
    (keys : alloc.vec.Vec String) : Prop :=
  keys.length ≤ i ∧ units.length = keys.length ∧ starts.length = keys.length ∧
    members.length ≤ keys.length

theorem adv_ok {α} {s : Slice Std.U8} {i : Std.Usize}
    {r : core.result.Result (α × Std.Usize) canon.ParseError} {v : α} {j : Std.Usize}
    (h : Adv s i r) (e : r = .Ok (v, j)) : i.val < j.val ∧ j.val ≤ s.length := by
  subst e; exact h

theorem strOk_ok {s : Slice Std.U8} {i : Std.Usize}
    {r : core.result.Result (String × Std.Usize) canon.ParseError} {t : String} {j : Std.Usize}
    (h : StrOk s i r) (e : r = .Ok (t, j)) : i.val < j.val ∧ j.val ≤ s.length := by
  subst e; exact ⟨h.1, h.2.1⟩

theorem one_val : (1#usize : Std.Usize).val = 1 := by simp

set_option hygiene false in
/-- The termination argument: every recursive call of the parser's mutual block lowers
`4 * (bytes left) + rank` (rank: value 2, array/object 1, a loop 3 while open, 0 once closed). -/
macro "parse_decreasing" : tactic => `(tactic| (
  simp_wf
  all_goals (
    try (have := adv_ok (v := v) (j := j) r_post (by assumption))
    try (have := strOk_ok (t := key) (j := j) r_post (by assumption))
    try (have := r1_post _ (by assumption))
    try (have := adv_ok (v := v) (j := j2) r2_post (by assumption))
    have := one_val
    have : s.length = s.val.length := rfl
    first | omega | (split_ifs <;> first | omega | contradiction))))

mutual

theorem parse_value_spec (hnfc : NfcFits) (s : Slice Std.U8) (i depth : Std.Usize)
    (hi : i.val ≤ s.length) :
    canon.parse_value s i depth ⦃ r => Adv s i r ⦄ := by
  unfold canon.parse_value
  step*
  all_goals first
    | (simp only [Adv]; done)
    | (rename_i p hp; obtain ⟨t, j⟩ := p; rw [hp] at r_post; simp only [StrOk] at r_post
       step*
       simp only [Adv]; exact ⟨r_post.1, r_post.2.1⟩)
    | (rename_i p hp; obtain ⟨n, j⟩ := p; rw [hp] at r_post; simp only [Adv] at r_post
       step*
       simp only [Adv]; exact r_post)
termination_by 4 * (s.length - i.val) + 2
decreasing_by all_goals parse_decreasing

theorem parse_array_loop_spec (hnfc : NfcFits) (s : Slice Std.U8) (depth i : Std.Usize)
    (items : alloc.vec.Vec canon.CanonValue) (fault : Option canon.ParseError) (op : Bool)
    (hi : i.val ≤ s.length) (hd : depth.val < 256) (hit : items.length ≤ i.val) :
    canon.parse_array_loop s depth i items fault op ⦃ (j, items', _) =>
      i.val ≤ j.val ∧ j.val ≤ s.length ∧ items'.length ≤ j.val ⦄ := by
  unfold canon.parse_array_loop
  step*
  rename_i p hp; obtain ⟨v, j⟩ := p; rw [hp] at r_post; simp only [Adv] at r_post
  step*
  all_goals (simp only [alloc.vec.Vec.length, items1_post, List.length_append,
    List.length_singleton] at *; scalar_tac)
termination_by 4 * (s.length - i.val) + (if op then 3 else 0)
decreasing_by all_goals parse_decreasing

theorem parse_array_spec (hnfc : NfcFits) (s : Slice Std.U8) (i depth : Std.Usize) :
    canon.parse_array s i depth ⦃ r => Adv s i r ⦄ := by
  have hmd : canon.MAX_DEPTH.val = 256 := max_depth_val
  unfold canon.parse_array
  step as ⟨r, hr⟩
  cases r with
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, Adv]
  | Ok j =>
    obtain ⟨hj1, hj2⟩ := hr j rfl
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step*
    all_goals try (simp only [Adv]; done)
    all_goals simp only [Adv]
    all_goals first
      | scalar_tac
      | (obtain ⟨hb, _⟩ := b_post (by assumption); scalar_tac)
termination_by 4 * (s.length - i.val) + 1
decreasing_by all_goals parse_decreasing

theorem parse_object_loop_spec (hnfc : NfcFits) (s : Slice Std.U8) (depth i : Std.Usize)
    (members : alloc.vec.Vec (String × canon.CanonValue))
    (units : alloc.vec.Vec (alloc.vec.Vec Std.U16)) (starts : alloc.vec.Vec Std.Usize)
    (keys : alloc.vec.Vec String) (fault : Option canon.ParseError) (op : Bool)
    (hi : i.val ≤ s.length) (hd : depth.val < 256) (hinv : ObjInv i.val members units starts keys) :
    canon.parse_object_loop s depth i members units starts keys fault op ⦃ (j, m', u', st', k', _) =>
      i.val ≤ j.val ∧ j.val ≤ s.length ∧ ObjInv j.val m' u' st' k' ⦄ := by
  obtain ⟨hk, hu, hs, hm⟩ := hinv
  unfold canon.parse_object_loop
  step*
  any_goals (rename_i p hp; obtain ⟨key, j⟩ := p; rw [hp] at r_post; simp only [StrOk] at r_post
             obtain ⟨hj1, hj2, x, hx⟩ := r_post; have hkb := hnfc x; rw [← hx] at hkb
             step*)
  any_goals (obtain ⟨v, j2⟩ := p1; rename_i hp; rw [hp] at r2_post; simp only [Adv] at r2_post
             step*)
  all_goals (simp_all only [ObjInv, alloc.vec.Vec.length, List.length_append,
    List.length_singleton]; try scalar_tac)
termination_by 4 * (s.length - i.val) + (if op then 3 else 0)
decreasing_by all_goals parse_decreasing

theorem parse_object_spec (hnfc : NfcFits) (s : Slice Std.U8) (i depth : Std.Usize) :
    canon.parse_object s i depth ⦃ r => Adv s i r ⦄ := by
  have hmd : canon.MAX_DEPTH.val = 256 := max_depth_val
  unfold canon.parse_object
  step as ⟨r, hr⟩
  cases r with
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, Adv]
  | Ok j =>
    obtain ⟨hj1, hj2⟩ := hr j rfl
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step*
    all_goals try (simp only [Adv]; done)
    all_goals first
      | (simp [ObjInv, alloc.vec.Vec.new]; done)
      | (simp only [Adv]; scalar_tac)
      | (obtain ⟨hb, _⟩ := b_post (by assumption); simp only [Adv]; scalar_tac)

termination_by 4 * (s.length - i.val) + 1
decreasing_by all_goals parse_decreasing

end

@[step]
theorem digit_at_spec (s : Slice Std.U8) (i : Std.Usize) :
    canon.digit_at s i ⦃ r => r = true → i.val < s.length ⦄ := by
  unfold canon.digit_at; step*

@[step]
theorem finish_top_level_spec (s : Slice Std.U8) (i : Std.Usize)
    (hi : i.val ≤ s.length) : canon.finish_top_level s i ⦃ _ => True ⦄ := by
  unfold canon.finish_top_level
  step*

@[step]
theorem parse_top_level_general_spec (hnfc : NfcFits) (p : canon.Parser)
    (hi : p.i.val ≤ p.s.length) :
    canon.parse_top_level_general p ⦃ (_, p') => p'.s = p.s ∧ p'.i.val ≤ p.s.length ⦄ := by
  unfold canon.parse_top_level_general
  have := parse_value_spec hnfc
  step*
  obtain ⟨v, j⟩ := p1
  have := adv_ok r_post (by assumption)
  exact WP.spec.ret ⟨rfl, this.2⟩

@[step]
theorem parse_document_spec (hnfc : NfcFits) (input : Str) :
    canon.parse_document input ⦃ _ => True ⦄ := by
  unfold canon.parse_document
  simp only [core.str.Str.as_bytes, bind_tc_ok]
  step*
  all_goals (obtain ⟨v, j⟩ := p; have := adv_ok r_post (by assumption); step*)

/-- **The production parser always returns.** For every input (any byte string, any length;
Aeneas' `Str`), `parse_document`, the body of `CanonValue::parse_typed` and so of
`CanonValue::parse`, evaluates to `ok`: an `Ok` value or an `Err` parse error. It never panics,
never overflows an integer, never indexes out of bounds, never exceeds `usize::MAX` elements in a
vector, and terminates. The one hypothesis, `NfcFits`, is Rust's `String` invariant for the values
the trusted NFC primitive returns. -/
theorem parse_document_total (hnfc : NfcFits) (input : Str) :
    ∃ r, canon.parse_document input = ok r := by
  obtain ⟨r, h, _⟩ := spec_imp_exists (parse_document_spec hnfc input)
  exact ⟨r, h⟩

end Refinement.Parse
