import Refinement.Spec

/-!
# The object-member helpers of the serializer

`unmark_stripped` (which members a preimage strips), `write_members`' first loop (NFC keys, their
UTF-16 sort keys and member indices of the kept members), and the equality tests the serializer
uses.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core

namespace Refinement

theorem slice_eq_u8_ok {a b : Slice Std.U8} {r : Bool}
    (h : core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b = ok r) :
    r = decide (vals a.val = vals b.val) := by
  have := spec_ok_eq (core.slice.cmp.PartialEqSlice.eq_homo_spec core.cmp.PartialEqU8 a b
    (fun x y => by simp)) h
  have hv : a = b ↔ vals a.val = vals b.val := by
    rw [Slice.eq_iff]
    constructor
    · intro e; rw [e]
    · intro e
      exact List.map_injective_iff.mpr (fun x y hxy => UScalar.eq_of_val_eq hxy) e
  cases r <;> simp_all

theorem allM_eq_ok : ∀ (l : List (Std.U16 × Std.U16)) (r : Bool),
    List.allM (fun (x : Std.U16 × Std.U16) => core.cmp.PartialEqU16.eq x.1 x.2) l = ok r →
    r = l.all (fun x => decide (x.1 = x.2))
  | [], r, h => by
    have h' : (ok true : Result Bool) = ok r := h
    simp at h'; simp [h']
  | x :: l, r, h => by
    simp only [List.allM] at h
    obtain ⟨b, hb, h⟩ := bind_eq_ok.mp h
    simp only [liftFun2, ok_eq_ok] at hb; subst hb
    split at h
    · rename_i hb
      rw [allM_eq_ok l r h]
      simp_all
    · rename_i hb
      have h' : (ok false : Result Bool) = ok r := h
      simp at h'; subst h'
      simp_all

theorem zip_self_mem {α} {l : List α} {x : α × α} (h : x ∈ l.zip l) : x.1 = x.2 := by
  obtain ⟨n, hn, hx⟩ := List.mem_iff_getElem.mp h
  simp at hx hn
  rw [← hx]

theorem vec_eq_u16_ok {a b : alloc.vec.Vec Std.U16} {r : Bool}
    (h : alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU16 a b = ok r) :
    r = decide (vals a.val = vals b.val) := by
  unfold alloc.vec.partial_eq.PartialEqVec.eq at h
  have inj : ∀ {x y : List Std.U16}, vals x = vals y → x = y := fun e =>
    List.map_injective_iff.mpr (fun x y hxy => UScalar.eq_of_val_eq hxy) e
  split at h
  · rename_i hlen
    have := allM_eq_ok _ r h
    subst this
    by_cases hab : vals a.val = vals b.val
    · have e := inj hab
      simp only [hab, decide_true]
      apply List.all_eq_true.mpr
      intro x hx
      rw [e] at hx
      simp [zip_self_mem hx]
    · simp only [hab, decide_false]
      apply Bool.eq_false_iff.mpr
      intro hall
      apply hab
      have hl : a.val.length = b.val.length := by simpa using hlen
      congr 1
      apply List.ext_getElem hl
      intro n h1 h2
      have := List.all_eq_true.mp hall (a.val[n], b.val[n])
        (List.mem_iff_getElem.mpr ⟨n, by simp; omega, by simp⟩)
      simpa using this
  · rename_i hlen
    have h' : (ok false : Result Bool) = ok r := h
    simp at h'; subst h'
    rw [eq_comm, decide_eq_false_iff_not]
    intro e
    apply hlen
    have := congrArg List.length e
    simpa using this

/-! ## Stripped members -/

/-- Whether member `p`'s raw key is the byte string `t` (as `unmark_key` compares it). -/
def keyIs (t : List Nat) (p : String × canon.CanonValue) : Prop := Averin.utf8 p.1.toList = t

noncomputable instance (t : List Nat) (p : String × canon.CanonValue) : Decidable (keyIs t p) :=
  inferInstanceAs (Decidable (_ = _))

theorem set_take_succ {α} : ∀ (l : List α) (j : Nat), j < l.length → ∀ x : α,
    (l.set j x).take (j + 1) = l.take j ++ [x]
  | [], _, h, _ => by simp at h
  | a :: l, 0, _, x => by simp
  | a :: l, j + 1, h, x => by
    simp only [List.set_cons_succ, List.take_succ_cons, List.cons_append]
    rw [set_take_succ l j (by simpa using h) x]

theorem set_drop_succ {α} : ∀ (l : List α) (j : Nat) (x : α),
    (l.set j x).drop (j + 1) = l.drop (j + 1)
  | [], _, _ => by simp
  | a :: l, 0, x => by simp
  | a :: l, j + 1, x => by
    simp only [List.set_cons_succ, List.drop_succ_cons]
    exact set_drop_succ l j x

theorem unmark_key_loop_ok : ∀ (m : Nat) (members : alloc.vec.Vec (String × canon.CanonValue))
    (key : Slice Std.U8) (keep keep' : Slice Bool) (j : Std.Usize),
    members.val.length - j.val = m → keep.val.length = members.val.length →
    canon.unmark_key_loop members key keep j = ok keep' →
    keep'.val = keep.val.take j.val ++
      List.zipWith (fun b p => b && !decide (keyIs (vals key.val) p))
        (keep.val.drop j.val) (members.val.drop j.val) := by
  intro m
  induction m with
  | zero =>
    intro members key keep keep' j hm hl h
    unfold canon.unmark_key_loop at h
    dsimp only at h
    split at h
    · rename_i hlt; have : j.val < members.val.length := by scalar_tac
      omega
    · simp at h; subst h
      have : members.val.drop j.val = [] := by simp; omega
      simp [this]; omega
  | succ m ih =>
    intro members key keep keep' j hm hl h
    unfold canon.unmark_key_loop at h
    dsimp only at h
    split at h
    · rename_i hlt
      have hj : j.val < members.val.length := by scalar_tac
      obtain ⟨⟨k, v⟩, hkv, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, hkv⟩ := vec_index_ok hkv
      obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
      have hs1v := stringSlice_ok hs1
      obtain ⟨b, hb, h⟩ := bind_eq_ok.mp h
      have hbv := slice_eq_u8_ok hb
      obtain ⟨keep1, hk1, h⟩ := bind_eq_ok.mp h
      obtain ⟨j1, hj1, h⟩ := bind_eq_ok.mp h
      have hj1v := uadd_ok hj1; simp at hj1v
      have hkeep1 : keep1.val = keep.val.set j.val (keep.val[j.val]'(by omega) && !b) := by
        split at hk1
        · rename_i hbt
          have := spec_ok_eq (Slice.update_spec keep j false (by simpa using (show j.val < keep.val.length by omega))) hk1
          subst this; simp [hbt]
        · rename_i hbf
          simp at hk1; subst hk1
          simp [hbf]
      have hl1 : keep1.val.length = members.val.length := by rw [hkeep1]; simp [hl]
      rw [ih members key keep1 keep' j1 (by omega) hl1 h, hkeep1, hj1v]
      rw [List.drop_eq_getElem_cons (l := keep.val) (by omega),
        List.drop_eq_getElem_cons (l := members.val) hj, List.zipWith_cons_cons]
      have hkey : (members.val[j.val]) = (k, v) := hkv.symm
      rw [hkey, hbv]
      simp only [keyIs, hs1v]
      rw [set_take_succ _ _ (by omega), set_drop_succ]
      simp
      rfl
    · rename_i hge; have : ¬ j.val < members.val.length := by scalar_tac
      omega

/-- A `&str` is its UTF-8 bytes (`Str := Slice U8` in Aeneas). -/
def strSlice (t : Str) : Slice Std.U8 := t

/-- The members `unmark_stripped` keeps: those whose raw key is none of the strip keys. -/
noncomputable def keptBy (ts : List (List Nat)) (p : String × canon.CanonValue) : Bool :=
  decide (∀ t ∈ ts, ¬ keyIs t p)

theorem zipWith_compose {α} (f g : Bool → α → Bool) :
    ∀ (keep : List Bool) (ms : List α), keep.length = ms.length →
    List.zipWith f (List.zipWith g keep ms) ms = List.zipWith (fun b p => f (g b p) p) keep ms
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | b :: keep, p :: ms, h => by
    simp only [List.zipWith_cons_cons]
    rw [zipWith_compose f g keep ms (by simpa using h)]

theorem zipWith_fst {α} : ∀ (keep : List Bool) (ms : List α), keep.length = ms.length →
    List.zipWith (fun b _ => b) keep ms = keep
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | b :: keep, p :: ms, h => by
    simp only [List.zipWith_cons_cons]
    rw [zipWith_fst keep ms (by simpa using h)]

theorem unmark_stripped_ok : ∀ (m : Nat) (members : alloc.vec.Vec (String × canon.CanonValue))
    (strip : Slice Str) (i : Std.Usize) (keep keep' : Slice Bool),
    strip.val.length - i.val = m → keep.val.length = members.val.length →
    canon.unmark_stripped members strip i keep = ok keep' →
    keep'.val = List.zipWith (fun b p => b && keptBy ((strip.val.drop i.val).map (fun t => vals (strSlice t).val)) p)
      keep.val members.val := by
  intro m
  induction m with
  | zero =>
    intro members strip i keep keep' hm hl h
    unfold canon.unmark_stripped at h
    dsimp only at h
    split at h
    · rename_i hlt; have : i.val < strip.val.length := by scalar_tac
      omega
    · simp at h; subst h
      have : strip.val.drop i.val = [] := by simp; omega
      simp only [this, List.map_nil, keptBy, List.not_mem_nil, false_imp_iff, imp_true_iff,
        decide_true, Bool.and_true]
      exact (zipWith_fst _ _ hl).symm
  | succ m ih =>
    intro members strip i keep keep' hm hl h
    unfold canon.unmark_stripped at h
    dsimp only at h
    split at h
    · rename_i hlt
      have hi : i.val < strip.val.length := by scalar_tac
      obtain ⟨t, ht, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, htv⟩ := slice_index_ok ht
      obtain ⟨t1, ht1, h⟩ := bind_eq_ok.mp h
      have ht1' : t1 = strSlice t := by simp [core.str.Str.as_bytes] at ht1; rw [← ht1]; rfl
      obtain ⟨keep1, hk1, h⟩ := bind_eq_ok.mp h
      obtain ⟨i2, hi2, h⟩ := bind_eq_ok.mp h
      have hi2v := uadd_ok hi2; simp at hi2v
      have hk1v := unmark_key_loop_ok _ members t1 keep keep1 0#usize rfl hl hk1
      simp only [show (0#usize : Std.Usize).val = 0 from rfl, List.take_zero, List.drop_zero,
        List.nil_append] at hk1v
      have hl1 : keep1.val.length = members.val.length := by rw [hk1v]; simp [hl]
      rw [ih members strip i2 keep1 keep' (by omega) hl1 h, hk1v,
        zipWith_compose _ _ _ _ hl]
      congr 1
      funext b p
      rw [List.drop_eq_getElem_cons hi, ← htv, ht1']
      simp only [keptBy, List.map_cons, List.mem_cons, forall_eq_or_imp, hi2v]
      cases b <;> simp [Bool.decide_and]
    · rename_i hge; have : ¬ i.val < strip.val.length := by scalar_tac
      omega

end Refinement
