import Refinement.Object

/-!
# The whole serializer

`write_canonical_model` — **`canon::write_canonical` refines `Canon.ser`**: if the production
serializer reports no duplicate key, the value denotes a model value and the appended bytes are
its canonical text, `utf8 (ser m)`.

`write_object_model` is the same for a top-level object with a strip list (the record and
checkpoint preimages): the model value is the object of the members whose raw key is not stripped.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core
open Averin.Canon

namespace Refinement

/-- The raw strip keys of a `&[&str]` argument. -/
def stripKeys (strip : Slice Str) : List (List Nat) := strip.val.map (fun t => vals (strSlice t).val)

/-- An object, with the members whose raw key is in `ts` removed, denotes `m`. -/
def CanonObjStrip (members : List (String × canon.CanonValue)) (ts : List (List Nat)) (m : CV) :
    Prop :=
  ∃ qs L, CanonPairs (members.filter (keptBy ts)) qs ∧ L.Perm qs ∧ KeySorted L ∧
    m = .obj (toMembers L)

theorem write_object_ok {members : alloc.vec.Vec (String × canon.CanonValue)} {strip : Slice Str}
    {out w : alloc.vec.Vec Std.U8} (hv : ValuesOk members)
    (h : canon.write_object members strip out = ok (true, w)) :
    ∃ m, CanonObjStrip members.val (stripKeys strip) m ∧
      vals w.val = vals out.val ++ Averin.utf8 (ser m) := by
  unfold canon.write_object at h
  obtain ⟨keep, hkeep, h⟩ := bind_eq_ok.mp h
  have hkv := spec_ok_eq (alloc.vec.from_elem_spec core.clone.CloneBool true _ rfl) hkeep
  obtain ⟨⟨s, back⟩, hs, h⟩ := bind_eq_ok.mp h
  simp [alloc.vec.Vec.deref_mut] at hs; obtain ⟨rfl, rfl⟩ := hs
  obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
  have hsl : keep.slice.val.length = members.val.length := by
    have : keep.slice.val = keep.val := rfl
    rw [this, hkv.1]; simp
  have hs1v := unmark_stripped_ok _ members strip 0#usize keep.slice s1 rfl hsl hs1
  have hs1v' : s1.val = members.val.map (keptBy (stripKeys strip)) := by
    rw [hs1v]
    have : keep.slice.val = List.replicate members.val.length true := by
      have e : keep.slice.val = keep.val := rfl
      rw [e, hkv.1]; simp
    rw [this]
    simp only [show (0#usize : Std.Usize).val = 0 from rfl, List.drop_zero, stripKeys]
    generalize members.val = l
    induction l with
    | nil => simp
    | cons p l ih => simp [List.replicate_succ, ih]
  have hl2 : (alloc.vec.Vec.deref ({ slice := s1 } : alloc.vec.Vec Bool)).val.length =
      members.val.length := by
    have : (alloc.vec.Vec.deref ({ slice := s1 } : alloc.vec.Vec Bool)).val = s1.val := by
      simp [alloc.vec.Vec.deref, alloc.vec.Vec.val]
    rw [this, hs1v']; simp
  obtain ⟨qs, L, hq, hp, hsrt, hb⟩ := write_members_ok hl2 hv h
  have hkf : keepFilter members (alloc.vec.Vec.deref ({ slice := s1 } : alloc.vec.Vec Bool)).val =
      members.val.filter (keptBy (stripKeys strip)) := by
    have : (alloc.vec.Vec.deref ({ slice := s1 } : alloc.vec.Vec Bool)).val =
        members.val.map (keptBy (stripKeys strip)) := by
      simp [alloc.vec.Vec.deref, alloc.vec.Vec.val, hs1v']
    rw [this, keepFilter_map]
  rw [hkf] at hq
  exact ⟨_, ⟨qs, L, hq, hp, hsrt, rfl⟩, hb⟩

theorem write_array_loop_ok : ∀ (k : Nat) (items : Slice canon.CanonValue)
    (out w : alloc.vec.Vec Std.U8) (unique u : Bool) (i : Std.Usize),
    items.val.length - i.val = k →
    (∀ x ∈ items.val, ∀ (out w : alloc.vec.Vec Std.U8), canon.write_canonical x out = ok (true, w) →
      ∃ m, Canon x m ∧ vals w.val = vals out.val ++ Averin.utf8 (ser m)) →
    canon.write_array_loop items out unique i = ok (w, u) → u = true →
    unique = true ∧ ∃ xs, CanonElems (items.val.drop i.val) xs ∧
      vals w.val = vals out.val ++ Averin.utf8 (serElems (toCVs xs) (decide (i.val = 0))) := by
  intro k
  induction k with
  | zero =>
    intro items out w unique u i hk hx h hu
    unfold canon.write_array_loop at h
    dsimp only at h
    split at h
    · rename_i hlt; have : i.val < items.val.length := by scalar_tac
      omega
    · simp at h; obtain ⟨rfl, rfl⟩ := h
      refine ⟨hu, [], ?_, by simp [toCVs, serElems]⟩
      have : items.val.drop i.val = [] := by simp; omega
      rw [this]; exact CanonElems.nil
  | succ k ih =>
    intro items out w unique u i hk hx h hu
    unfold canon.write_array_loop at h
    dsimp only at h
    split at h
    · rename_i hlt
      have hi : i.val < items.val.length := by scalar_tac
      obtain ⟨out1, ho1, h⟩ := bind_eq_ok.mp h
      obtain ⟨cv, hcv, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, hcvv⟩ := slice_index_ok hcv
      obtain ⟨⟨b, out2⟩, hw, h⟩ := bind_eq_ok.mp h
      obtain ⟨unique1, hu1, h⟩ := bind_eq_ok.mp h
      obtain ⟨i2, hi2, h⟩ := bind_eq_ok.mp h
      have hi2v := uadd_ok hi2; simp at hi2v
      obtain ⟨r1, xs, r2, r3⟩ := ih items out2 w unique1 u i2 (by omega) hx h hu
      subst r1
      have hbt : b = true ∧ unique = true := by
        cases b
        · simp at hu1
        · simp at hu1; exact ⟨rfl, hu1⟩
      obtain ⟨rfl, rfl⟩ := hbt
      obtain ⟨m, hm, hmv⟩ := hx cv (by rw [hcvv]; exact List.getElem_mem hi) out1 out2 hw
      refine ⟨rfl, m :: xs, ?_, ?_⟩
      · rw [List.drop_eq_getElem_cons hi, ← hcvv, ← hi2v]
        exact CanonElems.cons hm r2
      · rw [r3, hmv]
        have ho1v : vals out1.val = vals out.val ++ (if 0 < i.val then [44] else []) := by
          split at ho1
          · rename_i hpos
            have : 0 < i.val := by scalar_tac
            rw [push_ok ho1]; simp [this]
          · rename_i hz
            have : ¬ 0 < i.val := by scalar_tac
            simp at ho1; subst ho1; simp [this]
        rw [ho1v, hi2v]
        simp only [toCVs, serElems, utf8_append]
        by_cases hz : i.val = 0
        · simp [hz]
        · have : 0 < i.val := by omega
          simp [hz, this, utf8_cons, enc_ascii]
    · rename_i hge; have : ¬ i.val < items.val.length := by scalar_tac
      omega

/-- **`write_canonical` refines `ser`.** -/
theorem write_canonical_model : ∀ (n : Nat) (v : canon.CanonValue), sizeOf v = n →
    ∀ (out w : alloc.vec.Vec Std.U8), canon.write_canonical v out = ok (true, w) →
    ∃ m, Canon v m ∧ vals w.val = vals out.val ++ Averin.utf8 (ser m) := by
  intro n
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    intro v hn out w h
    unfold canon.write_canonical at h
    split at h
    · -- null
      obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
      simp only [lift_eq_ok] at hs; subst hs
      obtain ⟨o, ho, h⟩ := bind_eq_ok.mp h
      have hw : o = w := (Prod.mk.inj (Result.ok_injective h)).2
      subst hw
      refine ⟨.null, Canon.null, ?_⟩
      rw [extend_u8_ok ho]
      simp [Std.Array.to_slice, ser, utf8_cons, enc_ascii]
    · -- bool
      rename_i b
      split at h
      · rename_i hb
        obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
        simp only [lift_eq_ok] at hs; subst hs
        obtain ⟨o, ho, h⟩ := bind_eq_ok.mp h
        have hw : o = w := (Prod.mk.inj (Result.ok_injective h)).2
        subst hw
        subst hb
        refine ⟨.bool true, Canon.bool true, ?_⟩
        rw [extend_u8_ok ho]
        simp [Std.Array.to_slice, ser, utf8_cons, enc_ascii]
      · rename_i hb
        obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
        simp only [lift_eq_ok] at hs; subst hs
        obtain ⟨o, ho, h⟩ := bind_eq_ok.mp h
        have hw : o = w := (Prod.mk.inj (Result.ok_injective h)).2
        subst hw
        simp at hb; subst hb
        refine ⟨.bool false, Canon.bool false, ?_⟩
        rw [extend_u8_ok ho]
        simp [Std.Array.to_slice, ser, utf8_cons, enc_ascii]
    · -- int
      rename_i k
      obtain ⟨o, ho, h⟩ := bind_eq_ok.mp h
      have hw : o = w := (Prod.mk.inj (Result.ok_injective h)).2
      subst hw
      exact ⟨.int k.val, Canon.int k, by rw [write_int_model ho]; rfl⟩
    · -- string
      rename_i s
      obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
      obtain ⟨s2, hs2, h⟩ := bind_eq_ok.mp h
      obtain ⟨s3, hs3, h⟩ := bind_eq_ok.mp h
      obtain ⟨o, ho, h⟩ := bind_eq_ok.mp h
      have hw : o = w := (Prod.mk.inj (Result.ok_injective h)).2
      subst hw
      have hnfc : NfcOf s s2 := ⟨s1, hs1, by simpa [canon.nfc] using hs2⟩
      exact ⟨.str s2.toList, Canon.str s s2 hnfc, escape_into_model (stringSlice_ok hs3) ho⟩
    · -- array
      rename_i items
      unfold canon.write_array at h
      obtain ⟨o1, ho1, h⟩ := bind_eq_ok.mp h
      obtain ⟨⟨o2, u⟩, ho2, h⟩ := bind_eq_ok.mp h
      obtain ⟨o3, ho3, h⟩ := bind_eq_ok.mp h
      simp at h; obtain ⟨rfl, rfl⟩ := h
      have hitems : (alloc.vec.Vec.deref items).val = items.val := by
        simp [alloc.vec.Vec.deref]
      obtain ⟨_, xs, hxs, hbytes⟩ := write_array_loop_ok _ (alloc.vec.Vec.deref items) o1 o2 true
        true 0#usize rfl (by
          intro x hx out' w' hw'
          rw [hitems] at hx
          exact ih _ (hn ▸ sizeOf_item hx) x rfl out' w' hw') ho2 rfl
      simp only [show (0#usize : Std.Usize).val = 0 from rfl, List.drop_zero, decide_true,
        hitems] at hxs hbytes
      refine ⟨.arr (toCVs xs), Canon.arr items xs hxs, ?_⟩
      rw [push_ok ho3]
      simp only [vals, List.map_append] at hbytes ⊢
      rw [hbytes, push_ok ho1]
      simp [ser, utf8_cons, utf8_append, enc_ascii]
    · -- object
      rename_i members
      obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
      simp at hs; subst hs
      obtain ⟨m, ⟨qs, L, hq, hp, hsrt, rfl⟩, hb⟩ := write_object_ok (by
        intro p hp out' w' hw'
        exact ih _ (hn ▸ sizeOf_member (k := p.1) (by simpa using hp)) p.2 rfl out' w' hw') h
      have hall : members.val.filter (keptBy (stripKeys (Std.Array.empty Str).to_slice)) =
          members.val := by
        apply List.filter_eq_self.mpr
        intro p _
        simp [keptBy, stripKeys, Std.Array.to_slice, Std.Array.empty]
      rw [hall] at hq
      exact ⟨_, Canon.obj members qs L hq hp hsrt, hb⟩

end Refinement
