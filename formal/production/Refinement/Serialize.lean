import Refinement.Members

/-!
# `canon::write_canonical` refines `Canon.ser`

`write_canonical_model`: whenever the production serializer returns `true` (no duplicate key after
NFC anywhere), the value it serialized denotes a model value `m` (`Canon v m`) and the appended
bytes are exactly `utf8 (ser m)`. The same holds for `write_object` with a strip list, which the
record and checkpoint preimages use.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core
open Averin.Canon

namespace Refinement

/-- The kept members' NFC keys, as produced by `write_members`' first loop. -/
structure Entry where
  idx : Nat
  key : String

theorem loop0_ok : ∀ (m : Nat) (members : alloc.vec.Vec (String × canon.CanonValue))
    (keep : Slice Bool) (keys : alloc.vec.Vec String) (units : alloc.vec.Vec (alloc.vec.Vec Std.U16))
    (src : alloc.vec.Vec Std.Usize) (i : Std.Usize) keys' units' src',
    members.val.length - i.val = m → keep.val.length = members.val.length →
    canon.write_members_loop0 members keep keys units src i = ok (keys', units', src') →
    ∃ es : List Entry,
      es.map Entry.idx = (List.range' i.val (members.val.length - i.val)).filter
        (fun j => keep.val[j]!) ∧
      (∀ e ∈ es, ∃ h : e.idx < members.val.length, NfcOf (members.val[e.idx]).1 e.key) ∧
      keys'.val = keys.val ++ es.map Entry.key ∧
      src'.val.map (·.val) = src.val.map (·.val) ++ es.map Entry.idx ∧
      units'.val.map (fun u => vals u.val) =
        units.val.map (fun u => vals u.val) ++ es.map (fun e => utf16Units e.key.toList) := by
  intro m
  induction m with
  | zero =>
    intro members keep keys units src i keys' units' src' hm hl h
    unfold canon.write_members_loop0 at h
    dsimp only at h
    split at h
    · rename_i hlt; have : i.val < members.val.length := by scalar_tac
      omega
    · simp at h; obtain ⟨rfl, rfl, rfl⟩ := h
      refine ⟨[], ?_, by simp, by simp, by simp, by simp⟩
      have : members.val.length - i.val = 0 := by omega
      simp [this]
  | succ m ih =>
    intro members keep keys units src i keys' units' src' hm hl h
    unfold canon.write_members_loop0 at h
    dsimp only at h
    split at h
    · rename_i hlt
      have hi : i.val < members.val.length := by scalar_tac
      obtain ⟨b, hb, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, hbv⟩ := slice_index_ok hb
      obtain ⟨⟨keys1, units1, src1⟩, h1, h⟩ := bind_eq_ok.mp h
      obtain ⟨i2, hi2, h⟩ := bind_eq_ok.mp h
      have hi2v := uadd_ok hi2; simp at hi2v
      obtain ⟨es, e1, e2, e3, e4, e5⟩ := ih members keep keys1 units1 src1 i2 keys' units' src'
        (by omega) hl h
      have hrange : List.range' i.val (members.val.length - i.val) =
          i.val :: List.range' i2.val (members.val.length - i2.val) := by
        rw [hi2v]
        have : members.val.length - i.val = (members.val.length - (i.val + 1)) + 1 := by omega
        rw [this, List.range'_succ]
      have hkb : keep.val[i.val]! = b := by
        rw [getElem!_pos keep.val i.val (by omega)]; exact hbv.symm
      split at h1
      · rename_i hbt
        obtain ⟨⟨k, v⟩, hkv, h1⟩ := bind_eq_ok.mp h1
        obtain ⟨_, hkv⟩ := vec_index_ok hkv
        obtain ⟨s1, hs1, h1⟩ := bind_eq_ok.mp h1
        obtain ⟨key, hkey, h1⟩ := bind_eq_ok.mp h1
        obtain ⟨s2, hs2, h1⟩ := bind_eq_ok.mp h1
        obtain ⟨v1, hv1, h1⟩ := bind_eq_ok.mp h1
        obtain ⟨units2, hu2, h1⟩ := bind_eq_ok.mp h1
        obtain ⟨keys2, hk2, h1⟩ := bind_eq_ok.mp h1
        obtain ⟨src2, hs2', h1⟩ := bind_eq_ok.mp h1
        simp at h1; obtain ⟨rfl, rfl, rfl⟩ := h1
        have hnfc : NfcOf k key := ⟨s1, hs1, by simpa [canon.nfc] using hkey⟩
        have hunits : vals v1.val = utf16Units key.toList :=
          utf16_units_model (stringSlice_ok hs2) hv1
        refine ⟨⟨i.val, key⟩ :: es, ?_, ?_, ?_, ?_, ?_⟩
        · rw [hrange, List.filter_cons, hkb, hbt]; simp [e1]
        · intro e he
          simp only [List.mem_cons] at he
          rcases he with rfl | he
          · exact ⟨hi, by rw [← hkv]; exact hnfc⟩
          · exact e2 e he
        · rw [e3, push_ok hk2]; simp
        · rw [e4, push_ok hs2']; simp
        · rw [e5, push_ok hu2]; simp [hunits]
      · rename_i hbf
        simp at h1; obtain ⟨rfl, rfl, rfl⟩ := h1
        refine ⟨es, ?_, e2, e3, e4, e5⟩
        rw [hrange, List.filter_cons, hkb]; simp [hbf, e1]
    · rename_i hge; have : ¬ i.val < members.val.length := by scalar_tac
      omega

/-- Member `i` (a default out of range, which the extracted code never reaches). -/
def memAt (members : alloc.vec.Vec (String × canon.CanonValue)) (i : Nat) :
    String × canon.CanonValue :=
  members.val.getD i ("", .Null)

/-- The model member written for sort position `t`: its NFC key and its value's denotation. -/
noncomputable def entryF (members : alloc.vec.Vec (String × canon.CanonValue))
    (keys : alloc.vec.Vec String) (src : alloc.vec.Vec Std.Usize) (t : Nat) : List Char × CV :=
  ((keys.val.getD t "").toList, mOf (memAt members (src.val.getD t 0#usize).val).2)

/-- The code units stored for sort position `t`. -/
def unitsAt (units : alloc.vec.Vec (alloc.vec.Vec Std.U16)) (t : Nat) : List Nat :=
  vals (units.val.getD t (alloc.vec.Vec.new Std.U16)).val

/-- Serializing any member value is correct (supplied by the induction on value size). -/
def ValuesOk (members : alloc.vec.Vec (String × canon.CanonValue)) : Prop :=
  ∀ p ∈ members.val, ∀ (out w : alloc.vec.Vec Std.U8),
    canon.write_canonical p.2 out = ok (true, w) →
    ∃ m, Canon p.2 m ∧ vals w.val = vals out.val ++ Averin.utf8 (ser m)

theorem utf8_comma_colon : Averin.utf8 [','] = [44] ∧ Averin.utf8 [':'] = [58] ∧
    Averin.utf8 ['{'] = [123] ∧ Averin.utf8 ['}'] = [125] ∧
    Averin.utf8 ['['] = [91] ∧ Averin.utf8 [']'] = [93] := by
  simp [utf8_cons, enc_ascii]

theorem utf8_serMembers_cons (k : List Char) (v : CV) (ms : Members) (first : Bool) :
    Averin.utf8 (serMembers (.cons k v ms) first) =
      (if first then [] else [44]) ++ Averin.utf8 (serStr k) ++ [58] ++ Averin.utf8 (ser v) ++
        Averin.utf8 (serMembers ms false) := by
  rw [serMembers]
  simp only [utf8_append, utf8_cons, List.append_assoc]
  cases first <;> simp [utf8_cons, enc_ascii]

theorem loop1_ok : ∀ (k : Nat) (members : alloc.vec.Vec (String × canon.CanonValue))
    (out : alloc.vec.Vec Std.U8) (keys : alloc.vec.Vec String)
    (units : alloc.vec.Vec (alloc.vec.Vec Std.U16)) (src order : alloc.vec.Vec Std.Usize)
    (unique : Bool) (n : Std.Usize) (w : alloc.vec.Vec Std.U8) (u : Bool),
    order.val.length - n.val = k → ValuesOk members →
    canon.write_members_loop1 members out keys units src order unique n = ok (w, u) → u = true →
    unique = true ∧
    (∀ t ∈ order.val.drop n.val, t.val < keys.val.length ∧ t.val < src.val.length ∧
      (src.val.getD t.val 0#usize).val < members.val.length ∧
      Canon (memAt members (src.val.getD t.val 0#usize).val).2
        (mOf (memAt members (src.val.getD t.val 0#usize).val).2)) ∧
    vals w.val = vals out.val ++ Averin.utf8 (serMembers (toMembers
      ((order.val.drop n.val).map (fun t => entryF members keys src t.val))) (decide (n.val = 0))) ∧
    (∀ t, 0 < t → n.val ≤ t → (ht : t < order.val.length) →
      unitsAt units (order.val[t - 1]).val ≠ unitsAt units (order.val[t]).val) := by
  intro k
  induction k with
  | zero =>
    intro members out keys units src order unique n w u hk hv h hu
    unfold canon.write_members_loop1 at h
    dsimp only at h
    split at h
    · rename_i hlt; have : n.val < order.val.length := by scalar_tac
      omega
    · simp at h; obtain ⟨rfl, rfl⟩ := h
      have hd : order.val.drop n.val = [] := by simp; omega
      refine ⟨hu, by simp [hd], by simp [hd, toMembers, serMembers], ?_⟩
      intro t _ ht1 ht2; omega
  | succ k ih =>
    intro members out keys units src order unique n w u hk hv h hu
    unfold canon.write_members_loop1 at h
    dsimp only at h
    split at h
    · rename_i hlt
      have hn : n.val < order.val.length := by scalar_tac
      obtain ⟨⟨out1, unique1⟩, h1, h⟩ := bind_eq_ok.mp h
      obtain ⟨i1, hi1, h⟩ := bind_eq_ok.mp h
      obtain ⟨_, hi1v⟩ := vec_index_ok hi1
      obtain ⟨s, hs, h⟩ := bind_eq_ok.mp h
      obtain ⟨hsk, hsv⟩ := vec_index_ok hs
      obtain ⟨s1, hs1, h⟩ := bind_eq_ok.mp h
      obtain ⟨out2, ho2, h⟩ := bind_eq_ok.mp h
      obtain ⟨out3, ho3, h⟩ := bind_eq_ok.mp h
      obtain ⟨i2, hi2, h⟩ := bind_eq_ok.mp h
      obtain ⟨hsrc, hi2v⟩ := vec_index_ok hi2
      obtain ⟨⟨k', cv⟩, hcv, h⟩ := bind_eq_ok.mp h
      obtain ⟨hmem, hcvv⟩ := vec_index_ok hcv
      obtain ⟨⟨b, out4⟩, hw, h⟩ := bind_eq_ok.mp h
      obtain ⟨unique2, hu2, h⟩ := bind_eq_ok.mp h
      obtain ⟨n1, hn1, h⟩ := bind_eq_ok.mp h
      have hn1v := uadd_ok hn1; simp at hn1v
      obtain ⟨r1, r2, r3, r4⟩ := ih members out4 keys units src order unique2 n1 w u
        (by omega) hv h hu
      subst r1
      have hbt : b = true ∧ unique1 = true := by
        cases b
        · simp at hu2
        · simp at hu2; exact ⟨rfl, hu2⟩
      obtain ⟨rfl, rfl⟩ := hbt
      -- the separator and the duplicate check
      have hsep : unique = true ∧ vals out1.val = vals out.val ++ (if 0 < n.val then [44] else []) ∧
          (0 < n.val → unitsAt units (order.val[n.val - 1]'(by omega)).val ≠
            unitsAt units (order.val[n.val]).val) := by
        split at h1
        · rename_i hpos
          have hpos' : 0 < n.val := by scalar_tac
          obtain ⟨o2, ho, h1⟩ := bind_eq_ok.mp h1
          obtain ⟨j1, hj1, h1⟩ := bind_eq_ok.mp h1
          have hj1v := usub_ok hj1; simp at hj1v
          obtain ⟨p1, hp1, h1⟩ := bind_eq_ok.mp h1
          obtain ⟨_, hp1v⟩ := vec_index_ok hp1
          obtain ⟨v, hv', h1⟩ := bind_eq_ok.mp h1
          obtain ⟨hvl, hvv⟩ := vec_index_ok hv'
          obtain ⟨p2, hp2, h1⟩ := bind_eq_ok.mp h1
          obtain ⟨_, hp2v⟩ := vec_index_ok hp2
          obtain ⟨v1, hv1, h1⟩ := bind_eq_ok.mp h1
          obtain ⟨hv1l, hv1v⟩ := vec_index_ok hv1
          obtain ⟨bb, hbb, h1⟩ := bind_eq_ok.mp h1
          have hbbv := vec_eq_u16_ok hbb
          obtain ⟨b1, hb1, h1⟩ := bind_eq_ok.mp h1
          simp at h1; obtain ⟨rfl, rfl⟩ := h1
          have hbb' : bb = false ∧ unique = true := by
            cases bb
            · simp at hb1; exact ⟨rfl, hb1⟩
            · simp at hb1
          obtain ⟨hbbf, rfl⟩ := hbb'
          refine ⟨rfl, by rw [push_ok ho]; simp [hpos'], fun _ => ?_⟩
          rw [hbbf] at hbbv
          simp only [unitsAt]
          have e1 : order.val[n.val - 1] = p1 := by rw [hp1v]; congr 1; omega
          have e2 : order.val[n.val] = p2 := by rw [hp2v]
          rw [e1, e2, List.getD_eq_getElem _ _ hvl, List.getD_eq_getElem _ _ hv1l, ← hvv, ← hv1v]
          simpa using hbbv
        · rename_i hz
          have hz' : ¬ 0 < n.val := by scalar_tac
          simp at h1; obtain ⟨rfl, rfl⟩ := h1
          exact ⟨rfl, by simp [hz'], fun h => absurd h hz'⟩
      obtain ⟨rfl, hsep2, hsep3⟩ := hsep
      refine ⟨rfl, ?_, ?_, ?_⟩
      · -- validity of every position from `n` on
        rw [List.drop_eq_getElem_cons hn]
        intro t ht
        simp only [List.mem_cons] at ht
        rcases ht with rfl | ht
        · have ei : order.val[n.val] = i1 := hi1v.symm
          rw [ei]
          have hs2 : src.val.getD i1.val 0#usize = i2 := by
            rw [List.getD_eq_getElem _ _ hsrc, hi2v]
          rw [hs2]
          have hma : memAt members i2.val = (k', cv) := by
            unfold memAt; rw [List.getD_eq_getElem _ _ hmem]; exact hcvv.symm
          rw [hma]
          obtain ⟨m, hm, _⟩ := hv (k', cv) (by rw [hcvv]; simp) out3 out4 hw
          exact ⟨hsk, hsrc, hmem, by rw [mOf_spec hm]; exact hm⟩
        · rw [hn1v] at r2; exact r2 t ht
      · -- the bytes
        rw [r3, List.drop_eq_getElem_cons hn, List.map_cons]
        have ei : order.val[n.val] = i1 := hi1v.symm
        rw [ei]
        have hkey : (keys.val.getD i1.val "") = s := by rw [List.getD_eq_getElem _ _ hsk, hsv]
        have hs2 : src.val.getD i1.val 0#usize = i2 := by rw [List.getD_eq_getElem _ _ hsrc, hi2v]
        have hma : memAt members i2.val = (k', cv) := by
          unfold memAt; rw [List.getD_eq_getElem _ _ hmem]; exact hcvv.symm
        obtain ⟨m, hm, hwv⟩ := hv (k', cv) (by rw [hcvv]; simp) out3 out4 hw
        simp only [entryF, hkey, hs2, hma, mOf_spec hm, toMembers]
        rw [utf8_serMembers_cons, hwv, push_ok ho3]
        have e2 := escape_into_model (stringSlice_ok hs1) ho2
        simp only [vals] at e2 hsep2 ⊢
        simp only [List.map_append, List.map_cons, List.map_nil]
        rw [e2, hsep2, hn1v]
        have : decide (n.val + 1 = 0) = false := by simp
        rw [this]
        by_cases hz : n.val = 0
        · simp [hz]
        · have : 0 < n.val := by omega
          simp [hz, this]
      · intro t ht0 ht1 ht2
        by_cases hte : t = n.val
        · subst hte; exact hsep3 ht0
        · exact r4 t ht0 (by omega) ht2
    · rename_i hge
      have : ¬ n.val < order.val.length := by scalar_tac
      omega

end Refinement
