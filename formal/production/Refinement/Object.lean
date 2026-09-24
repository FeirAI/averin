import Refinement.Serialize

/-!
# `canon::write_members`: an object's canonical text

Composes the member loops with the sort: the written members are the kept members (NFC keys,
denoted values), permuted into strictly increasing RCP key order — exactly a `Canon` object.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP averin_decision_core
open Averin.Canon

namespace Refinement

theorem getElem_of_map_eq {α β γ} {f : α → γ} {g : β → γ} {l1 : List α} {l2 : List β}
    (h : l1.map f = l2.map g) (i : Nat) (h1 : i < l1.length) (h2 : i < l2.length) :
    f l1[i] = g l2[i] := by
  have := List.getElem_of_eq h (i := i) (by simpa using h1)
  simpa using this

/-- Non-decreasing with distinct neighbours is strictly increasing. -/
theorem strict_of_le_adj {α} (key : α → List Nat) : ∀ (l : List α),
    l.Pairwise (fun a b => ¬ key b < key a) →
    (∀ t (h : t + 1 < l.length), key (l[t]'(by omega)) ≠ key l[t + 1]) →
    l.Pairwise (fun a b => key a < key b)
  | [], _, _ => List.Pairwise.nil
  | [a], _, _ => by simp
  | a :: c :: rest, hle, hadj => by
    have hrest := strict_of_le_adj key (c :: rest) hle.of_cons
      (fun t h => hadj (t + 1) (by simp at h ⊢; omega))
    have hac : key a < key c := by
      have h1 : ¬ key c < key a := List.rel_of_pairwise_cons hle (by simp)
      have h2 : key a ≠ key c := hadj 0 (by simp)
      by_contra h3
      exact h2 (List.le_antisymm (List.not_lt.mp h1) (List.not_lt.mp h3))
    refine List.Pairwise.cons ?_ hrest
    intro b hb
    simp only [List.mem_cons] at hb
    rcases hb with rfl | hb
    · exact hac
    · have hcb : ¬ key b < key c := List.rel_of_pairwise_cons hle.of_cons hb
      by_contra hab
      exact (List.le_trans (List.not_lt.mp hcb) (List.not_lt.mp hab)) hac

theorem unitsAt_ukey (units : alloc.vec.Vec (alloc.vec.Vec Std.U16)) (p : Std.Usize) :
    unitsAt units p.val = ukey (alloc.vec.Vec.deref units) p := by
  simp only [unitsAt, ukey, alloc.vec.Vec.deref, Slice.from_val]
  cases h : units.val[p.val]? with
  | none =>
    rw [List.getD_eq_getElem?_getD, h]; simp
  | some v =>
    rw [List.getD_eq_getElem?_getD, h]; simp

theorem canonPairs_of_all (members : alloc.vec.Vec (String × canon.CanonValue)) :
    ∀ (es : List Entry), (∀ e ∈ es, NfcOf (memAt members e.idx).1 e.key ∧
      Canon (memAt members e.idx).2 (mOf (memAt members e.idx).2)) →
    CanonPairs (es.map (fun e => memAt members e.idx))
      (es.map (fun e => (e.key.toList, mOf (memAt members e.idx).2)))
  | [], _ => CanonPairs.nil
  | e :: es, hall => by
    have h1 := hall e (by simp)
    have h2 := canonPairs_of_all members es (fun e' he' => hall e' (by simp [he']))
    simp only [List.map_cons]
    generalize memAt members e.idx = p at h1 ⊢
    obtain ⟨k, v⟩ := p
    exact CanonPairs.cons h1.1 h1.2 h2

/-- The members whose `keep` flag is set, in insertion order. -/
def keepFilter (members : alloc.vec.Vec (String × canon.CanonValue)) (keep : List Bool) :
    List (String × canon.CanonValue) :=
  ((List.range members.val.length).filter (fun j => keep[j]!)).map (memAt members)

theorem write_members_ok {members : alloc.vec.Vec (String × canon.CanonValue)} {keep : Slice Bool}
    {out w : alloc.vec.Vec Std.U8} (hl : keep.val.length = members.val.length)
    (hv : ValuesOk members) (h : canon.write_members members keep out = ok (true, w)) :
    ∃ qs L, CanonPairs (keepFilter members keep.val) qs ∧ L.Perm qs ∧ KeySorted L ∧
      vals w.val = vals out.val ++ Averin.utf8 (ser (.obj (toMembers L))) := by
  unfold canon.write_members at h
  obtain ⟨⟨keys, units, src⟩, h0, h⟩ := bind_eq_ok.mp h
  obtain ⟨es, e1, e2, e3, e4, e5⟩ := loop0_ok _ members keep _ _ _ 0#usize keys units src rfl hl h0
  simp only [alloc.vec.Vec.new, alloc.vec.Vec.from_val, List.nil_append, List.map_nil,
    show (0#usize : Std.Usize).val = 0 from rfl, Nat.sub_zero] at e1 e3 e4 e5
  obtain ⟨pos, hpos, h⟩ := bind_eq_ok.mp h
  have hposv := positions_ok hpos
  obtain ⟨order, hord, h⟩ := bind_eq_ok.mp h
  obtain ⟨hperm, hsorted⟩ := sort_ok _ _ _ order rfl hord
  obtain ⟨out1, ho1, h⟩ := bind_eq_ok.mp h
  obtain ⟨⟨out2, uniq⟩, hl1, h⟩ := bind_eq_ok.mp h
  obtain ⟨out3, ho3, h⟩ := bind_eq_ok.mp h
  simp at h; obtain ⟨rfl, rfl⟩ := h
  obtain ⟨_, hvalid, hbytes, hadj⟩ := loop1_ok _ members out1 keys units src order true 0#usize
    out2 true rfl hv hl1 rfl
  simp only [show (0#usize : Std.Usize).val = 0 from rfl, List.drop_zero, decide_true] at hvalid hbytes hadj
  -- sizes
  have hn' : units.val.length = es.length := by
    have := congrArg List.length e5; simpa using this
  have hkeys : keys.val.length = es.length := by rw [e3]; simp
  have hsrcl : src.val.length = es.length := by
    have := congrArg List.length e4; simpa using this
  have hposl : (alloc.vec.Vec.deref pos).val.map (·.val) = List.range es.length := by
    simp only [alloc.vec.Vec.deref, Slice.from_val]; rw [hposv]; simp [hn']
  -- the entry of sort position `t`
  let G : Entry → List Char × CV := fun e => (e.key.toList, mOf (memAt members e.idx).2)
  have hF : ∀ t (ht : t < es.length), entryF members keys src t = G es[t] := by
    intro t ht
    simp only [entryF, G]
    have hk : keys.val.getD t "" = es[t].key := by
      rw [List.getD_eq_getElem _ _ (by omega)]; simp [e3]
    have hs : (src.val.getD t 0#usize).val = es[t].idx := by
      rw [List.getD_eq_getElem _ _ (by omega)]
      exact getElem_of_map_eq e4 t (by omega) ht
    rw [hk, hs]
  have hunit : ∀ p : Std.Usize, (hp : p.val < es.length) →
      ukey (alloc.vec.Vec.deref units) p = utf16Units es[p.val].key.toList := by
    intro p hp
    simp only [ukey, alloc.vec.Vec.deref, Slice.from_val]
    rw [List.getElem?_eq_getElem (by omega)]
    simp only [Option.map_some, Option.getD_some]
    exact getElem_of_map_eq e5 p.val (by omega) hp
  have hmemord : ∀ p ∈ order.val, p.val < es.length := by
    intro p hp
    have hp' := hperm.mem_iff.mp hp
    have : p.val ∈ (alloc.vec.Vec.deref pos).val.map (·.val) := List.mem_map_of_mem hp'
    rw [hposl] at this
    simpa using this
  -- the written members, in sort order
  let L := order.val.map (fun p => entryF members keys src p.val)
  refine ⟨es.map G, L, ?_, ?_, ?_, ?_⟩
  · -- the denotation of the kept members, in insertion order
    have hkf : keepFilter members keep.val = es.map (fun e => memAt members e.idx) := by
      simp only [keepFilter, List.range_eq_range', ← e1, List.map_map]
      rfl
    rw [hkf]
    have hall : ∀ e ∈ es, NfcOf (memAt members e.idx).1 e.key ∧
        Canon (memAt members e.idx).2 (mOf (memAt members e.idx).2) := by
      intro e he
      obtain ⟨t, ht, rfl⟩ := List.getElem_of_mem he
      obtain ⟨hi, hn⟩ := e2 es[t] he
      have hma : memAt members es[t].idx = members.val[es[t].idx] := by
        unfold memAt; rw [List.getD_eq_getElem _ _ hi]
      refine ⟨by rw [hma]; exact hn, ?_⟩
      -- position `t` is written somewhere in `order`
      have htpos : t ∈ (alloc.vec.Vec.deref pos).val.map (·.val) := by rw [hposl]; simpa using ht
      obtain ⟨p, hp, hpt⟩ := List.mem_map.mp htpos
      have hpo : p ∈ order.val := hperm.symm.mem_iff.mp hp
      obtain ⟨_, _, _, hc⟩ := hvalid p hpo
      have hs : (src.val.getD p.val 0#usize).val = es[t].idx := by
        have hpl := hmemord p hpo
        rw [List.getD_eq_getElem _ _ (by omega)]
        have := getElem_of_map_eq e4 p.val (by omega) hpl
        subst hpt
        exact this
      rw [hs] at hc; exact hc
    exact canonPairs_of_all members es hall
  · -- a permutation of them
    have hLpos : L.Perm (((alloc.vec.Vec.deref pos).val.map (·.val)).map
        (entryF members keys src)) := by
      rw [List.map_map]; exact hperm.map _
    refine hLpos.trans (List.Perm.of_eq ?_)
    rw [hposl]
    apply List.ext_getElem (by simp)
    intro t h1 h2
    simp only [List.getElem_map, List.getElem_range]
    exact hF t (by simpa using h1)
  · -- in strictly increasing key order
    have hstrict : order.val.Pairwise (fun p q => ukey (alloc.vec.Vec.deref units) p <
        ukey (alloc.vec.Vec.deref units) q) := by
      apply strict_of_le_adj
      · apply hsorted.imp
        intro a b hab
        simpa [keyLe] using hab
      · intro t ht
        have := hadj (t + 1) (by omega) (by omega) ht
        simp only [Nat.add_sub_cancel] at this
        rw [unitsAt_ukey, unitsAt_ukey] at this
        exact this
    simp only [KeySorted, L, List.pairwise_map]
    apply hstrict.imp_of_mem
    intro p q hp hq hpq
    have hpl := hmemord p hp
    have hql := hmemord q hq
    rw [hF _ hpl, hF _ hql]
    simp only [G, keyLt]
    rw [← hunit p hpl, ← hunit q hql]
    exact hpq
  · -- the bytes
    rw [push_ok ho3]
    simp only [vals, List.map_append] at hbytes ⊢
    rw [hbytes, push_ok ho1]
    simp only [ser, utf8_cons, utf8_append, List.map_append]
    simp [enc_ascii, L]

theorem range_filter_map_getD {α} (d : α) (f : α → Bool) : ∀ (l : List α),
    ((List.range l.length).filter (fun j => (l.map f)[j]!)).map (fun j => l.getD j d) =
      l.filter f
  | [] => by simp
  | a :: l => by
    rw [List.length_cons, List.range_succ_eq_map, List.filter_cons, List.filter_map]
    have ih := range_filter_map_getD d f l
    have e : ((fun j => ((a :: l).map f)[j]!) ∘ Nat.succ) = (fun j => (l.map f)[j]!) := by
      funext j; simp
    rw [e]
    by_cases hfa : f a = true
    · simp only [List.map_cons, getElem!_pos, List.length_cons, Nat.zero_lt_succ,
        List.getElem_cons_zero, hfa, if_true, List.map_cons, List.map_map]
      rw [List.filter_cons_of_pos hfa]
      simp only [List.getD_cons_zero, List.cons.injEq, true_and]
      rw [← ih]
      apply List.map_congr_left
      intro j _; simp
    · simp only [List.map_cons, getElem!_pos, List.length_cons, Nat.zero_lt_succ,
        List.getElem_cons_zero]
      rw [if_neg (by simpa using hfa), List.filter_cons_of_neg (by simpa using hfa),
        List.map_map, ← ih]
      apply List.map_congr_left
      intro j _; simp

theorem keepFilter_map (members : alloc.vec.Vec (String × canon.CanonValue))
    (f : String × canon.CanonValue → Bool) :
    keepFilter members (members.val.map f) = members.val.filter f := by
  simp only [keepFilter]
  exact range_filter_map_getD _ f members.val

end Refinement
