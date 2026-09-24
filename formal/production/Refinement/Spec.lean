import Refinement.Sort

/-!
# What a production value means: its canonical model value

`Canon v m` relates a production `canon::CanonValue` `v` to the model value `m : Canon.CV` it
denotes under RCP (spec/rcp-v1.md §2–§5):

* strings and object keys are NFC-normalized (`NfcOf`, through the trusted `AverinTrusted.nfc`);
* integers are the `i64` value;
* an object denotes its members **as a set**: the model member list is any permutation of the
  (NFC key, value) pairs that is strictly increasing in RCP key order (`keyLt`, UTF-16 code units).
  Strictness is the RCP §5 "no duplicate key after NFC" invariant; a value violating it anywhere
  denotes nothing.

`Canon` is a specification, not an implementation: it says nothing about how to sort.
`canon_functional` shows each value denotes at most one model value, and `canon_perm_members`
that the raw insertion order of members is irrelevant. `SemEq` (same denotation) is the semantic
equality under which the production hash is binding (`Refinement.Seal`).
-/

open Aeneas Aeneas.Std Result averin_decision_core
open Averin.Canon

namespace Refinement

/-- `r` is the NFC normalization of the Rust string `s` (`canon::nfc`, trusted). -/
def NfcOf (s r : String) : Prop :=
  ∃ sl, AverinGlue.stringSlice s = ok sl ∧ AverinTrusted.nfc sl = r

theorem nfcOf_functional {s r r' : String} (h : NfcOf s r) (h' : NfcOf s r') : r = r' := by
  obtain ⟨sl, h1, h2⟩ := h
  obtain ⟨sl', h1', h2'⟩ := h'
  rw [h1] at h1'; simp at h1'; subst h1'; rw [← h2, ← h2']

def toCVs : List CV → CVs
  | [] => .nil
  | v :: vs => .cons v (toCVs vs)

def toMembers : List (List Char × CV) → Members
  | [] => .nil
  | (k, v) :: ms => .cons k v (toMembers ms)

theorem toCVs_inj : ∀ {a b : List CV}, toCVs a = toCVs b → a = b
  | [], [], _ => rfl
  | [], _ :: _, h => by simp [toCVs] at h
  | _ :: _, [], h => by simp [toCVs] at h
  | x :: a, y :: b, h => by
    simp only [toCVs, CVs.cons.injEq] at h
    rw [h.1, toCVs_inj h.2]

theorem toMembers_inj : ∀ {a b : List (List Char × CV)}, toMembers a = toMembers b → a = b
  | [], [], _ => rfl
  | [], _ :: _, h => by simp [toMembers] at h
  | _ :: _, [], h => by simp [toMembers] at h
  | (k, x) :: a, (k', y) :: b, h => by
    simp only [toMembers, Members.cons.injEq] at h
    rw [h.1, h.2.1, toMembers_inj h.2.2]

/-- RCP §2/§5: strictly increasing keys. -/
def KeySorted (L : List (List Char × CV)) : Prop := L.Pairwise (fun a b => keyLt a.1 b.1)

mutual
/-- `v` denotes the model value `m`. -/
inductive Canon : canon.CanonValue → CV → Prop
  | null : Canon .Null .null
  | bool (b : Bool) : Canon (.Bool b) (.bool b)
  | int (n : Std.I64) : Canon (.Int n) (.int n.val)
  | str (s r : String) : NfcOf s r → Canon (.Str s) (.str r.toList)
  | arr (items : alloc.vec.Vec canon.CanonValue) (xs : List CV) :
      CanonElems items.val xs → Canon (.Array items) (.arr (toCVs xs))
  | obj (members : alloc.vec.Vec (String × canon.CanonValue)) (qs L : List (List Char × CV)) :
      CanonPairs members.val qs → L.Perm qs → KeySorted L → Canon (.Object members) (.obj (toMembers L))
/-- Elementwise `Canon`. -/
inductive CanonElems : List canon.CanonValue → List CV → Prop
  | nil : CanonElems [] []
  | cons {v m vs ms} : Canon v m → CanonElems vs ms → CanonElems (v :: vs) (m :: ms)
/-- Memberwise: NFC key and `Canon` value, in insertion order. -/
inductive CanonPairs : List (String × canon.CanonValue) → List (List Char × CV) → Prop
  | nil : CanonPairs [] []
  | cons {k r v m ps qs} : NfcOf k r → Canon v m → CanonPairs ps qs →
      CanonPairs ((k, v) :: ps) ((r.toList, m) :: qs)
end

/-! ## Sizes (for induction over nested values) -/

theorem listN_sizeOf_lt {α} [SizeOf α] : ∀ {n} (l : Data.ListN.ListN α n) {x : α},
    x ∈ l.toList → sizeOf x < sizeOf l
  | _, .nil, _, h => by simp [Data.ListN.ListN.toList] at h
  | _, .cons a l, x, h => by
    simp only [Data.ListN.ListN.toList, List.mem_cons] at h
    simp only [Data.ListN.ListN.cons.sizeOf_spec]
    rcases h with rfl | h
    · omega
    · have := listN_sizeOf_lt l h; omega

theorem vec_sizeOf_lt {α} [SizeOf α] {v : alloc.vec.Vec α} {x : α} (h : x ∈ v.val) :
    sizeOf x < sizeOf v := by
  obtain ⟨⟨n, l, b⟩⟩ := v
  simp only [alloc.vec.Vec.val, Slice.val] at h
  simp only [alloc.vec.Vec.mk.sizeOf_spec, Slice.mk.sizeOf_spec]
  have := listN_sizeOf_lt l h; omega

theorem sizeOf_item {items : alloc.vec.Vec canon.CanonValue} {x : canon.CanonValue}
    (h : x ∈ items.val) : sizeOf x < sizeOf (canon.CanonValue.Array items) := by
  simp only [canon.CanonValue.Array.sizeOf_spec]
  have := vec_sizeOf_lt h; omega

theorem sizeOf_member {members : alloc.vec.Vec (String × canon.CanonValue)} {k : String}
    {x : canon.CanonValue} (h : (k, x) ∈ members.val) :
    sizeOf x < sizeOf (canon.CanonValue.Object members) := by
  simp only [canon.CanonValue.Object.sizeOf_spec]
  have := vec_sizeOf_lt h
  simp only [Prod.mk.sizeOf_spec] at this
  omega

/-! ## Denotations are unique -/

/-- Two strictly key-sorted permutations of the same members are equal. -/
theorem keySorted_perm_eq : ∀ {L L' : List (List Char × CV)}, L.Perm L' → KeySorted L →
    KeySorted L' → L = L' := by
  intro L L' hp hs hs'
  unfold KeySorted at hs hs'
  refine List.Perm.eq_of_pairwise (le := fun a b => keyLt a.1 b.1) ?_ hs hs' hp
  intro a b _ _ h1 h2
  exact absurd (List.lt_trans h1 h2) (List.lt_irrefl _)

theorem elems_functional : ∀ {l : List canon.CanonValue} {xs xs' : List CV},
    (∀ v ∈ l, ∀ m m', Canon v m → Canon v m' → m = m') →
    CanonElems l xs → CanonElems l xs' → xs = xs'
  | [], _, _, _, h, h' => by cases h; cases h'; rfl
  | v :: l, _, _, hf, h, h' => by
    cases h with
    | cons hv hl =>
      cases h' with
      | cons hv' hl' =>
        rw [hf v (by simp) _ _ hv hv',
          elems_functional (fun w hw => hf w (by simp [hw])) hl hl']

theorem pairs_functional : ∀ {l : List (String × canon.CanonValue)} {qs qs' : List (List Char × CV)},
    (∀ p ∈ l, ∀ m m', Canon p.2 m → Canon p.2 m' → m = m') →
    CanonPairs l qs → CanonPairs l qs' → qs = qs'
  | [], _, _, _, h, h' => by cases h; cases h'; rfl
  | (k, v) :: l, _, _, hf, h, h' => by
    cases h with
    | cons hk hv hl =>
      cases h' with
      | cons hk' hv' hl' =>
        rw [nfcOf_functional hk hk', hf (k, v) (by simp) _ _ hv hv',
          pairs_functional (fun w hw => hf w (by simp [hw])) hl hl']

/-- **Denotations are unique.** -/
theorem canon_functional : ∀ (n : Nat) (v : canon.CanonValue), sizeOf v = n →
    ∀ m m', Canon v m → Canon v m' → m = m' := by
  intro n
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    intro v hn m m' h h'
    cases h with
    | null => cases h'; rfl
    | bool b => cases h'; rfl
    | int k => cases h'; rfl
    | str s r hr => cases h' with | str _ r' hr' => rw [nfcOf_functional hr hr']
    | arr items xs hx =>
      cases h' with
      | arr _ xs' hx' =>
        rw [elems_functional (fun w hw => ih _ (hn ▸ sizeOf_item hw) w rfl) hx hx']
    | obj members qs L hq hp hs =>
      cases h' with
      | obj _ qs' L' hq' hp' hs' =>
        have hqq := pairs_functional (fun w hw => ih _ (hn ▸ sizeOf_member hw) w.2 rfl) hq hq'
        subst hqq
        rw [keySorted_perm_eq (hp.trans hp'.symm) hs hs']

open Classical in
/-- The model value `v` denotes, when it denotes one (`Canon` is functional). -/
noncomputable def mOf (v : canon.CanonValue) : CV :=
  if h : ∃ m, Canon v m then Classical.choose h else .null

theorem mOf_spec {v : canon.CanonValue} {m : CV} (h : Canon v m) : mOf v = m := by
  have hex : ∃ m, Canon v m := ⟨m, h⟩
  unfold mOf
  rw [dif_pos hex]
  exact canon_functional _ v rfl _ _ (Classical.choose_spec hex) h

/-- Semantic equality: the two values denote the same canonical model value. -/
def SemEq (v w : canon.CanonValue) : Prop := ∃ m, Canon v m ∧ Canon w m

theorem canonPairs_perm {l l' : List (String × canon.CanonValue)} (hp : l.Perm l') :
    ∀ {qs}, CanonPairs l qs → ∃ qs', CanonPairs l' qs' ∧ qs'.Perm qs := by
  induction hp with
  | nil => intro qs h; exact ⟨qs, h, List.Perm.refl _⟩
  | cons x _ ih =>
    intro qs h
    cases h with
    | cons hk hv hl =>
      obtain ⟨qs', h', hp'⟩ := ih hl
      exact ⟨_, CanonPairs.cons hk hv h', hp'.cons _⟩
  | swap x y l =>
    intro qs h
    cases h with
    | cons hk hv hl =>
      cases hl with
      | cons hk' hv' hl' =>
        exact ⟨_, CanonPairs.cons hk' hv' (CanonPairs.cons hk hv hl'), List.Perm.swap _ _ _⟩
  | trans _ _ ih1 ih2 =>
    intro qs h
    obtain ⟨q1, h1, p1⟩ := ih1 h
    obtain ⟨q2, h2, p2⟩ := ih2 h1
    exact ⟨q2, h2, p2.trans p1⟩

/-- **Insertion order is irrelevant**: permuting an object's members does not change what it
denotes. -/
theorem canon_perm_members {members members' : alloc.vec.Vec (String × canon.CanonValue)}
    (hp : members.val.Perm members'.val) (m : CV) :
    Canon (.Object members) m → Canon (.Object members') m := by
  intro h
  cases h with
  | obj _ qs L hq hL hs =>
    obtain ⟨qs', hq', hpq⟩ := canonPairs_perm hp hq
    exact Canon.obj members' qs' L hq' (hL.trans hpq.symm) hs

end Refinement
