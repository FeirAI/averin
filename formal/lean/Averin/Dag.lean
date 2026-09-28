/-!
# No omission, no injection: a verified bundle is exactly the signed closure

Models `core/src/dag.rs::build` (parents resolve, Kahn acyclicity, heads) and the frontier checks
of `core/src/checkpoint.rs::validate_chain` (RCP §10.1 steps 2 and 4).

`Hash` is an abstract `content_hash`. The link to the signed history is `Consistent`: every
record present in the bundle has the parents the key holder sealed under that hash (this is what
`Averin.Seal.record_seal_sound` gives, absent a SHA-256 collision / Ed25519 forgery).

* `no_omission` — every causal ancestor (in the *signed* history) of anything present is itself
  present. Deleting a record from the middle of a run breaks verification.
* `coverage` — with acyclicity, every present record is an ancestor-or-self of a head.
* `bundle_eq_closure` — **headline**: when the latest checkpoint's frontier equals the heads, the
  bundle's records are *exactly* the ancestor-closure of that signed frontier. Nothing the
  checkpoint committed is missing, and nothing it did not commit is present.
-/

namespace Averin.Dag

abbrev Hash := Nat

/-- A record present in the bundle: its `content_hash` and `causal_prev_hashes`. -/
structure Rec where
  h : Hash
  parents : List Hash

/-- The signed history: parents of each sealed record, by content hash. -/
abbrev History := Hash → Option (List Hash)

section
variable (R : List Rec) (T : History)

def Present (x : Hash) : Prop := ∃ r ∈ R, r.h = x

/-- Each present record carries exactly the parents that were sealed under its hash. -/
def Consistent : Prop := ∀ r ∈ R, T r.h = some r.parents

/-- `dag.rs`: every `causal_prev_hash` resolves to a present record (else `MissingParent`). -/
def ParentsResolve : Prop := ∀ r ∈ R, ∀ p ∈ r.parents, Present R p

/-- `dag.rs` Kahn sort succeeded: a topological rank exists. -/
def Acyclic : Prop := ∃ rank : Hash → Nat, ∀ r ∈ R, ∀ p ∈ r.parents, rank p < rank r.h

/-- A head is present and referenced as a parent by no present record. -/
def Head (x : Hash) : Prop := Present R x ∧ ∀ r ∈ R, x ∉ r.parents
end

/-- `Anc T a x`: `a` is `x` or a causal ancestor of `x` in the signed history. -/
inductive Anc (T : History) : Hash → Hash → Prop
  | refl (x : Hash) : Anc T x x
  | step {a x : Hash} {ps : List Hash} {p : Hash} :
      T x = some ps → p ∈ ps → Anc T a p → Anc T a x

theorem Anc.trans {T : History} {a b c : Hash} (hab : Anc T a b) (hbc : Anc T b c) : Anc T a c := by
  induction hbc with
  | refl => exact hab
  | step hx hp _ ih => exact Anc.step hx hp ih

/-- **No omission.** Everything the signed history places causally before a present record is
present too. -/
theorem no_omission {R : List Rec} {T : History} (hc : Consistent R T) (hp : ParentsResolve R)
    {a x : Hash} (hx : Present R x) (hanc : Anc T a x) : Present R a := by
  induction hanc with
  | refl => exact hx
  | step hT hmem _ ih =>
    obtain ⟨r, hr, rfl⟩ := hx
    rw [hc r hr] at hT
    cases hT
    exact ih (hp r hr _ hmem)

theorem le_sum_of_mem : ∀ {l : List Nat} {n : Nat}, n ∈ l → n ≤ l.sum
  | _ :: _, _, .head _ => by simp
  | _ :: _, _, .tail _ h => by simp only [List.sum_cons]; have := le_sum_of_mem h; omega

/-- **Coverage.** In an acyclic bundle every present record reaches a head. -/
theorem coverage {R : List Rec} {T : History} (hc : Consistent R T) (hacyc : Acyclic R)
    {x : Hash} (hx : Present R x) : ∃ hd, Head R hd ∧ Anc T x hd := by
  obtain ⟨rank, hrank⟩ := hacyc
  let M := (R.map fun r => rank r.h).sum
  have hbound : ∀ y, Present R y → rank y ≤ M := by
    rintro y ⟨r, hr, rfl⟩
    exact le_sum_of_mem (List.mem_map.mpr ⟨r, hr, rfl⟩)
  suffices ∀ n, ∀ y, Present R y → M - rank y = n → ∃ hd, Head R hd ∧ Anc T y hd from
    this _ x hx rfl
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro y hy hn
    by_cases hhead : ∃ r ∈ R, y ∈ r.parents
    · obtain ⟨r, hr, hyr⟩ := hhead
      have hlt := hrank r hr y hyr
      have hrp : Present R r.h := ⟨r, hr, rfl⟩
      have hb := hbound r.h hrp
      obtain ⟨hd, hhd, hanc⟩ := ih (M - rank r.h) (by omega) r.h hrp rfl
      exact ⟨hd, hhd, Anc.trans (Anc.step (hc r hr) hyr (Anc.refl y)) hanc⟩
    · exact ⟨y, ⟨hy, fun r hr hm => hhead ⟨r, hr, hm⟩⟩, Anc.refl y⟩

/--
**The bundle is exactly the signed closure of the latest frontier.** Under the checks the Rust
verifier performs — parents resolve, the DAG is acyclic, and the latest checkpoint's `frontier`
equals the actual heads (`LatestFrontierMismatch` otherwise) — a hash is present iff it is an
ancestor-or-self (in the signed history) of a member of that frontier.
-/
theorem bundle_eq_closure {R : List Rec} {T : History} (hc : Consistent R T)
    (hp : ParentsResolve R) (hacyc : Acyclic R) (frontier : List Hash)
    (hfront : ∀ x, x ∈ frontier ↔ Head R x) (a : Hash) :
    Present R a ↔ ∃ f ∈ frontier, Anc T a f := by
  constructor
  · intro ha
    obtain ⟨hd, hhd, hanc⟩ := coverage hc hacyc ha
    exact ⟨hd, (hfront hd).mpr hhd, hanc⟩
  · rintro ⟨f, hf, hanc⟩
    exact no_omission hc hp ((hfront f).mp hf).1 hanc

/-- Every *earlier* checkpoint's committed history is also fully present, provided its frontier
members are (`FrontierMemberMissing` otherwise). -/
theorem earlier_checkpoint_closed {R : List Rec} {T : History} (hc : Consistent R T)
    (hp : ParentsResolve R) (frontier : List Hash) (hmem : ∀ f ∈ frontier, Present R f)
    {a f : Hash} (hf : f ∈ frontier) (hanc : Anc T a f) : Present R a :=
  no_omission hc hp (hmem f hf) hanc

end Averin.Dag
