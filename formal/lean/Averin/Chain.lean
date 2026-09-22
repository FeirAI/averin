/-!
# The checkpoint chain is a single, uniquely determined history

Models the chain checks of `core/src/checkpoint.rs::validate_chain` (RCP §10.1 steps 3 and 6):
`checkpoint_seq` starts at 0 and increases by exactly 1, seq 0 has `prev_checkpoint_hash = null`,
and each later checkpoint's `prev_checkpoint_hash` equals its predecessor's recomputed
`checkpoint_hash`.

The chain is represented newest-first. `hash` is the checkpoint hash function; it is *not*
assumed injective — conclusions carry an explicit collision instead (for the real
`checkpoint_hash`, `Averin.Seal.checkpointHashOf_binding` turns hash equality into body equality
up to a SHA-256 collision).

* `unique_history` — two chains that pass the checks and end in the same checkpoint hash are
  identical, element for element. A signed latest checkpoint therefore commits its entire
  history: no fork can be spliced in and no earlier checkpoint swapped out.
* `seq_eq_length` — the newest checkpoint's seq equals the number of predecessors (no gaps).
-/

namespace Averin.Chain

abbrev Hash := Nat

structure CP (Body : Type) where
  seq : Nat
  prev : Option Hash
  body : Body

variable {Body : Type}

/-- `validate_chain`'s structural checks, newest-first. -/
def Valid (hash : CP Body → Hash) : List (CP Body) → Prop
  | [] => True
  | c :: rest =>
    c.seq = rest.length ∧
    c.prev = (match rest with | [] => none | d :: _ => some (hash d)) ∧
    Valid hash rest

def Collision (hash : CP Body → Hash) : Prop := ∃ x y, x ≠ y ∧ hash x = hash y

theorem seq_eq_length (hash : CP Body → Hash) {c : CP Body} {rest : List (CP Body)}
    (h : Valid hash (c :: rest)) : c.seq = rest.length := h.1

/-- **History uniqueness.** Valid chains with the same newest checkpoint hash are identical, or the
checkpoint hash has a collision. -/
theorem unique_history (hash : CP Body → Hash) :
    ∀ (cs ds : List (CP Body)) (c d : CP Body),
      Valid hash (c :: cs) → Valid hash (d :: ds) → hash c = hash d →
      (c :: cs = d :: ds) ∨ Collision hash
  | cs, ds, c, d, hc, hd, h => by
    by_cases hcd : c = d
    · subst hcd
      obtain ⟨hs1, hp1, hv1⟩ := hc
      obtain ⟨hs2, hp2, hv2⟩ := hd
      match cs, ds, hs1, hs2, hp1, hp2, hv1, hv2 with
      | [], [], _, _, _, _, _, _ => exact Or.inl rfl
      | [], _ :: _, hs1, hs2, _, _, _, _ => simp at hs1 hs2; omega
      | _ :: _, [], hs1, hs2, _, _, _, _ => simp at hs1 hs2; omega
      | c' :: cs', d' :: ds', _, _, hp1, hp2, hv1, hv2 =>
        rw [hp1] at hp2
        simp only [Option.some.injEq] at hp2
        rcases unique_history hash cs' ds' c' d' hv1 hv2 hp2 with he | hcol
        · exact Or.inl (by rw [he])
        · exact Or.inr hcol
    · exact Or.inr ⟨c, d, hcd, h⟩

/-- Every checkpoint in a valid chain sits at seq = its depth from the root (no gaps, no repeats). -/
theorem seqs_exact (hash : CP Body → Hash) :
    ∀ (cs : List (CP Body)), Valid hash cs → ∀ i (hi : i < cs.length),
      cs[i].seq = cs.length - 1 - i
  | [], _, i, hi => by simp at hi
  | c :: rest, h, 0, _ => by simpa using h.1
  | _ :: rest, h, i + 1, hi => by
    have := seqs_exact hash rest h.2.2 i (by simpa using hi)
    simp only [List.getElem_cons_succ, List.length_cons]
    rw [this]; omega

end Averin.Chain
