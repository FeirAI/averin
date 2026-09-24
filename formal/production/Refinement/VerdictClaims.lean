import Refinement.Verdict

/-!
# The verdict model's theorems, transported to the production kernel

`decide_claims_refines` makes every claim of `verify::verdict::decide_claims` the model's
`decideClaim` on the evidence state the checked facts correspond to. The model theorems about
`decideClaim` and `Supports` (`formal/lean/Averin/Verdict.lean`, plans 002 and 009) therefore hold
for the production kernel's results. The claim order of plan 002 is inclusion of satisfied claims,
with `insufficient` and `refuted` distinct reasons:

* `production_support_erasure`: for fixed signed records, pins, policy and authenticated adverse
  evidence (one `Fixed`), deleting supporting attachments never turns a claim satisfied and never
  changes whether it is refuted (so a refutation cannot be deleted into `insufficient`, and
  `insufficient` cannot be deleted into `satisfied`).
* `production_satisfied_supports`: a satisfied production claim (including the requested one and
  the capstones) has an inductive evidence derivation `Supports`; the capstone and historical
  inversions follow.
* The committed-contradiction, historical-policy, at/after-cutoff and total-revocation results.
-/

open Aeneas Aeneas.Std Result averin_decision_core
open Averin.Verdict

namespace Refinement

section Model
variable {m : Fixed} {a : List Attachment}

/-- A claim the model decides as satisfied is exactly a supported claim. -/
theorem decideClaim_satisfied_iff (c : Claim) :
    decideClaim m a c = .satisfied ↔ Supports m a c := by
  refine ⟨decideClaim_satisfied_only m a c, fun hs => ?_⟩
  have hp := (supportP_iff m a c).mpr hs
  cases c with
  | integrity =>
    rw [model_integrity]; simp [show IntegrityP m from hp]
  | authenticated =>
    rw [model_authenticated]
    have hI : IntegrityP m := hp.1
    have hR : RecordsProven m a := ⟨hI.1, hp.2⟩
    simp [hI, hR]
  | authorized =>
    obtain ⟨⟨hI, hrp⟩, hr, hu, hc, hn, hk, ho, hv, hd, hat⟩ := hp
    have hA : ¬ CurrentAdverse m := by
      unfold CurrentAdverse; simp only [not_or, Bool.not_eq_true]
      exact ⟨hc, not_not.mpr hn, by simpa using hk, by simpa using ho.1, by simpa using ho.2⟩
    rw [model_authorized]
    simp [hI, hA, show RecordsProven m a from ⟨hI.1, hrp⟩, hr, hv,
      show PolicyEvidence m a from ⟨hd, hat⟩, hu]
  | historicalAuthorized =>
    obtain ⟨⟨hI, hrp⟩, hT, hr, hu, hc, ho, hh, hsr, hd, hat⟩ := hp
    have hR : ¬ HistoricalRefutation m := by
      unfold HistoricalRefutation; simp only [not_or, Bool.not_eq_true]
      exact ⟨hc, hh, by simpa using ho.1, by simpa using ho.2⟩
    rw [model_historical]
    simp [hT, hI, hR, show RecordsProven m a from ⟨hI.1, hrp⟩, hr, hu, hsr,
      show PolicyEvidence m a from ⟨hd, hat⟩]
  | temporal =>
    obtain ⟨hc, hn, hk, ho, hv, hat⟩ := hp
    have hA : ¬ CurrentAdverse m := by
      unfold CurrentAdverse; simp only [not_or, Bool.not_eq_true]
      exact ⟨hc, not_not.mpr hn, by simpa using hk, by simpa using ho.1, by simpa using ho.2⟩
    rw [model_temporal]
    simp [hA, hv, hat]
  | completeBrokered =>
    obtain ⟨⟨⟨hI, hrp⟩, hr, hu, hc, hn, hk, ho, hv, hd, hat⟩, _, hb⟩ := hp
    have hA : ¬ CurrentAdverse m := by
      unfold CurrentAdverse; simp only [not_or, Bool.not_eq_true]
      exact ⟨hc, not_not.mpr hn, by simpa using hk, by simpa using ho.1, by simpa using ho.2⟩
    have ht := (supportP_iff m a .completeBrokered).mpr hs
    rw [model_completeBrokered]
    simp [hI, hA, show RecordsProven m a from ⟨hI.1, hrp⟩, hr, hv,
      show PolicyEvidence m a from ⟨hd, hat⟩, hu, ht.2.1.2.2.2.2.2, hb]
  | completeIntrospected =>
    obtain ⟨⟨⟨hI, hrp⟩, hr, hu, hc, hn, hk, ho, hv, hd, hat⟩, _, hb⟩ := hp
    have hA : ¬ CurrentAdverse m := by
      unfold CurrentAdverse; simp only [not_or, Bool.not_eq_true]
      exact ⟨hc, not_not.mpr hn, by simpa using hk, by simpa using ho.1, by simpa using ho.2⟩
    have ht := (supportP_iff m a .completeIntrospected).mpr hs
    rw [model_completeIntrospected]
    simp [hI, hA, show RecordsProven m a from ⟨hI.1, hrp⟩, hr, hv,
      show PolicyEvidence m a from ⟨hd, hat⟩, hu, ht.2.1.2.2.2.2.2, hb]

theorem ite_sat_ne_refuted (p : Prop) [Decidable p] :
    (if p then Decision.satisfied else .insufficient) ≠ .refuted := by
  split <;> simp

/-- Refutation depends only on the fixed evidence: it is the same for every attachment list. -/
theorem decideClaim_refuted_fixed (c : Claim) (a a' : List Attachment) :
    decideClaim m a c = .refuted ↔ decideClaim m a' c = .refuted := by
  cases c <;>
  simp only [model_integrity, model_authenticated, model_authorized, model_temporal,
    model_historical, model_completeBrokered, model_completeIntrospected] <;>
  split_ifs <;> simp_all

end Model

@[simp] theorem decOf_satisfied {d : verify.verdict.ClaimDecision} :
    decOf d = .satisfied ↔ d = .Satisfied := by cases d <;> simp [decOf]

@[simp] theorem decOf_refuted {d : verify.verdict.ClaimDecision} :
    decOf d = .refuted ↔ d = .Refuted := by cases d <;> simp [decOf]

section Production
variable {f : VF} {m : Fixed} {a : List Attachment} {r : verify.verdict.ClaimResults}

/-- The production result of a claim is the model decision (a restatement of the refinement for
a given run of the kernel). -/
theorem production_claim (h : Corresponds f m a) (hr : verify.verdict.decide_claims f = ok r)
    (c : Claim) : decOf (resultOf r c) = decideClaim m a c := by
  obtain ⟨r', hr', hc, -⟩ := decide_claims_refines h
  rw [hr, ok_eq_ok] at hr'; subst hr'
  exact hc c

/-- A satisfied production claim has an evidence derivation in the model. -/
theorem production_satisfied_supports (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r) {c : Claim}
    (hc : resultOf r c = .Satisfied) : Supports m a c := by
  have := production_claim h hr c
  rw [hc] at this
  exact (decideClaim_satisfied_iff c).mp this.symm

/-- The caller's requested claim is satisfied only with an evidence derivation. -/
theorem production_requested_supports (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r)
    (hc : r.requested_decision = .Satisfied) : Supports m a (claimOf f.policy.requested) := by
  obtain ⟨r', hr', -, -, hq⟩ := decide_claims_refines h
  rw [hr, ok_eq_ok] at hr'; subst hr'
  exact production_satisfied_supports h hr (hq ▸ hc)

/-- **Support erasure for the production kernel (plan 002 claim order).** Two runs of the kernel on
facts corresponding to the same fixed evidence `m` with attachments `small ⊆ large`: every claim
satisfied with the smaller attachment set is satisfied with the larger one, and a claim is refuted
with one exactly when it is refuted with the other. Deleting unsigned support can only move a claim
from `satisfied` to `insufficient`. -/
theorem production_support_erasure {fs fl : VF} {small large : List Attachment}
    (hs : Corresponds fs m small) (hl : Corresponds fl m large) (he : Erased small large) :
    ∃ rs rl, verify.verdict.decide_claims fs = ok rs ∧ verify.verdict.decide_claims fl = ok rl ∧
      ∀ c, (resultOf rs c = .Satisfied → resultOf rl c = .Satisfied) ∧
        (resultOf rs c = .Refuted ↔ resultOf rl c = .Refuted) := by
  obtain ⟨rs, hrs, hcs, -⟩ := decide_claims_refines hs
  obtain ⟨rl, hrl, hcl, -⟩ := decide_claims_refines hl
  refine ⟨rs, rl, hrs, hrl, fun c => ⟨fun hsat => ?_, ?_⟩⟩
  · have h1 : decideClaim m small c = .satisfied := by rw [← hcs c, hsat]; rfl
    have h2 := (decideClaim_satisfied_iff c).mpr
      (support_erasure he ((decideClaim_satisfied_iff c).mp h1))
    rw [← hcl c] at h2
    exact decOf_satisfied.mp h2
  · rw [← decOf_refuted, ← decOf_refuted, hcs c, hcl c]
    exact decideClaim_refuted_fixed c small large

/-- A contradiction among committed signed records refutes `authorized` and both capstones. -/
theorem production_committed_contradiction_refuted (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r) (hc : CommittedContradiction m) :
    r.authorized = .Refuted ∧ r.complete_brokered = .Refuted ∧
      r.complete_introspected = .Refuted := by
  have k := committed_contradiction_refuted m a hc
  have e1 := production_claim h hr .authorized
  have e2 := production_claim h hr .completeBrokered
  have e3 := production_claim h hr .completeIntrospected
  simp only [resultOf] at e1 e2 e3
  rw [k.1] at e1; rw [k.2.1] at e2; rw [k.2.2] at e3
  exact ⟨decOf_refuted.mp e1, decOf_refuted.mp e2, decOf_refuted.mp e3⟩

/-- A satisfied production brokered capstone has every model prerequisite: pinned signers and role
keys, revocation and attestation readiness, no committed contradiction, every capstone check. -/
theorem production_capstone_prerequisites (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r) (hc : r.complete_brokered = .Satisfied) :
    (∀ x ∈ m.records, x.signer ∈ m.pinnedSigners) ∧
    (∀ x ∈ m.records, (x.contributesRole = true ∨ x.grantRecord = true) →
      x.roleKey ∈ m.pinnedRoles) ∧
    RevocationReady m a ∧ AttestationReady m a ∧
    ¬ CommittedContradiction m ∧ BrokeredCapstone m :=
  capstone_prerequisites (production_satisfied_supports (c := .completeBrokered) h hr hc)

theorem production_introspected_capstone_prerequisites (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r) (hc : r.complete_introspected = .Satisfied) :
    (∀ x ∈ m.records, x.signer ∈ m.pinnedSigners) ∧
    (∀ x ∈ m.records, (x.contributesRole = true ∨ x.grantRecord = true) →
      x.roleKey ∈ m.pinnedRoles) ∧
    RevocationReady m a ∧ AttestationReady m a ∧
    ¬ CommittedContradiction m ∧ IntrospectedCapstone m :=
  introspected_capstone_prerequisites
    (production_satisfied_supports (c := .completeIntrospected) h hr hc)

/-! ### Plan 009: the historical claim -/

/-- Under the strict policy the production historical claim is never satisfied. -/
theorem production_historical_requires_policy (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r) (hp : m.temporalPolicy = false) :
    r.historical_authorized_as_of_snapshot ≠ .Satisfied := by
  intro hs
  exact historical_requires_policy m a hp
    (decOf_satisfied.mpr hs ▸ (production_claim h hr .historicalAuthorized)).symm

/-- A satisfied production historical claim has every model obligation, in particular a ready
snapshot of the caller's mode (`SnapshotReady`) and no historical adverse evidence. -/
theorem production_historical_supports (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r)
    (hs : r.historical_authorized_as_of_snapshot = .Satisfied) :
    Supports m a .historicalAuthorized :=
  production_satisfied_supports (c := .historicalAuthorized) h hr hs

/-- A receipt without an authenticated ordinal blocks the production historical claim. -/
theorem production_historical_requires_order (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r) {x : Receipt} (hx : x ∈ m.receipts)
    (hn : x.order = none) : r.historical_authorized_as_of_snapshot ≠ .Satisfied :=
  fun hs => historical_requires_order hx hn (production_historical_supports h hr hs)

/-- Without a snapshot attachment the production historical claim is not satisfied. -/
theorem production_historical_requires_snapshot (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r)
    (hn : ∀ x ∈ a, ∀ b w k, x ≠ .snapshot b w k) :
    r.historical_authorized_as_of_snapshot ≠ .Satisfied :=
  fun hs => historical_requires_snapshot hn (production_historical_supports h hr hs)

/-- An authenticated ordinal at or after an authenticated cutoff refutes the production claim. -/
theorem production_at_or_after_refutes (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r) {x : Receipt} (hx : x ∈ m.receipts)
    (hv : x.validated = true) (hat : AtOrAfter m x) (hsel : m.temporalPolicy = true) :
    r.historical_authorized_as_of_snapshot = .Refuted := by
  have e := production_claim h hr .historicalAuthorized
  rw [at_or_after_refutes (a := a) hx hv hat hsel] at e
  exact decOf_refuted.mp e

/-- A total revocation of a validated receipt's grant refutes the production historical claim. -/
theorem production_total_revocation_refutes (h : Corresponds f m a)
    (hr : verify.verdict.decide_claims f = ok r) {x : Receipt} (hx : x ∈ m.receipts)
    (hv : x.validated = true) (ht : x.grantId ∈ m.revoked) (hsel : m.temporalPolicy = true) :
    r.historical_authorized_as_of_snapshot = .Refuted := by
  have e := production_claim h hr .historicalAuthorized
  rw [total_revocation_refutes (a := a) hx hv ht hsel] at e
  exact decOf_refuted.mp e

end Production

end Refinement
