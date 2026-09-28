import Refinement.VerdictLists
import Averin.Verdict

/-!
# The production verdict kernel refines the Lean verdict model (plan 012, phase B)

`verify::verdict::decide_claims` (and every helper it calls) is extracted by Charon/Aeneas from
`core/src/verify/verdict.rs` into `Extracted/Funs.lean`. This file proves that, for every evidence
state of the model (`Averin.Verdict.Fixed` and an attachment list) that the verifier's checked facts
correspond to, each claim the production kernel computes is exactly `Averin.Verdict.decideClaim`
of that state (`decide_claims_refines`). The model's theorems then hold for the production kernel:
deleting supporting attachments never adds a satisfied claim and never changes a refutation
(`production_support_erasure`), a satisfied production claim has a `Supports` derivation
(`production_satisfied_supports`), and the capstone and historical inversions follow.

**What is and is not covered.** The production side is the pure kernel: it maps the checked facts
(`ValidatedFacts`) and the caller's `ClaimPolicy` to the claim results. `Corresponds f m a` states,
fact by fact, which model predicate each checked fact is (for example `pinned_role_authority`
is `RoleContributorsProven m a`, the seal vector attests `RecordProven` for every record). That
the verifier's passes in `verify.rs` (signatures, pins, joins, Merkle paths, snapshot checks) compute
facts satisfying `Corresponds` is **not** proved here: it is the trusted boundary, pinned by the
call-path checks (`manifest.json`), the verdict oracle differential and the adversarial suite. The
kernel's own combination of those facts (every conjunction, disjunction, the revocation-mode
matches, the historical gating, the capstone conjunction, the list searches) is proved.

The Lean statements below restate no kernel logic: the production side is the generated code, the
model side is `decideClaim`; `Corresponds` only names what each input fact means.
-/

open Aeneas Aeneas.Std Result averin_decision_core
open Averin.Verdict

namespace Refinement

abbrev VF := verify.verdict.ValidatedFacts

/-! ## Enumerations -/

/-- A production claim decision as a model decision. -/
def decOf : verify.verdict.ClaimDecision → Decision
  | .Satisfied => .satisfied
  | .Insufficient => .insufficient
  | .Refuted => .refuted

/-- A model decision as a production claim decision (the inverse of `decOf`). -/
def encOf : Decision → verify.verdict.ClaimDecision
  | .satisfied => .Satisfied
  | .insufficient => .Insufficient
  | .refuted => .Refuted

@[simp] theorem decOf_encOf (d : Decision) : decOf (encOf d) = d := by cases d <;> rfl

/-- The claim a caller requests. -/
def claimOf : verify.verdict.RequestedClaim → Claim
  | .Integrity => .integrity
  | .Authenticated => .authenticated
  | .Authorized => .authorized
  | .HistoricalAuthorizedAsOfSnapshot => .historicalAuthorized
  | .CompleteBrokered => .completeBrokered
  | .CompleteIntrospected => .completeIntrospected

/-- The caller's revocation mode. -/
def modeOf : verify.verdict.RevocationRequirement → RevocationMode
  | .Pinned => .pinned
  | .Disclosed => .disclosed
  | .Merkle => .merkle
  | .Both => .both

/-! ## What each checked fact means -/

/-- Every snapshot attachment names the same signed snapshot (boundary time, watermark). The
verifier accepts v2 revocation artifacts only when they sign one identical snapshot (plan 009);
the model allows several, so this is part of the correspondence. -/
def SingleSnapshot (a : List Attachment) : Prop :=
  ∀ b w k b' w' k', Attachment.snapshot b w k ∈ a → Attachment.snapshot b' w' k' ∈ a →
    b = b' ∧ w = w'

/-- A snapshot of kind `k` (disclosed list `false`, Merkle root `true`) is attached. -/
def SnapshotOfKind (a : List Attachment) (k : Bool) : Prop :=
  ∃ b w, Attachment.snapshot b w k ∈ a

/-- An attached snapshot is fresh for the caller's clock, maximum age and minimum watermark. -/
def SnapshotFresh (m : Fixed) (a : List Attachment) : Prop :=
  ∃ b w k, Attachment.snapshot b w k ∈ a ∧
    b ≤ m.evalTime ∧ m.evalTime ≤ b + m.maxAge ∧ m.minWatermark ≤ w

/-- Every receipt's grant has a Merkle path attached. -/
def ReceiptPaths (m : Fixed) (a : List Attachment) : Prop :=
  ∀ r ∈ m.receipts, Attachment.path r.grantId ∈ a

/-- Every receipt is proven before its grant's cutoffs, at or below an attached snapshot's
watermark, with its grant's state certified by the disclosed list or by its own Merkle path. -/
def ReceiptsProvenBefore (m : Fixed) (a : List Attachment) : Prop :=
  ∃ b w k, Attachment.snapshot b w k ∈ a ∧
    ∀ r ∈ m.receipts, ProvenBefore m w r ∧ (SnapshotOfKind a false ∨ Attachment.path r.grantId ∈ a)

/-- Every grant record's disclosure is attached (and there is one). -/
def DisclosureComplete (m : Fixed) (a : List Attachment) : Prop :=
  (∃ r ∈ m.records, r.grantRecord = true) ∧
    ∀ r ∈ m.records, r.grantRecord = true → Attachment.disclosure r.id ∈ a

instance (m : Fixed) (a : List Attachment) : Decidable (DisclosureComplete m a) := by
  unfold DisclosureComplete; infer_instance

theorem disclosureReady_iff {m : Fixed} {a : List Attachment} :
    DisclosureReady m a ↔ m.policy.requireDisclosure = false ∨ DisclosureComplete m a := Iff.rfl

/-- The verified seal vector: one seal per verified record, each naming a record hash and an
externally pinned key. -/
def SealsPinned (f : VF) : Prop :=
  0 < f.record_count.val ∧ f.pinned_record_seals.val.length = f.record_count.val ∧
    ∀ s ∈ f.pinned_record_seals.val, Nonempty' s.record_hash ∧ s.key_bytes ∈ f.pinned_signer_keys.val

instance (f : VF) : Decidable (SealsPinned f) := by unfold SealsPinned; infer_instance

/-- Some verified TSA anchor names the latest checkpoint. -/
def LatestAnchored (f : VF) : Prop :=
  ∃ x ∈ f.anchors.val, AnchorsCheckpoint x f.latest_checkpoint_sequence

instance (f : VF) : Decidable (LatestAnchored f) := by unfold LatestAnchored; infer_instance

/-- The checked facts `f` describe the model evidence state `(m, a)`: each fact is the model
predicate it is named after. This is the verifier's obligation (trusted boundary, see above). -/
structure Corresponds (f : VF) (m : Fixed) (a : List Attachment) : Prop where
  single : SingleSnapshot a
  integrity : f.structural_integrity = true ↔ IntegrityP m
  seals : SealsPinned f ↔ m.records ≠ [] ∧ ∀ r ∈ m.records, RecordProven m a r
  anchored : LatestAnchored f ↔ HasAnchor m a
  attestation : f.attestation_valid = true ↔ AttestationReady m a
  issuer : f.revocation_issuer_pinned = m.revocationIssuerPinned
  disclosedFresh : f.disclosed_revocation_fresh = true ↔ m.disclosedFresh = true ∧ HasAnchor m a
  merkleFresh : f.merkle_revocation_fresh = true ↔ m.merkleFresh = true ∧ HasAnchor m a
  paths : f.merkle_nonmembership_complete = true ↔ PathReady m a
  role : f.pinned_role_authority = true ↔ RoleContributorsProven m a
  brokered : f.brokered_use_valid = m.brokeredUseValid
  introspected : f.introspected_use_valid = m.introspectedUseValid
  disclosure : f.disclosure_complete = true ↔ DisclosureComplete m a
  committed : f.immutable_record_contradiction = true ↔ CommittedContradiction m
  checked : f.checked_contradiction = m.checkedContradiction
  revoked : f.revoked_membership = true ↔ ¬ NoAuthenticatedRevocation m
  opening : f.adverse_disclosure = m.adverseOpening
  anchorOrder : f.adverse_anchor = m.adverseAnchor
  mode : modeOf f.policy.revocation = m.policy.revocation
  requireDisclosure : f.policy.require_disclosure = m.policy.requireDisclosure
  requireAttestation : f.policy.require_attestation = m.policy.requireAttestation
  manifest : f.capstone.manifest = m.capstone.manifest
  twoPhase : f.capstone.two_phase = m.capstone.twoPhase
  noIncompleteIntent : f.capstone.no_incomplete_intent = true ↔
    m.capstone.noIncompleteIntent = true ∧ ∀ u ∈ m.capstone.uses, u ∈ m.capstone.twoPhaseCompleted
  taxonomy : f.capstone.taxonomy = m.capstone.taxonomy
  everyActionVerified : f.capstone.every_action_verified = true ↔
    ∀ u ∈ m.capstone.uses, u ∈ m.capstone.actionVerified
  everyPopReverified : f.capstone.every_pop_reverified = true ↔
    ∀ u ∈ m.capstone.uses, u ∈ m.capstone.popVerified
  grantLog : f.capstone.grant_log = m.capstone.grantLog
  attestationCheck : f.capstone.attestation = m.capstone.attestation
  noViolation : f.capstone.no_violation = m.capstone.noViolation
  noPending : f.capstone.no_pending = m.capstone.noPending
  boundedReuse : f.capstone.bounded_reuse = m.capstone.boundedReuse
  cosignatures : f.capstone.cosignatures = m.capstone.cosignatures
  delegation : f.capstone.delegation = m.capstone.delegation
  revocationCheck : f.capstone.revocation = m.capstone.revocation
  federation : f.capstone.federation = m.capstone.federation
  coverage : f.capstone.coverage = m.capstone.coverage
  brokeredSurface : f.capstone.brokered_surface = true ↔
    m.capstone.uses ≠ [] ∧ m.capstone.nativePresent = false ∧
      ∀ u ∈ m.capstone.uses, u ∈ m.capstone.matched
  introspectedSurface : f.capstone.introspected_surface = true ↔
    m.capstone.uses = [] ∧ m.capstone.nativePresent = true ∧ m.capstone.introspection = true
  selected : f.historical.selected = m.temporalPolicy
  historicalAdverse : (f.historical.adverse || f.historical.checked_contradiction) = true ↔
    HistoricalAdverse m
  snapshotVerified : f.historical.snapshot_verified = true ↔ SnapshotFresh m a
  listUsable : f.historical.v2_list_usable = true ↔ SnapshotOfKind a false
  merkleUsable : f.historical.v2_merkle_usable = true ↔ SnapshotOfKind a true
  merklePaths : f.historical.merkle_paths_complete = true ↔
    SnapshotOfKind a true ∧ ReceiptPaths m a
  historicalUse :
    (f.historical.brokered_use_valid || f.historical.introspected_use_valid) = true ↔
      m.histUseValid = true ∧ ReceiptsProvenBefore m a

/-! ## The historical snapshot (plan 009) -/

section
variable {m : Fixed} {a : List Attachment}

theorem kindReady_false (hs : SingleSnapshot a) :
    SnapshotKindReady m a false ↔
      SnapshotOfKind a false ∧ SnapshotFresh m a ∧ ReceiptsProvenBefore m a := by
  constructor
  · rintro ⟨x, hx, hk⟩
    cases x with
    | snapshot b w k =>
      obtain ⟨rfl, h1, h2, h3, -, h5⟩ := hk
      exact ⟨⟨b, w, hx⟩, ⟨b, w, false, hx, h1, h2, h3⟩,
        ⟨b, w, false, hx, fun r hr => ⟨h5 r hr, Or.inl ⟨b, w, hx⟩⟩⟩⟩
    | _ => exact hk.elim
  · rintro ⟨⟨b, w, hl⟩, ⟨b2, w2, k2, h2, f1, f2, f3⟩, ⟨b3, w3, k3, h3, hall⟩⟩
    obtain ⟨e1, e2⟩ := hs _ _ _ _ _ _ hl h2
    obtain ⟨e3, e4⟩ := hs _ _ _ _ _ _ hl h3
    subst e1 e2 e3 e4
    exact ⟨_, hl, rfl, f1, f2, f3, fun h => absurd h (by simp), fun r hr => (hall r hr).1⟩

theorem kindReady_true (hs : SingleSnapshot a) :
    SnapshotKindReady m a true ↔
      SnapshotOfKind a true ∧ SnapshotFresh m a ∧ ReceiptPaths m a ∧
        ReceiptsProvenBefore m a := by
  constructor
  · rintro ⟨x, hx, hk⟩
    cases x with
    | snapshot b w k =>
      obtain ⟨rfl, h1, h2, h3, h4, h5⟩ := hk
      exact ⟨⟨b, w, hx⟩, ⟨b, w, true, hx, h1, h2, h3⟩, h4 rfl,
        ⟨b, w, true, hx, fun r hr => ⟨h5 r hr, Or.inr (h4 rfl r hr)⟩⟩⟩
    | _ => exact hk.elim
  · rintro ⟨⟨b, w, hl⟩, ⟨b2, w2, k2, h2, f1, f2, f3⟩, hp, ⟨b3, w3, k3, h3, hall⟩⟩
    obtain ⟨e1, e2⟩ := hs _ _ _ _ _ _ hl h2
    obtain ⟨e3, e4⟩ := hs _ _ _ _ _ _ hl h3
    subst e1 e2 e3 e4
    exact ⟨_, hl, rfl, f1, f2, f3, fun _ => hp, fun r hr => (hall r hr).1⟩

/-- Under the default (pinned) mode a fresh snapshot under which every receipt is proven before
is a ready snapshot of one kind: the disclosed list, or else a Merkle root with every path. -/
theorem pinned_kind (hs : SingleSnapshot a) (hS : SnapshotFresh m a)
    (hP : ReceiptsProvenBefore m a) :
    SnapshotKindReady m a false ∨ SnapshotKindReady m a true := by
  by_cases hl : SnapshotOfKind a false
  · exact Or.inl ((kindReady_false hs).mpr ⟨hl, hS, hP⟩)
  · obtain ⟨b, w, k, hx, -⟩ := id hS
    cases k with
    | false => exact absurd ⟨b, w, hx⟩ hl
    | true =>
      obtain ⟨b3, w3, k3, h3, hall⟩ := hP
      refine Or.inr ((kindReady_true hs).mpr ⟨⟨b, w, hx⟩, ?_, ?_, ⟨b3, w3, k3, h3, hall⟩⟩)
      · exact hS
      · exact fun r hr => (hall r hr).2.resolve_left hl

end

/-- The caller's disclosure and attestation requirements are met. -/
def PolicyEvidence (m : Fixed) (a : List Attachment) : Prop :=
  DisclosureReady m a ∧ (m.policy.requireAttestation = false ∨ AttestationReady m a)

instance (m : Fixed) (a : List Attachment) : Decidable (PolicyEvidence m a) := by
  unfold PolicyEvidence; infer_instance

/-- The fixed adverse evidence that refutes current authorization, `temporal` and the capstones
(the disjunction in `decideClaim`). -/
def CurrentAdverse (m : Fixed) : Prop :=
  CommittedContradiction m ∨ ¬ NoAuthenticatedRevocation m ∨ m.checkedContradiction = true ∨
    m.adverseOpening = true ∨ m.adverseAnchor = true

instance (m : Fixed) : Decidable (CurrentAdverse m) := by unfold CurrentAdverse; infer_instance


/-- The adverse evidence of the historical claim (the refutation disjunction of `decideHistorical`
minus the integrity check). -/
def HistoricalRefutation (m : Fixed) : Prop :=
  CommittedContradiction m ∨ HistoricalAdverse m ∨ m.adverseOpening = true ∨ m.adverseAnchor = true

instance (m : Fixed) : Decidable (HistoricalRefutation m) := by
  unfold HistoricalRefutation; infer_instance

/-! ## The model's decision, claim by claim

`decideClaim` restated as a refutation condition and a support condition over the predicates the
checked facts name. These are theorems about the model only. -/

/-- The seal/pin half of `authenticated`: every record is proven by a pinned key. -/
def RecordsProven (m : Fixed) (a : List Attachment) : Prop :=
  m.records ≠ [] ∧ ∀ r ∈ m.records, RecordProven m a r

instance (m : Fixed) (a : List Attachment) : Decidable (RecordsProven m a) := by
  unfold RecordsProven; infer_instance

section
variable {m : Fixed} {a : List Attachment}

-- The claim tests of `decideClaim` (`Claim` derives a `BEq` that simp does not evaluate).
@[simp] theorem bne_integrity : (Claim.integrity != Claim.temporal) = true := rfl
@[simp] theorem bne_authenticated : (Claim.authenticated != Claim.temporal) = true := rfl
@[simp] theorem bne_authorized : (Claim.authorized != Claim.temporal) = true := rfl
@[simp] theorem bne_completeBrokered : (Claim.completeBrokered != Claim.temporal) = true := rfl
@[simp] theorem bne_completeIntrospected :
    (Claim.completeIntrospected != Claim.temporal) = true := rfl
@[simp] theorem bne_temporal : (Claim.temporal != Claim.temporal) = false := rfl

theorem integrityP_iff : IntegrityP m ↔ m.records ≠ [] ∧ ∀ r ∈ m.records, r.id ∈ m.sealed := Iff.rfl

theorem model_integrity :
    decideClaim m a .integrity = if IntegrityP m then .satisfied else .refuted := by
  by_cases hI : IntegrityP m <;> simp [decideClaim, supportB, hI]

theorem model_authenticated :
    decideClaim m a .authenticated =
      if ¬ IntegrityP m then .refuted else if RecordsProven m a then .satisfied
      else .insufficient := by
  by_cases hI : IntegrityP m
  · by_cases hR : RecordsProven m a
    · have : AuthenticatedP m a := ⟨hI, hR.2⟩
      simp [decideClaim, supportB, hI, hR, this]
    · have : ¬ AuthenticatedP m a := fun h => hR ⟨hI.1, h.2⟩
      simp [decideClaim, supportB, hI, hR, this]
  · simp [decideClaim, supportB, hI]

theorem model_authorized :
    decideClaim m a .authorized =
      if ¬ IntegrityP m ∨ CurrentAdverse m then .refuted
      else if RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
          PolicyEvidence m a ∧ UseSurfaceValid m then .satisfied
      else .insufficient := by
  unfold CurrentAdverse
  by_cases hA : CommittedContradiction m ∨ ¬ NoAuthenticatedRevocation m ∨
      m.checkedContradiction = true ∨ m.adverseOpening = true ∨ m.adverseAnchor = true
  · simp only [hA, or_true, ↓reduceIte]
    simp [decideClaim, hA]
  · by_cases hI : IntegrityP m
    · have e : AuthorizedP m a ↔ (RecordsProven m a ∧ RoleContributorsProven m a ∧
          RevocationReady m a ∧ PolicyEvidence m a ∧ UseSurfaceValid m) := by
        simp only [AuthorizedP, AuthenticatedP, RecordsProven, PolicyEvidence, NoAdverseOpening]
        simp only [not_or, Bool.not_eq_true] at hA
        obtain ⟨h1, h2, h3, h4, h5⟩ := hA
        constructor
        · rintro ⟨⟨_, hp⟩, hr, hu, _, _, _, _, hv, hd, hat⟩
          exact ⟨⟨hI.1, hp⟩, hr, hv, ⟨hd, hat⟩, hu⟩
        · rintro ⟨⟨_, hp⟩, hr, hv, ⟨hd, hat⟩, hu⟩
          exact ⟨⟨hI, hp⟩, hr, hu, h1, not_not.mp h2, h3, ⟨h4, h5⟩, hv, hd, hat⟩
      have hA' := hA
      simp only [not_or] at hA'
      by_cases hS : AuthorizedP m a
      · have := e.mp hS
        simp [decideClaim, supportB, hI, hA, hS, this]
      · have : ¬ (RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
            PolicyEvidence m a ∧ UseSurfaceValid m) := fun h => hS (e.mpr h)
        simp [decideClaim, supportB, hI, hA, hS, this]
    · simp [decideClaim, supportB, hI, hA]

theorem temporalP_iff (hA : ¬ CurrentAdverse m) :
    TemporalP m a ↔ RevocationReady m a ∧ AttestationReady m a := by
  unfold CurrentAdverse at hA
  simp only [not_or, Bool.not_eq_true] at hA
  obtain ⟨h1, h2, h3, h4, h5⟩ := hA
  constructor
  · rintro ⟨_, _, _, _, hv, hat⟩; exact ⟨hv, hat⟩
  · rintro ⟨hv, hat⟩; exact ⟨h1, not_not.mp h2, h3, ⟨h4, h5⟩, hv, hat⟩

theorem model_temporal :
    decideClaim m a .temporal =
      if CurrentAdverse m then .refuted
      else if RevocationReady m a ∧ AttestationReady m a then .satisfied
      else .insufficient := by
  by_cases hA : CurrentAdverse m
  · have hA' := hA; unfold CurrentAdverse at hA'
    simp [decideClaim, hA, hA']
  · have e := temporalP_iff (a := a) hA
    have hA' := hA; unfold CurrentAdverse at hA'
    by_cases hS : RevocationReady m a ∧ AttestationReady m a
    · simp [decideClaim, supportB, hA, hA', hS, e.mpr hS]
    · have : ¬ TemporalP m a := fun h => hS (e.mp h)
      simp [decideClaim, supportB, hA, hA', hS, this]

theorem authorizedP_iff' (hI : IntegrityP m) (hA : ¬ CurrentAdverse m) :
    AuthorizedP m a ↔ (RecordsProven m a ∧ RoleContributorsProven m a ∧
      RevocationReady m a ∧ PolicyEvidence m a ∧ UseSurfaceValid m) := by
  unfold CurrentAdverse at hA
  simp only [AuthorizedP, AuthenticatedP, RecordsProven, PolicyEvidence, NoAdverseOpening]
  simp only [not_or, Bool.not_eq_true] at hA
  obtain ⟨h1, h2, h3, h4, h5⟩ := hA
  constructor
  · rintro ⟨⟨_, hp⟩, hr, hu, _, _, _, _, hv, hd, hat⟩
    exact ⟨⟨hI.1, hp⟩, hr, hv, ⟨hd, hat⟩, hu⟩
  · rintro ⟨⟨_, hp⟩, hr, hv, ⟨hd, hat⟩, hu⟩
    exact ⟨⟨hI, hp⟩, hr, hu, h1, not_not.mp h2, h3, ⟨h4, h5⟩, hv, hd, hat⟩

theorem model_completeBrokered :
    decideClaim m a .completeBrokered =
      if ¬ IntegrityP m ∨ CurrentAdverse m then .refuted
      else if (RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
          PolicyEvidence m a ∧ UseSurfaceValid m) ∧ (RevocationReady m a ∧ AttestationReady m a) ∧
          BrokeredCapstone m then .satisfied
      else .insufficient := by
  by_cases hA : CurrentAdverse m
  · have hA' := hA; unfold CurrentAdverse at hA'
    simp [decideClaim, hA, hA']
  · have hA' := hA; unfold CurrentAdverse at hA'
    by_cases hI : IntegrityP m
    · have e1 := authorizedP_iff' (a := a) hI hA
      have e2 := temporalP_iff (a := a) hA
      by_cases hS : (RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
          PolicyEvidence m a ∧ UseSurfaceValid m) ∧ (RevocationReady m a ∧ AttestationReady m a) ∧
          BrokeredCapstone m
      · have : AuthorizedP m a ∧ TemporalP m a ∧ BrokeredCapstone m :=
          ⟨e1.mpr hS.1, e2.mpr hS.2.1, hS.2.2⟩
        simp [decideClaim, supportB, hA, hA', hI, hS, this]
      · have : ¬ (AuthorizedP m a ∧ TemporalP m a ∧ BrokeredCapstone m) :=
          fun h => hS ⟨e1.mp h.1, e2.mp h.2.1, h.2.2⟩
        simp only [decideClaim, supportB, hA', hI, hS, this]
        simp [hA]
    · simp [decideClaim, supportB, hA, hA', hI]

theorem model_completeIntrospected :
    decideClaim m a .completeIntrospected =
      if ¬ IntegrityP m ∨ CurrentAdverse m then .refuted
      else if (RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
          PolicyEvidence m a ∧ UseSurfaceValid m) ∧ (RevocationReady m a ∧ AttestationReady m a) ∧
          IntrospectedCapstone m then .satisfied
      else .insufficient := by
  by_cases hA : CurrentAdverse m
  · have hA' := hA; unfold CurrentAdverse at hA'
    simp [decideClaim, hA, hA']
  · have hA' := hA; unfold CurrentAdverse at hA'
    by_cases hI : IntegrityP m
    · have e1 := authorizedP_iff' (a := a) hI hA
      have e2 := temporalP_iff (a := a) hA
      by_cases hS : (RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
          PolicyEvidence m a ∧ UseSurfaceValid m) ∧ (RevocationReady m a ∧ AttestationReady m a) ∧
          IntrospectedCapstone m
      · have : AuthorizedP m a ∧ TemporalP m a ∧ IntrospectedCapstone m :=
          ⟨e1.mpr hS.1, e2.mpr hS.2.1, hS.2.2⟩
        simp [decideClaim, supportB, hA, hA', hI, hS, this]
      · have : ¬ (AuthorizedP m a ∧ TemporalP m a ∧ IntrospectedCapstone m) :=
          fun h => hS ⟨e1.mp h.1, e2.mp h.2.1, h.2.2⟩
        simp only [decideClaim, supportB, hA', hI, hS, this]
        simp [hA]
    · simp [decideClaim, supportB, hA, hA', hI]

theorem model_historical :
    decideClaim m a .historicalAuthorized =
      if m.temporalPolicy = true ∧ (¬ IntegrityP m ∨ HistoricalRefutation m) then .refuted
      else if m.temporalPolicy = true ∧ IntegrityP m ∧ RecordsProven m a ∧
          (RoleContributorsProven m a ∧ m.histUseValid = true ∧ SnapshotReady m a ∧
            PolicyEvidence m a) then .satisfied
      else .insufficient := by
  by_cases hT : m.temporalPolicy = true
  · by_cases hR : HistoricalRefutation m
    · have hR' := hR; unfold HistoricalRefutation at hR'
      simp [decideClaim, decideHistorical, hT, hR, hR']
    · have hR' := hR; unfold HistoricalRefutation at hR'
      simp only [not_or, Bool.not_eq_true] at hR'
      obtain ⟨h1, h2, h3, h4⟩ := hR'
      by_cases hI : IntegrityP m
      · have e : HistoricalP m a ↔ (RecordsProven m a ∧ (RoleContributorsProven m a ∧
            m.histUseValid = true ∧ SnapshotReady m a ∧ PolicyEvidence m a)) := by
          simp only [HistoricalP, AuthenticatedP, RecordsProven, PolicyEvidence, NoAdverseOpening]
          constructor
          · rintro ⟨⟨_, hp⟩, _, hr, hu, _, _, _, hs, hd, hat⟩
            exact ⟨⟨hI.1, hp⟩, hr, hu, hs, hd, hat⟩
          · rintro ⟨⟨_, hp⟩, hr, hu, hs, hd, hat⟩
            exact ⟨⟨hI, hp⟩, hT, hr, hu, h1, ⟨h3, h4⟩, h2, hs, hd, hat⟩
        by_cases hS : RecordsProven m a ∧ (RoleContributorsProven m a ∧
            m.histUseValid = true ∧ SnapshotReady m a ∧ PolicyEvidence m a)
        · simp [decideClaim, decideHistorical, supportB, hT, hR, hI, h1, h2, h3, h4, e.mpr hS, hS]
        · have : ¬ HistoricalP m a := fun h => hS (e.mp h)
          simp only [decideClaim, decideHistorical, supportB, hT, hI, h1, h2, h3, h4, this, hS]
          simp [hR]
      · simp [decideClaim, decideHistorical, supportB, hT, hR, hI, h1, h2, h3, h4]
  · simp [decideClaim, decideHistorical, hT]

end

/-! ## Boolean helpers of the kernel -/

theorem bool_eq_decide {b : Bool} {p : Prop} [Decidable p] (h : b = true ↔ p) : b = decide p := by
  cases b <;> simp_all

theorem decision_ok (r s : Bool) :
    verify.verdict.decision r s =
      ok (if r then .Refuted else if s then .Satisfied else .Insufficient) := by
  unfold verify.verdict.decision
  cases r <;> cases s <;> rfl

theorem pinned_record_keys_ok (f : VF) :
    verify.verdict.pinned_record_keys f = ok (decide (SealsPinned f)) := by
  unfold verify.verdict.pinned_record_keys
  by_cases h0 : f.record_count > 0#usize
  · have h0' : 0 < f.record_count.val := by scalar_tac
    simp only [h0, ↓reduceIte]
    by_cases hl : alloc.vec.Vec.len f.pinned_record_seals = f.record_count
    · have hl' : f.pinned_record_seals.val.length = f.record_count.val := by
        have := congrArg (·.val) hl; simpa using this
      simp only [hl, ↓reduceIte, seals_pinned_ok]
      simp [SealsPinned, h0', hl', alloc.vec.Vec.deref]
    · have hl' : f.pinned_record_seals.val.length ≠ f.record_count.val := by
        intro e; apply hl; apply UScalar.eq_of_val_eq; simpa using e
      simp [hl, SealsPinned, hl']
  · have h0' : ¬ 0 < f.record_count.val := by scalar_tac
    simp [h0, SealsPinned, h0']

theorem anchored_latest_ok (f : VF) :
    verify.verdict.anchored_at (alloc.vec.Vec.deref f.anchors) f.latest_checkpoint_sequence =
      ok (decide (LatestAnchored f)) := by
  rw [anchored_at_ok]
  simp only [ok_eq_ok, decide_eq_decide]
  simp [LatestAnchored, alloc.vec.Vec.deref]

section
variable {f : VF} {m : Fixed} {a : List Attachment}

theorem revocation_ready_ok (h : Corresponds f m a) :
    verify.verdict.revocation_ready f = ok (decide (RevocationReady m a)) := by
  have hm := h.mode
  unfold verify.verdict.revocation_ready
  simp only [bool_eq_decide h.disclosedFresh, bool_eq_decide h.merkleFresh,
    bool_eq_decide h.paths, h.issuer]
  unfold RevocationReady
  cases hr : f.policy.revocation <;> rw [hr] at hm <;> simp only [modeOf] at hm <;>
    simp only [← hm] <;>
    by_cases h1 : m.revocationIssuerPinned = true <;> by_cases h2 : m.disclosedFresh = true <;>
    by_cases h3 : m.merkleFresh = true <;> by_cases h4 : HasAnchor m a <;>
    by_cases h5 : PathReady m a <;> simp_all

theorem adverse_ok (h : Corresponds f m a) :
    verify.verdict.adverse f = ok (decide (CurrentAdverse m)) := by
  unfold verify.verdict.adverse
  simp only [bool_eq_decide h.committed, h.checked, bool_eq_decide h.revoked, h.opening,
    h.anchorOrder]
  unfold CurrentAdverse
  by_cases h1 : CommittedContradiction m <;> by_cases h2 : NoAuthenticatedRevocation m <;>
    by_cases h3 : m.checkedContradiction = true <;> by_cases h4 : m.adverseOpening = true <;>
    by_cases h5 : m.adverseAnchor = true <;> simp_all

theorem policy_evidence_ready_ok (h : Corresponds f m a) :
    verify.verdict.policy_evidence_ready f =
      ok (decide (PolicyEvidence m a)) := by
  unfold verify.verdict.policy_evidence_ready PolicyEvidence
  simp only [h.requireDisclosure, h.requireAttestation, bool_eq_decide h.disclosure,
    bool_eq_decide h.attestation]
  simp only [disclosureReady_iff]
  by_cases h1 : m.policy.requireDisclosure = true <;>
    by_cases h2 : m.policy.requireAttestation = true <;>
    by_cases h3 : AttestationReady m a <;>
    by_cases h4 : DisclosureComplete m a <;> simp_all

theorem authorization_ready_ok (h : Corresponds f m a) {rev : Bool} :
    verify.verdict.authorization_ready f rev =
      ok (decide (RoleContributorsProven m a ∧ rev = true ∧ PolicyEvidence m a ∧
        UseSurfaceValid m)) := by
  unfold verify.verdict.authorization_ready
  simp only [bool_eq_decide h.role, h.brokered, h.introspected, policy_evidence_ready_ok h,
    bind_tc_ok]
  unfold UseSurfaceValid
  by_cases h1 : RoleContributorsProven m a <;> by_cases h0 : rev = true <;>
    by_cases h2 : PolicyEvidence m a <;>
    by_cases h3 : m.brokeredUseValid = true <;> by_cases h4 : m.introspectedUseValid = true <;>
    simp_all

theorem authorization_refuted_ok (h : Corresponds f m a) :
    verify.verdict.authorization_refuted f = ok (decide (¬ IntegrityP m ∨ CurrentAdverse m)) := by
  unfold verify.verdict.authorization_refuted
  simp only [adverse_ok h, bind_tc_ok, bool_eq_decide h.integrity]
  by_cases h1 : IntegrityP m <;> by_cases h2 : CurrentAdverse m <;> simp_all

theorem authorized_ok (h : Corresponds f m a) {pk rev : Bool} :
    verify.verdict.authorized f pk rev =
      ok (decide (IntegrityP m ∧ pk = true ∧ RoleContributorsProven m a ∧ rev = true ∧
        PolicyEvidence m a ∧ UseSurfaceValid m)) := by
  unfold verify.verdict.authorized
  simp only [authorization_ready_ok h, bind_tc_ok, bool_eq_decide h.integrity]
  by_cases h1 : IntegrityP m <;> by_cases h0 : pk = true <;> simp_all

theorem temporal_ok (h : Corresponds f m a) {anch rev : Bool} :
    verify.verdict.temporal f anch rev =
      ok (decide (anch = true ∧ AttestationReady m a ∧ rev = true)) := by
  unfold verify.verdict.temporal
  simp only [bool_eq_decide h.attestation]
  by_cases h1 : AttestationReady m a <;> by_cases h0 : anch = true <;>
    by_cases h2 : rev = true <;> simp_all

theorem ite_ok_or (b c : Bool) : (if b = true then ok true else ok c : Result Bool) = ok (b || c) := by
  cases b <;> rfl

theorem historical_adverse_ok (h : Corresponds f m a) :
    verify.verdict.historical_adverse f = ok (decide (HistoricalRefutation m)) := by
  have hh := h.historicalAdverse
  unfold verify.verdict.historical_adverse
  simp only [bool_eq_decide h.committed, h.opening, h.anchorOrder]
  unfold HistoricalRefutation
  by_cases hA : f.historical.adverse = true <;> by_cases hC : f.historical.checked_contradiction = true <;>
    by_cases h1 : CommittedContradiction m <;> by_cases h2 : HistoricalAdverse m <;>
    by_cases h3 : m.adverseOpening = true <;> by_cases h4 : m.adverseAnchor = true <;> simp_all

theorem ite_ok_and (b c : Bool) : (if b = true then ok c else ok false : Result Bool) = ok (b && c) := by
  cases b <;> rfl

open Classical in
theorem historical_ready_ok (h : Corresponds f m a) :
    verify.verdict.historical_ready f =
      ok (decide (RoleContributorsProven m a ∧ m.histUseValid = true ∧ SnapshotReady m a ∧
        PolicyEvidence m a)) := by
  have hs := h.single
  have hu := h.historicalUse
  have hm := h.mode
  have kf := fun k => (kindReady_false (m := m) hs).mp k
  have kt := fun k => (kindReady_true (m := m) hs).mp k
  have kf' := fun k => (kindReady_false (m := m) hs).mpr k
  have kt' := fun k => (kindReady_true (m := m) hs).mpr k
  have kp := fun hS hP => pinned_kind (m := m) hs hS hP
  unfold verify.verdict.historical_ready verify.verdict.historical_revocation
  simp only [policy_evidence_ready_ok h, bind_tc_ok, bool_eq_decide h.role,
    bool_eq_decide h.snapshotVerified, h.issuer, bool_eq_decide h.listUsable,
    bool_eq_decide h.merkleUsable, bool_eq_decide h.merklePaths, ite_ok_or]
  rw [bool_eq_decide hu]
  unfold SnapshotReady
  cases hr : f.policy.revocation <;> rw [hr] at hm <;> simp only [modeOf] at hm <;>
    simp only [← hm, ite_ok_and, bind_tc_ok, ok_eq_ok] <;> rw [Bool.eq_iff_iff] <;>
    simp only [Bool.and_eq_true, decide_eq_true_eq, and_true]
  · -- pinned: a fresh snapshot under which every receipt is proven is a ready snapshot
    constructor
    · rintro ⟨h1, hS, hi, hpe, hh, hp⟩
      exact ⟨h1, hh, ⟨hi, kp hS hp⟩, hpe⟩
    · rintro ⟨h1, hh, ⟨hi, k | k⟩, hpe⟩
      · exact ⟨h1, (kf k).2.1, hi, hpe, hh, (kf k).2.2⟩
      · exact ⟨h1, (kt k).2.1, hi, hpe, hh, (kt k).2.2.2⟩
  · -- disclosed
    constructor
    · rintro ⟨h1, hS, ⟨hi, hl⟩, hpe, hh, hp⟩
      exact ⟨h1, hh, ⟨hi, kf' ⟨hl, hS, hp⟩⟩, hpe⟩
    · rintro ⟨h1, hh, ⟨hi, k⟩, hpe⟩
      exact ⟨h1, (kf k).2.1, ⟨hi, (kf k).1⟩, hpe, hh, (kf k).2.2⟩
  · -- merkle
    constructor
    · rintro ⟨h1, hS, ⟨hi, hk, -, hpa⟩, hpe, hh, hp⟩
      exact ⟨h1, hh, ⟨hi, kt' ⟨hk, hS, hpa, hp⟩⟩, hpe⟩
    · rintro ⟨h1, hh, ⟨hi, k⟩, hpe⟩
      exact ⟨h1, (kt k).2.1, ⟨hi, (kt k).1, (kt k).1, (kt k).2.2.1⟩, hpe, hh, (kt k).2.2.2⟩
  · -- both
    constructor
    · rintro ⟨h1, hS, ⟨hi, hl, hk, -, hpa⟩, hpe, hh, hp⟩
      exact ⟨h1, hh, ⟨hi, kf' ⟨hl, hS, hp⟩, kt' ⟨hk, hS, hpa, hp⟩⟩, hpe⟩
    · rintro ⟨h1, hh, ⟨hi, k, k'⟩, hpe⟩
      exact ⟨h1, (kf k).2.1, ⟨hi, (kf k).1, (kt k').1, (kt k').1, (kt k').2.2.1⟩, hpe, hh,
        (kf k).2.2⟩

theorem capstone_base_ok (h : Corresponds f m a) :
    verify.verdict.CapstoneFacts.base f.capstone =
      ok (m.capstone.manifest && (m.capstone.twoPhase &&
        (decide (m.capstone.noIncompleteIntent = true ∧
          ∀ u ∈ m.capstone.uses, u ∈ m.capstone.twoPhaseCompleted) &&
        (m.capstone.taxonomy && (decide (∀ u ∈ m.capstone.uses, u ∈ m.capstone.actionVerified) &&
        (decide (∀ u ∈ m.capstone.uses, u ∈ m.capstone.popVerified) &&
        (m.capstone.grantLog && (m.capstone.attestation && (m.capstone.noViolation &&
        (m.capstone.noPending && (m.capstone.boundedReuse && (m.capstone.cosignatures &&
        (m.capstone.delegation && (m.capstone.revocation && (m.capstone.federation &&
          m.capstone.coverage))))))))))))))) := by
  unfold verify.verdict.CapstoneFacts.base
  simp only [ite_ok_and, h.manifest, h.twoPhase, bool_eq_decide h.noIncompleteIntent, h.taxonomy,
    bool_eq_decide h.everyActionVerified, bool_eq_decide h.everyPopReverified, h.grantLog,
    h.attestationCheck, h.noViolation, h.noPending, h.boundedReuse, h.cosignatures, h.delegation,
    h.revocationCheck, h.federation, h.coverage]

theorem capstoneBase_iff :
    CapstoneBase m ↔ (m.capstone.manifest = true ∧ m.capstone.twoPhase = true ∧
      (m.capstone.noIncompleteIntent = true ∧
        ∀ u ∈ m.capstone.uses, u ∈ m.capstone.twoPhaseCompleted) ∧
      m.capstone.taxonomy = true ∧ (∀ u ∈ m.capstone.uses, u ∈ m.capstone.actionVerified) ∧
      (∀ u ∈ m.capstone.uses, u ∈ m.capstone.popVerified) ∧ m.capstone.grantLog = true ∧
      m.capstone.attestation = true ∧ m.capstone.noViolation = true ∧
      m.capstone.noPending = true ∧ m.capstone.boundedReuse = true ∧
      m.capstone.cosignatures = true ∧ m.capstone.delegation = true ∧
      m.capstone.revocation = true ∧ m.capstone.federation = true ∧
      m.capstone.coverage = true) ∧ (∀ u ∈ m.capstone.uses, u ∈ m.capstone.matched) := by
  unfold CapstoneBase
  constructor
  · rintro ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15⟩
    exact ⟨⟨h1, h2, ⟨h3, fun u hu => (h4 u hu).2.2.2⟩, h5, fun u hu => (h4 u hu).2.2.1,
      fun u hu => (h4 u hu).2.1, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15⟩,
      fun u hu => (h4 u hu).1⟩
  · rintro ⟨⟨h1, h2, ⟨h3, ht⟩, h5, ha, hp, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15⟩, hm⟩
    exact ⟨h1, h2, h3, fun u hu => ⟨hm u hu, hp u hu, ha u hu, ht u hu⟩, h5, h6, h7, h8, h9,
      h10, h11, h12, h13, h14, h15⟩

theorem brokered_ok (h : Corresponds f m a) :
    verify.verdict.CapstoneFacts.brokered f.capstone = ok (decide (BrokeredCapstone m)) := by
  unfold verify.verdict.CapstoneFacts.brokered
  simp only [capstone_base_ok h, bind_tc_ok, ite_ok_and, bool_eq_decide h.brokeredSurface,
    ok_eq_ok]
  rw [Bool.eq_iff_iff]
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  unfold BrokeredCapstone
  rw [capstoneBase_iff]
  constructor
  · rintro ⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩,
      hu, hn, hm⟩
    exact ⟨⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩, hm⟩, hu, hn⟩
  · rintro ⟨⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩, hm⟩,
      hu, hn⟩
    exact ⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩, hu, hn, hm⟩

theorem introspected_ok (h : Corresponds f m a) :
    verify.verdict.CapstoneFacts.introspected f.capstone =
      ok (decide (IntrospectedCapstone m)) := by
  unfold verify.verdict.CapstoneFacts.introspected
  simp only [capstone_base_ok h, bind_tc_ok, ite_ok_and, bool_eq_decide h.introspectedSurface,
    ok_eq_ok]
  rw [Bool.eq_iff_iff]
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  unfold IntrospectedCapstone
  rw [capstoneBase_iff]
  constructor
  · rintro ⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩,
      hu, hn, hi⟩
    exact ⟨⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩,
      fun u hm => absurd hm (by simp [hu])⟩, hu, hn, hi⟩
  · rintro ⟨⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩, -⟩,
      hu, hn, hi⟩
    exact ⟨⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16⟩, hu, hn, hi⟩

/-! ## Each claim of the kernel is the model's decision -/

@[simp] theorem encOf_refuted : encOf .refuted = .Refuted := rfl
@[simp] theorem encOf_satisfied : encOf .satisfied = .Satisfied := rfl
@[simp] theorem encOf_insufficient : encOf .insufficient = .Insufficient := rfl

theorem integrity_claim_ok (h : Corresponds f m a) :
    verify.verdict.integrity_claim f = ok (encOf (decideClaim m a .integrity)) := by
  unfold verify.verdict.integrity_claim
  rw [decision_ok, model_integrity, bool_eq_decide h.integrity]
  by_cases hI : IntegrityP m <;> simp [hI]

theorem authenticated_claim_ok (h : Corresponds f m a) :
    verify.verdict.authenticated_claim f (decide (SealsPinned f)) =
      ok (encOf (decideClaim m a .authenticated)) := by
  have hs : SealsPinned f ↔ RecordsProven m a := h.seals
  unfold verify.verdict.authenticated_claim
  rw [decision_ok, model_authenticated, bool_eq_decide h.integrity]
  by_cases hI : IntegrityP m <;> by_cases hR : RecordsProven m a <;> simp_all

theorem authorized_claim_ok (h : Corresponds f m a) :
    verify.verdict.authorized_claim f (decide (SealsPinned f)) (decide (RevocationReady m a)) =
      ok (encOf (decideClaim m a .authorized)) := by
  have hs : SealsPinned f ↔ RecordsProven m a := h.seals
  unfold verify.verdict.authorized_claim
  simp only [authorization_refuted_ok h, authorized_ok h, bind_tc_ok, decision_ok,
    model_authorized]
  by_cases hI : IntegrityP m <;> by_cases hA : CurrentAdverse m <;>
    by_cases hR : RecordsProven m a <;> by_cases h1 : RoleContributorsProven m a <;>
    by_cases h2 : RevocationReady m a <;> by_cases h3 : PolicyEvidence m a <;>
    by_cases h4 : UseSurfaceValid m <;> simp_all

theorem temporal_claim_ok (h : Corresponds f m a) :
    verify.verdict.temporal_claim f (decide (LatestAnchored f)) (decide (RevocationReady m a)) =
      ok (encOf (decideClaim m a .temporal)) := by
  have hl : LatestAnchored f ↔ HasAnchor m a := h.anchored
  have hat : AttestationReady m a → HasAnchor m a := fun h => h.2
  unfold verify.verdict.temporal_claim
  simp only [adverse_ok h, temporal_ok h, bind_tc_ok, decision_ok, model_temporal]
  by_cases hA : CurrentAdverse m <;> by_cases h1 : HasAnchor m a <;>
    by_cases h2 : AttestationReady m a <;> by_cases h3 : RevocationReady m a <;> simp_all

theorem historical_claim_ok (h : Corresponds f m a) :
    verify.verdict.historical_claim f (decide (SealsPinned f)) =
      ok (encOf (decideClaim m a .historicalAuthorized)) := by
  have hs : SealsPinned f ↔ RecordsProven m a := h.seals
  unfold verify.verdict.historical_claim
  simp only [historical_adverse_ok h, historical_ready_ok h, bind_tc_ok, decision_ok,
    model_historical, h.selected, bool_eq_decide h.integrity]
  by_cases hT : m.temporalPolicy = true <;> by_cases hI : IntegrityP m <;>
    by_cases hA : HistoricalRefutation m <;> by_cases hR : RecordsProven m a <;>
    by_cases h1 : RoleContributorsProven m a <;> by_cases h2 : m.histUseValid = true <;>
    by_cases h3 : SnapshotReady m a <;> by_cases h4 : PolicyEvidence m a <;> simp_all

theorem complete_claim_ok (h : Corresponds f m a) (c : Prop) [Decidable c] :
    verify.verdict.complete_claim f (decide (SealsPinned f)) (decide (LatestAnchored f))
        (decide (RevocationReady m a)) (decide c) =
      ok (encOf (if ¬ IntegrityP m ∨ CurrentAdverse m then .refuted
        else if (RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
            PolicyEvidence m a ∧ UseSurfaceValid m) ∧
            (RevocationReady m a ∧ AttestationReady m a) ∧ c then .satisfied
        else .insufficient)) := by
  have hs : SealsPinned f ↔ RecordsProven m a := h.seals
  have hl : LatestAnchored f ↔ HasAnchor m a := h.anchored
  have hat : AttestationReady m a → HasAnchor m a := fun h => h.2
  unfold verify.verdict.complete_claim
  simp only [authorization_refuted_ok h, authorized_ok h, temporal_ok h, bind_tc_ok, decision_ok,
    ite_ok_and]
  by_cases hR : ¬ IntegrityP m ∨ CurrentAdverse m
  · simp [hR]
  · have hI : IntegrityP m := by simp only [not_or, not_not] at hR; exact hR.1
    have e : ((decide (IntegrityP m ∧ decide (SealsPinned f) = true ∧ RoleContributorsProven m a ∧
          decide (RevocationReady m a) = true ∧ PolicyEvidence m a ∧ UseSurfaceValid m) &&
        (decide (decide (LatestAnchored f) = true ∧ AttestationReady m a ∧
          decide (RevocationReady m a) = true) && decide c)) = true) ↔
        ((RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
          PolicyEvidence m a ∧ UseSurfaceValid m) ∧
          (RevocationReady m a ∧ AttestationReady m a) ∧ c) := by
      simp only [Bool.and_eq_true, decide_eq_true_eq]
      constructor
      · rintro ⟨⟨-, hp, h1, h2, h3, h4⟩, ⟨-, h5, -⟩, h6⟩
        exact ⟨⟨hs.mp hp, h1, h2, h3, h4⟩, ⟨h2, h5⟩, h6⟩
      · rintro ⟨⟨hp, h1, h2, h3, h4⟩, ⟨-, h5⟩, h6⟩
        exact ⟨⟨hI, hs.mpr hp, h1, h2, h3, h4⟩, ⟨hl.mpr (hat h5), h5, h2⟩, h6⟩
    rw [decide_eq_false hR]
    simp only [Bool.false_eq_true, ↓reduceIte, hR]
    by_cases hS : (RecordsProven m a ∧ RoleContributorsProven m a ∧ RevocationReady m a ∧
          PolicyEvidence m a ∧ UseSurfaceValid m) ∧ (RevocationReady m a ∧ AttestationReady m a) ∧ c
    · rw [if_pos (e.mpr hS), if_pos hS]; rfl
    · rw [if_neg (fun x => hS (e.mp x)), if_neg hS]; rfl

end

/-- The claim results as a function of the claim. -/
def resultOf (r : verify.verdict.ClaimResults) : Claim → verify.verdict.ClaimDecision
  | .integrity => r.integrity
  | .authenticated => r.authenticated
  | .authorized => r.authorized
  | .historicalAuthorized => r.historical_authorized_as_of_snapshot
  | .temporal => r.temporal
  | .completeBrokered => r.complete_brokered
  | .completeIntrospected => r.complete_introspected

/-- **Refinement.** For facts that correspond to a model evidence state, the production kernel
returns, and every claim it reports is the model's `decideClaim` on that state; the requested
claim is the caller's, with its decision. -/
theorem decide_claims_refines {f : VF} {m : Fixed} {a : List Attachment}
    (h : Corresponds f m a) :
    ∃ r, verify.verdict.decide_claims f = ok r ∧
      (∀ c, decOf (resultOf r c) = decideClaim m a c) ∧
      r.requested = f.policy.requested ∧
      r.requested_decision = resultOf r (claimOf f.policy.requested) := by
  unfold verify.verdict.decide_claims
  simp only [pinned_record_keys_ok, anchored_latest_ok, revocation_ready_ok h, brokered_ok h,
    introspected_ok h, integrity_claim_ok h, authenticated_claim_ok h, authorized_claim_ok h,
    historical_claim_ok h, temporal_claim_ok h, complete_claim_ok h, bind_tc_ok,
    ← model_completeBrokered, ← model_completeIntrospected]
  cases hr : f.policy.requested <;>
    exact ⟨_, rfl, fun c => by cases c <;> simp [resultOf], rfl, rfl⟩

end Refinement
