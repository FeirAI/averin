import Std

/-!
# Evidence and claim order for the offline verifier

This is a model of the production `verify/verdict.rs` decision boundary, not a proof that
`verify.rs` extracted the right facts. `Fixed` holds signed records/checkpoints, externally
pinned keys and authenticated adverse statements (signed revocation lists, validated commitment
openings, and contradictory verified TSA timestamps). `Attachment` holds positive support that
can disappear: a usable anchor, disclosure, Merkle path or attestation artifact.
Cryptographic validity is represented by the fixed `sealed` and `roleSigned` sets; the
oracle and Rust property corpus check the production extraction against this model.

Removing independently authenticated adverse evidence is outside `support_erasure`: it changes
`Fixed.revoked`, `adverseOpening` or `adverseAnchor` and can remove a real contradiction.
Production must still honor every such item while present.

Plan 009 adds `historicalAuthorized` (`historical_authorized_as_of_snapshot`). Its positive
basis is `db_serialized_v1`: resource-signed receipt ordinals (fixed, inside signed records) and
authenticated revocation cutoffs (fixed adverse statements, like `revoked`) share one ordinal
domain; the signed snapshot (boundary time, high watermark) is a removable attachment. The caller
fixes the policy, evaluation time, maximum age and minimum watermark. Self-reported record times
are modelled as a fixed field no definition consults.
-/

namespace Averin.Verdict

-- The model quantifies only over finite evidence lists. These instances evaluate bounded
-- quantifiers by `List.all`/`List.any`, so the oracle remains executable without choice.
instance listDecidableForallMem {α : Type} (l : List α) (p : α → Prop)
    [DecidablePred p] : Decidable (∀ x ∈ l, p x) :=
  decidable_of_iff (l.all (fun x => decide (p x)) = true) (by
    simp only [List.all_eq_true, decide_eq_true_eq])

instance listDecidableExistsMem {α : Type} (l : List α) (p : α → Prop)
    [DecidablePred p] : Decidable (∃ x ∈ l, p x) :=
  decidable_of_iff (l.any (fun x => decide (p x)) = true) (by
    simp only [List.any_eq_true, decide_eq_true_eq])

structure Record where
  id : Nat
  hash : Nat
  signer : Nat
  roleKey : Nat
  grantId : Nat
  contributesRole : Bool
  grantRecord : Bool
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

/-- A resource-signed authorization receipt. `order` is its authenticated ordinal; `validated`
means every grant/PoP/outcome check passed (for a revoked grant, on the shadow ledger). -/
structure Receipt where
  id : Nat
  grantId : Nat
  order : Option Nat
  validated : Bool
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

structure CapstoneChecks where
  manifest : Bool
  twoPhase : Bool
  noIncompleteIntent : Bool
  uses : List Nat
  matched : List Nat
  popVerified : List Nat
  actionVerified : List Nat
  twoPhaseCompleted : List Nat
  taxonomy : Bool
  grantLog : Bool
  attestation : Bool
  noViolation : Bool
  noPending : Bool
  boundedReuse : Bool
  cosignatures : Bool
  delegation : Bool
  revocation : Bool
  federation : Bool
  coverage : Bool
  nativePresent : Bool
  introspection : Bool
  deriving Repr

inductive Attachment where
  | anchor (checkpoint : Nat) (time : Nat)
  | disclosure (record : Nat)
  | path (grant : Nat)
  | attestation (checkpoint : Nat)
  -- A signed revocation snapshot: database boundary time and authorization high watermark.
  -- `merkle` snapshots certify a grant's state only through a per-grant `path`.
  | snapshot (boundary : Nat) (watermark : Nat) (merkle : Bool)
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

inductive Claim where
  | integrity | authenticated | authorized | historicalAuthorized | temporal
  | completeBrokered | completeIntrospected
  deriving DecidableEq, BEq, Repr

inductive RevocationMode where
  | pinned | disclosed | merkle | both
  deriving DecidableEq, Repr

structure Policy where
  requested : Claim
  revocation : RevocationMode
  requireDisclosure : Bool
  requireAttestation : Bool
  deriving Repr

structure Fixed where
  records : List Record
  sealed : List Nat
  roleSigned : List Nat
  pinnedSigners : List Nat
  pinnedRoles : List Nat
  checkpoint : Nat
  changedAt : Option Nat
  revoked : List Nat
  usedGrantIds : List Nat
  -- A validated contradictory commitment opening is adverse evidence, like a signed issuer list.
  adverseOpening : Bool
  -- Verified TSA anchors with reversed or noncanonical time also contradict temporal authority.
  adverseAnchor : Bool
  revocationIssuerPinned : Bool
  disclosedFresh : Bool
  merkleFresh : Bool
  policy : Policy
  -- Checked brokered PoP/join or resource-signed introspection pass, respectively.
  brokeredUseValid : Bool
  introspectedUseValid : Bool
  capstone : CapstoneChecks
  -- Plan 009. The caller selected `db_serialized_v1`, with its clock and bounds.
  temporalPolicy : Bool
  evalTime : Nat
  maxAge : Nat
  minWatermark : Nat
  receipts : List Receipt
  -- Authenticated prospective revocations `(grant, cutoff)`; total ones are `revoked`.
  cutoffs : List (Nat × Nat)
  -- The non-ordering use obligations of the historical view (joins, PoP, taxonomy, pending).
  histUseValid : Bool
  -- A checked contradiction among revocation-blocked receipts, or an outcome signing another
  -- ordinal than its intent.
  historicalContradiction : Bool
  -- Record-asserted times (`agent_ts`, `used_at`, `received_ts`). Never consulted.
  selfTimes : List (Nat × Nat)
  deriving Repr

def CommittedContradiction (f : Fixed) : Prop :=
  ∃ r ∈ f.records, ∃ s ∈ f.records,
    r.grantRecord = true ∧ s.grantRecord = true ∧
    r.grantId = s.grantId ∧ r.hash ≠ s.hash

instance (f : Fixed) : Decidable (CommittedContradiction f) := by
  unfold CommittedContradiction
  infer_instance

def HasAnchor (f : Fixed) (a : List Attachment) : Prop :=
  ∃ x ∈ a, match x with
    | .anchor checkpoint _ => checkpoint = f.checkpoint
    | _ => False

instance (f : Fixed) (a : List Attachment) : Decidable (HasAnchor f a) := by
  unfold HasAnchor
  letI : DecidablePred (fun x : Attachment => match x with
      | .anchor checkpoint _ => checkpoint = f.checkpoint
      | _ => False) := fun x => by cases x <;> infer_instance
  exact listDecidableExistsMem a _

def KeyHonored (f : Fixed) (a : List Attachment) : Prop :=
  match f.changedAt with
  | none => True
  | some change => ∃ x ∈ a, match x with
      | .anchor checkpoint time => checkpoint = f.checkpoint ∧ time ≤ change
      | _ => False

instance (f : Fixed) (a : List Attachment) : Decidable (KeyHonored f a) := by
  unfold KeyHonored
  cases f.changedAt with
  | none => infer_instance
  | some change =>
      letI : DecidablePred (fun x : Attachment => match x with
          | .anchor checkpoint time => checkpoint = f.checkpoint ∧ time ≤ change
          | _ => False) := fun x => by cases x <;> infer_instance
      exact listDecidableExistsMem a _

def RecordProven (f : Fixed) (a : List Attachment) (r : Record) : Prop :=
  r ∈ f.records ∧ r.id ∈ f.sealed ∧ r.signer ∈ f.pinnedSigners ∧ KeyHonored f a

instance (f : Fixed) (a : List Attachment) (r : Record) :
    Decidable (RecordProven f a r) := by
  unfold RecordProven
  infer_instance

def RoleProven (f : Fixed) (a : List Attachment) (r : Record) : Prop :=
  RecordProven f a r ∧ r.id ∈ f.roleSigned ∧ r.roleKey ∈ f.pinnedRoles

instance (f : Fixed) (a : List Attachment) (r : Record) :
    Decidable (RoleProven f a r) := by
  unfold RoleProven
  infer_instance

def DisclosureReady (f : Fixed) (a : List Attachment) : Prop :=
  f.policy.requireDisclosure = false ∨
    (∃ r ∈ f.records, r.grantRecord = true) ∧
      ∀ r ∈ f.records, r.grantRecord = true → .disclosure r.id ∈ a

instance (f : Fixed) (a : List Attachment) : Decidable (DisclosureReady f a) := by
  unfold DisclosureReady
  infer_instance

def PathReady (f : Fixed) (a : List Attachment) : Prop :=
  ∀ gid ∈ f.usedGrantIds, .path gid ∈ a

instance (f : Fixed) (a : List Attachment) : Decidable (PathReady f a) := by
  unfold PathReady
  infer_instance

def NoAuthenticatedRevocation (f : Fixed) : Prop :=
  ∀ gid ∈ f.usedGrantIds, gid ∉ f.revoked

instance (f : Fixed) : Decidable (NoAuthenticatedRevocation f) := by
  unfold NoAuthenticatedRevocation
  infer_instance

def RevocationReady (f : Fixed) (a : List Attachment) : Prop :=
  match f.policy.revocation with
  | .pinned => f.revocationIssuerPinned = false ∨
      (f.disclosedFresh = true ∧ HasAnchor f a)
  | .disclosed => f.revocationIssuerPinned = true ∧
      f.disclosedFresh = true ∧ HasAnchor f a
  | .merkle => f.revocationIssuerPinned = true ∧
      f.merkleFresh = true ∧ HasAnchor f a ∧ PathReady f a
  | .both => f.revocationIssuerPinned = true ∧
      f.disclosedFresh = true ∧ f.merkleFresh = true ∧
      HasAnchor f a ∧ PathReady f a

instance (f : Fixed) (a : List Attachment) : Decidable (RevocationReady f a) := by
  unfold RevocationReady
  cases f.policy.revocation <;> infer_instance

def AttestationReady (f : Fixed) (a : List Attachment) : Prop :=
  .attestation f.checkpoint ∈ a ∧ HasAnchor f a

instance (f : Fixed) (a : List Attachment) : Decidable (AttestationReady f a) := by
  unfold AttestationReady
  infer_instance

def RoleContributorsProven (f : Fixed) (a : List Attachment) : Prop :=
  (∃ r ∈ f.records, r.grantRecord = true) ∧
  ∀ r ∈ f.records, (r.contributesRole = true ∨ r.grantRecord = true) →
    RoleProven f a r

instance (f : Fixed) (a : List Attachment) : Decidable (RoleContributorsProven f a) := by
  unfold RoleContributorsProven
  infer_instance

def NoAdverseOpening (f : Fixed) : Prop :=
  f.adverseOpening = false ∧ f.adverseAnchor = false

def UseSurfaceValid (f : Fixed) : Prop :=
  f.brokeredUseValid = true ∨ f.introspectedUseValid = true

instance (f : Fixed) : Decidable (UseSurfaceValid f) := by
  unfold UseSurfaceValid
  infer_instance

instance (f : Fixed) : Decidable (NoAdverseOpening f) := by
  unfold NoAdverseOpening
  infer_instance

def CapstoneBase (f : Fixed) : Prop :=
  f.capstone.manifest = true ∧
  f.capstone.twoPhase = true ∧ f.capstone.noIncompleteIntent = true ∧
  (∀ u ∈ f.capstone.uses, u ∈ f.capstone.matched ∧
    u ∈ f.capstone.popVerified ∧ u ∈ f.capstone.actionVerified ∧
    u ∈ f.capstone.twoPhaseCompleted) ∧
  f.capstone.taxonomy = true ∧ f.capstone.grantLog = true ∧
  f.capstone.attestation = true ∧ f.capstone.noViolation = true ∧
  f.capstone.noPending = true ∧ f.capstone.boundedReuse = true ∧
  f.capstone.cosignatures = true ∧ f.capstone.delegation = true ∧
  f.capstone.revocation = true ∧ f.capstone.federation = true ∧
  f.capstone.coverage = true

instance (f : Fixed) : Decidable (CapstoneBase f) := by
  unfold CapstoneBase
  infer_instance

def BrokeredCapstone (f : Fixed) : Prop :=
  CapstoneBase f ∧ f.capstone.uses ≠ [] ∧ f.capstone.nativePresent = false

instance (f : Fixed) : Decidable (BrokeredCapstone f) := by
  unfold BrokeredCapstone
  infer_instance

def IntrospectedCapstone (f : Fixed) : Prop :=
  CapstoneBase f ∧ f.capstone.uses = [] ∧ f.capstone.nativePresent = true ∧
  f.capstone.introspection = true

instance (f : Fixed) : Decidable (IntrospectedCapstone f) := by
  unfold IntrospectedCapstone
  infer_instance

/-- The authenticated ordinal is at or below the snapshot watermark and strictly below every
authenticated cutoff of its grant. Equality with a cutoff is not before it. -/
def OrderedBefore (f : Fixed) (w : Nat) (r : Receipt) : Prop :=
  match r.order with
  | none => False
  | some o => o ≤ w ∧ ∀ p ∈ f.cutoffs, p.1 = r.grantId → o < p.2

instance (f : Fixed) (w : Nat) (r : Receipt) : Decidable (OrderedBefore f w r) := by
  unfold OrderedBefore
  cases r.order <;> infer_instance

def ProvenBefore (f : Fixed) (w : Nat) (r : Receipt) : Prop :=
  r.validated = true ∧ r.grantId ∉ f.revoked ∧ OrderedBefore f w r

instance (f : Fixed) (w : Nat) (r : Receipt) : Decidable (ProvenBefore f w r) := by
  unfold ProvenBefore
  infer_instance

/-- An authenticated ordinal at or after an authenticated cutoff of the same grant. -/
def AtOrAfter (f : Fixed) (r : Receipt) : Prop :=
  match r.order with
  | none => False
  | some o => ∃ p ∈ f.cutoffs, p.1 = r.grantId ∧ p.2 ≤ o

instance (f : Fixed) (r : Receipt) : Decidable (AtOrAfter f r) := by
  unfold AtOrAfter
  cases r.order <;> infer_instance

def HistoricalAdverse (f : Fixed) : Prop :=
  f.historicalContradiction = true ∨
    ∃ r ∈ f.receipts, r.validated = true ∧ (r.grantId ∈ f.revoked ∨ AtOrAfter f r)

instance (f : Fixed) : Decidable (HistoricalAdverse f) := by
  unfold HistoricalAdverse
  infer_instance

def SnapshotOk (f : Fixed) (a : List Attachment) (b w : Nat) (merkle : Bool) : Prop :=
  b ≤ f.evalTime ∧ f.evalTime ≤ b + f.maxAge ∧ f.minWatermark ≤ w ∧
  (merkle = true → ∀ r ∈ f.receipts, .path r.grantId ∈ a) ∧
  ∀ r ∈ f.receipts, ProvenBefore f w r

instance (f : Fixed) (a : List Attachment) (b w : Nat) (m : Bool) :
    Decidable (SnapshotOk f a b w m) := by
  unfold SnapshotOk
  infer_instance

/-- A fresh signed snapshot under which every receipt is proven before any revocation. -/
def SnapshotReady (f : Fixed) (a : List Attachment) : Prop :=
  ∃ x ∈ a, match x with
    | .snapshot b w m => SnapshotOk f a b w m
    | _ => False

instance (f : Fixed) (a : List Attachment) : Decidable (SnapshotReady f a) := by
  unfold SnapshotReady
  letI : DecidablePred (fun x : Attachment => match x with
      | .snapshot b w m => SnapshotOk f a b w m
      | _ => False) := fun x => by cases x <;> infer_instance
  exact listDecidableExistsMem a _

-- A validated fact has an evidence derivation. In particular, an embedded key cannot build
-- `authenticated`: `RecordProven` requires membership in the fixed external pin set.
inductive Supports (f : Fixed) (a : List Attachment) : Claim → Prop where
  | integrity (h : f.records ≠ []) (hs : ∀ r ∈ f.records, r.id ∈ f.sealed) : Supports f a .integrity
  | authenticated (hi : Supports f a .integrity)
      (hp : ∀ r ∈ f.records, RecordProven f a r) : Supports f a .authenticated
  | authorized (ha : Supports f a .authenticated)
      (hr : RoleContributorsProven f a)
      (hu : UseSurfaceValid f)
      (hc : ¬ CommittedContradiction f) (hn : NoAuthenticatedRevocation f)
      (ho : NoAdverseOpening f)
      (hv : RevocationReady f a) (hd : DisclosureReady f a)
      (hat : f.policy.requireAttestation = false ∨ AttestationReady f a) :
      Supports f a .authorized
  | historicalAuthorized (ha : Supports f a .authenticated)
      (hsel : f.temporalPolicy = true)
      (hr : RoleContributorsProven f a) (hu : f.histUseValid = true)
      (hc : ¬ CommittedContradiction f) (ho : NoAdverseOpening f)
      (hh : ¬ HistoricalAdverse f) (hs : SnapshotReady f a) (hd : DisclosureReady f a)
      (hat : f.policy.requireAttestation = false ∨ AttestationReady f a) :
      Supports f a .historicalAuthorized
  | temporal (hc : ¬ CommittedContradiction f)
      (hn : NoAuthenticatedRevocation f) (ho : NoAdverseOpening f)
      (hv : RevocationReady f a) (hat : AttestationReady f a) : Supports f a .temporal
  | completeBrokered (ha : Supports f a .authorized)
      (ht : Supports f a .temporal) (hc : BrokeredCapstone f) : Supports f a .completeBrokered
  | completeIntrospected (ha : Supports f a .authorized)
      (ht : Supports f a .temporal) (hc : IntrospectedCapstone f) : Supports f a .completeIntrospected

def Erased (small large : List Attachment) : Prop :=
  ∀ x, x ∈ small → x ∈ large

/-! ## Executable model, evaluated by the verdict oracle -/

def IntegrityP (f : Fixed) : Prop :=
  f.records ≠ [] ∧ ∀ r ∈ f.records, r.id ∈ f.sealed

instance (f : Fixed) : Decidable (IntegrityP f) := by
  unfold IntegrityP
  infer_instance

def AuthenticatedP (f : Fixed) (a : List Attachment) : Prop :=
  IntegrityP f ∧ ∀ r ∈ f.records, RecordProven f a r

instance (f : Fixed) (a : List Attachment) : Decidable (AuthenticatedP f a) := by
  unfold AuthenticatedP
  infer_instance

def AuthorizedP (f : Fixed) (a : List Attachment) : Prop :=
  AuthenticatedP f a ∧ RoleContributorsProven f a ∧ UseSurfaceValid f ∧
  ¬ CommittedContradiction f ∧ NoAuthenticatedRevocation f ∧ NoAdverseOpening f ∧
  RevocationReady f a ∧ DisclosureReady f a ∧
  (f.policy.requireAttestation = false ∨ AttestationReady f a)

instance (f : Fixed) (a : List Attachment) : Decidable (AuthorizedP f a) := by
  unfold AuthorizedP
  infer_instance

def HistoricalP (f : Fixed) (a : List Attachment) : Prop :=
  AuthenticatedP f a ∧ f.temporalPolicy = true ∧ RoleContributorsProven f a ∧
  f.histUseValid = true ∧ ¬ CommittedContradiction f ∧ NoAdverseOpening f ∧
  ¬ HistoricalAdverse f ∧ SnapshotReady f a ∧ DisclosureReady f a ∧
  (f.policy.requireAttestation = false ∨ AttestationReady f a)

instance (f : Fixed) (a : List Attachment) : Decidable (HistoricalP f a) := by
  unfold HistoricalP
  infer_instance

def TemporalP (f : Fixed) (a : List Attachment) : Prop :=
  ¬ CommittedContradiction f ∧ NoAuthenticatedRevocation f ∧
  NoAdverseOpening f ∧ RevocationReady f a ∧ AttestationReady f a

instance (f : Fixed) (a : List Attachment) : Decidable (TemporalP f a) := by
  unfold TemporalP
  infer_instance

/-- Finite evidence relation evaluated by the oracle. The signature/pin/anchor derivations
are inside this predicate; a caller cannot provide an unqualified `complete` Boolean. -/
def SupportP (f : Fixed) (a : List Attachment) : Claim → Prop
  | .integrity => IntegrityP f
  | .authenticated => AuthenticatedP f a
  | .authorized => AuthorizedP f a
  | .historicalAuthorized => HistoricalP f a
  | .temporal => TemporalP f a
  | .completeBrokered => AuthorizedP f a ∧ TemporalP f a ∧ BrokeredCapstone f
  | .completeIntrospected => AuthorizedP f a ∧ TemporalP f a ∧ IntrospectedCapstone f

def supportB (f : Fixed) (a : List Attachment) : Claim → Bool
  | .integrity => decide (IntegrityP f)
  | .authenticated => decide (AuthenticatedP f a)
  | .authorized => decide (AuthorizedP f a)
  | .historicalAuthorized => decide (HistoricalP f a)
  | .temporal => decide (TemporalP f a)
  | .completeBrokered => decide (AuthorizedP f a ∧ TemporalP f a ∧ BrokeredCapstone f)
  | .completeIntrospected => decide (AuthorizedP f a ∧ TemporalP f a ∧ IntrospectedCapstone f)

theorem authorizedP_iff (f : Fixed) (a : List Attachment) :
    AuthorizedP f a ↔ Supports f a .authorized := by
  constructor
  · rintro ⟨ha, hr, hu, hc, hn, ho, hv, hd, hp⟩
    exact .authorized (.authenticated (.integrity ha.1.1 ha.1.2) ha.2)
      hr hu hc hn ho hv hd hp
  · intro h
    cases h with
    | authorized ha hr hu hc hn ho hv hd hp =>
        cases ha with
        | authenticated hi hrec =>
            cases hi with
            | integrity hne hs => exact ⟨⟨⟨hne, hs⟩, hrec⟩, hr, hu, hc, hn, ho, hv, hd, hp⟩

theorem historicalP_iff (f : Fixed) (a : List Attachment) :
    HistoricalP f a ↔ Supports f a .historicalAuthorized := by
  constructor
  · rintro ⟨ha, hsel, hr, hu, hc, ho, hh, hs, hd, hat⟩
    exact .historicalAuthorized (.authenticated (.integrity ha.1.1 ha.1.2) ha.2)
      hsel hr hu hc ho hh hs hd hat
  · intro h
    cases h with
    | historicalAuthorized ha hsel hr hu hc ho hh hs hd hat =>
        cases ha with
        | authenticated hi hrec =>
            cases hi with
            | integrity hne hs' =>
                exact ⟨⟨⟨hne, hs'⟩, hrec⟩, hsel, hr, hu, hc, ho, hh, hs, hd, hat⟩

/-- The executable finite-evidence predicate and the inductive proof claims agree. -/
theorem supportP_iff (f : Fixed) (a : List Attachment) (c : Claim) :
    SupportP f a c ↔ Supports f a c := by
  constructor
  · intro h
    cases c with
    | integrity => exact .integrity h.1 h.2
    | authenticated => exact .authenticated (.integrity h.1.1 h.1.2) h.2
    | authorized =>
        exact (authorizedP_iff f a).mp h
    | historicalAuthorized => exact (historicalP_iff f a).mp h
    | temporal => exact .temporal h.1 h.2.1 h.2.2.1 h.2.2.2.1 h.2.2.2.2
    | completeBrokered =>
        rcases h with ⟨ha, ht, hb⟩
        exact .completeBrokered ((authorizedP_iff f a).mp ha)
          (.temporal ht.1 ht.2.1 ht.2.2.1 ht.2.2.2.1 ht.2.2.2.2) hb
    | completeIntrospected =>
        rcases h with ⟨ha, ht, hb⟩
        exact .completeIntrospected ((authorizedP_iff f a).mp ha)
          (.temporal ht.1 ht.2.1 ht.2.2.1 ht.2.2.2.1 ht.2.2.2.2) hb
  · intro h
    cases h with
    | integrity hn hs => exact ⟨hn, hs⟩
    | authenticated hi hp =>
        cases hi with
        | integrity hn hs => exact ⟨⟨hn, hs⟩, hp⟩
    | authorized ha hr hu hc hn ho hv hd hp =>
        exact (authorizedP_iff f a).mpr (.authorized ha hr hu hc hn ho hv hd hp)
    | historicalAuthorized ha hsel hr hu hc ho hh hs hd hat =>
        exact (historicalP_iff f a).mpr (.historicalAuthorized ha hsel hr hu hc ho hh hs hd hat)
    | temporal hc hn ho hv hat => exact ⟨hc, hn, ho, hv, hat⟩
    | completeBrokered ha ht hb =>
        cases ht with
        | temporal hc hn ho hv hat =>
            exact ⟨(authorizedP_iff f a).mpr ha, ⟨hc, hn, ho, hv, hat⟩, hb⟩
    | completeIntrospected ha ht hb =>
        cases ht with
        | temporal hc hn ho hv hat =>
            exact ⟨(authorizedP_iff f a).mpr ha, ⟨hc, hn, ho, hv, hat⟩, hb⟩

theorem supportB_iff (f : Fixed) (a : List Attachment) (c : Claim) :
    supportB f a c = true ↔ Supports f a c := by
  cases c with
  | integrity => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .integrity)
  | authenticated => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .authenticated)
  | authorized => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .authorized)
  | historicalAuthorized => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .historicalAuthorized)
  | temporal => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .temporal)
  | completeBrokered => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .completeBrokered)
  | completeIntrospected => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .completeIntrospected)

inductive Decision where
  | satisfied | insufficient | refuted
  deriving DecidableEq, Repr

/-- The historical claim is never positive under the strict policy. When selected, its adverse
evidence is the per-receipt ordering (and total revocations of validated receipts), not bare
revocation membership: a use of a prospectively revoked grant proven before its cutoff is not a
contradiction of this claim, although current revocation still refutes `authorized`. -/
def decideHistorical (f : Fixed) (a : List Attachment) : Decision :=
  if f.temporalPolicy = false then .insufficient
  else if CommittedContradiction f ∨ HistoricalAdverse f ∨
      f.adverseOpening = true ∨ f.adverseAnchor = true then .refuted
  else if !supportB f a .integrity then .refuted
  else if supportB f a .historicalAuthorized then .satisfied else .insufficient

def decideClaim (f : Fixed) (a : List Attachment) (c : Claim) : Decision :=
  if c = .historicalAuthorized then decideHistorical f a
  else if (c = .authorized ∨ c = .temporal ∨ c = .completeBrokered ∨
      c = .completeIntrospected) ∧
      (CommittedContradiction f ∨ ¬ NoAuthenticatedRevocation f ∨
        f.adverseOpening = true ∨ f.adverseAnchor = true) then .refuted
  else if c != .temporal && !supportB f a .integrity then .refuted
  else if supportB f a c then .satisfied else .insufficient

/-- A positive executable verdict always has an inductive evidence derivation. -/
theorem decideClaim_satisfied_only (f : Fixed) (a : List Attachment) (c : Claim)
    (h : decideClaim f a c = .satisfied) : Supports f a c := by
  unfold decideClaim at h
  split at h
  · subst c
    unfold decideHistorical at h
    split at h
    · contradiction
    split at h
    · contradiction
    split at h
    · contradiction
    split at h
    · exact (supportB_iff f a .historicalAuthorized).mp (by assumption)
    · contradiction
  split at h
  · contradiction
  split at h
  · contradiction
  split at h
  · exact (supportB_iff f a c).mp (by assumption)
  · contradiction

theorem hasAnchor_mono {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (ha : HasAnchor f small) : HasAnchor f large := by
  obtain ⟨x, hx, ht⟩ := ha
  exact ⟨x, h _ hx, ht⟩

theorem keyHonored_mono {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (hk : KeyHonored f small) : KeyHonored f large := by
  cases hs : f.changedAt with
  | none => simp [KeyHonored, hs]
  | some change =>
      simp only [KeyHonored, hs] at hk ⊢
      obtain ⟨x, hx, ht⟩ := hk
      exact ⟨x, h _ hx, ht⟩

theorem recordProven_mono {f : Fixed} {small large : List Attachment} {r : Record}
    (h : Erased small large) (hr : RecordProven f small r) : RecordProven f large r := by
  exact ⟨hr.1, hr.2.1, hr.2.2.1, keyHonored_mono h hr.2.2.2⟩

theorem roleProven_mono {f : Fixed} {small large : List Attachment} {r : Record}
    (h : Erased small large) (hr : RoleProven f small r) : RoleProven f large r := by
  exact ⟨recordProven_mono h hr.1, hr.2.1, hr.2.2⟩

theorem disclosureReady_mono {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (hr : DisclosureReady f small) : DisclosureReady f large := by
  rcases hr with hn | hp
  · exact Or.inl hn
  · exact Or.inr ⟨hp.1, fun r hm hg => h _ (hp.2 r hm hg)⟩

theorem pathReady_mono {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (hr : PathReady f small) : PathReady f large := by
  exact fun gid hm => h _ (hr gid hm)

theorem revocationReady_mono {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (hr : RevocationReady f small) :
    RevocationReady f large := by
  cases hm : f.policy.revocation with
  | pinned =>
      simp only [RevocationReady, hm] at hr ⊢
      rcases hr with hnone | ⟨hfresh, ha⟩
      · exact Or.inl hnone
      · exact Or.inr ⟨hfresh, hasAnchor_mono h ha⟩
  | disclosed =>
      simp only [RevocationReady, hm] at hr ⊢
      exact ⟨hr.1, hr.2.1, hasAnchor_mono h hr.2.2⟩
  | merkle =>
      simp only [RevocationReady, hm] at hr ⊢
      exact ⟨hr.1, hr.2.1, hasAnchor_mono h hr.2.2.1,
        pathReady_mono h hr.2.2.2⟩
  | both =>
      simp only [RevocationReady, hm] at hr ⊢
      exact ⟨hr.1, hr.2.1, hr.2.2.1,
        hasAnchor_mono h hr.2.2.2.1, pathReady_mono h hr.2.2.2.2⟩

theorem attestationReady_mono {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (hr : AttestationReady f small) :
    AttestationReady f large :=
  ⟨h _ hr.1, hasAnchor_mono h hr.2⟩

theorem roleContributors_mono {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (hr : RoleContributorsProven f small) :
    RoleContributorsProven f large :=
  ⟨hr.1, fun r hm hrole => roleProven_mono h (hr.2 r hm hrole)⟩

theorem snapshotReady_mono {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (hr : SnapshotReady f small) : SnapshotReady f large := by
  obtain ⟨x, hx, hs⟩ := hr
  refine ⟨x, h _ hx, ?_⟩
  cases x with
  | snapshot b w m =>
      exact ⟨hs.1, hs.2.1, hs.2.2.1, fun hm r hr => h _ (hs.2.2.2.1 hm r hr), hs.2.2.2.2⟩
  | _ => exact hs

/-- Deleting unsigned support cannot add any claim, while authenticated authority statements
remain fixed. This is an inclusion theorem on supported claims, not a textual status order. -/
theorem support_erasure {f : Fixed} {small large : List Attachment}
    (h : Erased small large) {c : Claim} (hc : Supports f small c) : Supports f large c := by
  induction hc with
  | integrity hn hs => exact .integrity hn hs
  | authenticated hi hp ih =>
      exact .authenticated ih (fun r hr => recordProven_mono h (hp r hr))
  | authorized ha hr hu hc hn ho hv hd hat ih =>
      exact .authorized ih (roleContributors_mono h hr) hu hc hn ho
        (revocationReady_mono h hv) (disclosureReady_mono h hd)
        (hat.elim Or.inl (fun ha => Or.inr (attestationReady_mono h ha)))
  | historicalAuthorized ha hsel hr hu hc ho hh hs hd hat ih =>
      exact .historicalAuthorized ih hsel (roleContributors_mono h hr) hu hc ho hh
        (snapshotReady_mono h hs) (disclosureReady_mono h hd)
        (hat.elim Or.inl (fun ha => Or.inr (attestationReady_mono h ha)))
  | temporal hc hn ho hv hat =>
      exact .temporal hc hn ho (revocationReady_mono h hv) (attestationReady_mono h hat)
  | completeBrokered ha ht hc iha iht => exact .completeBrokered iha iht hc
  | completeIntrospected ha ht hc iha iht => exact .completeIntrospected iha iht hc

/-- The same positive-claim order applies to the executable oracle, not just `Supports`. -/
theorem supportB_erasure {f : Fixed} {small large : List Attachment} {c : Claim}
    (h : Erased small large) (hc : supportB f small c = true) :
    supportB f large c = true :=
  (supportB_iff f large c).mpr (support_erasure h ((supportB_iff f small c).mp hc))

/-- A contradiction from committed signed records refutes the actual executable decision
for every attachment set, even after arbitrary unsigned attachments disappear. -/
theorem committed_contradiction_refuted (f : Fixed) (a : List Attachment)
    (h : CommittedContradiction f) :
    decideClaim f a .authorized = .refuted ∧
    decideClaim f a .completeBrokered = .refuted ∧
    decideClaim f a .completeIntrospected = .refuted := by
  simp [decideClaim, h]

theorem committed_contradiction_refutes_authorization (f : Fixed) (a : List Attachment)
    (h : CommittedContradiction f) : ¬ Supports f a .authorized := by
  intro hs
  cases hs with
  | authorized _ _ _ hc _ _ _ _ _ => exact hc h

theorem committed_contradiction_refutes_capstones (f : Fixed) (a : List Attachment)
    (h : CommittedContradiction f) :
    ¬ Supports f a .completeBrokered ∧ ¬ Supports f a .completeIntrospected := by
  constructor
  · intro hs
    cases hs with
    | completeBrokered ha _ _ => exact committed_contradiction_refutes_authorization f a h ha
  · intro hs
    cases hs with
    | completeIntrospected ha _ _ => exact committed_contradiction_refutes_authorization f a h ha

/-- The capstone inverts to the actual evidence obligations, including externally pinned
record signers and roles. No arbitrary Boolean `complete` input can create these premises. -/
theorem capstone_prerequisites {f : Fixed} {a : List Attachment}
    (hc : Supports f a .completeBrokered) :
    (∀ r ∈ f.records, r.signer ∈ f.pinnedSigners) ∧
    (∀ r ∈ f.records, (r.contributesRole = true ∨ r.grantRecord = true) →
      r.roleKey ∈ f.pinnedRoles) ∧
    RevocationReady f a ∧ AttestationReady f a ∧
    ¬ CommittedContradiction f ∧ BrokeredCapstone f := by
  cases hc with
  | completeBrokered ha ht hcap =>
      cases ha with
      | authorized hAuth hr _ hcontra _ _ _ _ _ =>
          cases hAuth with
          | authenticated _ hp =>
              cases ht with
              | temporal _ _ _ hv hat =>
                  exact ⟨(fun r hm => (hp r hm).2.2.1),
                    (fun r hm hrole => (hr.2 r hm hrole).2.2), hv, hat, hcontra, hcap⟩

theorem introspected_capstone_prerequisites {f : Fixed} {a : List Attachment}
    (hc : Supports f a .completeIntrospected) :
    (∀ r ∈ f.records, r.signer ∈ f.pinnedSigners) ∧
    (∀ r ∈ f.records, (r.contributesRole = true ∨ r.grantRecord = true) →
      r.roleKey ∈ f.pinnedRoles) ∧
    RevocationReady f a ∧ AttestationReady f a ∧
    ¬ CommittedContradiction f ∧ IntrospectedCapstone f := by
  cases hc with
  | completeIntrospected ha ht hcap =>
      cases ha with
      | authorized hAuth hr _ hcontra _ _ _ _ _ =>
          cases hAuth with
          | authenticated _ hp =>
              cases ht with
              | temporal _ _ _ hv hat =>
                  exact ⟨(fun r hm => (hp r hm).2.2.1),
                    (fun r hm hrole => (hr.2 r hm hrole).2.2), hv, hat, hcontra, hcap⟩

/-- The executable brokered capstone cannot skip a join, PoP, action, sequence,
attestation, delegation, federation, or coverage prerequisite. -/
theorem brokered_capstone_all_checks {f : Fixed} {a : List Attachment}
    (hc : Supports f a .completeBrokered) :
    f.capstone.manifest = true ∧ f.capstone.twoPhase = true ∧
    f.capstone.noIncompleteIntent = true ∧
    (∀ u ∈ f.capstone.uses, u ∈ f.capstone.matched ∧
      u ∈ f.capstone.popVerified ∧ u ∈ f.capstone.actionVerified ∧
      u ∈ f.capstone.twoPhaseCompleted) ∧
    f.capstone.taxonomy = true ∧ f.capstone.grantLog = true ∧
    f.capstone.attestation = true ∧ f.capstone.noViolation = true ∧
    f.capstone.noPending = true ∧ f.capstone.boundedReuse = true ∧
    f.capstone.cosignatures = true ∧ f.capstone.delegation = true ∧
    f.capstone.revocation = true ∧ f.capstone.federation = true ∧
    f.capstone.coverage = true ∧ f.capstone.uses ≠ [] ∧
    f.capstone.nativePresent = false := by
  cases hc with
  | completeBrokered _ _ hcap =>
      simpa only [BrokeredCapstone, CapstoneBase, and_assoc] using hcap

theorem introspected_capstone_all_checks {f : Fixed} {a : List Attachment}
    (hc : Supports f a .completeIntrospected) :
    CapstoneBase f ∧ f.capstone.uses = [] ∧
    f.capstone.nativePresent = true ∧ f.capstone.introspection = true := by
  cases hc with
  | completeIntrospected _ _ hcap => exact hcap

/-- Fixed pinned key status and change time: deleting anchors never restores trust to a
compromised key. -/
theorem key_status_conservative {f : Fixed} {small large : List Attachment}
    (h : Erased small large) (hk : KeyHonored f small) : KeyHonored f large :=
  keyHonored_mono h hk

/-! ## Plan 009: historical ordering -/

/-- The strict (default) policy never yields a positive historical claim. -/
theorem historical_requires_policy (f : Fixed) (a : List Attachment)
    (h : f.temporalPolicy = false) : decideClaim f a .historicalAuthorized ≠ .satisfied := by
  simp [decideClaim, decideHistorical, h]

/-- A receipt with no authenticated ordinal (stripped order evidence) blocks the claim. -/
theorem historical_requires_order {f : Fixed} {a : List Attachment} {r : Receipt}
    (hr : r ∈ f.receipts) (hn : r.order = none) : ¬ Supports f a .historicalAuthorized := by
  intro hs
  cases hs with
  | historicalAuthorized _ _ _ _ _ _ _ hsnap _ _ =>
      obtain ⟨x, _, hx⟩ := hsnap
      cases x with
      | snapshot b w m =>
          have hp := (hx.2.2.2.2 r hr).2.2
          simp [OrderedBefore, hn] at hp
      | _ => exact hx

/-- Without a snapshot attachment (stripped or never exported) the claim is not supported. -/
theorem historical_requires_snapshot {f : Fixed} {a : List Attachment}
    (hn : ∀ x ∈ a, ∀ b w m, x ≠ .snapshot b w m) : ¬ Supports f a .historicalAuthorized := by
  intro hs
  cases hs with
  | historicalAuthorized _ _ _ _ _ _ _ hsnap _ _ =>
      obtain ⟨x, hx, hok⟩ := hsnap
      cases x with
      | snapshot b w m => exact hn _ hx b w m rfl
      | _ => exact hok

/-- An authenticated ordinal equal to or above an authenticated cutoff refutes the claim. -/
theorem at_or_after_refutes {f : Fixed} {a : List Attachment} {r : Receipt}
    (hr : r ∈ f.receipts) (hv : r.validated = true) (hat : AtOrAfter f r)
    (hsel : f.temporalPolicy = true) : decideClaim f a .historicalAuthorized = .refuted := by
  have hadv : HistoricalAdverse f := Or.inr ⟨r, hr, hv, Or.inr hat⟩
  simp [decideClaim, decideHistorical, hsel, hadv]

/-- A total (compromise or legacy) revocation of a validated receipt's grant refutes the claim,
whatever ordering evidence exists: legacy total revocations stay total. -/
theorem total_revocation_refutes {f : Fixed} {a : List Attachment} {r : Receipt}
    (hr : r ∈ f.receipts) (hv : r.validated = true) (ht : r.grantId ∈ f.revoked)
    (hsel : f.temporalPolicy = true) : decideClaim f a .historicalAuthorized = .refuted := by
  have hadv : HistoricalAdverse f := Or.inr ⟨r, hr, hv, Or.inl ht⟩
  simp [decideClaim, decideHistorical, hsel, hadv]

/-- Cutoffs and receipts share one ordinal domain. An honest snapshot at watermark `w` discloses
exactly the cutoffs allocated at or below `w`. Substituting an earlier honest snapshot cannot turn
a receipt ordered at/after a cutoff into one proven before: either the earlier snapshot contains
the cutoff, or the receipt's ordinal exceeds its watermark. -/
theorem earlier_snapshot_cannot_flip (history : List (Nat × Nat)) (w g o c : Nat)
    (hc : (g, c) ∈ history) (hco : c ≤ o) :
    ¬ (o ≤ w ∧ ∀ p ∈ history.filter (fun p => decide (p.2 ≤ w)), p.1 = g → o < p.2) := by
  rintro ⟨how, hall⟩
  have hmem : (g, c) ∈ history.filter (fun p => decide (p.2 ≤ w)) := by
    simp only [List.mem_filter, decide_eq_true_eq]
    exact ⟨hc, Nat.le_trans hco how⟩
  exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le (hall _ hmem rfl) hco)

/-- Record-asserted times (a self-reported `used_at` or revocation timestamp) cannot change any
claim: replacing them leaves every supported claim unchanged. -/
theorem supports_ignore_self_times {f : Fixed} {a : List Attachment} {c : Claim}
    (t : List (Nat × Nat)) (h : Supports f a c) : Supports { f with selfTimes := t } a c := by
  induction h with
  | integrity hn hs => exact .integrity hn hs
  | authenticated _ hp ih => exact .authenticated ih hp
  | authorized _ hr hu hc hn ho hv hd hat ih => exact .authorized ih hr hu hc hn ho hv hd hat
  | historicalAuthorized _ hsel hr hu hc ho hh hs hd hat ih =>
      exact .historicalAuthorized ih hsel hr hu hc ho hh hs hd hat
  | temporal hc hn ho hv hat => exact .temporal hc hn ho hv hat
  | completeBrokered _ _ hc iha iht => exact .completeBrokered iha iht hc
  | completeIntrospected _ _ hc iha iht => exact .completeIntrospected iha iht hc

theorem self_times_cannot_strengthen {f : Fixed} {a : List Attachment} {c : Claim}
    (t : List (Nat × Nat)) (h : Supports { f with selfTimes := t } a c) :
    Supports f a c := by
  have := supports_ignore_self_times (f := { f with selfTimes := t }) f.selfTimes h
  exact this

end Averin.Verdict
