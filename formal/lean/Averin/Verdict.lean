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
  deriving DecidableEq, BEq, ReflBEq, LawfulBEq, Repr

inductive Claim where
  | integrity | authenticated | authorized | temporal | completeBrokered | completeIntrospected
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
  | .temporal => TemporalP f a
  | .completeBrokered => AuthorizedP f a ∧ TemporalP f a ∧ BrokeredCapstone f
  | .completeIntrospected => AuthorizedP f a ∧ TemporalP f a ∧ IntrospectedCapstone f

def supportB (f : Fixed) (a : List Attachment) : Claim → Bool
  | .integrity => decide (IntegrityP f)
  | .authenticated => decide (AuthenticatedP f a)
  | .authorized => decide (AuthorizedP f a)
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
  | temporal => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .temporal)
  | completeBrokered => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .completeBrokered)
  | completeIntrospected => simpa only [supportB, SupportP, decide_eq_true_eq] using
      (supportP_iff f a .completeIntrospected)

inductive Decision where
  | satisfied | insufficient | refuted
  deriving DecidableEq, Repr

def decideClaim (f : Fixed) (a : List Attachment) (c : Claim) : Decision :=
  if (c = .authorized ∨ c = .temporal ∨ c = .completeBrokered ∨
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

end Averin.Verdict
