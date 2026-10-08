//! Pure claim decision kernel. Inputs are validated facts constructed only by the parent
//! verifier after signature, pin, role, join, and checkpoint checks. The bundle cannot name a
//! claim policy or manufacture this type through the public API.

use crate::canon::CanonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimDecision {
    Satisfied,
    Insufficient,
    Refuted,
}

impl ClaimDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Insufficient => "insufficient",
            Self::Refuted => "refuted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequestedClaim {
    #[default]
    Integrity,
    Authenticated,
    Authorized,
    /// Plan 009: every receipt was authorized as of an authenticated revocation snapshot, ordered
    /// before any applicable prospective cutoff under the caller's `db_serialized_v1` policy.
    HistoricalAuthorizedAsOfSnapshot,
    CompleteBrokered,
    CompleteIntrospected,
}

impl RequestedClaim {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Authenticated => "authenticated",
            Self::Authorized => "authorized",
            Self::HistoricalAuthorizedAsOfSnapshot => "historical_authorized_as_of_snapshot",
            Self::CompleteBrokered => "complete_brokered",
            Self::CompleteIntrospected => "complete_introspected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevocationRequirement {
    /// With pinned issuers, require a fresh disclosed list. Merkle-only and dual-mode
    /// deployments must select their mode explicitly. No bundle field selects the policy.
    #[default]
    Pinned,
    Disclosed,
    Merkle,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClaimPolicy {
    pub requested: RequestedClaim,
    pub revocation: RevocationRequirement,
    pub require_disclosure: bool,
    pub require_attestation: bool,
}

impl ClaimPolicy {
    pub(super) fn parse(opts: &CanonValue) -> Result<Self, String> {
        let Some(raw) = opts.get("claim_policy") else {
            return Ok(Self::default());
        };
        let fields = raw.as_object().ok_or("claim_policy must be an object")?;
        for (key, _) in fields {
            if !matches!(
                key.as_str(),
                "requested" | "revocation" | "require_disclosure" | "require_attestation"
            ) {
                return Err(format!("claim_policy has unknown field {key:?}"));
            }
        }
        let requested = match raw.get("requested") {
            None => RequestedClaim::Integrity,
            Some(CanonValue::Str(s)) if s == "integrity" => RequestedClaim::Integrity,
            Some(CanonValue::Str(s)) if s == "authenticated" => RequestedClaim::Authenticated,
            Some(CanonValue::Str(s)) if s == "authorized" => RequestedClaim::Authorized,
            Some(CanonValue::Str(s)) if s == "historical_authorized_as_of_snapshot" => {
                RequestedClaim::HistoricalAuthorizedAsOfSnapshot
            }
            Some(CanonValue::Str(s)) if s == "complete_brokered" => {
                RequestedClaim::CompleteBrokered
            }
            Some(CanonValue::Str(s)) if s == "complete_introspected" => {
                RequestedClaim::CompleteIntrospected
            }
            _ => return Err("claim_policy.requested is invalid".into()),
        };
        let revocation = match raw.get("revocation") {
            None => RevocationRequirement::Pinned,
            Some(CanonValue::Str(s)) if s == "pinned" => RevocationRequirement::Pinned,
            Some(CanonValue::Str(s)) if s == "disclosed" => RevocationRequirement::Disclosed,
            Some(CanonValue::Str(s)) if s == "merkle" => RevocationRequirement::Merkle,
            Some(CanonValue::Str(s)) if s == "both" => RevocationRequirement::Both,
            _ => return Err("claim_policy.revocation is invalid".into()),
        };
        let bool_field = |name: &str| -> Result<bool, String> {
            match raw.get(name) {
                None => Ok(false),
                Some(CanonValue::Bool(b)) => Ok(*b),
                _ => Err(format!("claim_policy.{name} must be a boolean")),
            }
        };
        Ok(Self {
            requested,
            revocation,
            require_disclosure: bool_field("require_disclosure")?,
            require_attestation: bool_field("require_attestation")?,
        })
    }
}

/// Each `Satisfied` field is a positive claim. The information order is inclusion of the
/// positive claim set; `Insufficient` and `Refuted` grant no claim and remain distinct reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimResults {
    pub integrity: ClaimDecision,
    pub authenticated: ClaimDecision,
    pub authorized: ClaimDecision,
    /// Plan 009. Distinct from `temporal` (anchor/attestation freshness): this is the historical
    /// authorization of every receipt as of the authenticated revocation snapshot.
    pub historical_authorized_as_of_snapshot: ClaimDecision,
    pub temporal: ClaimDecision,
    pub complete_brokered: ClaimDecision,
    pub complete_introspected: ClaimDecision,
    pub requested: RequestedClaim,
    pub requested_decision: ClaimDecision,
}

impl ClaimResults {
    pub(super) fn fatal() -> Self {
        Self {
            integrity: ClaimDecision::Refuted,
            authenticated: ClaimDecision::Refuted,
            authorized: ClaimDecision::Refuted,
            historical_authorized_as_of_snapshot: ClaimDecision::Refuted,
            temporal: ClaimDecision::Refuted,
            complete_brokered: ClaimDecision::Refuted,
            complete_introspected: ClaimDecision::Refuted,
            requested: RequestedClaim::Integrity,
            requested_decision: ClaimDecision::Refuted,
        }
    }

    pub(super) fn to_canon(self) -> CanonValue {
        let field =
            |name: &str, v: ClaimDecision| (name.to_string(), CanonValue::string(v.as_str()));
        CanonValue::object(vec![
            field("integrity", self.integrity),
            field("authenticated", self.authenticated),
            field("authorized", self.authorized),
            field(
                "historical_authorized_as_of_snapshot",
                self.historical_authorized_as_of_snapshot,
            ),
            field("temporal", self.temporal),
            field("complete_brokered", self.complete_brokered),
            field("complete_introspected", self.complete_introspected),
            (
                "requested".into(),
                CanonValue::string(self.requested.as_str()),
            ),
            field("requested_decision", self.requested_decision),
        ])
        .expect("unique claim keys")
    }
}

/// This type and all its fields are invisible outside `verify`. Its constructor receives only
/// outputs of the verifier's checked passes, never fields copied directly from a bundle or a
/// mutable public report. Pinned key identities and signed record hashes are kept for audit.
pub(super) struct PinnedRecordSeal {
    pub(super) record_hash: String,
    pub(super) key_bytes: [u8; 32],
}

pub(super) struct AnchoredCheckpoint {
    pub(super) checkpoint_hash: String,
    pub(super) timestamp: String,
    pub(super) sequence: i64,
}

/// Each field is set by a named production validation pass. The capstone is expanded here so
/// removing any prerequisite changes the executable decision; no opaque `complete` fact exists.
pub(super) struct CapstoneFacts {
    pub(super) manifest: bool,
    pub(super) two_phase: bool,
    pub(super) no_incomplete_intent: bool,
    pub(super) taxonomy: bool,
    pub(super) every_action_verified: bool,
    pub(super) every_pop_reverified: bool,
    pub(super) grant_log: bool,
    pub(super) attestation: bool,
    pub(super) no_violation: bool,
    pub(super) no_pending: bool,
    pub(super) bounded_reuse: bool,
    pub(super) cosignatures: bool,
    pub(super) delegation: bool,
    pub(super) revocation: bool,
    pub(super) federation: bool,
    pub(super) coverage: bool,
    pub(super) brokered_surface: bool,
    pub(super) introspected_surface: bool,
}

impl CapstoneFacts {
    fn base(&self) -> bool {
        self.manifest
            && self.two_phase
            && self.no_incomplete_intent
            && self.taxonomy
            && self.every_action_verified
            && self.every_pop_reverified
            && self.grant_log
            && self.attestation
            && self.no_violation
            && self.no_pending
            && self.bounded_reuse
            && self.cosignatures
            && self.delegation
            && self.revocation
            && self.federation
            && self.coverage
    }
    fn brokered(&self) -> bool {
        self.base() && self.brokered_surface
    }
    fn introspected(&self) -> bool {
        self.base() && self.introspected_surface
    }
}

/// Plan 009 facts, each produced by the checked historical pass in `verify.rs`.
pub(super) struct HistoricalFacts {
    /// The caller selected `db_serialized_v1`. Never derived from the bundle.
    pub(super) selected: bool,
    /// A usable signed v2 snapshot matched the project, the caller's clock, age and watermark.
    pub(super) snapshot_verified: bool,
    /// Every brokered receipt passed the shared validation path (legacy or shadow) and is
    /// `proven_before`; the other brokered-use obligations of `authorized` hold.
    pub(super) brokered_use_valid: bool,
    pub(super) introspected_use_valid: bool,
    /// A validated receipt at/after its cutoff, a receipt of a totally revoked grant, or an
    /// outcome/intent ordinal contradiction.
    pub(super) adverse: bool,
    /// Checked Tier-B contradictions, counting violations among revocation-blocked receipts.
    pub(super) checked_contradiction: bool,
    /// A usable signed v2 disclosed list is present.
    pub(super) v2_list_usable: bool,
    /// A usable signed v2 Merkle root is present.
    pub(super) v2_merkle_usable: bool,
    /// Every receipt's grant has a valid v2 membership or non-membership proof.
    pub(super) merkle_paths_complete: bool,
}

pub(super) struct ValidatedFacts {
    pub(super) historical: HistoricalFacts,
    pub(super) structural_integrity: bool,
    pub(super) record_count: usize,
    pub(super) pinned_record_seals: Vec<PinnedRecordSeal>,
    pub(super) pinned_signer_keys: Vec<[u8; 32]>,
    pub(super) pinned_role_authority: bool,
    pub(super) latest_checkpoint_sequence: i64,
    pub(super) anchors: Vec<AnchoredCheckpoint>,
    pub(super) attestation_valid: bool,
    pub(super) brokered_use_valid: bool,
    pub(super) introspected_use_valid: bool,
    pub(super) capstone: CapstoneFacts,
    /// Contradiction entirely inside fixed signed records/checkpoints, independent of support.
    pub(super) immutable_record_contradiction: bool,
    /// Other contradictions established by checked Tier-B passes (including policy-pinned
    /// external facts). They are still adverse while present but may have a narrower erasure law.
    pub(super) checked_contradiction: bool,
    pub(super) adverse_disclosure: bool,
    /// Contradictory/noncanonical times among independently verified TSA anchors.
    pub(super) adverse_anchor: bool,
    pub(super) revoked_membership: bool,
    pub(super) revocation_issuer_pinned: bool,
    pub(super) disclosed_revocation_fresh: bool,
    pub(super) merkle_revocation_fresh: bool,
    /// Every brokered use and indexed native credential supplied a valid non-membership path
    /// against the checked root. Root freshness alone never certifies a hidden grant set.
    pub(super) merkle_nonmembership_complete: bool,
    pub(super) disclosure_complete: bool,
    pub(super) policy: ClaimPolicy,
}

// The list checks of the kernel are search loops: the loop condition is the search (no closure,
// iterator adapter or early return), so Charon/Aeneas extract them (plan 012,
// `formal/production/Refinement/VerdictLists.lean`).

/// `key` is one of the externally pinned signer keys.
fn key_pinned(keys: &[[u8; 32]], key: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < keys.len() && keys[i] != *key {
        i += 1;
    }
    i < keys.len()
}

/// The seal names a record hash and an externally pinned key.
fn seal_pinned(seal: &PinnedRecordSeal, keys: &[[u8; 32]]) -> bool {
    !seal.record_hash.is_empty() && key_pinned(keys, &seal.key_bytes)
}

/// Every seal names a record hash and an externally pinned key.
fn seals_pinned(seals: &[PinnedRecordSeal], keys: &[[u8; 32]]) -> bool {
    let mut i = 0;
    while i < seals.len() && seal_pinned(&seals[i], keys) {
        i += 1;
    }
    i == seals.len()
}

/// The anchor is a verified TSA anchor of the checkpoint with this sequence.
fn anchors_checkpoint(a: &AnchoredCheckpoint, sequence: i64) -> bool {
    a.sequence == sequence && !a.checkpoint_hash.is_empty() && !a.timestamp.is_empty()
}

/// Some anchor is a verified TSA anchor of the checkpoint with this sequence.
fn anchored_at(anchors: &[AnchoredCheckpoint], sequence: i64) -> bool {
    let mut i = 0;
    while i < anchors.len() && !anchors_checkpoint(&anchors[i], sequence) {
        i += 1;
    }
    i < anchors.len()
}

// The claim decision kernel. Plan 012 extracts every function from here to `decide_claims` from
// this source with Charon/Aeneas and proves each claim function equal to the Lean verdict model's
// `decideClaim` (`formal/production/Refinement/Verdict.lean`), so the model's support-erasure and
// claim-order theorems hold for this code. Keep it in the extractable subset: plain search loops,
// small helper functions, no closures, iterator adapters or derived `PartialEq`. A function that
// takes `f` calls its helpers before it branches on a field of `f` (otherwise Aeneas passes a
// rebuilt `f` to the helper), a negation is kept first in a disjunction (Aeneas mistypes a
// trailing `!x` operand as `Prop`), and a conjunction with a `bool` parameter uses the
// non-short-circuit `&`/`|` (Aeneas cannot join that branch; every operand is a plain value, so
// the result is the same).

/// A claim is refuted by fixed adverse evidence, else satisfied by its support, else insufficient.
fn decision(refuted: bool, satisfied: bool) -> ClaimDecision {
    if refuted {
        ClaimDecision::Refuted
    } else if satisfied {
        ClaimDecision::Satisfied
    } else {
        ClaimDecision::Insufficient
    }
}

/// Require one externally pinned signing key for every verified record, with the record hash
/// bound to that exact key. The vector is emitted only after the seal check passes.
fn pinned_record_keys(f: &ValidatedFacts) -> bool {
    f.record_count > 0
        && f.pinned_record_seals.len() == f.record_count
        && seals_pinned(&f.pinned_record_seals, &f.pinned_signer_keys)
}

/// Current revocation readiness under the caller's revocation mode.
fn revocation_ready(f: &ValidatedFacts) -> bool {
    match f.policy.revocation {
        RevocationRequirement::Pinned => {
            !f.revocation_issuer_pinned || f.disclosed_revocation_fresh
        }
        RevocationRequirement::Disclosed => {
            f.revocation_issuer_pinned && f.disclosed_revocation_fresh
        }
        RevocationRequirement::Merkle => {
            f.revocation_issuer_pinned
                && f.merkle_revocation_fresh
                && f.merkle_nonmembership_complete
        }
        RevocationRequirement::Both => {
            f.revocation_issuer_pinned
                && f.disclosed_revocation_fresh
                && f.merkle_revocation_fresh
                && f.merkle_nonmembership_complete
        }
    }
}

/// Authenticated adverse evidence against current authorization, the temporal claim and the
/// capstones.
fn adverse(f: &ValidatedFacts) -> bool {
    f.immutable_record_contradiction
        || f.checked_contradiction
        || f.revoked_membership
        || f.adverse_disclosure
        || f.adverse_anchor
}

/// The caller's disclosure and attestation requirements, shared by `authorized` and the
/// historical claim.
fn policy_evidence_ready(f: &ValidatedFacts) -> bool {
    (!f.policy.require_disclosure || f.disclosure_complete)
        && (!f.policy.require_attestation || f.attestation_valid)
}

/// Every obligation of `authorized` beyond authentication and the absence of adverse evidence.
fn authorization_ready(f: &ValidatedFacts, revocation: bool) -> bool {
    f.pinned_role_authority
        && revocation
        && policy_evidence_ready(f)
        && (f.brokered_use_valid || f.introspected_use_valid)
}

/// `authorized`, `complete_brokered` and `complete_introspected` are refuted by adverse evidence
/// or with `integrity`.
fn authorization_refuted(f: &ValidatedFacts) -> bool {
    let adverse = adverse(f);
    !f.structural_integrity || adverse
}

/// The positive `authorized` claim (when it is not refuted).
fn authorized(f: &ValidatedFacts, pinned_record_keys: bool, revocation: bool) -> bool {
    let ready = authorization_ready(f, revocation);
    f.structural_integrity && pinned_record_keys && ready
}

/// The positive `temporal` claim (when it is not refuted).
fn temporal(f: &ValidatedFacts, anchored_latest: bool, revocation: bool) -> bool {
    anchored_latest && f.attestation_valid && revocation
}

/// Plan 009: the caller's revocation mode, applied to the v2 snapshot evidence.
fn historical_revocation(f: &ValidatedFacts) -> bool {
    let h = &f.historical;
    f.revocation_issuer_pinned
        && match f.policy.revocation {
            RevocationRequirement::Pinned => true,
            RevocationRequirement::Disclosed => h.v2_list_usable,
            RevocationRequirement::Merkle => h.v2_merkle_usable && h.merkle_paths_complete,
            RevocationRequirement::Both => {
                h.v2_list_usable && h.v2_merkle_usable && h.merkle_paths_complete
            }
        }
}

/// Plan 009: adverse evidence against the historical claim. The per-receipt ordering and the
/// historical contradiction count replace current revocation membership and the legacy count.
fn historical_adverse(f: &ValidatedFacts) -> bool {
    f.immutable_record_contradiction
        || f.historical.checked_contradiction
        || f.adverse_disclosure
        || f.adverse_anchor
        || f.historical.adverse
}

/// Plan 009: every obligation of the historical claim beyond authentication and the absence of
/// adverse evidence.
fn historical_ready(f: &ValidatedFacts) -> bool {
    f.pinned_role_authority
        && f.historical.snapshot_verified
        && historical_revocation(f)
        && policy_evidence_ready(f)
        && (f.historical.brokered_use_valid || f.historical.introspected_use_valid)
}

/// `integrity` is satisfied or refuted.
fn integrity_claim(f: &ValidatedFacts) -> ClaimDecision {
    decision(!f.structural_integrity, true)
}

fn authenticated_claim(f: &ValidatedFacts, pinned_record_keys: bool) -> ClaimDecision {
    let integrity = f.structural_integrity;
    let refuted = !integrity;
    let satisfied = integrity & pinned_record_keys;
    decision(refuted, satisfied)
}

fn authorized_claim(
    f: &ValidatedFacts,
    pinned_record_keys: bool,
    revocation: bool,
) -> ClaimDecision {
    let refuted = authorization_refuted(f);
    let satisfied = authorized(f, pinned_record_keys, revocation);
    decision(refuted, satisfied)
}

fn temporal_claim(f: &ValidatedFacts, anchored_latest: bool, revocation: bool) -> ClaimDecision {
    let refuted = adverse(f);
    let satisfied = temporal(f, anchored_latest, revocation);
    decision(refuted, satisfied)
}

/// Plan 009: the historical claim replaces current-revocation readiness and adverse revocation
/// membership with the per-receipt ordering against an authenticated snapshot. Every other
/// obligation of `authorized` still applies. Under the strict policy it is never positive (and
/// never refuted).
fn historical_claim(f: &ValidatedFacts, pinned_record_keys: bool) -> ClaimDecision {
    let adverse = historical_adverse(f);
    let ready = historical_ready(f);
    let selected = f.historical.selected;
    let integrity = f.structural_integrity;
    let refuted = selected & (!integrity | adverse);
    let satisfied = selected & integrity & pinned_record_keys & ready;
    decision(refuted, satisfied)
}

/// A capstone: `authorized` and `temporal` satisfied and the surface's capstone checks.
fn complete_claim(
    f: &ValidatedFacts,
    pinned_record_keys: bool,
    anchored_latest: bool,
    revocation: bool,
    surface: bool,
) -> ClaimDecision {
    let refuted = authorization_refuted(f);
    let authorized = authorized(f, pinned_record_keys, revocation);
    let temporal = temporal(f, anchored_latest, revocation);
    decision(refuted, authorized && temporal && surface)
}

/// The claim decision kernel: a pure function of the checked facts and the caller's policy.
pub(super) fn decide_claims(f: &ValidatedFacts) -> ClaimResults {
    let pinned_record_keys = pinned_record_keys(f);
    let anchored_latest = anchored_at(&f.anchors, f.latest_checkpoint_sequence);
    let revocation = revocation_ready(f);
    let brokered = f.capstone.brokered();
    let introspected = f.capstone.introspected();
    let integrity = integrity_claim(f);
    let authenticated = authenticated_claim(f, pinned_record_keys);
    let authorized = authorized_claim(f, pinned_record_keys, revocation);
    let historical_authorized_as_of_snapshot = historical_claim(f, pinned_record_keys);
    let temporal = temporal_claim(f, anchored_latest, revocation);
    let complete_brokered =
        complete_claim(f, pinned_record_keys, anchored_latest, revocation, brokered);
    let complete_introspected = complete_claim(
        f,
        pinned_record_keys,
        anchored_latest,
        revocation,
        introspected,
    );
    let requested_decision = match f.policy.requested {
        RequestedClaim::Integrity => integrity,
        RequestedClaim::Authenticated => authenticated,
        RequestedClaim::Authorized => authorized,
        RequestedClaim::HistoricalAuthorizedAsOfSnapshot => historical_authorized_as_of_snapshot,
        RequestedClaim::CompleteBrokered => complete_brokered,
        RequestedClaim::CompleteIntrospected => complete_introspected,
    };
    ClaimResults {
        integrity,
        authenticated,
        authorized,
        historical_authorized_as_of_snapshot,
        temporal,
        complete_brokered,
        complete_introspected,
        requested: f.policy.requested,
        requested_decision,
    }
}

#[cfg(test)]
mod differential {
    use super::*;

    fn bit(n: usize, k: usize) -> bool {
        n & (1 << k) != 0
    }

    // Mirrors Oracle/Verdict.lean's checked-fact projection. The Lean oracle also models the
    // signed records and support attachments used to derive these facts. Bundle-byte extraction
    // remains a separate end-to-end obligation, covered by adversarial tests.
    // Mirrors Oracle/Verdict.lean `histFacts`/`histAttachments` and its named cases: one receipt
    // of grant 7 with ordinal 4 (or `order`), evaluation time 8, maximum age 5, minimum watermark 3.
    // `list`/`merkle` are the present snapshot attachments as (boundary, watermark).
    struct Hist {
        n: usize,
        order: Option<i64>,
        list: Option<(i64, i64)>,
        merkle: Option<(i64, i64)>,
        path: bool,
        contradiction: bool,
        cutoffs: Option<Vec<i64>>,
        mode: RevocationRequirement,
        issuer: bool,
    }

    fn historical(h: &Hist) -> (HistoricalFacts, bool) {
        let n = h.n;
        let validated = bit(n, 4);
        let revoked = bit(n, 7);
        let cutoffs: Vec<i64> = h.cutoffs.clone().unwrap_or_else(|| {
            [(5, 9), (6, 4)]
                .into_iter()
                .filter(|(b, _)| bit(n, *b))
                .map(|(_, c)| c)
                .collect()
        });
        let snapshot = h.list.or(h.merkle);
        let watermark = snapshot.map_or(0, |(_, w)| w);
        let proven = validated
            && !revoked
            && h.order
                .is_some_and(|o| o <= watermark && cutoffs.iter().all(|c| o < *c));
        let fresh = snapshot.is_some_and(|(b, w)| b <= 8 && 8 <= b + 5 && 3 <= w);
        let adverse =
            validated && (revoked || h.order.is_some_and(|o| cutoffs.iter().any(|c| *c <= o)));
        (
            HistoricalFacts {
                selected: bit(n, 0),
                snapshot_verified: fresh,
                // Each receipt's grant state is certified by the disclosed list or by its own
                // Merkle path (the `historicalUse` fact of `Refinement.Corresponds`).
                brokered_use_valid: bit(n, 8) && proven && (h.list.is_some() || h.path),
                introspected_use_valid: false,
                adverse,
                checked_contradiction: h.contradiction,
                v2_list_usable: h.list.is_some(),
                v2_merkle_usable: h.merkle.is_some(),
                merkle_paths_complete: h.merkle.is_some() && h.path,
            },
            revoked,
        )
    }

    fn hist_case(name: &str) -> Option<Hist> {
        let base = |n: usize| Hist {
            n,
            order: bit(n, 3).then_some(4),
            list: bit(n, 1).then_some((
                if bit(n, 2) { 1 } else { 5 },
                if bit(n, 9) { 2 } else { 10 },
            )),
            merkle: None,
            path: false,
            contradiction: false,
            cutoffs: None,
            mode: RevocationRequirement::Pinned,
            issuer: true,
        };
        let special = base(0x11B);
        let merkle_only = |path: bool, mode| Hist {
            list: None,
            merkle: Some((5, 10)),
            path,
            mode,
            ..base(0x11B)
        };
        Some(match name {
            "hist_beyond_watermark" => Hist {
                order: Some(11),
                ..special
            },
            "hist_merkle_missing_path" => merkle_only(false, RevocationRequirement::Pinned),
            "hist_merkle_path" => merkle_only(true, RevocationRequirement::Pinned),
            "hist_contradiction" => Hist {
                contradiction: true,
                ..special
            },
            "hist_future_boundary" => Hist {
                list: Some((9, 10)),
                ..special
            },
            "hist_merkle_missing_path_at_cutoff" => Hist {
                cutoffs: Some(vec![4]),
                ..merkle_only(false, RevocationRequirement::Pinned)
            },
            "hist_disclosed_mode_merkle_snapshot" => {
                merkle_only(true, RevocationRequirement::Disclosed)
            }
            "hist_merkle_mode_list_snapshot" => Hist {
                mode: RevocationRequirement::Merkle,
                ..special
            },
            "hist_merkle_mode_merkle_snapshot" => merkle_only(true, RevocationRequirement::Merkle),
            "hist_both_mode_list_only" => Hist {
                mode: RevocationRequirement::Both,
                ..special
            },
            "hist_both_mode_both_snapshots" => Hist {
                merkle: Some((5, 10)),
                path: true,
                mode: RevocationRequirement::Both,
                ..special
            },
            "hist_issuer_unpinned" => Hist {
                issuer: false,
                ..special
            },
            _ => base(name.strip_prefix("hist_")?.parse().ok()?),
        })
    }

    fn facts(name: &str) -> ValidatedFacts {
        if let Some(h) = hist_case(name) {
            let mut result = facts("bits_191");
            let (historical, revoked) = historical(&h);
            result.historical = historical;
            result.revoked_membership = revoked;
            result.policy.revocation = h.mode;
            result.revocation_issuer_pinned = h.issuer;
            return result;
        }
        let n = name
            .strip_prefix("bits_")
            .and_then(|s| s.parse().ok())
            .unwrap_or(191);
        let pin = bit(n, 0);
        let anchor = bit(n, 1);
        let role = bit(n, 2);
        let use_ok = bit(n, 3);
        let rev_fresh = bit(n, 4) && anchor;
        let attestation = bit(n, 5) && anchor;
        let revoked = bit(n, 6);
        let disclosed = bit(n, 7);
        let key = [1; 32];
        let mut result = ValidatedFacts {
            historical: HistoricalFacts {
                selected: false,
                snapshot_verified: false,
                brokered_use_valid: false,
                introspected_use_valid: false,
                adverse: false,
                checked_contradiction: false,
                v2_list_usable: false,
                v2_merkle_usable: false,
                merkle_paths_complete: false,
            },
            structural_integrity: true,
            record_count: 1,
            pinned_record_seals: if pin && anchor {
                vec![PinnedRecordSeal {
                    record_hash: "h1".into(),
                    key_bytes: key,
                }]
            } else {
                vec![]
            },
            pinned_signer_keys: if pin { vec![key] } else { vec![] },
            pinned_role_authority: role,
            latest_checkpoint_sequence: 10,
            anchors: if anchor {
                vec![AnchoredCheckpoint {
                    checkpoint_hash: "cp10".into(),
                    timestamp: "5".into(),
                    sequence: 10,
                }]
            } else {
                vec![]
            },
            attestation_valid: attestation,
            brokered_use_valid: use_ok,
            introspected_use_valid: false,
            capstone: CapstoneFacts {
                manifest: true,
                two_phase: true,
                no_incomplete_intent: true,
                taxonomy: true,
                every_action_verified: true,
                every_pop_reverified: true,
                grant_log: true,
                attestation: true,
                no_violation: true,
                no_pending: true,
                bounded_reuse: true,
                cosignatures: true,
                delegation: true,
                revocation: true,
                federation: true,
                coverage: true,
                brokered_surface: true,
                introspected_surface: false,
            },
            immutable_record_contradiction: false,
            checked_contradiction: false,
            adverse_disclosure: false,
            adverse_anchor: false,
            revoked_membership: revoked,
            revocation_issuer_pinned: true,
            disclosed_revocation_fresh: rev_fresh,
            merkle_revocation_fresh: false,
            merkle_nonmembership_complete: false,
            disclosure_complete: disclosed,
            policy: ClaimPolicy {
                requested: RequestedClaim::Authorized,
                revocation: RevocationRequirement::Pinned,
                require_disclosure: true,
                require_attestation: false,
            },
        };
        if let Some(i) = name
            .strip_prefix("capstone_")
            .and_then(|s| s.parse::<usize>().ok())
        {
            match i {
                0 => result.capstone.manifest = false,
                1 => result.capstone.two_phase = false,
                2 | 6 => result.capstone.no_incomplete_intent = false,
                3 | 18 | 19 => result.capstone.brokered_surface = false,
                4 => result.capstone.every_pop_reverified = false,
                5 => result.capstone.every_action_verified = false,
                7 => result.capstone.taxonomy = false,
                8 => result.capstone.grant_log = false,
                9 => result.capstone.attestation = false,
                10 => result.capstone.no_violation = false,
                11 => result.capstone.no_pending = false,
                12 => result.capstone.bounded_reuse = false,
                13 => result.capstone.cosignatures = false,
                14 => result.capstone.delegation = false,
                15 => result.capstone.revocation = false,
                16 => result.capstone.federation = false,
                17 => result.capstone.coverage = false,
                _ => panic!("unknown capstone case {i}"),
            }
        }
        match name {
            "adverse_opening" => result.adverse_disclosure = true,
            "adverse_anchor" => result.adverse_anchor = true,
            "checked_contradiction" => result.checked_contradiction = true,
            "missing_seal" => {
                result.structural_integrity = false;
                result.pinned_record_seals.clear();
            }
            "missing_path" | "present_path" => {
                result.policy.revocation = RevocationRequirement::Both;
                result.merkle_revocation_fresh = true;
                result.merkle_nonmembership_complete = name == "present_path";
            }
            "anchorless_default" => {
                result.anchors.clear();
                result.attestation_valid = false;
                result.revocation_issuer_pinned = false;
                result.disclosed_revocation_fresh = false;
                result.policy.require_disclosure = false;
            }
            "required_attestation_missing" => {
                result.attestation_valid = false;
                result.policy.require_attestation = true;
            }
            "noncontributor_role" | "non_grant_shared_gid" => {
                result.record_count = 2;
                result.pinned_record_seals.push(PinnedRecordSeal {
                    record_hash: "h2".into(),
                    key_bytes: key,
                });
            }
            "introspected" => {
                result.brokered_use_valid = false;
                result.introspected_use_valid = true;
                result.capstone.brokered_surface = false;
                result.capstone.introspected_surface = true;
            }
            "committed_conflict" => {
                result.record_count = 2;
                result.pinned_record_seals.push(PinnedRecordSeal {
                    record_hash: "h2".into(),
                    key_bytes: key,
                });
                result.immutable_record_contradiction = true;
            }
            _ if name.starts_with("bits_") || name.starts_with("capstone_") => {}
            _ => panic!("unknown verdict oracle case {name}"),
        }
        result
    }

    #[test]
    fn verdict_differential() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../formal/oracle/verdict-expected.json"
        );
        let expected = std::fs::read_to_string(path).expect("build verdict_oracle first");
        let rows = CanonValue::parse(&expected).expect("verdict oracle JSON");
        let rows = rows.as_array().expect("oracle rows");
        assert_eq!(
            rows.len(),
            1324,
            "all finite fact, capstone and historical cases"
        );
        for row in rows {
            let name = row
                .get("name")
                .and_then(CanonValue::as_str)
                .expect("case name");
            let got = decide_claims(&facts(name));
            for (field, actual) in [
                ("integrity", got.integrity),
                ("authenticated", got.authenticated),
                ("authorized", got.authorized),
                (
                    "historical_authorized_as_of_snapshot",
                    got.historical_authorized_as_of_snapshot,
                ),
                ("temporal", got.temporal),
                ("complete_brokered", got.complete_brokered),
                ("complete_introspected", got.complete_introspected),
            ] {
                assert_eq!(
                    row.get(field).and_then(CanonValue::as_str),
                    Some(actual.as_str()),
                    "{name}.{field}"
                );
            }
        }
    }

    /// Builds the legacy report fields the old `action_completeness` conjunction reads, from the
    /// checked facts they were derived from (the inverse of the projection in `verify.rs`
    /// where `CapstoneFacts` is built). Fields the corpus cannot express keep their neutral value.
    fn report_from_facts(f: &ValidatedFacts) -> super::super::VerifyReport {
        use crate::verify::fatal_config_report;
        let c = &f.capstone;
        let mut r = fatal_config_report(None, "oracle");
        r.ok = f.structural_integrity;
        r.keys_externally_pinned = !f.pinned_signer_keys.is_empty();
        r.body_bound_role_evidence = f.pinned_role_authority;
        r.coverage_manifest = if c.manifest {
            Some(CanonValue::Bool(true))
        } else {
            None
        };
        r.one_phase_use_present = !c.two_phase;
        r.intent_without_outcome = usize::from(!c.no_incomplete_intent);
        r.taxonomy_status = if c.taxonomy { "validated" } else { "absent" }.into();
        r.uses_action_unverified = usize::from(!c.every_action_verified);
        r.uses_matched = usize::from(c.brokered_surface);
        r.uses_pop_reverified = if c.every_pop_reverified {
            r.uses_matched
        } else {
            0
        };
        r.broker_trust = if c.grant_log {
            "sequence_verified"
        } else {
            "assumed"
        }
        .into();
        r.attestation_status = if c.attestation {
            "attested_claims"
        } else {
            "absent"
        }
        .into();
        r.unmatched_violation = usize::from(!c.no_violation);
        r.unmatched_pending = usize::from(!c.no_pending);
        r.bounded_reuse_overspent = usize::from(!c.bounded_reuse);
        r.cosig_threshold_failures = usize::from(!c.cosignatures);
        r.delegation_monotonicity_violations = usize::from(!c.delegation);
        r.revocation_status = if c.revocation { "fresh" } else { "stale" }.into();
        r.cross_broker_suppression = usize::from(!c.federation);
        r.side_effect_closure_status = if c.coverage { "closed" } else { "open" }.into();
        r.native_credential_present = c.introspected_surface;
        r.introspection_status = if c.introspected_surface {
            "attested"
        } else {
            "absent"
        }
        .into();
        r.claims = decide_claims(f);
        r
    }

    /// SB-28: the Level-3 label is never stronger than the kernel. Over every corpus case, a
    /// brokered label implies kernel `complete_brokered` satisfied (introspected likewise).
    /// Prints the cases where the bare conjunction was stronger (those were overclaims).
    #[test]
    fn action_completeness_label_never_stronger_than_kernel() {
        use crate::verify::ActionCompleteness as A;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../formal/oracle/verdict-expected.json"
        );
        let rows = CanonValue::parse(&std::fs::read_to_string(path).expect("corpus")).unwrap();
        let mut labelled = 0;
        let mut overclaims = Vec::new();
        for row in rows.as_array().unwrap() {
            let name = row.get("name").and_then(CanonValue::as_str).unwrap();
            let f = facts(name);
            let r = report_from_facts(&f);
            let label = A::of(&r);
            match label {
                A::AttestedCompleteOverBrokeredSurface => {
                    labelled += 1;
                    assert_eq!(
                        r.claims.complete_brokered,
                        ClaimDecision::Satisfied,
                        "{name}"
                    );
                }
                A::AttestedCompleteOverIntrospectedSurface => {
                    labelled += 1;
                    assert_eq!(
                        r.claims.complete_introspected,
                        ClaimDecision::Satisfied,
                        "{name}"
                    );
                }
                _ => {}
            }
            {
                let bare = A::of_conjunction_uncapped(&r);
                if bare != label {
                    overclaims.push(format!("{name}:{}", bare.as_str()));
                }
            }
        }
        assert!(labelled > 0, "the corpus must exercise a granted label");
        eprintln!("OVERCLAIMS {}: {:?}", overclaims.len(), overclaims);
    }

    /// SB-28: with every conjunct of the legacy conjunction true, a kernel that does not satisfy the
    /// matching capstone claim downgrades the label to `claimed_over_manifest`.
    #[test]
    fn action_completeness_label_is_capped_by_the_kernel() {
        use crate::verify::ActionCompleteness as A;
        for decision in [ClaimDecision::Insufficient, ClaimDecision::Refuted] {
            let mut brokered = report_from_facts(&facts("bits_191"));
            assert_eq!(A::of(&brokered), A::AttestedCompleteOverBrokeredSurface);
            brokered.claims.complete_brokered = decision;
            assert_eq!(A::of(&brokered), A::ClaimedOverManifest, "{decision:?}");
            // the other surface's claim is irrelevant to the brokered label
            let mut other = report_from_facts(&facts("bits_191"));
            other.claims.complete_introspected = decision;
            assert_eq!(A::of(&other), A::AttestedCompleteOverBrokeredSurface);

            let mut native = report_from_facts(&facts("introspected"));
            native.claims.complete_introspected = ClaimDecision::Satisfied;
            assert_eq!(A::of(&native), A::AttestedCompleteOverIntrospectedSurface);
            native.claims.complete_introspected = decision;
            assert_eq!(A::of(&native), A::ClaimedOverManifest, "{decision:?}");
        }
    }
}
