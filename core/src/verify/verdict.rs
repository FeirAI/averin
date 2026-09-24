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
    CompleteBrokered,
    CompleteIntrospected,
}

impl RequestedClaim {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Authenticated => "authenticated",
            Self::Authorized => "authorized",
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

pub(super) struct ValidatedFacts {
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
    pub(super) committed_contradiction: bool,
    pub(super) adverse_disclosure: bool,
    /// Contradictory/noncanonical times among independently verified TSA anchors.
    pub(super) adverse_anchor: bool,
    pub(super) revoked_membership: bool,
    pub(super) revocation_issuer_pinned: bool,
    pub(super) disclosed_revocation_fresh: bool,
    pub(super) merkle_revocation_fresh: bool,
    pub(super) disclosure_complete: bool,
    pub(super) policy: ClaimPolicy,
}

impl ValidatedFacts {
    pub(super) fn decide(&self) -> ClaimResults {
        use ClaimDecision::{Insufficient, Refuted, Satisfied};
        // Require one externally pinned signing key for every verified record, with the record
        // hash bound to that exact key. The vector is emitted only after the seal check passes.
        let pinned_record_keys = self.record_count > 0
            && self.pinned_record_seals.len() == self.record_count
            && self.pinned_record_seals.iter().all(|p| {
                !p.record_hash.is_empty() && self.pinned_signer_keys.contains(&p.key_bytes)
            });
        let anchored_latest = self.anchors.iter().any(|a| {
            a.sequence == self.latest_checkpoint_sequence
                && !a.checkpoint_hash.is_empty()
                && !a.timestamp.is_empty()
        });
        let integrity = if self.structural_integrity {
            Satisfied
        } else {
            Refuted
        };
        let authenticated = if integrity != Satisfied {
            integrity
        } else if pinned_record_keys {
            Satisfied
        } else {
            Insufficient
        };
        let revocation = match self.policy.revocation {
            RevocationRequirement::Pinned => {
                !self.revocation_issuer_pinned || self.disclosed_revocation_fresh
            }
            RevocationRequirement::Disclosed => {
                self.revocation_issuer_pinned && self.disclosed_revocation_fresh
            }
            RevocationRequirement::Merkle => {
                self.revocation_issuer_pinned && self.merkle_revocation_fresh
            }
            RevocationRequirement::Both => {
                self.revocation_issuer_pinned
                    && self.disclosed_revocation_fresh
                    && self.merkle_revocation_fresh
            }
        };
        let adverse = self.committed_contradiction
            || self.revoked_membership
            || self.adverse_disclosure
            || self.adverse_anchor;
        let temporal = if adverse {
            Refuted
        } else if anchored_latest && self.attestation_valid && revocation {
            Satisfied
        } else {
            Insufficient
        };
        let evidence_ready = self.pinned_role_authority
            && revocation
            && (!self.policy.require_disclosure || self.disclosure_complete)
            && (!self.policy.require_attestation || self.attestation_valid);
        let authorized = if adverse {
            Refuted
        } else if authenticated == Refuted {
            Refuted
        } else if authenticated == Satisfied
            && evidence_ready
            && (self.brokered_use_valid || self.introspected_use_valid)
        {
            Satisfied
        } else {
            Insufficient
        };
        let complete_brokered = if authorized == Refuted {
            Refuted
        } else if authorized == Satisfied && temporal == Satisfied && self.capstone.brokered() {
            Satisfied
        } else {
            Insufficient
        };
        let complete_introspected = if authorized == Refuted {
            Refuted
        } else if authorized == Satisfied && temporal == Satisfied && self.capstone.introspected() {
            Satisfied
        } else {
            Insufficient
        };
        let requested_decision = match self.policy.requested {
            RequestedClaim::Integrity => integrity,
            RequestedClaim::Authenticated => authenticated,
            RequestedClaim::Authorized => authorized,
            RequestedClaim::CompleteBrokered => complete_brokered,
            RequestedClaim::CompleteIntrospected => complete_introspected,
        };
        ClaimResults {
            integrity,
            authenticated,
            authorized,
            temporal,
            complete_brokered,
            complete_introspected,
            requested: self.policy.requested,
            requested_decision,
        }
    }
}
