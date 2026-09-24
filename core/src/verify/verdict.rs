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
                self.revocation_issuer_pinned
                    && self.merkle_revocation_fresh
                    && self.merkle_nonmembership_complete
            }
            RevocationRequirement::Both => {
                self.revocation_issuer_pinned
                    && self.disclosed_revocation_fresh
                    && self.merkle_revocation_fresh
                    && self.merkle_nonmembership_complete
            }
        };
        let adverse = self.immutable_record_contradiction
            || self.checked_contradiction
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
        let authorized = if adverse || authenticated == Refuted {
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

#[cfg(test)]
mod differential {
    use super::*;

    fn bit(n: usize, k: usize) -> bool {
        n & (1 << k) != 0
    }

    // Mirrors Oracle/Verdict.lean's checked-fact projection. The Lean oracle also models the
    // signed records and support attachments used to derive these facts. Bundle-byte extraction
    // remains a separate end-to-end obligation, covered by adversarial tests.
    fn facts(name: &str) -> ValidatedFacts {
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
        assert_eq!(rows.len(), 287, "all finite fact and capstone cases");
        for row in rows {
            let name = row
                .get("name")
                .and_then(CanonValue::as_str)
                .expect("case name");
            let got = facts(name).decide();
            for (field, actual) in [
                ("integrity", got.integrity),
                ("authenticated", got.authenticated),
                ("authorized", got.authorized),
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
}
