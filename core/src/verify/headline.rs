//! The headline word and CLI exit code for a finished report. Not part of the claim kernel: it only
//! reads a serialized report (it is deliberately outside `verdict.rs`, which the production extraction hashes).

use crate::canon::CanonValue;

/// The headline a consumer may show for a verified report. Same rule as `claimVerdict` in
/// `verifier/claim-verdict.js` (the browser verifier and web app); `averin-verify bundle` prints
/// this word. It is a function of the report only: `ok`, `keys_externally_pinned` and the
/// versioned `claims` contract. It never reads anything the bundle can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimVerdict {
    /// The requested claim is satisfied and the signing keys were pinned externally.
    Pass,
    /// The requested claim is satisfied, but only under the bundle's own (unpinned) keys.
    Consistent,
    /// The requested claim is not satisfied, or the claims contract is missing or invalid.
    Insufficient,
    /// The legacy `ok` is false, or the requested claim is refuted.
    Fail,
}

impl ClaimVerdict {
    pub fn word(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Consistent => "CONSISTENT",
            Self::Insufficient => "INSUFFICIENT",
            Self::Fail => "FAIL",
        }
    }

    /// CLI exit code: 0 PASS, 2 CONSISTENT, 1 FAIL or INSUFFICIENT.
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Consistent => 2,
            Self::Insufficient | Self::Fail => 1,
        }
    }
}

/// Reads a serialized report (`report_to_canon` / `verify_bundle_with_json` output).
pub fn claim_verdict(report: &CanonValue) -> ClaimVerdict {
    let flag = |k: &str| matches!(report.get(k), Some(CanonValue::Bool(true)));
    let claims = report.get("claims");
    let requested = claims
        .and_then(|c| c.get("requested"))
        .and_then(CanonValue::as_str);
    let decision = claims
        .and_then(|c| c.get("requested_decision"))
        .and_then(CanonValue::as_str);
    let known_claim = matches!(
        requested,
        Some(
            "integrity"
                | "authenticated"
                | "authorized"
                | "historical_authorized_as_of_snapshot"
                | "complete_brokered"
                | "complete_introspected"
        )
    );
    let known_decision = matches!(decision, Some("satisfied" | "insufficient" | "refuted"));
    let own_field = match (claims, requested) {
        (Some(c), Some(r)) => c.get(r).and_then(CanonValue::as_str),
        _ => None,
    };
    let valid = report.get("claims_version").and_then(CanonValue::as_str) == Some("2")
        && known_claim
        && known_decision
        && own_field == decision;
    if !flag("ok") || (valid && decision == Some("refuted")) {
        ClaimVerdict::Fail
    } else if !valid || decision == Some("insufficient") {
        ClaimVerdict::Insufficient
    } else if flag("keys_externally_pinned") {
        ClaimVerdict::Pass
    } else {
        ClaimVerdict::Consistent
    }
}
