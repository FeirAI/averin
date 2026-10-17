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

/// True when a month-segment report carries a residual that one month cannot close: its base is not the pinned
/// previous head, its record completeness was not evaluated (it has parents before its base), or it has a base at
/// all and so lists `cross_month_uses` (single use, nonce and ledger replay, ghost grants and revocation across
/// months). Such a report never earns PASS or CONSISTENT on its own; `averin-verify chain` closes them across months.
pub fn segment_residual(report: &CanonValue) -> bool {
    let Some(sg) = report.get("segment") else {
        return false;
    };
    let unpinned = sg.get("link").and_then(CanonValue::as_str) == Some("base_unpinned");
    let incomplete = sg
        .get("not_evaluated")
        .and_then(CanonValue::as_array)
        .is_some_and(|a| {
            a.iter()
                .any(|x| matches!(x.as_str(), Some("record_completeness" | "cross_month_uses")))
        });
    unpinned || incomplete
}

/// Reads a serialized report (`report_to_canon` / `verify_bundle_with_json` output). A month segment with a
/// residual a single month cannot close (see [`segment_residual`]) is capped at INSUFFICIENT.
pub fn claim_verdict(report: &CanonValue) -> ClaimVerdict {
    month_claim_verdict(report, true)
}

/// As [`claim_verdict`], with the segment residual cap optional. The chain verdict passes `false` because it
/// checks the link and the cross-month completeness itself.
pub fn month_claim_verdict(report: &CanonValue, cap_segment_residual: bool) -> ClaimVerdict {
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
    } else if !valid
        || decision == Some("insufficient")
        || (cap_segment_residual && segment_residual(report))
    {
        ClaimVerdict::Insufficient
    } else if flag("keys_externally_pinned") {
        ClaimVerdict::Pass
    } else {
        ClaimVerdict::Consistent
    }
}
