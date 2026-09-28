const CLAIMS = new Set([
  "integrity", "authenticated", "authorized", "historical_authorized_as_of_snapshot",
  "complete_brokered", "complete_introspected",
]);
const DECISIONS = new Set(["satisfied", "insufficient", "refuted"]);

// A missing or unknown claims contract cannot accept a caller's required claim.
export function claimVerdict(report) {
  const claims = report?.claims;
  const valid = report?.claims_version === "2"
    && CLAIMS.has(claims?.requested)
    && DECISIONS.has(claims?.requested_decision)
    && claims?.[claims.requested] === claims.requested_decision;
  if (!report?.ok || (valid && claims.requested_decision === "refuted")) {
    return {word: "FAIL", className: "fail", valid};
  }
  if (!valid || claims.requested_decision === "insufficient") {
    return {word: "INSUFFICIENT", className: "qual", valid};
  }
  return report.keys_externally_pinned
    ? {word: "PASS", className: "pass", valid}
    : {word: "CONSISTENT", className: "qual", valid};
}

// V-L3: the legacy `ok` is a separate integrity result and can be false while the caller's requested
// historical_authorized_as_of_snapshot claim is satisfied. A consumer of that claim must read claims.*
// directly, never infer it from ok. Returns the decision to show next to the legacy verdict when that
// claim was requested (claims_version "2"): the requested decision under a valid claims contract
// (a known decision equal to the claim's own field), else "insufficient". The CLI
// (core/src/bin/averin_verify.rs) and the web app apply the same rule.
export function historicalClaimNote(report) {
  const claims = report?.claims;
  if (report?.claims_version !== "2" || claims?.requested !== "historical_authorized_as_of_snapshot") return null;
  const valid = DECISIONS.has(claims.requested_decision)
    && claims.historical_authorized_as_of_snapshot === claims.requested_decision;
  return valid ? claims.requested_decision : "insufficient";
}
