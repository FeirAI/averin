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

// V-L3: the legacy `ok` stays false while any revoked grant was used, even when the caller's
// requested historical_authorized_as_of_snapshot claim is satisfied (the use happened before a
// prospective cutoff). A consumer of that claim must read claims.* directly, never infer it from
// ok, so name the claim's own decision here for callers to show next to the legacy verdict.
export function historicalClaimNote(report) {
  if (report?.claims_version !== "2") return null;
  const claims = report?.claims;
  if (claims?.requested !== "historical_authorized_as_of_snapshot") return null;
  return claims?.historical_authorized_as_of_snapshot ?? claims?.requested_decision ?? "insufficient";
}
