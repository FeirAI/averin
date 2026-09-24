const CLAIMS = new Set(["integrity", "authenticated", "authorized", "complete_brokered", "complete_introspected"]);
const DECISIONS = new Set(["satisfied", "insufficient", "refuted"]);

// A missing or unknown claims contract cannot accept a caller's required claim.
export function claimVerdict(report) {
  const claims = report?.claims;
  const valid = report?.claims_version === "1"
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
