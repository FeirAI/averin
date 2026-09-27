type Verdict = { word: "PASS" | "CONSISTENT" | "INSUFFICIENT" | "FAIL"; className: "pass" | "qual" | "fail"; valid: boolean };
const claims = new Set([
  "integrity", "authenticated", "authorized", "historical_authorized_as_of_snapshot",
  "complete_brokered", "complete_introspected",
]);
const decisions = new Set(["satisfied", "insufficient", "refuted"]);

export function claimVerdict(report: any): Verdict {
  const c = report?.claims;
  const valid = report?.claims_version === "2"
    && claims.has(c?.requested)
    && decisions.has(c?.requested_decision)
    && c?.[c.requested] === c.requested_decision;
  if (!report?.ok || (valid && c.requested_decision === "refuted")) return {word: "FAIL", className: "fail", valid};
  if (!valid || c.requested_decision === "insufficient") return {word: "INSUFFICIENT", className: "qual", valid};
  return report.keys_externally_pinned
    ? {word: "PASS", className: "pass", valid}
    : {word: "CONSISTENT", className: "qual", valid};
}

// V-L3: the legacy `ok` stays false while any revoked grant was used, even when the caller's
// requested historical_authorized_as_of_snapshot claim is satisfied (the use happened before a
// prospective cutoff). A consumer of that claim must read claims.* directly, never infer it from
// ok, so name the claim's own decision here for callers to show next to the legacy verdict.
export function historicalClaimNote(report: any): string | null {
  if (report?.claims_version !== "2") return null;
  const claims = report?.claims;
  if (claims?.requested !== "historical_authorized_as_of_snapshot") return null;
  return claims?.historical_authorized_as_of_snapshot ?? claims?.requested_decision ?? "insufficient";
}
