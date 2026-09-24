type Verdict = { word: "PASS" | "CONSISTENT" | "INSUFFICIENT" | "FAIL"; className: "pass" | "qual" | "fail"; valid: boolean };
const claims = new Set(["integrity", "authenticated", "authorized", "complete_brokered", "complete_introspected"]);
const decisions = new Set(["satisfied", "insufficient", "refuted"]);

export function claimVerdict(report: any): Verdict {
  const c = report?.claims;
  const valid = report?.claims_version === "1"
    && claims.has(c?.requested)
    && decisions.has(c?.requested_decision)
    && c?.[c.requested] === c.requested_decision;
  if (!report?.ok || (valid && c.requested_decision === "refuted")) return {word: "FAIL", className: "fail", valid};
  if (!valid || c.requested_decision === "insufficient") return {word: "INSUFFICIENT", className: "qual", valid};
  return report.keys_externally_pinned
    ? {word: "PASS", className: "pass", valid}
    : {word: "CONSISTENT", className: "qual", valid};
}
