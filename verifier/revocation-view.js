// Plan 009 (ADR 0007): current revocation and historical ordering are separate results. Current
// revocation always blocks; the historical section appears only under the caller-selected
// db_serialized_v1 policy and never claims physical action time.
const ORDERING = {
  at_or_after: "at or after the cutoff",
  indeterminate: "indeterminate",
};

// V-L4: "proven before revocation" is only true of a grant that IS a revoked_prospective grant
// (the receipt precedes that grant's own cutoff). A proven_before receipt against a grant that is
// not_revoked was never headed for a cutoff at all, so label it as authorized-as-of-snapshot
// instead of implying a revocation the grant never had. Any other or unknown grant state is
// conservative: never say "proven before revocation" unless the grant is revoked_prospective, and
// never say "grant not revoked" unless current_revocation is exactly not_revoked.
function provenBeforeLabel(grantRevocations, grantId) {
  const g = (grantRevocations || []).find((g) => g?.grant_id === grantId);
  const state = g?.current_revocation;
  if (state === "revoked_prospective") return "proven before revocation";
  if (state === "not_revoked") return "authorized as of snapshot (grant not revoked)";
  return "indeterminate";
}

export function revocationView(report) {
  const t = report?.revocation_temporal;
  if (!t || !Array.isArray(t.grant_revocations)) return null;
  const current = t.grant_revocations
    .filter((g) => g?.current_revocation && g.current_revocation !== "not_revoked" && g.current_revocation !== "not_evaluated")
    .map((g) => {
      const cutoff = g.current_revocation === "revoked_prospective" ? ` (cutoff ordinal ${g.cutoff_order})` : "";
      return `${g.grant_id}: ${String(g.current_revocation).replace("_", " ")}${cutoff} — current uses are blocked`;
    });
  const evaluated = t.grant_revocations.some((g) => g?.current_revocation && g.current_revocation !== "not_evaluated");
  if (t.policy !== "db_serialized_v1") return { current, evaluated, historical: null };
  const snap = t.snapshot ?? {};
  const snapshot = snap.status === "verified"
    ? `verified snapshot of ${snap.project_id} at ${snap.boundary_time} (watermark ${snap.authorization_high_watermark})`
    : `snapshot ${snap.status ?? "absent"}${snap.reason ? `: ${snap.reason}` : ""}`;
  const decision = report?.claims_version === "2" ? (report?.claims?.historical_authorized_as_of_snapshot ?? "insufficient") : "unavailable";
  const receipts = (Array.isArray(t.receipt_ordering) ? t.receipt_ordering : []).map((r) => {
    const order = r.authorization_order == null ? "no ordinal" : `ordinal ${r.authorization_order}`;
    const label = r.historical_ordering === "proven_before"
      ? provenBeforeLabel(t.grant_revocations, r.grant_id)
      : (ORDERING[r.historical_ordering] ?? "indeterminate");
    return `${r.record_id} (${r.kind}, ${order}): ${label}`;
  });
  return {
    current,
    evaluated,
    historical: {
      policy: t.policy,
      snapshot,
      decision,
      receipts,
      basis: "Averin database order under honest resource and revocation signers; not physical action time. A TSA anchor never proves this order.",
    },
  };
}
