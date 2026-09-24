// Plan 009 (ADR 0007): current revocation and historical ordering are separate results. The
// current section always reflects blocking; the historical section appears only when the caller
// selected db_serialized_v1, and never claims physical action time.

export type RevocationView = {
  current: string[];
  historical: { policy: string; snapshot: string; decision: string; receipts: string[]; basis: string } | null;
};

const ORDERING: Record<string, string> = {
  proven_before: "proven before revocation",
  at_or_after: "at or after the cutoff",
  indeterminate: "indeterminate",
};

export function revocationView(report: any): RevocationView | null {
  const t = report?.revocation_temporal;
  if (!t || !Array.isArray(t.grant_revocations)) return null;
  const current = t.grant_revocations
    .filter((g: any) => g?.current_revocation && g.current_revocation !== "not_revoked" && g.current_revocation !== "not_evaluated")
    .map((g: any) => {
      const cutoff = g.current_revocation === "revoked_prospective" ? ` (cutoff ordinal ${g.cutoff_order})` : "";
      return `${g.grant_id}: ${String(g.current_revocation).replace("_", " ")}${cutoff} — current uses are blocked`;
    });
  if (t.policy !== "db_serialized_v1") return { current, historical: null };
  const snap = t.snapshot ?? {};
  const snapshot = snap.status === "verified"
    ? `verified snapshot of ${snap.project_id} at ${snap.boundary_time} (watermark ${snap.authorization_high_watermark})`
    : `snapshot ${snap.status ?? "absent"}${snap.reason ? `: ${snap.reason}` : ""}`;
  const decision = report?.claims_version === "2" ? (report?.claims?.historical_authorized_as_of_snapshot ?? "insufficient") : "unavailable";
  const receipts = (Array.isArray(t.receipt_ordering) ? t.receipt_ordering : []).map((r: any) => {
    const order = r.authorization_order == null ? "no ordinal" : `ordinal ${r.authorization_order}`;
    return `${r.record_id} (${r.kind}, ${order}): ${ORDERING[r.historical_ordering] ?? "indeterminate"}`;
  });
  return {
    current,
    historical: {
      policy: t.policy,
      snapshot,
      decision,
      receipts,
      basis: "Averin database order under honest resource and revocation signers; not physical action time. A TSA anchor never proves this order.",
    },
  };
}
