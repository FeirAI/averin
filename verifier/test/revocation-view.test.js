import { test, expect } from "bun:test";
import { revocationView } from "../revocation-view.js";

const report = (policy) => ({
  claims_version: "2",
  claims: { historical_authorized_as_of_snapshot: policy === "strict" ? "insufficient" : "satisfied" },
  revocation_temporal: {
    policy,
    snapshot: { status: "verified", project_id: "p1", boundary_time: "2026-09-24T10:00:00.000Z", authorization_high_watermark: 4 },
    grant_revocations: [
      { grant_id: "g1", current_revocation: "revoked_prospective", cutoff_order: 2 },
      { grant_id: "g2", current_revocation: "not_revoked", cutoff_order: null },
    ],
    receipt_ordering: [{ record_id: "use-1", kind: "use", grant_id: "g1", authorization_order: 1, historical_ordering: "proven_before" }],
  },
});

test("current revocation is always shown and stays blocking", () => {
  const v = revocationView(report("strict"));
  expect(v.current).toEqual(["g1: revoked prospective (cutoff ordinal 2) — current uses are blocked"]);
  expect(v.historical).toBeNull();
});

test("historical ordering is separate and names its trust basis", () => {
  const v = revocationView(report("db_serialized_v1"));
  expect(v.historical.decision).toBe("satisfied");
  expect(v.historical.receipts).toEqual(["use-1 (use, ordinal 1): proven before revocation"]);
  expect(v.historical.basis).toContain("not physical action time");
});

test("an unknown claims contract never shows a historical decision", () => {
  expect(revocationView({ ...report("db_serialized_v1"), claims_version: "1" }).historical.decision).toBe("unavailable");
  expect(revocationView({})).toBeNull();
});

test("proven_before for a not_revoked grant reads as authorized as of snapshot, not a revocation", () => {
  const r = report("db_serialized_v1");
  r.revocation_temporal.receipt_ordering = [
    { record_id: "use-2", kind: "use", grant_id: "g2", authorization_order: 3, historical_ordering: "proven_before" },
  ];
  const v = revocationView(r);
  expect(v.historical.receipts).toEqual(["use-2 (use, ordinal 3): authorized as of snapshot (grant not revoked)"]);
});

test("proven_before for an unknown or unverified-revocation grant is indeterminate, never a claim either way", () => {
  const r = report("db_serialized_v1");
  r.revocation_temporal.grant_revocations.push({ grant_id: "g3", current_revocation: "revoked_unverified", cutoff_order: null });
  r.revocation_temporal.receipt_ordering = [
    { record_id: "use-3", kind: "use", grant_id: "g3", authorization_order: 1, historical_ordering: "proven_before" },
    { record_id: "use-4", kind: "use", grant_id: "no-such-grant", authorization_order: 1, historical_ordering: "proven_before" },
  ];
  const v = revocationView(r);
  expect(v.historical.receipts).toEqual([
    "use-3 (use, ordinal 1): indeterminate",
    "use-4 (use, ordinal 1): indeterminate",
  ]);
});

test("unevaluated revocation is never presented as clean", () => {
  const r = {claims_version: "2", revocation_temporal: {policy: "strict", grant_revocations: [
    {grant_id: "g1", current_revocation: "not_evaluated", cutoff_order: null}]}};
  const v = revocationView(r);
  expect(v.evaluated).toBe(false);
  expect(v.current).toEqual([]);
  expect(revocationView({...r, revocation_temporal: {...r.revocation_temporal, grant_revocations: [
    {grant_id: "g1", current_revocation: "not_revoked", cutoff_order: null}]}}).evaluated).toBe(true);
});
