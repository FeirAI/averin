import {expect, test} from "vitest";
import {revocationView} from "./revocationView";

const report = (policy: string) => ({
  claims_version: "2",
  claims: {historical_authorized_as_of_snapshot: policy === "strict" ? "insufficient" : "satisfied"},
  revocation_temporal: {
    policy,
    snapshot: {status: "verified", project_id: "p1", boundary_time: "2026-09-24T10:00:00.000Z", authorization_high_watermark: 4},
    grant_revocations: [
      {grant_id: "g1", current_revocation: "revoked_prospective", cutoff_order: 2},
      {grant_id: "g2", current_revocation: "not_revoked", cutoff_order: null},
    ],
    receipt_ordering: [{record_id: "use-1", kind: "use", grant_id: "g1", authorization_order: 1, historical_ordering: "proven_before"}],
  },
});

test("current revocation is always shown and stays blocking", () => {
  const v = revocationView(report("strict"))!;
  expect(v.current).toEqual(["g1: revoked prospective (cutoff ordinal 2) — current uses are blocked"]);
  expect(v.historical).toBeNull();
});

test("historical ordering is separate and names its trust basis", () => {
  const v = revocationView(report("db_serialized_v1"))!;
  expect(v.current.length).toBe(1);
  expect(v.historical!.decision).toBe("satisfied");
  expect(v.historical!.receipts).toEqual(["use-1 (use, ordinal 1): proven before revocation"]);
  expect(v.historical!.snapshot).toContain("watermark 4");
  expect(v.historical!.basis).toContain("not physical action time");
});

test("an unknown claims contract never shows a historical decision", () => {
  const v = revocationView({...report("db_serialized_v1"), claims_version: "1"})!;
  expect(v.historical!.decision).toBe("unavailable");
  expect(revocationView({})).toBeNull();
});

test("unevaluated revocation is never presented as clean", () => {
  const r = {claims_version: "2", revocation_temporal: {policy: "strict", grant_revocations: [
    {grant_id: "g1", current_revocation: "not_evaluated", cutoff_order: null}]}};
  const v = revocationView(r)!;
  expect(v.evaluated).toBe(false);
  expect(v.current).toEqual([]);
  expect(revocationView({...r, revocation_temporal: {...r.revocation_temporal, grant_revocations: [
    {grant_id: "g1", current_revocation: "not_revoked", cutoff_order: null}]}})!.evaluated).toBe(true);
});
