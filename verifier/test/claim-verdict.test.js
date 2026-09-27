import { test, expect } from "bun:test";
import { claimVerdict, historicalClaimNote } from "../claim-verdict.js";

const report = (decision = "satisfied") => ({
  ok: true,
  keys_externally_pinned: true,
  claims_version: "2",
  claims: {requested: "authenticated", authenticated: decision, requested_decision: decision},
});

test("accepts only a pinned satisfied versioned claim", () => {
  expect(claimVerdict(report()).word).toBe("PASS");
  expect(claimVerdict({...report(), keys_externally_pinned: false}).word).toBe("CONSISTENT");
});

test("unknown or missing claims never accept a required claim", () => {
  expect(claimVerdict({...report(), claims_version: "3"}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: undefined}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: {...report().claims, requested_decision: "unknown"}}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: {...report().claims, authenticated: "insufficient"}}).word).toBe("INSUFFICIENT");
});

test("insufficient and refuted claims have distinct non-accepting verdicts", () => {
  expect(claimVerdict(report("insufficient")).word).toBe("INSUFFICIENT");
  expect(claimVerdict(report("refuted")).word).toBe("FAIL");
  expect(claimVerdict({...report(), ok: false}).word).toBe("FAIL");
});

const historicalReport = (decision = "satisfied", ok = false) => ({
  ok,
  claims_version: "2",
  claims: {
    requested: "historical_authorized_as_of_snapshot",
    historical_authorized_as_of_snapshot: decision,
    requested_decision: decision,
  },
});

test("historicalClaimNote names the requested historical claim's own decision even while ok is false", () => {
  expect(historicalClaimNote(historicalReport("satisfied", false))).toBe("satisfied");
  expect(historicalClaimNote(historicalReport("insufficient", false))).toBe("insufficient");
});

test("historicalClaimNote is null when a different claim was requested", () => {
  expect(historicalClaimNote(report())).toBeNull();
});

test("historicalClaimNote is null for an unsupported claims contract version", () => {
  expect(historicalClaimNote({...historicalReport(), claims_version: "1"})).toBeNull();
  expect(historicalClaimNote({})).toBeNull();
});
