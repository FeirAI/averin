import {expect, test} from "vitest";
import {claimVerdict, historicalClaimNote} from "./claimVerdict";

const report = (decision = "satisfied") => ({
  ok: true, keys_externally_pinned: true, claims_version: "2",
  claims: {requested: "authorized", authorized: decision, requested_decision: decision},
});

test("accepts only a pinned, versioned satisfied required claim", () => {
  expect(claimVerdict(report()).word).toBe("PASS");
  expect(claimVerdict({...report(), keys_externally_pinned: false}).word).toBe("CONSISTENT");
});

test("missing and malformed claim contracts never show PASS", () => {
  expect(claimVerdict({...report(), claims_version: "3"}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: undefined}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: {...report().claims, requested_decision: "unknown"}}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: {...report().claims, authorized: "insufficient"}}).word).toBe("INSUFFICIENT");
});

test("insufficient, refuted and failed integrity remain distinct", () => {
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

test("historicalClaimNote falls back to insufficient under an invalid claims contract", () => {
  const r = historicalReport("satisfied", false);
  expect(historicalClaimNote({...r, claims: {...r.claims, requested_decision: "refuted"}})).toBe("insufficient");
  expect(historicalClaimNote({...r, claims: {...r.claims, requested_decision: "maybe", historical_authorized_as_of_snapshot: "maybe"}})).toBe("insufficient");
  expect(historicalClaimNote({...r, claims: {requested: "historical_authorized_as_of_snapshot"}})).toBe("insufficient");
  expect(historicalClaimNote(historicalReport("refuted", false))).toBe("refuted");
});

// Same rule as the Rust claim_verdict (core/src/verify/headline.rs): `ok` and `keys_externally_pinned`
// count only as the JSON boolean true. A truthy non-boolean ("false", 1, "true") is not pinning and not ok.
test("only the boolean true counts for ok and keys_externally_pinned", () => {
  for (const v of ["false", "true", 1, "1", {}, []]) {
    expect(claimVerdict({...report(), keys_externally_pinned: v}).word).toBe("CONSISTENT");
    expect(claimVerdict({...report(), ok: v}).word).toBe("FAIL");
  }
  expect(claimVerdict({...report(), keys_externally_pinned: null}).word).toBe("CONSISTENT");
  expect(claimVerdict({...report(), ok: null}).word).toBe("FAIL");
});
