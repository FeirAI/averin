import { test, expect } from "bun:test";
import { claimVerdict } from "../claim-verdict.js";

const report = (decision = "satisfied") => ({
  ok: true,
  keys_externally_pinned: true,
  claims_version: "1",
  claims: {requested: "authenticated", authenticated: decision, requested_decision: decision},
});

test("accepts only a pinned satisfied versioned claim", () => {
  expect(claimVerdict(report()).word).toBe("PASS");
  expect(claimVerdict({...report(), keys_externally_pinned: false}).word).toBe("CONSISTENT");
});

test("unknown or missing claims never accept a required claim", () => {
  expect(claimVerdict({...report(), claims_version: "2"}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: undefined}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: {...report().claims, requested_decision: "unknown"}}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: {...report().claims, authenticated: "insufficient"}}).word).toBe("INSUFFICIENT");
});

test("insufficient and refuted claims have distinct non-accepting verdicts", () => {
  expect(claimVerdict(report("insufficient")).word).toBe("INSUFFICIENT");
  expect(claimVerdict(report("refuted")).word).toBe("FAIL");
  expect(claimVerdict({...report(), ok: false}).word).toBe("FAIL");
});
