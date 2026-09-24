import {expect, test} from "vitest";
import {claimVerdict} from "./claimVerdict";

const report = (decision = "satisfied") => ({
  ok: true, keys_externally_pinned: true, claims_version: "1",
  claims: {requested: "authorized", authorized: decision, requested_decision: decision},
});

test("accepts only a pinned, versioned satisfied required claim", () => {
  expect(claimVerdict(report()).word).toBe("PASS");
  expect(claimVerdict({...report(), keys_externally_pinned: false}).word).toBe("CONSISTENT");
});

test("missing and malformed claim contracts never show PASS", () => {
  expect(claimVerdict({...report(), claims_version: "2"}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: undefined}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: {...report().claims, requested_decision: "unknown"}}).word).toBe("INSUFFICIENT");
  expect(claimVerdict({...report(), claims: {...report().claims, authorized: "insufficient"}}).word).toBe("INSUFFICIENT");
});

test("insufficient, refuted and failed integrity remain distinct", () => {
  expect(claimVerdict(report("insufficient")).word).toBe("INSUFFICIENT");
  expect(claimVerdict(report("refuted")).word).toBe("FAIL");
  expect(claimVerdict({...report(), ok: false}).word).toBe("FAIL");
});
