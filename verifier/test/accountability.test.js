// The browser verifier surfaces ACCOUNTABILITY (grant/use/completeness + the Tier-B mode gates), not just
// record integrity, and lets the auditor PIN trust roots (verifyBundleWith). This test exercises that path on
// the real Go-produced broker bundle + its pinned opts, asserting the fields index.html renders are present and
// meaningful under pinning (grant accountability elevated, the use matched, keys externally pinned).
import { test, expect } from "bun:test";
import { initAverin } from "../averin.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "averin_decision_core.wasm");
const FIXTURE = JSON.parse(readFileSync(join(ROOT, "spec", "fixtures", "bundle-broker-valid.json"), "utf8"));

const averin = () => initAverin(new Uint8Array(readFileSync(WASM)));

test("pinned ROLE keys elevate accountability + expose the fields the UI renders", async () => {
  const v = await averin();
  const r = v.verifyBundleWith(FIXTURE.bundle, FIXTURE.opts);

  // Integrity baseline still holds.
  expect(r.ok).toBe(true);
  expect(r.records_proven).toBeGreaterThan(0);

  // Pinning broker_authority_keys/resource_authority_keys ELEVATES grant accountability — the axis the UI's
  // accountability row + broker_trust stat convey (NOT keys_externally_pinned, which tracks record-signing
  // authenticity and stays false here because the fixture pins roles, not generic signing keys).
  expect(r.broker_trust).toBe("sequence_verified");
  expect(r.grant_accountability).toBe("complete");
  expect(r.grant_verified).toBeGreaterThan(0);

  // The Tier-B use surface the UI shows: a matched use, no violations.
  expect(r.uses_matched).toBeGreaterThan(0);
  expect(r.unmatched_violation).toBe(0);

  // The capstone + its caveat fields are present (UI accountability row).
  expect(typeof r.action_completeness).toBe("string");
  expect(typeof r.resource_trust).toBe("string");
});

test("WITHOUT pinned keys the SAME bundle is NOT elevated (the honest downgrade the UI shows)", async () => {
  const v = await averin();
  const r = v.verifyBundle(JSON.stringify(FIXTURE.bundle));
  // No role pins -> accountability is not elevated: grants incomplete, the use unmatched, broker trust at the
  // export-consistency floor. keys_externally_pinned is false in BOTH cases (it is a different axis).
  expect(r.broker_trust).toBe("sequence_consistent_export");
  expect(r.grant_accountability).toBe("incomplete");
  expect(r.uses_matched).toBe(0);
  expect(r.keys_externally_pinned).toBe(false);
});
