// Regression: the WASM/FFI verifier must NOT be truncatable at an interior NUL.
//
// Before the fix, averin.js called the NUL-terminated `averin_verify_bundle_json`, so a file
// `‹valid bundle› 0x00 ‹arbitrary bytes›` was silently truncated at the first 0x00 and reported
// ok:true over a prefix only — a fail-OPEN on the auditor-facing browser verifier. verifyBundle now
// uses the length-aware `averin_verify_bundle_json_n`, so the full input is verified and an interior
// NUL fails closed (valid RCP never contains 0x00).
import { test, expect } from "bun:test";
import { initAverin } from "../averin.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "averin_decision_core.wasm");
const BUNDLE = join(ROOT, "spec", "fixtures", "bundle-valid.json");
const NUL = String.fromCharCode(0);

async function averin() {
  return initAverin(new Uint8Array(readFileSync(WASM)));
}

test("baseline: the clean bundle verifies", async () => {
  const v = await averin();
  expect(v.verifyBundle(readFileSync(BUNDLE, "utf8")).ok).toBe(true);
});

test("control: trailing garbage WITHOUT a NUL fails closed", async () => {
  const v = await averin();
  const clean = readFileSync(BUNDLE, "utf8");
  expect(v.verifyBundle(clean + '{"decoy":"x"}PADDING').ok).toBe(false);
});

test("interior NUL + trailing bytes fails closed (no prefix-only truncation)", async () => {
  const v = await averin();
  const clean = readFileSync(BUNDLE, "utf8");
  const attack = clean + NUL + JSON.stringify({ decoy: "unverified", evil: "x".repeat(40) }) + "PADDING";
  const report = v.verifyBundle(attack);
  expect(report.ok).toBe(false); // was true (3/3 "proven") before the length-aware fix
});

test("canonicalize rejects an interior NUL rather than truncating", async () => {
  const v = await averin();
  expect(() => v.canonicalize('{"a":1}' + NUL + "junk")).toThrow();
});

test("verifyBundleWith: interior NUL in the bundle fails closed (length-aware _with_n)", async () => {
  const v = await averin();
  const clean = readFileSync(BUNDLE, "utf8");
  const attack = clean + NUL + JSON.stringify({ decoy: "unverified" }) + "PADDING";
  // verifyBundleWith now uses averin_verify_bundle_with_n, so the full input is read and an interior NUL
  // fails closed at canonicalization instead of truncating to a verified prefix.
  expect(v.verifyBundleWith(attack, {}).ok).toBe(false);
});

test("the wasm exports ONLY the length-aware verify entrypoints (no NUL-truncatable variant)", async () => {
  const v = await averin();
  // The auditor-facing wasm must not expose a verify entrypoint a third party could call NUL-unsafe.
  expect(typeof v.x.averin_verify_bundle_json_n).toBe("function");
  expect(typeof v.x.averin_verify_bundle_with_n).toBe("function");
  expect(v.x.averin_verify_bundle_json).toBeUndefined();
  expect(v.x.averin_verify_bundle_with).toBeUndefined();
});
