// Regression: the WASM/FFI verifier must NOT be truncatable at an interior NUL.
//
// Before the fix, feir.js called the NUL-terminated `feir_verify_bundle_json`, so a file
// `‹valid bundle› 0x00 ‹arbitrary bytes›` was silently truncated at the first 0x00 and reported
// ok:true over a prefix only — a fail-OPEN on the auditor-facing browser verifier. verifyBundle now
// uses the length-aware `feir_verify_bundle_json_n`, so the full input is verified and an interior
// NUL fails closed (valid RCP never contains 0x00).
import { test, expect } from "bun:test";
import { initFeir } from "../feir.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "feir_decision_core.wasm");
const BUNDLE = join(ROOT, "spec", "fixtures", "bundle-valid.json");
const NUL = String.fromCharCode(0);

async function feir() {
  return initFeir(new Uint8Array(readFileSync(WASM)));
}

test("baseline: the clean bundle verifies", async () => {
  const v = await feir();
  expect(v.verifyBundle(readFileSync(BUNDLE, "utf8")).ok).toBe(true);
});

test("control: trailing garbage WITHOUT a NUL fails closed", async () => {
  const v = await feir();
  const clean = readFileSync(BUNDLE, "utf8");
  expect(v.verifyBundle(clean + '{"decoy":"x"}PADDING').ok).toBe(false);
});

test("interior NUL + trailing bytes fails closed (no prefix-only truncation)", async () => {
  const v = await feir();
  const clean = readFileSync(BUNDLE, "utf8");
  const attack = clean + NUL + JSON.stringify({ decoy: "unverified", evil: "x".repeat(40) }) + "PADDING";
  const report = v.verifyBundle(attack);
  expect(report.ok).toBe(false); // was true (3/3 "proven") before the length-aware fix
});

test("canonicalize rejects an interior NUL rather than truncating", async () => {
  const v = await feir();
  expect(() => v.canonicalize('{"a":1}' + NUL + "junk")).toThrow();
});
