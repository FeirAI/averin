// Locks the verdicts of the shipped browser-demo samples to the core so verifier/samples/*.json can never
// silently drift from what the WASM core actually decides. Regenerate the samples with
// `bun verifier/samples/make-samples.mjs` (from spec/fixtures/bundle-valid.json) if this ever fails.
import { test, expect } from "bun:test";
import { initAverin } from "../averin.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "averin_decision_core.wasm");
const SAMPLES = join(import.meta.dir, "..", "samples");

async function averin() {
  return initAverin(new Uint8Array(readFileSync(WASM)));
}

test("valid.json verifies ok and is NOT pinned (bundle-supplied trust root)", async () => {
  const v = await averin();
  const bundle = readFileSync(join(SAMPLES, "valid.json"), "utf8");
  const report = v.verifyBundle(bundle);
  expect(report.ok).toBe(true);
  expect(report.keys_externally_pinned).toBeFalsy();
});

test("valid.json + demo-keys.json verifies ok and IS externally pinned", async () => {
  const v = await averin();
  const bundle = readFileSync(join(SAMPLES, "valid.json"), "utf8");
  const opts = JSON.parse(readFileSync(join(SAMPLES, "demo-keys.json"), "utf8"));
  const report = v.verifyBundleWith(bundle, opts);
  expect(report.ok).toBe(true);
  expect(report.keys_externally_pinned).toBe(true);
});

test("tampered.json is detected as NOT ok", async () => {
  const v = await averin();
  const bundle = readFileSync(join(SAMPLES, "tampered.json"), "utf8");
  const report = v.verifyBundle(bundle);
  expect(report.ok).toBe(false);
  expect(report.first_broken_link).toBeTruthy();
});

test("tampered.json is also detected as NOT ok when the demo keys are pinned", async () => {
  const v = await averin();
  const bundle = readFileSync(join(SAMPLES, "tampered.json"), "utf8");
  const opts = JSON.parse(readFileSync(join(SAMPLES, "demo-keys.json"), "utf8"));
  const report = v.verifyBundleWith(bundle, opts);
  expect(report.ok).toBe(false);
});
