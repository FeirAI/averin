// Supply-chain pin: the .wasm is the trust root, so initFeir must REFUSE to instantiate a core whose digest
// does not match the pinned build (fail-closed). Without this, a swapped/tampered binary (MitM/CDN swap of
// just the .wasm) would run and could certify a forged bundle ok:true — a fail-open one level up.
import { test, expect } from "bun:test";
import { initFeir, sha256Hex } from "../feir.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "feir_decision_core.wasm");
const BUNDLE = join(ROOT, "spec", "fixtures", "bundle-valid.json");

const bytes = () => new Uint8Array(readFileSync(WASM));
const ZERO = "sha256:" + "0".repeat(64);

test("a matching pinned digest loads and is exposed for display", async () => {
  const want = await sha256Hex(bytes());
  const v = await initFeir(bytes(), { expectedSha256: "sha256:" + want });
  expect(v.wasmSha256).toBe(want);
  // and it actually verifies (the pin did not break the happy path).
  expect(v.verifyBundle(readFileSync(BUNDLE, "utf8")).ok).toBe(true);
});

test("the prefix is optional and the match is case-insensitive", async () => {
  const want = await sha256Hex(bytes());
  const v = await initFeir(bytes(), { expectedSha256: want.toUpperCase() });
  expect(v.wasmSha256).toBe(want);
});

test("a MISMATCHED pinned digest fails closed (refuses to instantiate)", async () => {
  await expect(initFeir(bytes(), { expectedSha256: ZERO })).rejects.toThrow(/digest mismatch/);
});

test("no pin still loads (back-compat) but reports the computed digest", async () => {
  const v = await initFeir(bytes());
  expect(v.wasmSha256).toBe(await sha256Hex(bytes()));
});

test("the committed sidecar digest matches the built wasm (pin is not stale)", async () => {
  const sidecar = readFileSync(join(import.meta.dir, "..", "feir_decision_core.wasm.sha256"), "utf8").trim();
  const pinned = sidecar.replace(/^sha256:/, "").split(/\s+/)[0];
  expect(pinned).toBe(await sha256Hex(bytes()));
});
