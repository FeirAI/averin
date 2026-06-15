import { test, expect } from "bun:test";
import { initFeir } from "../feir.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "feir_decision_core.wasm");
const BUNDLE = join(ROOT, "spec", "fixtures", "bundle-valid.json");

async function feir() {
  return initFeir(new Uint8Array(readFileSync(WASM)));
}

test("verifies a valid bundle offline in wasm (same core as CLI/FFI)", async () => {
  const v = await feir();
  const report = v.verifyBundle(readFileSync(BUNDLE, "utf8"));
  expect(report.ok).toBe(true);
  expect(report.records_proven).toBe(3);
  expect(report.chain_ok).toBe(true);
});

test("detects a tampered bundle", async () => {
  const v = await feir();
  const tampered = readFileSync(BUNDLE, "utf8").replace("billing-agent", "evilxx-agent");
  const report = v.verifyBundle(tampered);
  expect(report.ok).toBe(false);
});

test("canonicalize matches the core and rejects floats", async () => {
  const v = await feir();
  expect(v.canonicalize('{"b":1,"a":2}')).toBe('{"a":2,"b":1}');
  expect(v.canonicalize('{"a":1.5}')).toStartWith("ERROR:");
});
