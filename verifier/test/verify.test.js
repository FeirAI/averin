import { test, expect } from "bun:test";
import { initAverin } from "../averin.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "averin_decision_core.wasm");
const BUNDLE = join(ROOT, "spec", "fixtures", "bundle-valid.json");

async function averin() {
  return initAverin(new Uint8Array(readFileSync(WASM)));
}

test("verifies a valid bundle offline in wasm (same core as CLI/FFI)", async () => {
  const v = await averin();
  const report = v.verifyBundle(readFileSync(BUNDLE, "utf8"));
  expect(report.ok).toBe(true);
  expect(report.records_proven).toBe(3);
  expect(report.chain_ok).toBe(true);
});

test("detects a tampered bundle", async () => {
  const v = await averin();
  const tampered = readFileSync(BUNDLE, "utf8").replace("billing-agent", "evilxx-agent");
  const report = v.verifyBundle(tampered);
  expect(report.ok).toBe(false);
});

test("canonicalize matches the core and rejects floats", async () => {
  const v = await averin();
  expect(v.canonicalize('{"b":1,"a":2}')).toBe('{"a":2,"b":1}');
  expect(v.canonicalize('{"a":1.5}')).toStartWith("ERROR:");
});
