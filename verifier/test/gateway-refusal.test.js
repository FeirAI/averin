// cross-impl-refusal-vector: the WASM target replays the same rows as the native Rust test
// (core/tests/gateway_refusal.rs) and the cgo test (server/internal/core/refusal_vectors_test.go).
// The vectors are signed by TEST-ONLY keys listed in spec/test-keys.json.
import {test, expect} from "bun:test";
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {initAverin} from "../averin.js";

const root = join(import.meta.dir, "..", "..");

test("WASM replays the gateway refusal vectors", async () => {
  const rows = JSON.parse(readFileSync(join(root, "spec/fixtures/gateway-refusal-vectors.json"), "utf8"));
  expect(rows.length).toBe(4);
  const wasm = new Uint8Array(readFileSync(join(root, "target/wasm32-unknown-unknown/release/averin_decision_core.wasm")));
  const verifier = await initAverin(wasm);
  for (const row of rows) {
    const r = verifier.verifyBundleWith(row.bundle_json, row.opts_json);
    expect(r.ok).toBe(row.expected_ok);
    expect(r.gateway_refusals).toBe(row.expected_gateway_refusals);
    expect(r.gateway_refusal_attempts).toBe(row.expected_gateway_refusal_attempts);
    expect(r.gateway_refusals_by_class).toEqual(row.expected_gateway_refusals_by_class);
    expect(r.issues.some((i) => i.includes("gateway refusal"))).toBe(row.expected_refusal_issue);
  }
  const names = rows.map((r) => r.name);
  expect(names).toContain("legacy_event_type_only");
  expect(rows.find((r) => r.name === "legacy_event_type_only").expected_gateway_refusals).toBe(0);
});
