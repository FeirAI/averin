// feir-ops#16: the WASM target replays the same rows as the native Rust test (core/tests/canonical_shape.rs)
// and the cgo test (server/internal/core/canonical_shape_vectors_test.go). The bundles are signed by a
// TEST-ONLY seed-0 key, the key of spec/fixtures/bundle-valid.json.
import {test, expect} from "bun:test";
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {initAverin} from "../averin.js";

const root = join(import.meta.dir, "..", "..");

test("WASM replays the canonical-set and closed-member vectors", async () => {
  const rows = JSON.parse(readFileSync(join(root, "spec/fixtures/canonical-shape-vectors.json"), "utf8"));
  expect(rows.length).toBe(20);
  const wasm = new Uint8Array(readFileSync(join(root, "target/wasm32-unknown-unknown/release/averin_decision_core.wasm")));
  const verifier = await initAverin(wasm);
  for (const row of rows) {
    const r = verifier.verifyBundleWith(row.bundle_json, row.opts_json);
    expect(r.ok, row.name).toBe(row.expected_ok);
    expect(r.records_proven, row.name).toBe(row.expected_records_proven);
    expect(r.checkpoints_verified, row.name).toBe(row.expected_checkpoints_verified);
    const text = JSON.stringify(r.issues) + JSON.stringify(r.records);
    expect(text.includes(row.expected_reason), row.name).toBe(true);
  }
  const names = rows.map((r) => r.name);
  expect(names).toContain("r1_parents_unsorted");
  expect(names).toContain("r2_frontier_unsorted");
  expect(names).toContain("r3_extensions_open");
});
