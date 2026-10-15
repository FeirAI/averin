// AVE-01: the browser verifier is built from the same core, so a month segment verifies in wasm exactly as it
// does natively: the same report, the link pin honored, and a dropped record or a wrong base rejected.
import { test, expect } from "bun:test";
import { initAverin } from "../averin.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "averin_decision_core.wasm");
const month = (m) => readFileSync(join(ROOT, "spec", "fixtures", `segment-${m}.json`), "utf8");
const averin = () => initAverin(new Uint8Array(readFileSync(WASM)));

test("each month verifies in wasm and chains to the previous head", async () => {
  const v = await averin();
  let pin = "genesis";
  for (const [m, link, records] of [["2026-06", "genesis", 3], ["2026-07", "base_pinned", 2], ["2026-08", "base_pinned", 3]]) {
    const r = v.verifyBundleWith(month(m), JSON.stringify({ segment_base_checkpoint_hash: pin }));
    expect(r.ok).toBe(true);
    expect(r.records_total).toBe(records);
    expect(r.segment.month).toBe(m);
    expect(r.segment.link).toBe(link);
    pin = r.segment.head_checkpoint_hash;
  }
});

test("an unpinned base is reported as such, a wrong pin fails", async () => {
  const v = await averin();
  expect(v.verifyBundle(month("2026-07")).segment.link).toBe("base_unpinned");
  const wrong = JSON.stringify({ segment_base_checkpoint_hash: "sha256:" + "ab".repeat(32) });
  expect(v.verifyBundleWith(month("2026-07"), wrong).ok).toBe(false);
});

test("a month with a record removed fails", async () => {
  const v = await averin();
  const b = JSON.parse(month("2026-07"));
  b.records.shift();
  expect(v.verifyBundle(JSON.stringify(b)).ok).toBe(false);
});

test("the month that points before its base lists the earlier parent and reports the grant log as not evaluated", async () => {
  const v = await averin();
  const r = v.verifyBundle(month("2026-08"));
  expect(r.segment.earlier_parent_refs).toBe(1);
  expect(r.segment.not_evaluated).toEqual(["broker_grant_log", "federation_heads"]);
});
