import {test, expect} from "bun:test";
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {initAverin} from "../averin.js";

const root = join(import.meta.dir, "..", "..");
const base = JSON.parse(readFileSync(join(root, "spec/fixtures/bundle-broker-valid.json"), "utf8"));
const cases = JSON.parse(readFileSync(join(root, "spec/fixtures/verdict-attachment-cases.json"), "utf8"));
const fields = ["integrity", "authenticated", "authorized", "temporal", "complete_brokered", "complete_introspected"];

function input(c) {
  const bundle = structuredClone(base.bundle);
  if (c.strip_anchor) for (const checkpoint of bundle.checkpoints) delete checkpoint.anchor;
  if (c.malformed_disclosures) bundle.disclosures = "bad optional disclosure";
  const opts = structuredClone(base.opts);
  if (c.pin_signer) opts.signing_keys = bundle.keys.map(k => k.public_key);
  return {bundle, opts};
}

function support(r) {
  expect(r.claims_version).toBe("1");
  expect(fields).toContain(r.claims.requested);
  expect(r.claims.requested_decision).toBe(r.claims[r.claims.requested]);
  return new Set(fields.filter(k => r.claims[k] === "satisfied"));
}

function subset(a, b) {
  for (const value of a) expect(b.has(value)).toBe(true);
}

test("WASM claim corpus: support erasure across anchor, malformed optional and pin subsets", async () => {
  const wasm = new Uint8Array(readFileSync(join(root, "target/wasm32-unknown-unknown/release/averin_decision_core.wasm")));
  const verifier = await initAverin(wasm);
  const reports = new Map();
  for (const c of cases) {
    const {bundle, opts} = input(c);
    reports.set(c.name, support(verifier.verifyBundleWith(JSON.stringify(bundle), opts)));
  }
  subset(reports.get("anchor_removed"), reports.get("full"));
  subset(reports.get("self_signed_anchor_removed"), reports.get("self_signed"));
  subset(reports.get("anchor_removed_malformed"), reports.get("malformed_optional"));
  subset(reports.get("self_signed_anchor_removed_malformed"), reports.get("self_signed_malformed"));
  // A malformed optional attachment can change diagnostics, but deleting it grants no authority.
  subset(reports.get("full"), reports.get("malformed_optional"));
  subset(reports.get("malformed_optional"), reports.get("full"));
  subset(reports.get("self_signed"), reports.get("full"));
});

test("WASM replays exact generated signed verdict corpus", async () => {
  const rows = JSON.parse(readFileSync(join(root, "spec/fixtures/verdict-generated.json"), "utf8"));
  expect(rows.length).toBeGreaterThanOrEqual(30);
  const wasm = new Uint8Array(readFileSync(join(root, "target/wasm32-unknown-unknown/release/averin_decision_core.wasm")));
  const verifier = await initAverin(wasm);
  let authorized = false;
  let brokeredComplete = false;
  let nativeComplete = false;
  let partialAnchorFailedPoP = false;
  for (const row of rows) {
    const report = verifier.verifyBundleWith(row.bundle_json, row.opts_json);
    expect(report.bundle_digest).toBe(row.expected_bundle_digest);
    expect(report.claims).toEqual(row.expected_claims);
    expect(report.ok).toBe(row.expected_ok);
    expect(report.action_completeness).toBe(row.expected_action_completeness);
    expect(report.unmatched_violation).toBe(row.expected_unmatched_violation);
    if (row.name === "v3_authorized/anchors_1/base") authorized = report.claims.authorized === "satisfied";
    if (row.name === "v3_capstone/anchors_1/base") brokeredComplete = report.claims.complete_brokered === "satisfied";
    if (row.name === "v3_native_capstone/anchors_1/base") nativeComplete = report.claims.complete_introspected === "satisfied";
    if (row.name === "failed_pop_partial_anchor/anchors_1/base") partialAnchorFailedPoP = !report.ok && report.unmatched_violation > 0;
  }
  expect(authorized).toBe(true);
  expect(brokeredComplete).toBe(true);
  expect(nativeComplete).toBe(true);
  expect(partialAnchorFailedPoP).toBe(true);
});
