// Broker-path coverage for the standalone WASM/JS offline verifier (feir's "verify in your browser"
// surface). Before this, the WASM verifier was only tested against a 3-record NON-broker bundle and
// feir.js could not even pin broker keys. This exercises the Tier-A/B credential-broker path against a
// real Go-produced bundle (spec/fixtures/bundle-broker-valid.json), through the same WASM core as the
// CLI/FFI, with pinned broker/resource/tsa roles — plus the fail-closed direction.
import { test, expect } from "bun:test";
import { initFeir } from "../feir.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "feir_decision_core.wasm");
const FIXTURE = join(ROOT, "spec", "fixtures", "bundle-broker-valid.json");

async function feir() {
  return initFeir(new Uint8Array(readFileSync(WASM)));
}

function fixture() {
  return JSON.parse(readFileSync(FIXTURE, "utf8"));
}

test("verifies a Tier-A/B broker bundle offline in wasm with pinned roles", async () => {
  const v = await feir();
  const f = fixture();
  const r = v.verifyBundleWith(JSON.stringify(f.bundle), f.opts);
  expect(r.ok).toBe(true);
  expect(r.uses_matched).toBe(1); // the closed two-phase use joins its grant
  expect(r.grant_verified).toBeGreaterThanOrEqual(1); // the gateway_enforced grant elevated
  expect(r.unmatched_violation).toBe(0);
});

test("fail-closed: broker/resource key-set overlap is rejected (R2 disjointness)", async () => {
  const v = await feir();
  const f = fixture();
  // Pin the SAME key as BOTH the broker and resource authority. The verifier rejects this as a fatal
  // config error (R2: the broker and resource recording-key sets MUST be disjoint, or a broker key
  // could also count as a resource key and self-sign a use receipt).
  const overlap = { ...f.opts, resource_authority_keys: f.opts.broker_authority_keys };
  const r = v.verifyBundleWith(JSON.stringify(f.bundle), overlap);
  expect(r.ok).toBe(false);
});

test("fail-closed: a tampered grant record fails verification", async () => {
  const v = await feir();
  const f = fixture();
  // Flip a byte inside the signed grant body — breaks its content_hash / authority sig.
  const tampered = JSON.stringify(f.bundle).replace("credential_grant", "credentialXgrant");
  const r = v.verifyBundleWith(tampered, f.opts);
  expect(r.ok).toBe(false);
});

test("fail-closed: WITHOUT pinned broker/resource keys the grant does not elevate", async () => {
  const v = await feir();
  const f = fixture();
  // No pinned authority keys -> the grant cannot reach gateway_enforced / grant_verified.
  const r = v.verifyBundleWith(JSON.stringify(f.bundle), {});
  expect(r.grant_verified).toBe(0);
});
