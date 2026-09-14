#!/usr/bin/env bun
// Regenerates verifier/samples/{valid,demo-keys,tampered}.json from spec/fixtures/bundle-valid.json.
// Bun, no dependencies. Run with: bun verifier/samples/make-samples.mjs
//
// Why these three files:
//  - valid.json      : the shipped fixture, byte-identical. Verifies CONSISTENT (unpinned) — no keys needed.
//  - demo-keys.json   : the PUBLIC ed25519pub: key that signed the fixture, so pinning it yields PASS. This
//                        is the record-signing key for the fixture's DEV seed [0u8; 32] (an all-zero seed
//                        hardcoded in core/examples/gen_fixtures.rs — deterministic and already public, not
//                        a secret). It is the same value the fixture itself declares under keys[0].public_key;
//                        we do not reimplement ed25519 keygen here, but this script asserts the value still
//                        matches the fixture on every regen so the sample can never silently drift from it.
//                        Independently confirmed by running, from core/:
//                          cargo run --example tmp_print_pubkey   (signing_key_from_seed(&[0u8;32]))
//                        which printed the same ed25519pub: string below. PUBLIC KEY ONLY — no private seed
//                        or secret material is written to this repo.
//  - tampered.json    : valid.json with one character flipped inside record r0's sealed body
//                        (received_ts 10:00:00.100Z -> 10:00:00.101Z), so content_hash/sig no longer match
//                        the body and the verifier reports a broken link. Everything else byte-identical.
//
// Re-run this whenever spec/fixtures/bundle-valid.json changes so the samples never drift from the core.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const FIXTURE = join(ROOT, "spec", "fixtures", "bundle-valid.json");

const DEMO_PUBKEY = "ed25519pub:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";

// The exact substring tampered: one character in r0's received_ts, inside its signed body.
const TAMPER_FROM = "2026-06-15T10:00:00.100Z";
const TAMPER_TO = "2026-06-15T10:00:00.101Z";

function main() {
  mkdirSync(HERE, { recursive: true });

  const bundleText = readFileSync(FIXTURE, "utf8");
  const bundle = JSON.parse(bundleText);

  const declaredKey = bundle?.keys?.[0]?.public_key;
  if (declaredKey !== DEMO_PUBKEY) {
    throw new Error(
      `fixture's declared signing key changed (now ${declaredKey}) — regenerate DEMO_PUBKEY in ` +
        `make-samples.mjs (see the derivation note at the top of this file) before writing samples`,
    );
  }

  // valid.json: byte-identical copy of the shipped fixture.
  writeFileSync(join(HERE, "valid.json"), bundleText);

  // demo-keys.json: the opts.json shape the UI's "pin trust roots" textarea expects. Pinning signing_keys
  // is the ONLY opt that flips the trust root to pinned and the verdict to a green PASS.
  const demoKeys = { signing_keys: [DEMO_PUBKEY] };
  writeFileSync(join(HERE, "demo-keys.json"), JSON.stringify(demoKeys, null, 2) + "\n");

  // tampered.json: one character changed inside a sealed record body.
  const occurrences = bundleText.split(TAMPER_FROM).length - 1;
  if (occurrences !== 1) {
    throw new Error(
      `expected exactly one occurrence of "${TAMPER_FROM}" in the fixture, found ${occurrences} — ` +
        `pick a different unique tamper target before writing tampered.json`,
    );
  }
  const tampered = bundleText.replace(TAMPER_FROM, TAMPER_TO);
  writeFileSync(join(HERE, "tampered.json"), tampered);

  console.log("wrote valid.json, demo-keys.json, tampered.json in", HERE);
}

main();
