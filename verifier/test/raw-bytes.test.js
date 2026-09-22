// The browser path must verify the exact bytes of a file, like the CLI: no BOM stripping, no U+FFFD
// substitution, no trimming — otherwise the browser can PASS a file the CLI rejects, and `bundle_digest`
// would not bind the file the auditor supplied.
import { test, expect } from "bun:test";
import { initAverin, sha256Hex } from "../averin.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..");
const WASM = join(ROOT, "target", "wasm32-unknown-unknown", "release", "averin_decision_core.wasm");
const BUNDLE = join(ROOT, "spec", "fixtures", "bundle-valid.json");
const averin = () => initAverin(new Uint8Array(readFileSync(WASM)));

test("raw file bytes verify and bundle_digest binds exactly those bytes", async () => {
  const v = await averin();
  const raw = new Uint8Array(readFileSync(BUNDLE));
  const r = v.verifyBundle(raw);
  expect(r.ok).toBe(true);
  if (r.bundle_digest !== undefined) {
    expect(String(r.bundle_digest).replace(/^sha256:/, "")).toBe(await sha256Hex(raw));
  }
});

test("a BOM-prefixed file is rejected, as by the CLI", async () => {
  const v = await averin();
  const raw = new Uint8Array(readFileSync(BUNDLE));
  const withBom = new Uint8Array(raw.length + 3);
  withBom.set([0xef, 0xbb, 0xbf], 0);
  withBom.set(raw, 3);
  expect(v.verifyBundle(withBom).ok).toBe(false);
});

test("a lone surrogate in pasted text is refused rather than replaced", async () => {
  const v = await averin();
  expect(() => v.verifyBundle('{"a":"\uD800"}')).toThrow(/lone UTF-16 surrogate/);
});
