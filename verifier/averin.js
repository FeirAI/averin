// averin.js — load the averin decision-core WASM and verify export bundles, fully offline.
//
// No framework, no build step, no network: the whole verifier is this file + the .wasm + an HTML
// page. The WASM is the SAME Rust integrity core as the CLI and the cgo FFI (threat #10), exposed
// over a tiny C ABI (averin_alloc / averin_verify_bundle_json_n / averin_string_free / averin_dealloc). You
// can read every line.

/**
 * Load the verifier core. `opts.expectedSha256` PINS the .wasm — the trust root. When provided, the loaded
 * bytes are digested and a MISMATCH refuses to instantiate (fail-closed): a substituted/tampered core (a
 * MitM/CDN swap of just the binary) must never run and certify bundles. This is the one-level-up supply-chain
 * defense — without it, a forged .wasm could report `ok:true` over anything. The digest is also exposed as
 * `verifier.wasmSha256` so a page can DISPLAY it for out-of-band comparison against the reproducible build
 * (see verifier/SUPPLY-CHAIN.md). Accepts a "sha256:"-prefixed or bare hex digest, case-insensitively.
 */
export async function initAverin(wasmSource, opts = {}) {
  let bytes;
  if (wasmSource instanceof Uint8Array) bytes = wasmSource;
  else if (wasmSource instanceof ArrayBuffer) bytes = new Uint8Array(wasmSource);
  else {
    const resp = await fetch(wasmSource);
    bytes = new Uint8Array(await resp.arrayBuffer());
  }
  const sha256 = await sha256Hex(bytes);
  const expected = normalizeDigest(opts.expectedSha256);
  if (expected && expected !== sha256) {
    // Fail CLOSED: do not instantiate a core that does not match the pinned build.
    throw new Error(
      `wasm digest mismatch — refusing to load a verifier core that does not match the pinned build ` +
        `(pinned sha256:${expected}, got sha256:${sha256})`,
    );
  }
  // The verify path is pure computation — it needs no host imports.
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const v = new AverinVerifier(instance);
  v.wasmSha256 = sha256;
  return v;
}

/** SHA-256 of `bytes` (Uint8Array) as lowercase hex, via WebCrypto (browser + Node/Bun). */
export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function normalizeDigest(d) {
  if (d === undefined || d === null) return null;
  const hex = String(d).trim().toLowerCase().replace(/^sha256:/, "");
  // A pin that is present but empty/malformed (e.g. "sha256:") must not silently disable the check.
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`invalid wasm pin (expected 64 hex chars): ${String(d)}`);
  return hex;
}

const NUL = String.fromCharCode(0);

class AverinVerifier {
  constructor(instance) {
    this.x = instance.exports;
  }

  _mem() {
    // Re-read after every call: a Rust allocation can grow memory and detach old views.
    return new Uint8Array(this.x.memory.buffer);
  }

  _writeBytes(input) {
    // Length-aware write: no NUL terminator. The callee is told the exact byte length and reads all of
    // it, so an interior 0x00 cannot truncate the input into a verified-only prefix. Used by verifyBundle.
    // A Uint8Array is passed through UNCHANGED, so the core verifies (and `bundle_digest` binds) the exact
    // bytes of the file — no BOM stripping, no U+FFFD substitution of invalid UTF-8, no trimming.
    if (input instanceof Uint8Array) {
      const ptr = this.x.averin_alloc(input.length);
      this._mem().set(input, ptr);
      return { ptr, len: input.length };
    }
    // A JS string with a lone surrogate would be silently re-encoded as U+FFFD by TextEncoder; refuse it.
    if (typeof input.isWellFormed === "function" && !input.isWellFormed()) {
      throw new Error("input contains a lone UTF-16 surrogate (not valid RCP)");
    }
    const bytes = new TextEncoder().encode(input);
    const ptr = this.x.averin_alloc(bytes.length);
    this._mem().set(bytes, ptr);
    return { ptr, len: bytes.length };
  }

  _writeCString(str) {
    // A C string ends at the first NUL, so an interior 0x00 in untrusted input would be silently
    // truncated at the FFI boundary and a valid prefix reported "ok" over bytes never read. Valid
    // RCP/JSON never contains 0x00, so reject it here. (verifyBundle uses the length-aware path below.)
    if (str.indexOf(NUL) !== -1) throw new Error("input contains a NUL byte (not valid RCP)");
    const bytes = new TextEncoder().encode(str);
    const size = bytes.length + 1;
    const ptr = this.x.averin_alloc(size);
    this._mem().set(bytes, ptr);
    this._mem()[ptr + bytes.length] = 0;
    return { ptr, size };
  }

  _readCString(ptr) {
    const mem = this._mem();
    let end = ptr;
    while (mem[end] !== 0) end++;
    return new TextDecoder().decode(mem.subarray(ptr, end));
  }

  _call1(fn, input) {
    const { ptr, size } = this._writeCString(input);
    let resultPtr = 0;
    try {
      resultPtr = fn.call(this.x, ptr);
      return resultPtr === 0 ? null : this._readCString(resultPtr);
    } finally {
      // always free both buffers with their matching frees, even if the call traps.
      if (resultPtr !== 0) this.x.averin_string_free(resultPtr);
      this.x.averin_dealloc(ptr, size);
    }
  }

  /** Verify an export bundle (JSON string, or its raw bytes as a Uint8Array) entirely offline. Returns the parsed report object. */
  verifyBundle(bundleJson) {
    // Length-aware call: the verifier reads exactly `len` bytes, so an interior NUL (never present in
    // valid RCP) cannot truncate the artifact into a prefix-only "ok" — it is verified in full and
    // fails closed. (The old NUL-terminated averin_verify_bundle_json truncated at the first 0x00.)
    const { ptr, len } = this._writeBytes(bundleJson);
    let resultPtr = 0;
    try {
      resultPtr = this.x.averin_verify_bundle_json_n(ptr, len);
      if (resultPtr === 0) throw new Error("verifier returned null (invalid input)");
      return JSON.parse(this._readCString(resultPtr));
    } finally {
      if (resultPtr !== 0) this.x.averin_string_free(resultPtr);
      this.x.averin_dealloc(ptr, len);
    }
  }

  /**
   * Verify an export bundle with out-of-band pinned trust roots, offline. `opts` is an object whose
   * optional arrays pin keys: `authority_keys` / `broker_authority_keys` / `resource_authority_keys` /
   * `signing_keys` / `tsa_keys` (`ed25519pub:` strings) and `tsa_spki_b64`. Pinning the broker +
   * resource recording keys is what elevates a credential-broker bundle to Tier-A grant accountability
   * and Tier-B action accountability (role-separated, ADR 0003 R2). Returns the parsed report.
   */
  verifyBundleWith(bundleJson, opts) {
    // LENGTH-AWARE call (averin_verify_bundle_with_n): both the bundle AND the pinned opts are passed with their
    // exact byte lengths, so an interior 0x00 in either (never present in valid RCP / an ed25519pub: or base64url
    // value) cannot truncate the bundle to a verified prefix NOR silently drop the pinned trust roots — the full
    // input is verified and fails closed. The NUL-truncatable C-string entrypoints are not compiled into the wasm.
    const a = this._writeBytes(
      typeof bundleJson === "string" || bundleJson instanceof Uint8Array ? bundleJson : JSON.stringify(bundleJson),
    );
    const o = this._writeBytes(typeof opts === "string" ? opts : JSON.stringify(opts ?? {}));
    let resultPtr = 0;
    try {
      resultPtr = this.x.averin_verify_bundle_with_n(a.ptr, a.len, o.ptr, o.len);
      if (resultPtr === 0) throw new Error("verifier returned null (invalid input)");
      return JSON.parse(this._readCString(resultPtr));
    } finally {
      if (resultPtr !== 0) this.x.averin_string_free(resultPtr);
      this.x.averin_dealloc(a.ptr, a.len);
      this.x.averin_dealloc(o.ptr, o.len);
    }
  }

  /** Canonicalize a JSON document under RCP v1 (or a string starting with "ERROR:"). */
  canonicalize(jsonDoc) {
    return this._call1(this.x.averin_rcp_canonicalize, jsonDoc) ?? "ERROR: null input";
  }
}
