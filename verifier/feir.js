// feir.js — load the feir decision-core WASM and verify export bundles, fully offline.
//
// No framework, no build step, no network: the whole verifier is this file + the .wasm + an HTML
// page. The WASM is the SAME Rust integrity core as the CLI and the cgo FFI (threat #10), exposed
// over a tiny C ABI (feir_alloc / feir_verify_bundle_json_n / feir_string_free / feir_dealloc). You
// can read every line.

export async function initFeir(wasmSource) {
  let bytes;
  if (wasmSource instanceof Uint8Array) bytes = wasmSource;
  else if (wasmSource instanceof ArrayBuffer) bytes = new Uint8Array(wasmSource);
  else {
    const resp = await fetch(wasmSource);
    bytes = new Uint8Array(await resp.arrayBuffer());
  }
  // The verify path is pure computation — it needs no host imports.
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return new FeirVerifier(instance);
}

const NUL = String.fromCharCode(0);

class FeirVerifier {
  constructor(instance) {
    this.x = instance.exports;
  }

  _mem() {
    // Re-read after every call: a Rust allocation can grow memory and detach old views.
    return new Uint8Array(this.x.memory.buffer);
  }

  _writeBytes(str) {
    // Length-aware write: no NUL terminator. The callee is told the exact byte length and reads all of
    // it, so an interior 0x00 cannot truncate the input into a verified-only prefix. Used by verifyBundle.
    const bytes = new TextEncoder().encode(str);
    const ptr = this.x.feir_alloc(bytes.length);
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
    const ptr = this.x.feir_alloc(size);
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
      if (resultPtr !== 0) this.x.feir_string_free(resultPtr);
      this.x.feir_dealloc(ptr, size);
    }
  }

  /** Verify an export bundle (JSON string) entirely offline. Returns the parsed report object. */
  verifyBundle(bundleJson) {
    // Length-aware call: the verifier reads exactly `len` bytes, so an interior NUL (never present in
    // valid RCP) cannot truncate the artifact into a prefix-only "ok" — it is verified in full and
    // fails closed. (The old NUL-terminated feir_verify_bundle_json truncated at the first 0x00.)
    const { ptr, len } = this._writeBytes(bundleJson);
    let resultPtr = 0;
    try {
      resultPtr = this.x.feir_verify_bundle_json_n(ptr, len);
      if (resultPtr === 0) throw new Error("verifier returned null (invalid input)");
      return JSON.parse(this._readCString(resultPtr));
    } finally {
      if (resultPtr !== 0) this.x.feir_string_free(resultPtr);
      this.x.feir_dealloc(ptr, len);
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
    // Both args go through _writeCString, which rejects an interior NUL (valid RCP never contains 0x00),
    // so this is NUL-truncation-safe (fail-closed on a malformed/adversarial bundle).
    const a = this._writeCString(bundleJson);
    const o = this._writeCString(typeof opts === "string" ? opts : JSON.stringify(opts ?? {}));
    let resultPtr = 0;
    try {
      resultPtr = this.x.feir_verify_bundle_with(a.ptr, o.ptr);
      if (resultPtr === 0) throw new Error("verifier returned null (invalid input)");
      return JSON.parse(this._readCString(resultPtr));
    } finally {
      if (resultPtr !== 0) this.x.feir_string_free(resultPtr);
      this.x.feir_dealloc(a.ptr, a.size);
      this.x.feir_dealloc(o.ptr, o.size);
    }
  }

  /** Canonicalize a JSON document under RCP v1 (or a string starting with "ERROR:"). */
  canonicalize(jsonDoc) {
    return this._call1(this.x.feir_rcp_canonicalize, jsonDoc) ?? "ERROR: null input";
  }
}
