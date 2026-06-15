// feir.js — load the feir decision-core WASM and verify export bundles, fully offline.
//
// No framework, no build step, no network: the whole verifier is this file + the .wasm + an HTML
// page. The WASM is the SAME Rust integrity core as the CLI and the cgo FFI (threat #10), exposed
// over a tiny C ABI (feir_alloc / feir_verify_bundle_json / feir_string_free / feir_dealloc). You
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

class FeirVerifier {
  constructor(instance) {
    this.x = instance.exports;
  }

  _mem() {
    // Re-read after every call: a Rust allocation can grow memory and detach old views.
    return new Uint8Array(this.x.memory.buffer);
  }

  _writeCString(str) {
    const bytes = new TextEncoder().encode(str);
    const size = bytes.length + 1;
    const ptr = this.x.feir_alloc(size);
    this._mem().set(bytes, ptr); // JSON never contains a raw NUL, so null-termination is safe
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
    const out = this._call1(this.x.feir_verify_bundle_json, bundleJson);
    if (out === null) throw new Error("verifier returned null (invalid input)");
    return JSON.parse(out);
  }

  /** Canonicalize a JSON document under RCP v1 (or a string starting with "ERROR:"). */
  canonicalize(jsonDoc) {
    return this._call1(this.x.feir_rcp_canonicalize, jsonDoc) ?? "ERROR: null input";
  }
}
