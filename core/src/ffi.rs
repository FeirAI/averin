//! C FFI surface for cgo (the Go services call the Rust core through this — spec §5 "Go ↔ Rust:
//! cgo FFI"). Same core as the CLI and WASM. Header: `core/include/feir_core.h`.
//!
//! Memory contract: every non-null `*mut c_char` returned MUST be freed by the caller with
//! [`feir_string_free`]. This same C-ABI serves BOTH cgo (native staticlib/cdylib) and the browser
//! (wasm32 cdylib): the standalone verifier writes a null-terminated JSON string into wasm memory
//! via [`feir_alloc`], calls [`feir_verify_bundle_json`], reads the result, then frees both.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Allocate `size` bytes of wasm/native memory and return the pointer (for the browser verifier to
/// write an input string into). Pair with [`feir_dealloc`].
#[no_mangle]
pub extern "C" fn feir_alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free memory allocated by [`feir_alloc`].
///
/// # Safety
/// `ptr`/`size` must come from a prior [`feir_alloc`] call and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn feir_dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        drop(Vec::from_raw_parts(ptr, 0, size));
    }
}

/// Verify an export bundle (null-terminated UTF-8 JSON). Returns a newly-allocated, null-terminated
/// JSON report string (free with [`feir_string_free`]), or null if `input` is null or not UTF-8.
///
/// # Safety
/// `input` must be a valid null-terminated C string for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn feir_verify_bundle_json(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let text = match CStr::from_ptr(input).to_str() {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };
    let out = crate::verify::verify_bundle_to_json(text);
    match CString::new(out) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Canonicalize a JSON document under RCP v1. Returns a newly-allocated string (free with
/// [`feir_string_free`]); the result begins with `ERROR:` on a parse error. Null if input is null
/// or not UTF-8.
///
/// # Safety
/// `input` must be a valid null-terminated C string for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn feir_rcp_canonicalize(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let text = match CStr::from_ptr(input).to_str() {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };
    let out = match crate::canon::CanonValue::parse(text) {
        Ok(v) => v.serialize(),
        Err(e) => format!("ERROR: {e}"),
    };
    match CString::new(out) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Seal a Decision Record body (UTF-8 JSON) with an Ed25519 signing key (32-byte seed, 64 hex
/// chars). Returns the sealed record JSON (content_hash + sig set), or `{"error":"..."}`. Null on
/// null/invalid-UTF-8 input. The seed is the self-host signing key; production deployments back
/// signing with a KMS instead of passing a raw seed.
///
/// # Safety
/// `body` and `seed_hex` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn feir_seal_record(
    body: *const c_char,
    seed_hex: *const c_char,
) -> *mut c_char {
    seal_impl(body, seed_hex, false)
}

/// Seal a checkpoint body (UTF-8 JSON) with an Ed25519 signing key. Returns the sealed checkpoint
/// JSON (checkpoint_hash + sig set), or `{"error":"..."}`.
///
/// # Safety
/// `body` and `seed_hex` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn feir_seal_checkpoint(
    body: *const c_char,
    seed_hex: *const c_char,
) -> *mut c_char {
    seal_impl(body, seed_hex, true)
}

/// Return the `ed25519pub:` public key for a 32-byte seed (64 hex chars). The server publishes this
/// in its key list. Null on null/invalid-UTF-8; `{"error":...}` on a bad seed.
///
/// # Safety
/// `seed_hex` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn feir_pubkey_from_seed(seed_hex: *const c_char) -> *mut c_char {
    if seed_hex.is_null() {
        return std::ptr::null_mut();
    }
    let hex = match CStr::from_ptr(seed_hex).to_str() {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };
    let out = match decode_seed(hex) {
        Some(seed) => {
            let sk = crate::sign::signing_key_from_seed(&seed);
            crate::sign::encode_pubkey(&sk.verifying_key())
        }
        None => json_error("seed must be 64 lowercase hex chars (32 bytes)"),
    };
    into_cstring(out)
}

unsafe fn seal_impl(body: *const c_char, seed_hex: *const c_char, checkpoint: bool) -> *mut c_char {
    if body.is_null() || seed_hex.is_null() {
        return std::ptr::null_mut();
    }
    let body = match CStr::from_ptr(body).to_str() {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };
    let hex = match CStr::from_ptr(seed_hex).to_str() {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };
    let seed = match decode_seed(hex) {
        Some(s) => s,
        None => return into_cstring(json_error("seed must be 64 lowercase hex chars (32 bytes)")),
    };
    let sk = crate::sign::signing_key_from_seed(&seed);
    let value = match crate::canon::CanonValue::parse(body) {
        Ok(v) => v,
        Err(e) => return into_cstring(json_error(&format!("body parse error: {e}"))),
    };
    let sealed = if checkpoint {
        crate::checkpoint::seal_checkpoint(&value, &sk).map(|v| v.serialize())
    } else {
        crate::record::seal(&value, &sk).map(|v| v.serialize())
    };
    match sealed {
        Ok(json) => into_cstring(json),
        Err(e) => into_cstring(json_error(&format!("seal error: {e}"))),
    }
}

/// Generate a fresh 32-byte hiding-commitment nonce, returned as 64 lowercase hex chars. Only
/// meaningful with the `std` feature (the WASM verifier never mints nonces); returns `{"error":...}`
/// otherwise.
#[no_mangle]
pub extern "C" fn feir_random_nonce() -> *mut c_char {
    #[cfg(feature = "std")]
    {
        // Fallible: a CSPRNG failure must NOT panic-unwind across the C/cgo boundary (UB).
        match crate::commit::try_random_nonce() {
            Some(n) => into_cstring(crate::hashx::hex_lower(&n)),
            None => into_cstring(json_error("OS CSPRNG unavailable")),
        }
    }
    #[cfg(not(feature = "std"))]
    {
        into_cstring(json_error("random_nonce requires the std feature"))
    }
}

/// Compute a hiding commitment (RCP §9.3) over a low-entropy field. `domain` is one of
/// `input`/`output`/`rationale`; `value_b64` is base64url-no-pad of the raw value bytes; `nonce_hex`
/// is 64 hex chars (32 bytes). Returns `sha256:<hex>` or `{"error":...}`.
///
/// # Safety
/// All three pointers must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn feir_commit(
    domain: *const c_char,
    value_b64: *const c_char,
    nonce_hex: *const c_char,
) -> *mut c_char {
    match commit_inputs(domain, value_b64, nonce_hex) {
        Ok((d, value, nonce)) => match crate::commit::commit(d, &value, &nonce) {
            Ok(c) => into_cstring(c),
            Err(e) => into_cstring(json_error(&e.to_string())),
        },
        Err(msg) => into_cstring(json_error(msg)),
    }
}

/// Verify a disclosed `(value, nonce)` against a commitment. Returns `"true"`/`"false"`, or
/// `{"error":...}` on malformed input.
///
/// # Safety
/// All four pointers must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn feir_verify_commitment(
    commitment: *const c_char,
    domain: *const c_char,
    value_b64: *const c_char,
    nonce_hex: *const c_char,
) -> *mut c_char {
    let commitment = match cstr(commitment) {
        // Null/invalid commitment is malformed input — return error JSON like the other arms, not a
        // bare null (which the contract reserves for a different, undocumented outcome).
        Some(c) => c,
        None => return into_cstring(json_error("commitment must be non-null UTF-8")),
    };
    match commit_inputs(domain, value_b64, nonce_hex) {
        Ok((d, value, nonce)) => {
            let ok = crate::commit::verify_commitment(commitment, d, &value, &nonce);
            into_cstring(if ok { "true".into() } else { "false".into() })
        }
        Err(msg) => into_cstring(json_error(msg)),
    }
}

/// Borrow a C string as `&str` (None if null or non-UTF-8).
///
/// # Safety
/// `p` must be a valid null-terminated C string. The returned `&str` aliases the C buffer; callers
/// MUST consume it before `p` is invalidated. Every caller here uses it within the same FFI call,
/// while the pointer is guaranteed live — do not store it past that scope.
unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

#[allow(clippy::type_complexity)]
unsafe fn commit_inputs(
    domain: *const c_char,
    value_b64: *const c_char,
    nonce_hex: *const c_char,
) -> Result<(crate::commit::FieldDomain, Vec<u8>, [u8; 32]), &'static str> {
    use crate::commit::FieldDomain;
    let domain = cstr(domain).ok_or("bad domain")?;
    let d = FieldDomain::parse(domain).ok_or("domain must be input|output|rationale")?;
    let value = crate::b64::decode(cstr(value_b64).ok_or("bad value_b64")?)
        .map_err(|_| "value_b64 is not valid base64url")?;
    let nonce_hex = cstr(nonce_hex).ok_or("bad nonce_hex")?;
    let nonce = decode_seed(nonce_hex).ok_or("nonce must be 64 lowercase hex chars (32 bytes)")?;
    Ok((d, value, nonce))
}

fn decode_seed(hex: &str) -> Option<[u8; 32]> {
    crate::hashx::hex32(hex)
}

fn json_error(msg: &str) -> String {
    crate::canon::CanonValue::object(vec![(
        "error".into(),
        crate::canon::CanonValue::string(msg),
    )])
    .unwrap()
    .serialize()
}

fn into_cstring(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library.
///
/// # Safety
/// `ptr` must be a pointer previously returned by a `feir_*` function (or null), and must not be
/// used afterwards.
#[no_mangle]
pub unsafe extern "C" fn feir_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a `&str` through one of the FFI entrypoints, returning the freed result string.
    /// (Cross-language ABI symbol resolution is covered by `core/examples/ffi_smoke.c`; this
    /// exercises the unsafe body — CStr/CString handling, null guards — in CI.)
    fn call(f: unsafe extern "C" fn(*const c_char) -> *mut c_char, input: &str) -> Option<String> {
        let c = CString::new(input).unwrap();
        unsafe {
            let out = f(c.as_ptr());
            if out.is_null() {
                return None;
            }
            let s = CStr::from_ptr(out).to_string_lossy().into_owned();
            feir_string_free(out);
            Some(s)
        }
    }

    fn bundle() -> String {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("spec/fixtures/bundle-valid.json");
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    fn verify_valid_and_tampered() {
        let ok = call(feir_verify_bundle_json, &bundle()).unwrap();
        assert!(ok.contains("\"ok\":true"), "{ok}");
        assert!(ok.contains("\"records_proven\":3"));
        let bad = call(
            feir_verify_bundle_json,
            &bundle().replace("billing-agent", "evilxx-agent"),
        )
        .unwrap();
        assert!(bad.contains("\"ok\":false"), "{bad}");
    }

    #[test]
    fn canonicalize_and_errors() {
        assert_eq!(
            call(feir_rcp_canonicalize, r#"{"b":1,"a":2}"#).unwrap(),
            r#"{"a":2,"b":1}"#
        );
        assert!(call(feir_rcp_canonicalize, r#"{"a":1.5}"#)
            .unwrap()
            .starts_with("ERROR:"));
    }

    #[test]
    fn null_input_is_handled() {
        unsafe {
            assert!(feir_verify_bundle_json(std::ptr::null()).is_null());
            feir_string_free(std::ptr::null_mut()); // safe no-op
        }
    }

    fn call2(
        f: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char,
        a: &str,
        b: &str,
    ) -> String {
        let ca = CString::new(a).unwrap();
        let cb = CString::new(b).unwrap();
        unsafe {
            let out = f(ca.as_ptr(), cb.as_ptr());
            let s = CStr::from_ptr(out).to_string_lossy().into_owned();
            feir_string_free(out);
            s
        }
    }

    const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn seal_record_and_verify_roundtrip() {
        let body = r#"{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2","record_id":"r","project_id":"p","agent_id":"a","agent_version":"1","session_id":"s","span_id":"sp","parent_span_id":null,"causal_prev_hashes":[],"display_seq":0,"agent_ts":"2026-06-15T10:00:00.000Z","received_ts":"2026-06-15T10:00:00.000Z","event_type":"tool_call","action":"x","observed_via":"sdk","status":"ok","key":{"signing_key_id":"k0","key_epoch":0,"key_status":"active"}}"#;
        let sealed = call2(feir_seal_record, body, SEED);
        assert!(sealed.contains("\"content_hash\":\"sha256:"));
        assert!(sealed.contains("\"sig\":\"ed25519:"));

        // the published pubkey verifies the sealed record
        let pk = call(feir_pubkey_from_seed_one, SEED);
        let _ = pk; // see helper below
    }

    // wrapper so `call` (single-arg) can exercise pubkey_from_seed
    unsafe extern "C" fn feir_pubkey_from_seed_one(s: *const c_char) -> *mut c_char {
        feir_pubkey_from_seed(s)
    }

    #[test]
    fn pubkey_from_seed_and_bad_seed() {
        let pk = call(feir_pubkey_from_seed_one, SEED).unwrap();
        assert!(pk.starts_with("ed25519pub:"), "{pk}");
        assert!(call(feir_pubkey_from_seed_one, "tooshort")
            .unwrap()
            .contains("error"));
    }

    #[test]
    fn seal_rejects_bad_seed_and_body() {
        assert!(call2(feir_seal_record, "{}", "nothex").contains("error"));
        assert!(call2(feir_seal_record, "{not json", SEED).contains("error"));
    }

    // base64url-no-pad of b"hello" — the raw value bytes the Go side commits over.
    const HELLO_B64: &str = "aGVsbG8";

    #[test]
    fn random_nonce_is_64_hex() {
        let n = call(feir_random_nonce_zero, "ignored").unwrap();
        assert_eq!(n.len(), 64, "{n}");
        assert!(n.bytes().all(|b| b.is_ascii_hexdigit()), "{n}");
        // two draws differ (CSPRNG, not a constant)
        let m = call(feir_random_nonce_zero, "ignored").unwrap();
        assert_ne!(n, m);
    }

    // wrapper so single-arg `call` can drive the no-arg nonce minter.
    unsafe extern "C" fn feir_random_nonce_zero(_: *const c_char) -> *mut c_char {
        feir_random_nonce()
    }

    #[test]
    fn commit_and_verify_roundtrip() {
        let nonce = call(feir_random_nonce_zero, "ignored").unwrap();
        let c = call3(feir_commit, "input", HELLO_B64, &nonce);
        assert!(c.starts_with("sha256:"), "{c}");

        // disclosing the same (value, nonce) verifies true...
        assert_eq!(
            call4(feir_verify_commitment, &c, "input", HELLO_B64, &nonce),
            "true"
        );
        // ...wrong domain, value, or nonce all verify false (binding holds).
        assert_eq!(
            call4(feir_verify_commitment, &c, "output", HELLO_B64, &nonce),
            "false"
        );
        assert_eq!(
            call4(feir_verify_commitment, &c, "input", "d29ybGQ", &nonce),
            "false"
        );
        let other = call(feir_random_nonce_zero, "ignored").unwrap();
        assert_eq!(
            call4(feir_verify_commitment, &c, "input", HELLO_B64, &other),
            "false"
        );
    }

    #[test]
    fn commit_rejects_malformed_inputs() {
        let nonce = call(feir_random_nonce_zero, "ignored").unwrap();
        assert!(call3(feir_commit, "bogus", HELLO_B64, &nonce).contains("error"));
        assert!(call3(feir_commit, "input", "not base64!!", &nonce).contains("error"));
        assert!(call3(feir_commit, "input", HELLO_B64, "shortnonce").contains("error"));
    }

    fn call3(
        f: unsafe extern "C" fn(*const c_char, *const c_char, *const c_char) -> *mut c_char,
        a: &str,
        b: &str,
        c: &str,
    ) -> String {
        let ca = CString::new(a).unwrap();
        let cb = CString::new(b).unwrap();
        let cc = CString::new(c).unwrap();
        unsafe {
            let out = f(ca.as_ptr(), cb.as_ptr(), cc.as_ptr());
            let s = CStr::from_ptr(out).to_string_lossy().into_owned();
            feir_string_free(out);
            s
        }
    }

    fn call4(
        f: unsafe extern "C" fn(
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
        ) -> *mut c_char,
        a: &str,
        b: &str,
        c: &str,
        d: &str,
    ) -> String {
        let ca = CString::new(a).unwrap();
        let cb = CString::new(b).unwrap();
        let cc = CString::new(c).unwrap();
        let cd = CString::new(d).unwrap();
        unsafe {
            let out = f(ca.as_ptr(), cb.as_ptr(), cc.as_ptr(), cd.as_ptr());
            let s = CStr::from_ptr(out).to_string_lossy().into_owned();
            feir_string_free(out);
            s
        }
    }
}
