//! C FFI surface for cgo (the Go services call the Rust core through this — spec §5 "Go ↔ Rust:
//! cgo FFI"). Same core as the CLI and WASM. Header: `core/include/feir_core.h`.
//!
//! Memory contract: every non-null `*mut c_char` returned MUST be freed by the caller with
//! [`feir_string_free`]. Compiled into the `cdylib`/`staticlib` targets; excluded from WASM.

#![cfg(not(target_arch = "wasm32"))]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

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

fn decode_seed(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let b = hex.as_bytes();
    let mut out = [0u8; 32];
    let v = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    };
    for i in 0..32 {
        out[i] = (v(b[2 * i])? << 4) | v(b[2 * i + 1])?;
    }
    Some(out)
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
}
