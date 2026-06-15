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
}
