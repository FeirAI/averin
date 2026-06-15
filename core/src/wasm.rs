//! WASM surface (`--features wasm`). The standalone offline verifier (`/verifier`) loads this and
//! verifies an exported bundle entirely in the browser — same Rust core as the CLI and FFI, so the
//! result is byte-identical (threat #10). Build:
//!   cargo build --release --target wasm32-unknown-unknown --no-default-features --features wasm

use wasm_bindgen::prelude::*;

/// Verify an export bundle (JSON string) fully offline. Returns a JSON report string (see
/// `verify::report_to_canon`). Never throws.
#[wasm_bindgen]
pub fn verify_bundle_json(input: &str) -> String {
    crate::verify::verify_bundle_to_json(input)
}

/// Canonicalize a JSON document under RCP v1 (exposed so the verifier UI can show canonical bytes).
/// Returns the canonical string, or a string beginning with `ERROR:` on a parse error.
#[wasm_bindgen]
pub fn rcp_canonicalize(input: &str) -> String {
    match crate::canon::CanonValue::parse(input) {
        Ok(v) => v.serialize(),
        Err(e) => format!("ERROR: {e}"),
    }
}
