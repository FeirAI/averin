//! C FFI surface for cgo (the Go services call the Rust core through this — spec §5 "Go ↔ Rust:
//! cgo FFI"). Same core as the CLI and WASM. Header: `core/include/averin_core.h`.
//!
//! Memory contract: every non-null `*mut c_char` returned MUST be freed by the caller with
//! [`averin_string_free`]. This same C-ABI serves BOTH cgo (native staticlib/cdylib) and the browser
//! (wasm32 cdylib): the standalone verifier writes a null-terminated JSON string into wasm memory
//! via [`averin_alloc`], calls [`averin_verify_bundle_json`], reads the result, then frees both.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Run a verifier closure, CATCHING any panic so it can never unwind across the C/cgo boundary (which is
/// undefined behavior) and never aborts the host process on untrusted input. On a panic the verifier fails
/// CLOSED — it returns a minimal `ok:false` report (no false `ok:true` is ever produced). The Go server links
/// the debug staticlib (panic=unwind), where this catches; the release CLI/WASM use panic=abort, where the
/// verifier is already panic-free on attacker input (the only known reachable panic — a Merkle-proof index
/// overflow — is fixed with checked arithmetic). `AssertUnwindSafe` is sound here: the closure borrows only
/// `&str` inputs and the verifier holds no observable state across the unwind.
fn catch_verify(f: impl FnOnce() -> String) -> String {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        r#"{"ok":false,"issues":["verifier panicked while processing this input — failing closed (please report this bundle as a verifier bug)"]}"#.to_string()
    })
}

/// Allocate `size` bytes of wasm/native memory and return the pointer (for the browser verifier to
/// write an input string into). Pair with [`averin_dealloc`].
#[no_mangle]
pub extern "C" fn averin_alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free memory allocated by [`averin_alloc`].
///
/// # Safety
/// `ptr`/`size` must come from a prior [`averin_alloc`] call and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn averin_dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        drop(Vec::from_raw_parts(ptr, 0, size));
    }
}

/// Verify an export bundle (null-terminated UTF-8 JSON). Returns a newly-allocated, null-terminated
/// JSON report string (free with [`averin_string_free`]), or null if `input` is null or not UTF-8.
///
/// **Untrusted input:** because a C string ends at the first NUL, any `0x00` byte in `input` silently
/// truncates verification to the prefix before it — and a valid prefix would then be reported `ok`
/// over a file whose tail was never read. A valid RCP bundle never contains `0x00`, so this is only
/// reachable with a malformed/adversarial artifact, but for any bundle you did not produce yourself
/// prefer [`averin_verify_bundle_json_n`], which reads an explicit length and cannot be truncated.
///
/// # Safety
/// `input` must be a valid null-terminated C string for the duration of the call.
///
/// NOT compiled for `wasm32`: the browser verifier (the auditor-facing surface) must expose ONLY the
/// length-aware [`averin_verify_bundle_json_n`], so a third party loading the `.wasm` cannot reach a
/// NUL-truncatable verify entrypoint. The cgo path (native) keeps this symbol and guards NUL on the Go side.
#[cfg(not(target_arch = "wasm32"))]
#[no_mangle]
pub unsafe extern "C" fn averin_verify_bundle_json(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let text = match CStr::from_ptr(input).to_str() {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };
    let out = catch_verify(|| crate::verify::verify_bundle_to_json(text));
    match CString::new(out) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Verify an export bundle from an explicit `(ptr, len)` byte span — the length-aware,
/// truncation-proof counterpart to [`averin_verify_bundle_json`]. Use this for UNTRUSTED input.
///
/// It reads exactly `len` bytes and does NOT stop at an interior NUL, so a buffer containing a `0x00`
/// (never present in valid RCP) is verified IN FULL and fails closed at canonicalization, instead of
/// being truncated at the first NUL and reported valid over only its prefix. Returns a
/// newly-allocated, null-terminated JSON report (free with [`averin_string_free`]); null if `ptr` is
/// null or the `len` bytes are not valid UTF-8.
///
/// # Safety
/// `ptr` must point to at least `len` initialized bytes that stay valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn averin_verify_bundle_json_n(ptr: *const u8, len: usize) -> *mut c_char {
    let text = match bytes_to_str(ptr, len) {
        Some(t) => t,
        None => return std::ptr::null_mut(),
    };
    into_cstring(catch_verify(|| crate::verify::verify_bundle_to_json(text)))
}

/// Verify an export bundle with out-of-band pinned trust roots. `opts_json` is a JSON object whose
/// optional arrays pin keys: `authority_keys`/`signing_keys`/`tsa_keys` (`ed25519pub:` strings; `signing_keys`
/// also accepts `{key,status,status_changed_at}` objects, and an empty `signing_keys` is an error) and
/// `tsa_spki_b64` (base64url DER). Used to elevate a credential-broker grant to `gateway_enforced`
/// (pin the broker recording key as `authority_keys`). Returns the same JSON report as
/// [`averin_verify_bundle_json`]; null if either pointer is null or not UTF-8.
///
/// NUL caveat: both arguments are read as C strings and stop at the first `0x00`. For an UNTRUSTED
/// bundle OR opts, prefer [`averin_verify_bundle_with_n`], which reads explicit lengths and cannot be
/// truncated (a `0x00` in `opts_json` would otherwise silently truncate the pinned trust roots).
///
/// # Safety
/// `bundle` and `opts_json` must be valid null-terminated C strings for the duration of the call.
///
/// NOT compiled for `wasm32` (see [`averin_verify_bundle_json`]): the browser verifier exposes only the
/// length-aware [`averin_verify_bundle_with_n`], so a `0x00` in the pinned `opts_json` cannot silently truncate
/// the trust roots in the auditor's `.wasm`. The cgo path keeps this symbol and guards NUL on the Go side.
#[cfg(not(target_arch = "wasm32"))]
#[no_mangle]
pub unsafe extern "C" fn averin_verify_bundle_with(
    bundle: *const c_char,
    opts_json: *const c_char,
) -> *mut c_char {
    let bundle = match cstr(bundle) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };
    let opts = match cstr(opts_json) {
        Some(o) => o,
        None => return std::ptr::null_mut(),
    };
    into_cstring(catch_verify(|| {
        crate::verify::verify_bundle_with_json(bundle, opts)
    }))
}

/// Verify an export bundle with pinned trust roots from explicit `(ptr, len)` byte spans — the
/// length-aware, truncation-proof counterpart to [`averin_verify_bundle_with`]. Reads exactly the given
/// lengths and does NOT stop at an interior NUL in EITHER the bundle or the opts, so a `0x00` (never
/// present in valid RCP / an `ed25519pub:` or base64url opts value) cannot truncate the bundle to a
/// verified prefix nor silently drop the pinned trust roots; the full input is verified and fails closed
/// at canonicalization. Returns the same JSON report; null if either span is null or not valid UTF-8.
///
/// # Safety
/// `bundle_ptr` and `opts_ptr` must each point to at least their `len` initialized bytes, valid for the call.
#[no_mangle]
pub unsafe extern "C" fn averin_verify_bundle_with_n(
    bundle_ptr: *const u8,
    bundle_len: usize,
    opts_ptr: *const u8,
    opts_len: usize,
) -> *mut c_char {
    let bundle = match bytes_to_str(bundle_ptr, bundle_len) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };
    let opts = match bytes_to_str(opts_ptr, opts_len) {
        Some(o) => o,
        None => return std::ptr::null_mut(),
    };
    into_cstring(catch_verify(|| {
        crate::verify::verify_bundle_with_json(bundle, opts)
    }))
}

/// Canonicalize a JSON document under RCP v1. Returns a newly-allocated string (free with
/// [`averin_string_free`]); the result begins with `ERROR:` on a parse error. Null if input is null
/// or not UTF-8.
///
/// # Safety
/// `input` must be a valid null-terminated C string for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn averin_rcp_canonicalize(input: *const c_char) -> *mut c_char {
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

/// Compute the canonical evidence hash `sha256:<64 lowercase hex>` over a JSON payload: RCP-v1
/// canonicalize, then SHA-256 the canonical bytes. This is the single source of truth for an
/// `evidence_hash` (ADR 0003 R1) — the broker/resource computes it here (NOT via Go `json.Marshal`)
/// so the offline verifier can re-derive the SAME hash from the evidence payload embedded in the
/// record (`extensions.broker.grant_evidence` / `use_evidence`) and confirm the signed `evidence_hash`
/// actually commits to the semantic match fields. Returns `{"error":...}` on a parse error; null if
/// `input` is null or not UTF-8.
///
/// # Safety
/// `input` must be a valid null-terminated C string for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn averin_rcp_evidence_hash(input: *const c_char) -> *mut c_char {
    let text = match cstr(input) {
        Some(t) => t,
        None => return std::ptr::null_mut(),
    };
    let out = match crate::canon::CanonValue::parse(text) {
        Ok(v) => crate::hashx::sha256_prefixed(v.serialize().as_bytes()),
        Err(e) => json_error(&format!("payload parse error: {e}")),
    };
    into_cstring(out)
}

/// Seal a Decision Record body (UTF-8 JSON) with an Ed25519 signing key (32-byte seed, 64 hex
/// chars). Returns the sealed record JSON (content_hash + sig set), or `{"error":"..."}`. Null on
/// null/invalid-UTF-8 input. The seed is the self-host signing key; production deployments back
/// signing with a KMS instead of passing a raw seed.
///
/// # Safety
/// `body` and `seed_hex` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn averin_seal_record(
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
pub unsafe extern "C" fn averin_seal_checkpoint(
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
pub unsafe extern "C" fn averin_pubkey_from_seed(seed_hex: *const c_char) -> *mut c_char {
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
pub extern "C" fn averin_random_nonce() -> *mut c_char {
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
pub unsafe extern "C" fn averin_commit(
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
pub unsafe extern "C" fn averin_verify_commitment(
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

/// Sign an authority evidence statement (RCP §11): the policy engine / approval service / credential
/// broker signs `LP(tag)‖LP(source)‖LP(record_id)‖utf8(evidence_hash)` so the verifier can elevate a
/// `gateway_enforced`/`policy_engine_signed`/`human_signed` record from `declared` to `verified`
/// under the pinned authority key. `evidence_hash` must be `sha256:<64 lowercase hex>`. Returns
/// `ed25519:<base64url>` or `{"error":...}`. The seed is the authority system's signing key.
///
/// Trust boundary: this signs `evidence_hash` as an opaque value — it does NOT (and cannot) check
/// that `evidence_hash == sha256(the real canonical evidence)`. Guaranteeing that binding is the
/// authority system's responsibility (the broker TCB; see ADR 0002 `broker_trust: assumed`).
///
/// # Safety
/// All five pointers must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn averin_sign_evidence(
    source: *const c_char,
    project_id: *const c_char,
    record_id: *const c_char,
    evidence_hash: *const c_char,
    seed_hex: *const c_char,
) -> *mut c_char {
    let (source, project_id, record_id, evidence_hash) = match (
        cstr(source),
        cstr(project_id),
        cstr(record_id),
        cstr(evidence_hash),
    ) {
        (Some(a), Some(p), Some(b), Some(c)) => (a, p, b, c),
        _ => {
            return into_cstring(json_error(
                "source/project_id/record_id/evidence_hash must be non-null UTF-8",
            ))
        }
    };
    // Only sign sources verify_authority can actually elevate to `verified` (mirror authority.rs).
    // Signing any other source mints an inert signature that can never verify — the same
    // can-never-verify class the empty-record_id guard below refuses; fail fast instead.
    if !matches!(
        source,
        "policy_engine_signed" | "human_signed" | "gateway_enforced"
    ) {
        return into_cstring(json_error(
            "source must be policy_engine_signed|human_signed|gateway_enforced",
        ));
    }
    if project_id.is_empty() || record_id.is_empty() {
        // project_id + record_id bind the evidence to a specific record in a specific tenant; an empty
        // one is unbindable (and verify_authority rejects it), so refuse to mint a sig that can never verify.
        return into_cstring(json_error("project_id and record_id must be non-empty"));
    }
    // Bind only a well-formed evidence_hash — the verifier requires sha256:<hex> to elevate.
    if crate::hashx::parse_sha256(evidence_hash).is_none() {
        return into_cstring(json_error(
            "evidence_hash must be sha256:<64 lowercase hex>",
        ));
    }
    let seed = match cstr(seed_hex).and_then(crate::hashx::hex32) {
        Some(s) => s,
        None => return into_cstring(json_error("seed must be 64 lowercase hex chars (32 bytes)")),
    };
    let sk = crate::sign::signing_key_from_seed(&seed);
    into_cstring(crate::authority::sign_evidence(
        source,
        project_id,
        record_id,
        evidence_hash,
        &sk,
    ))
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

/// Build a `&str` from an explicit `(ptr, len)` span, or `None` if null / not UTF-8. Unlike
/// [`cstr`], this does NOT stop at an interior NUL — all `len` bytes are returned, so a
/// truncation-based fail-open is impossible (a raw NUL is not valid RCP, so canonicalization rejects
/// it fail-closed downstream).
unsafe fn bytes_to_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).ok()
}

#[allow(clippy::type_complexity)]
unsafe fn commit_inputs(
    domain: *const c_char,
    value_b64: *const c_char,
    nonce_hex: *const c_char,
) -> Result<(crate::commit::FieldDomain, Vec<u8>, [u8; 32]), &'static str> {
    use crate::commit::FieldDomain;
    let domain = cstr(domain).ok_or("bad domain")?;
    let d = FieldDomain::parse(domain).ok_or("domain must be input|output|rationale|credential")?;
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
/// `ptr` must be a pointer previously returned by a `averin_*` function (or null), and must not be
/// used afterwards.
#[no_mangle]
pub unsafe extern "C" fn averin_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catch_verify_returns_fail_closed_json_on_panic() {
        // A panic inside the verifier must become a fail-CLOSED ok:false report, never a propagated panic that
        // would unwind across the cgo boundary (UB) or crash the host. (The release build uses panic=abort, so
        // this catch is the cgo/debug-profile defense; the only known reachable panic is separately fixed.)
        let out = catch_verify(|| panic!("synthetic verifier panic"));
        let v = crate::CanonValue::parse(&out).expect("fail-closed report is valid JSON");
        assert!(
            matches!(v.get("ok"), Some(crate::CanonValue::Bool(false))),
            "panic must yield ok:false: {out}"
        );
        // a normal (non-panicking) closure passes through unchanged.
        assert_eq!(catch_verify(|| "passthrough".to_string()), "passthrough");
    }

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
            averin_string_free(out);
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
        let ok = call(averin_verify_bundle_json, &bundle()).unwrap();
        assert!(ok.contains("\"ok\":true"), "{ok}");
        assert!(ok.contains("\"records_proven\":3"));
        let bad = call(
            averin_verify_bundle_json,
            &bundle().replace("billing-agent", "evilxx-agent"),
        )
        .unwrap();
        assert!(bad.contains("\"ok\":false"), "{bad}");
    }

    /// Call the length-aware verify entrypoint with raw bytes that MAY contain an interior NUL.
    fn call_n(bytes: &[u8]) -> Option<String> {
        unsafe {
            let out = averin_verify_bundle_json_n(bytes.as_ptr(), bytes.len());
            if out.is_null() {
                return None;
            }
            let s = CStr::from_ptr(out).to_string_lossy().into_owned();
            averin_string_free(out);
            Some(s)
        }
    }

    #[test]
    fn verify_bundle_json_n_is_truncation_proof() {
        // Clean bytes verify the same as the C-string path.
        let clean = bundle();
        let ok = call_n(clean.as_bytes()).unwrap();
        assert!(ok.contains("\"ok\":true"), "{ok}");

        // `‹valid bundle› 0x00 ‹arbitrary bytes›`: the length-aware entrypoint reads the FULL input,
        // so the interior NUL is seen and canonicalization fails closed — it is NOT truncated to an
        // "ok" prefix the way the NUL-terminated `averin_verify_bundle_json` would be. This is the
        // regression lock for the FFI/WASM truncation fail-open.
        let mut attack = clean.into_bytes();
        attack.push(0);
        attack.extend_from_slice(br#"{"decoy":"unverified"}PADDING"#);
        let bad = call_n(&attack).unwrap();
        assert!(
            bad.contains("\"ok\":false"),
            "interior NUL must fail closed: {bad}"
        );
    }

    /// Call the length-aware WITH entrypoint with raw bundle + opts spans (either MAY contain a NUL).
    fn call_with_n(bundle: &[u8], opts: &[u8]) -> Option<String> {
        unsafe {
            let out = averin_verify_bundle_with_n(
                bundle.as_ptr(),
                bundle.len(),
                opts.as_ptr(),
                opts.len(),
            );
            if out.is_null() {
                return None;
            }
            let s = CStr::from_ptr(out).to_string_lossy().into_owned();
            averin_string_free(out);
            Some(s)
        }
    }

    #[test]
    fn verify_bundle_with_n_opts_truncation_proof() {
        let clean = bundle();
        // empty opts {} verifies like the no-opts path.
        let ok = call_with_n(clean.as_bytes(), b"{}").unwrap();
        assert!(ok.contains("\"ok\":true"), "{ok}");

        // opts = `{}` ‹0x00› ‹junk›: the NUL-terminated `averin_verify_bundle_with` would stop at the NUL and
        // verify under the truncated, valid `{}` (no pinned trust roots). The length-aware entrypoint reads
        // the FULL opts span, so the interior NUL is seen and the opts parse fails CLOSED — the pinned trust
        // roots can never be silently truncated. Regression lock for the optsJSON truncation gap.
        let mut opts_attack = b"{}".to_vec();
        opts_attack.push(0);
        opts_attack.extend_from_slice(br#"{"decoy":1}"#);
        let bad = call_with_n(clean.as_bytes(), &opts_attack).unwrap();
        assert!(
            bad.contains("\"ok\":false") || bad.contains("error"),
            "interior NUL in opts must fail closed, not truncate the trust roots: {bad}"
        );
    }

    #[test]
    fn canonicalize_and_errors() {
        assert_eq!(
            call(averin_rcp_canonicalize, r#"{"b":1,"a":2}"#).unwrap(),
            r#"{"a":2,"b":1}"#
        );
        assert!(call(averin_rcp_canonicalize, r#"{"a":1.5}"#)
            .unwrap()
            .starts_with("ERROR:"));
    }

    #[test]
    fn rcp_evidence_hash_is_canonical_and_order_independent() {
        // The same evidence in different key order hashes identically — this is what lets the offline
        // verifier re-derive the broker/resource-computed evidence_hash regardless of serialization.
        let a = call(averin_rcp_evidence_hash, r#"{"b":1,"a":2}"#).unwrap();
        let b = call(averin_rcp_evidence_hash, r#"{"a":2,"b":1}"#).unwrap();
        assert_eq!(a, b, "evidence hash must be key-order independent");
        assert!(
            a.starts_with("sha256:") && a.len() == "sha256:".len() + 64,
            "{a}"
        );
        // It equals SHA-256 over the RCP canonical bytes (the verifier's own re-derivation path).
        let canon = call(averin_rcp_canonicalize, r#"{"a":2,"b":1}"#).unwrap();
        assert_eq!(a, crate::hashx::sha256_prefixed(canon.as_bytes()));
        // RCP forbids floats — a parse error is surfaced as an error object, never a silent hash.
        assert!(call(averin_rcp_evidence_hash, r#"{"a":1.5}"#)
            .unwrap()
            .contains("error"));
    }

    #[test]
    fn null_input_is_handled() {
        unsafe {
            assert!(averin_verify_bundle_json(std::ptr::null()).is_null());
            averin_string_free(std::ptr::null_mut()); // safe no-op
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
            averin_string_free(out);
            s
        }
    }

    const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn seal_record_and_verify_roundtrip() {
        let body = r#"{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2","record_id":"r","project_id":"p","agent_id":"a","agent_version":"1","session_id":"s","span_id":"sp","parent_span_id":null,"causal_prev_hashes":[],"display_seq":0,"agent_ts":"2026-06-15T10:00:00.000Z","received_ts":"2026-06-15T10:00:00.000Z","event_type":"tool_call","action":"x","observed_via":"sdk","status":"ok","key":{"signing_key_id":"k0","key_epoch":0,"key_status":"active"}}"#;
        let sealed = call2(averin_seal_record, body, SEED);
        assert!(sealed.contains("\"content_hash\":\"sha256:"));
        assert!(sealed.contains("\"sig\":\"ed25519:"));

        // the published pubkey verifies the sealed record
        let pk = call(averin_pubkey_from_seed_one, SEED);
        let _ = pk; // see helper below
    }

    // wrapper so `call` (single-arg) can exercise pubkey_from_seed
    unsafe extern "C" fn averin_pubkey_from_seed_one(s: *const c_char) -> *mut c_char {
        averin_pubkey_from_seed(s)
    }

    #[test]
    fn pubkey_from_seed_and_bad_seed() {
        let pk = call(averin_pubkey_from_seed_one, SEED).unwrap();
        assert!(pk.starts_with("ed25519pub:"), "{pk}");
        assert!(call(averin_pubkey_from_seed_one, "tooshort")
            .unwrap()
            .contains("error"));
    }

    #[test]
    fn seal_rejects_bad_seed_and_body() {
        assert!(call2(averin_seal_record, "{}", "nothex").contains("error"));
        assert!(call2(averin_seal_record, "{not json", SEED).contains("error"));
    }

    // base64url-no-pad of b"hello" — the raw value bytes the Go side commits over.
    const HELLO_B64: &str = "aGVsbG8";

    #[test]
    fn random_nonce_is_64_hex() {
        let n = call(averin_random_nonce_zero, "ignored").unwrap();
        assert_eq!(n.len(), 64, "{n}");
        assert!(n.bytes().all(|b| b.is_ascii_hexdigit()), "{n}");
        // two draws differ (CSPRNG, not a constant)
        let m = call(averin_random_nonce_zero, "ignored").unwrap();
        assert_ne!(n, m);
    }

    // wrapper so single-arg `call` can drive the no-arg nonce minter.
    unsafe extern "C" fn averin_random_nonce_zero(_: *const c_char) -> *mut c_char {
        averin_random_nonce()
    }

    #[test]
    fn commit_and_verify_roundtrip() {
        let nonce = call(averin_random_nonce_zero, "ignored").unwrap();
        let c = call3(averin_commit, "input", HELLO_B64, &nonce);
        assert!(c.starts_with("sha256:"), "{c}");

        // disclosing the same (value, nonce) verifies true...
        assert_eq!(
            call4(averin_verify_commitment, &c, "input", HELLO_B64, &nonce),
            "true"
        );
        // ...wrong domain, value, or nonce all verify false (binding holds).
        assert_eq!(
            call4(averin_verify_commitment, &c, "output", HELLO_B64, &nonce),
            "false"
        );
        assert_eq!(
            call4(averin_verify_commitment, &c, "input", "d29ybGQ", &nonce),
            "false"
        );
        let other = call(averin_random_nonce_zero, "ignored").unwrap();
        assert_eq!(
            call4(averin_verify_commitment, &c, "input", HELLO_B64, &other),
            "false"
        );
    }

    #[test]
    fn commit_rejects_malformed_inputs() {
        let nonce = call(averin_random_nonce_zero, "ignored").unwrap();
        assert!(call3(averin_commit, "bogus", HELLO_B64, &nonce).contains("error"));
        assert!(call3(averin_commit, "input", "not base64!!", &nonce).contains("error"));
        assert!(call3(averin_commit, "input", HELLO_B64, "shortnonce").contains("error"));
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
            averin_string_free(out);
            s
        }
    }

    #[test]
    fn sign_evidence_roundtrips_under_pinned_key() {
        use crate::authority::{verify_authority, AuthorityTrust};
        use crate::sign::signing_key_from_seed;
        let eh = crate::hashx::sha256_prefixed(b"grant-evidence-bytes");
        let sig = call5(
            averin_sign_evidence,
            "gateway_enforced",
            "proj-1",
            "rec-1",
            &eh,
            SEED,
        );
        assert!(sig.starts_with("ed25519:"), "{sig}");

        // A record carrying this authority block verifies to `gateway_enforced` under the broker key.
        let vk = signing_key_from_seed(&decode_seed(SEED).unwrap()).verifying_key();
        let mk = |pid: &str, rid: &str, src: &str, h: &str| {
            crate::canon::CanonValue::parse(&format!(
                r#"{{"project_id":"{pid}","record_id":"{rid}","authority":{{"source":"{src}","evidence_hash":"{h}","evidence_sig":"{sig}"}}}}"#
            ))
            .unwrap()
        };
        assert_eq!(
            verify_authority(&mk("proj-1", "rec-1", "gateway_enforced", &eh), &[vk]),
            AuthorityTrust::Verified
        );
        // Binding holds: a different project_id (cross-tenant replay), record_id, source, or evidence_hash fails.
        assert_eq!(
            verify_authority(&mk("proj-2", "rec-1", "gateway_enforced", &eh), &[vk]),
            AuthorityTrust::Failed
        );
        assert_eq!(
            verify_authority(&mk("proj-1", "OTHER", "gateway_enforced", &eh), &[vk]),
            AuthorityTrust::Failed
        );
        assert_eq!(
            verify_authority(&mk("proj-1", "rec-1", "human_signed", &eh), &[vk]),
            AuthorityTrust::Failed
        );
        let eh2 = crate::hashx::sha256_prefixed(b"different");
        assert_eq!(
            verify_authority(&mk("proj-1", "rec-1", "gateway_enforced", &eh2), &[vk]),
            AuthorityTrust::Failed
        );
    }

    #[test]
    fn sign_evidence_rejects_malformed() {
        let eh = crate::hashx::sha256_prefixed(b"x");
        assert!(call5(
            averin_sign_evidence,
            "gateway_enforced",
            "proj-1",
            "rec-1",
            "not-a-hash",
            SEED
        )
        .contains("error"));
        // empty record_id OR empty project_id is unbindable -> refused.
        assert!(call5(
            averin_sign_evidence,
            "gateway_enforced",
            "proj-1",
            "",
            &eh,
            SEED
        )
        .contains("error"));
        assert!(call5(
            averin_sign_evidence,
            "gateway_enforced",
            "",
            "rec-1",
            &eh,
            SEED
        )
        .contains("error"));
        assert!(call5(
            averin_sign_evidence,
            "gateway_enforced",
            "proj-1",
            "rec-1",
            &eh,
            "shortseed"
        )
        .contains("error"));
        // Refuse to mint an inert signature for a source verify_authority can never elevate.
        assert!(call5(
            averin_sign_evidence,
            "caller_declared",
            "proj-1",
            "rec-1",
            &eh,
            SEED
        )
        .contains("error"));
        assert!(call5(
            averin_sign_evidence,
            "gateway-enforced",
            "proj-1",
            "rec-1",
            &eh,
            SEED
        )
        .contains("error")); // typo
        assert!(call5(averin_sign_evidence, "", "proj-1", "rec-1", &eh, SEED).contains("error"));
        // policy_engine_signed / human_signed are valid elevating sources.
        assert!(call5(
            averin_sign_evidence,
            "policy_engine_signed",
            "proj-1",
            "rec-1",
            &eh,
            SEED
        )
        .starts_with("ed25519:"));
        assert!(call5(
            averin_sign_evidence,
            "human_signed",
            "proj-1",
            "rec-1",
            &eh,
            SEED
        )
        .starts_with("ed25519:"));
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
            averin_string_free(out);
            s
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn call5(
        f: unsafe extern "C" fn(
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
        ) -> *mut c_char,
        a: &str,
        b: &str,
        c: &str,
        d: &str,
        e: &str,
    ) -> String {
        let (ca, cb, cc, cd, ce) = (
            CString::new(a).unwrap(),
            CString::new(b).unwrap(),
            CString::new(c).unwrap(),
            CString::new(d).unwrap(),
            CString::new(e).unwrap(),
        );
        unsafe {
            let out = f(
                ca.as_ptr(),
                cb.as_ptr(),
                cc.as_ptr(),
                cd.as_ptr(),
                ce.as_ptr(),
            );
            let s = CStr::from_ptr(out).to_string_lossy().into_owned();
            averin_string_free(out);
            s
        }
    }
}
