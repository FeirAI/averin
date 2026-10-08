//! Decision Record integrity: compute/verify `content_hash` (RCP §9.1). Signing lives in
//! `sign.rs`; this module owns the hashing preimage.

use crate::canon::{member, write_object, CanonValue};
use crate::hashx::{lp_str_into, sha256_prefixed};
use crate::sign;
use ed25519_dalek::{SigningKey, VerifyingKey};

pub const RECORD_DOMAIN: &str = "flightrecorder.record.v2";
pub const CANON_VERSION: &str = "rcp-1";

#[derive(Debug, Clone, PartialEq)]
pub enum RecordError {
    NotObject,
    MissingField(&'static str),
    FieldNotString(&'static str),
    DomainMismatch { expected: String, found: String },
    CanonVersionMismatch { expected: String, found: String },
    TooLong,
    ContentHashMismatch { expected: String, computed: String },
    SignatureInvalid(String),
    UnknownField(String),
    DuplicateKey,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::NotObject => write!(f, "record is not a JSON object"),
            RecordError::MissingField(k) => write!(f, "missing required field '{k}'"),
            RecordError::FieldNotString(k) => write!(f, "field '{k}' is not a string"),
            RecordError::DomainMismatch { expected, found } => {
                write!(f, "domain mismatch: expected {expected:?}, found {found:?}")
            }
            RecordError::CanonVersionMismatch { expected, found } => {
                write!(
                    f,
                    "canon_version mismatch: expected {expected:?}, found {found:?}"
                )
            }
            RecordError::TooLong => write!(f, "body too long to length-prefix"),
            RecordError::ContentHashMismatch { expected, computed } => {
                write!(
                    f,
                    "content_hash mismatch: stored {expected}, computed {computed}"
                )
            }
            RecordError::SignatureInvalid(e) => write!(f, "signature invalid: {e}"),
            RecordError::UnknownField(k) => {
                write!(
                    f,
                    "unknown top-level field '{k}' (only 'extensions' may hold unknown keys)"
                )
            }
            RecordError::DuplicateKey => {
                write!(f, "duplicate object key after NFC normalization")
            }
        }
    }
}
impl std::error::Error for RecordError {}

/// The closed set of permitted top-level record keys (schema v2). RCP §6: unknown signed fields
/// are rejected; only `extensions` may hold arbitrary keys.
pub const ALLOWED_TOP_KEYS: &[&str] = &[
    "schema_version",
    "canon_version",
    "domain",
    "record_id",
    "project_id",
    "agent_id",
    "agent_version",
    "session_id",
    "span_id",
    "parent_span_id",
    "causal_prev_hashes",
    "display_seq",
    "agent_ts",
    "received_ts",
    "anchored_ts",
    "event_type",
    // Optional typed evidence kind, a SIBLING of `event_type` (does not replace it). Closed
    // value-set {budget-exhausted, chargeback-posted}, kebab-case per averin convention. It is a
    // normal signed top-level field (covered by content_hash/sig like any key — canon iterates
    // object keys), so it must be in ALLOWED_TOP_KEYS for validate_record_shape/verify_sealed to
    // accept it; it is NOT in REQUIRED_TOP_KEYS (optional). The JSON Schema pins the enum values;
    // the closed-key gate here only admits the field. See spec/decision-record.schema.json and
    // leria's averin-integration-handoff.md.
    "record_kind",
    "action",
    "observed_via",
    "input_commit",
    "output_commit",
    "rationale_commit",
    "credential_commit",
    "status",
    "tokens",
    "cost_micros_usd",
    "authority",
    "content",
    "content_hash",
    "sig",
    "key",
    "framework",
    "extensions",
];

/// Required top-level keys (schema v2). Absent ⇒ invalid.
pub const REQUIRED_TOP_KEYS: &[&str] = &[
    "schema_version",
    "canon_version",
    "domain",
    "record_id",
    "project_id",
    "agent_id",
    "agent_version",
    "session_id",
    "span_id",
    "parent_span_id",
    "causal_prev_hashes",
    "display_seq",
    "agent_ts",
    "received_ts",
    "event_type",
    "action",
    "observed_via",
    "status",
    "content_hash",
    "sig",
    "key",
];

/// Enforce the schema-v2 top-level shape: object, no unknown top-level keys (RCP §6), all
/// required keys present. (Nested `additionalProperties:false` is validated by the JSON Schema in
/// `/spec`; deeper structural checks land with the bundle verifier.)
pub fn validate_record_shape(record: &CanonValue) -> Result<(), RecordError> {
    let members = record.as_object().ok_or(RecordError::NotObject)?;
    for (k, _) in members {
        if !ALLOWED_TOP_KEYS.contains(&k.as_str()) {
            return Err(RecordError::UnknownField(k.clone()));
        }
    }
    for req in REQUIRED_TOP_KEYS {
        if record.get(req).is_none() {
            return Err(RecordError::MissingField(req));
        }
    }
    Ok(())
}

fn str_field<'a>(obj: &'a CanonValue, key: &'static str) -> Result<&'a str, RecordError> {
    obj.get(key)
        .ok_or(RecordError::MissingField(key))?
        .as_str()
        .ok_or(RecordError::FieldNotString(key))
}

/// Why a body has no hash preimage. Free of borrowed data so the preimage builder below stays in the
/// subset `formal/run-production-refinement.sh` extracts and proves; mapped to [`RecordError`] at
/// the public API.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum PreimageFault {
    NotObject,
    MissingDomain,
    DomainNotString,
    MissingCanonVersion,
    CanonVersionNotString,
    TooLong,
    DuplicateKey,
}

impl PreimageFault {
    pub(crate) fn into_record_error(self) -> RecordError {
        match self {
            PreimageFault::NotObject => RecordError::NotObject,
            PreimageFault::MissingDomain => RecordError::MissingField("domain"),
            PreimageFault::DomainNotString => RecordError::FieldNotString("domain"),
            PreimageFault::MissingCanonVersion => RecordError::MissingField("canon_version"),
            PreimageFault::CanonVersionNotString => RecordError::FieldNotString("canon_version"),
            PreimageFault::TooLong => RecordError::TooLong,
            PreimageFault::DuplicateKey => RecordError::DuplicateKey,
        }
    }
}

/// Generic domain-separated body hash (RCP §9.1): reads `domain`/`canon_version` from the body,
/// strips `strip` keys, and returns
/// `sha256:hex( SHA-256( LP(domain) ‖ LP(canon_version) ‖ RCP-serialize(body \ strip) ) )`.
/// Shared by records (`strip = [content_hash, sig]`) and checkpoints
/// (`strip = [anchor, checkpoint_hash, sig]`).
pub fn hash_body(value: &CanonValue, strip: &[&str]) -> Result<String, RecordError> {
    body_hash(value, strip).map_err(PreimageFault::into_record_error)
}

pub(crate) fn body_hash(value: &CanonValue, strip: &[&str]) -> Result<String, PreimageFault> {
    Ok(sha256_prefixed(&body_preimage(value, strip)?))
}

/// The exact bytes [`hash_body`] feeds SHA-256:
/// `LP(domain) ‖ LP(canon_version) ‖ RCP-serialize(body \ strip)`. Hidden `pub` so
/// `core/tests/oracle.rs` can compare it byte-for-byte against the Lean model's preimage.
#[doc(hidden)]
pub fn hash_body_preimage(value: &CanonValue, strip: &[&str]) -> Result<Vec<u8>, RecordError> {
    body_preimage(value, strip).map_err(PreimageFault::into_record_error)
}

/// [`hash_body_preimage`] before error mapping. A body with a duplicate key after NFC, at any depth,
/// has no preimage: it has no single canonical meaning to commit to (RCP §5).
pub(crate) fn body_preimage(value: &CanonValue, strip: &[&str]) -> Result<Vec<u8>, PreimageFault> {
    let members = match value {
        CanonValue::Object(m) => m,
        _ => return Err(PreimageFault::NotObject),
    };
    let domain = match member(value, "domain") {
        Some(CanonValue::Str(s)) => s,
        Some(_) => return Err(PreimageFault::DomainNotString),
        None => return Err(PreimageFault::MissingDomain),
    };
    let canon_version = match member(value, "canon_version") {
        Some(CanonValue::Str(s)) => s,
        Some(_) => return Err(PreimageFault::CanonVersionNotString),
        None => return Err(PreimageFault::MissingCanonVersion),
    };
    let mut preimage = Vec::new();
    if !lp_str_into(&mut preimage, domain) || !lp_str_into(&mut preimage, canon_version) {
        return Err(PreimageFault::TooLong);
    }
    if !write_object(members, strip, &mut preimage) {
        return Err(PreimageFault::DuplicateKey);
    }
    Ok(preimage)
}

/// Compute the canonical record `content_hash` (RCP §9.1).
///
/// The `domain` / `canon_version` are read from the body and re-bound into the preimage; callers
/// verifying a record should additionally confirm they equal the expected constants (see
/// [`verify_content_hash`]).
pub fn compute_content_hash(record: &CanonValue) -> Result<String, RecordError> {
    record_hash(record).map_err(PreimageFault::into_record_error)
}

// `body`, not `record`: a parameter named like the module would shadow it in the extracted model.
pub(crate) fn record_hash(body: &CanonValue) -> Result<String, PreimageFault> {
    Ok(sha256_prefixed(&record_preimage(body)?))
}

/// The exact bytes [`compute_content_hash`] feeds SHA-256 (body with `content_hash`/`sig` stripped).
/// Hidden `pub` for the Lean-oracle differential test (`core/tests/oracle.rs`).
#[doc(hidden)]
pub fn content_hash_preimage(record: &CanonValue) -> Result<Vec<u8>, RecordError> {
    record_preimage(record).map_err(PreimageFault::into_record_error)
}

/// The record preimage: the body without `content_hash`/`sig` (RCP §9.1).
pub(crate) fn record_preimage(body: &CanonValue) -> Result<Vec<u8>, PreimageFault> {
    body_preimage(body, &["content_hash", "sig"])
}

/// Verify a record's stored `content_hash` and that its declared domain/canon_version match
/// the expected v2 constants (a body cannot be reinterpreted under a different profile).
pub fn verify_content_hash(record: &CanonValue) -> Result<(), RecordError> {
    let domain = str_field(record, "domain")?;
    if domain != RECORD_DOMAIN {
        return Err(RecordError::DomainMismatch {
            expected: RECORD_DOMAIN.to_string(),
            found: domain.to_string(),
        });
    }
    let cv = str_field(record, "canon_version")?;
    if cv != CANON_VERSION {
        return Err(RecordError::CanonVersionMismatch {
            expected: CANON_VERSION.to_string(),
            found: cv.to_string(),
        });
    }
    let stored = str_field(record, "content_hash")?.to_string();
    let computed = compute_content_hash(record)?;
    if stored != computed {
        return Err(RecordError::ContentHashMismatch {
            expected: stored,
            computed,
        });
    }
    Ok(())
}

/// Return a clone of an object with `key` set to `value` (overwriting if present, else appended
/// in insertion order). Panics only if called on a non-object.
fn with_field(obj: &CanonValue, key: &str, value: CanonValue) -> CanonValue {
    let mut members = obj.as_object().expect("with_field on non-object").clone();
    if let Some(slot) = members.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value;
    } else {
        members.push((key.to_string(), value));
    }
    CanonValue::Object(members)
}

/// What [`seal_with_mode`] does with a body that [`verify_sealed`] would reject on shape,
/// domain or canon_version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealShapeMode {
    /// Return the error and seal nothing (the default; what [`seal`] does).
    Enforce,
    /// Count the violation in [`seal_shape_violations`] and seal anyway. A rollback switch only:
    /// a record sealed this way is rejected by every verifier.
    Shadow,
}

static SEAL_SHAPE_VIOLATIONS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many bodies [`seal_with_mode`] sealed in [`SealShapeMode::Shadow`] although
/// [`verify_sealed`] would reject their shape, domain or canon_version (process lifetime).
pub fn seal_shape_violations() -> u64 {
    SEAL_SHAPE_VIOLATIONS.load(core::sync::atomic::Ordering::Relaxed)
}

/// The shape, domain and canon_version part of [`verify_sealed`], applied to an already sealed
/// record: [`validate_record_shape`], then the domain pin, then the canon_version pin.
fn check_sealed_shape(sealed: &CanonValue) -> Result<(), RecordError> {
    validate_record_shape(sealed)?;
    let domain = str_field(sealed, "domain")?;
    if domain != RECORD_DOMAIN {
        return Err(RecordError::DomainMismatch {
            expected: RECORD_DOMAIN.to_string(),
            found: domain.to_string(),
        });
    }
    let cv = str_field(sealed, "canon_version")?;
    if cv != CANON_VERSION {
        return Err(RecordError::CanonVersionMismatch {
            expected: CANON_VERSION.to_string(),
            found: cv.to_string(),
        });
    }
    Ok(())
}

fn seal_unchecked(record: &CanonValue, sk: &SigningKey) -> Result<CanonValue, RecordError> {
    let content_hash = compute_content_hash(record)?;
    let sig = sign::sign(sign::RECORD_SIG_TAG, &content_hash, sk);
    let stripped = record.without_keys(&["content_hash", "sig"]);
    let with_hash = with_field(&stripped, "content_hash", CanonValue::Str(content_hash));
    Ok(with_field(&with_hash, "sig", CanonValue::Str(sig)))
}

/// Seal a record body: compute `content_hash` (RCP §9.1), sign it (RCP §9.2), and return the
/// record with both fields set. Any pre-existing `content_hash`/`sig` are ignored for hashing
/// and overwritten.
///
/// Rejects every body that [`verify_sealed`] would reject on shape (unknown or missing top-level
/// key), `domain` or `canon_version`, so `seal(b)` being `Ok` implies `verify_sealed` accepts the
/// result under the matching key. It does not check nested object shape (neither does
/// [`validate_record_shape`]).
pub fn seal(record: &CanonValue, sk: &SigningKey) -> Result<CanonValue, RecordError> {
    seal_with_mode(record, sk, SealShapeMode::Enforce)
}

/// [`seal`] with an explicit [`SealShapeMode`] (the cgo server maps `AVERIN_SEAL_SHAPE` to it).
pub fn seal_with_mode(
    record: &CanonValue,
    sk: &SigningKey,
    mode: SealShapeMode,
) -> Result<CanonValue, RecordError> {
    let sealed = seal_unchecked(record, sk)?;
    if let Err(e) = check_sealed_shape(&sealed) {
        match mode {
            SealShapeMode::Enforce => return Err(e),
            SealShapeMode::Shadow => {
                SEAL_SHAPE_VIOLATIONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    Ok(sealed)
}

/// Seal with no shape check: the old behaviour, kept only so tests can build records that a
/// verifier must reject. Never call from production code.
#[doc(hidden)]
pub fn seal_unchecked_for_tests(
    record: &CanonValue,
    sk: &SigningKey,
) -> Result<CanonValue, RecordError> {
    seal_unchecked(record, sk)
}

/// Verify a record's `sig` against the given verifying key (RCP §9.2). Does **not** re-check the
/// `content_hash` — call [`verify_content_hash`] first (or use [`verify_sealed`]).
pub fn verify_signature(record: &CanonValue, vk: &VerifyingKey) -> Result<(), RecordError> {
    let content_hash = str_field(record, "content_hash")?;
    let sig = str_field(record, "sig")?;
    sign::verify(sign::RECORD_SIG_TAG, content_hash, sig, vk)
        .map_err(|e| RecordError::SignatureInvalid(e.to_string()))
}

/// Full integrity check of a sealed record: schema-v2 shape (no unknown fields), domain/
/// canon_version, `content_hash`, and `sig`. This is the authenticity check external verifiers
/// must use — [`verify_content_hash`] alone only proves internal consistency, not authenticity.
pub fn verify_sealed(record: &CanonValue, vk: &VerifyingKey) -> Result<(), RecordError> {
    validate_record_shape(record)?;
    verify_content_hash(record)?;
    verify_signature(record, vk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(extensions: CanonValue) -> CanonValue {
        CanonValue::Object(vec![
            ("domain".into(), CanonValue::string(RECORD_DOMAIN)),
            ("canon_version".into(), CanonValue::string(CANON_VERSION)),
            ("extensions".into(), extensions),
        ])
    }

    /// A programmatically built body whose nested object has two keys that coincide only after NFC
    /// (`é` precomposed and decomposed) has no single canonical meaning: hashing fails closed
    /// instead of committing to text with a repeated key (RCP §5).
    #[test]
    fn nested_nfc_duplicate_key_has_no_content_hash() {
        let dup = CanonValue::Object(vec![
            ("\u{e9}".into(), CanonValue::Int(1)),
            ("e\u{301}".into(), CanonValue::Int(2)),
        ]);
        assert_eq!(
            compute_content_hash(&body(dup)),
            Err(RecordError::DuplicateKey)
        );
        let distinct = CanonValue::Object(vec![
            ("\u{e9}".into(), CanonValue::Int(1)),
            ("e".into(), CanonValue::Int(2)),
        ]);
        assert!(compute_content_hash(&body(distinct)).is_ok());
    }

    /// Stripped keys are matched before NFC and do not count as duplicates.
    #[test]
    fn stripped_keys_are_not_hashed() {
        let mut members = body(CanonValue::Null).as_object().unwrap().clone();
        let base = content_hash_preimage(&CanonValue::Object(members.clone())).unwrap();
        members.push(("content_hash".into(), CanonValue::string("x")));
        members.push(("sig".into(), CanonValue::string("y")));
        assert_eq!(
            content_hash_preimage(&CanonValue::Object(members)).unwrap(),
            base
        );
    }
}
