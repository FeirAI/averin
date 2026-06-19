//! Decision Record integrity: compute/verify `content_hash` (RCP §9.1). Signing lives in
//! `sign.rs`; this module owns the hashing preimage.

use crate::canon::CanonValue;
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
    // value-set {budget-exhausted, chargeback-posted}, kebab-case per feir convention. It is a
    // normal signed top-level field (covered by content_hash/sig like any key — canon iterates
    // object keys), so it must be in ALLOWED_TOP_KEYS for validate_record_shape/verify_sealed to
    // accept it; it is NOT in REQUIRED_TOP_KEYS (optional). The JSON Schema pins the enum values;
    // the closed-key gate here only admits the field. See spec/decision-record.schema.json and
    // leria's feir-integration-handoff.md.
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

/// Generic domain-separated body hash (RCP §9.1): reads `domain`/`canon_version` from the body,
/// strips `strip` keys, and returns
/// `sha256:hex( SHA-256( LP(domain) ‖ LP(canon_version) ‖ RCP-serialize(body \ strip) ) )`.
/// Shared by records (`strip = [content_hash, sig]`) and checkpoints
/// (`strip = [anchor, checkpoint_hash, sig]`).
pub fn hash_body(value: &CanonValue, strip: &[&str]) -> Result<String, RecordError> {
    if value.as_object().is_none() {
        return Err(RecordError::NotObject);
    }
    let domain = str_field(value, "domain")?.to_string();
    let canon_version = str_field(value, "canon_version")?.to_string();

    let body = value.without_keys(strip);
    let canon = body.serialize();

    let mut preimage = Vec::with_capacity(8 + domain.len() + canon_version.len() + canon.len());
    if !lp_str_into(&mut preimage, &domain) || !lp_str_into(&mut preimage, &canon_version) {
        return Err(RecordError::TooLong);
    }
    preimage.extend_from_slice(canon.as_bytes());
    Ok(sha256_prefixed(&preimage))
}

/// Compute the canonical record `content_hash` (RCP §9.1).
///
/// The `domain` / `canon_version` are read from the body and re-bound into the preimage; callers
/// verifying a record should additionally confirm they equal the expected constants (see
/// [`verify_content_hash`]).
pub fn compute_content_hash(record: &CanonValue) -> Result<String, RecordError> {
    hash_body(record, &["content_hash", "sig"])
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

/// Seal a record body: compute `content_hash` (RCP §9.1), sign it (RCP §9.2), and return the
/// record with both fields set. Any pre-existing `content_hash`/`sig` are ignored for hashing
/// and overwritten.
pub fn seal(record: &CanonValue, sk: &SigningKey) -> Result<CanonValue, RecordError> {
    let content_hash = compute_content_hash(record)?;
    let sig = sign::sign(sign::RECORD_SIG_TAG, &content_hash, sk);
    let stripped = record.without_keys(&["content_hash", "sig"]);
    let with_hash = with_field(&stripped, "content_hash", CanonValue::Str(content_hash));
    Ok(with_field(&with_hash, "sig", CanonValue::Str(sig)))
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
