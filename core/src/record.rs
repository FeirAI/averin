//! Decision Record integrity: compute/verify `content_hash` (RCP §9.1). Signing lives in
//! `sign.rs`; this module owns the hashing preimage.

use crate::canon::CanonValue;
use crate::hashx::{lp_str_into, sha256_prefixed};

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
        }
    }
}
impl std::error::Error for RecordError {}

fn str_field<'a>(obj: &'a CanonValue, key: &'static str) -> Result<&'a str, RecordError> {
    obj.get(key)
        .ok_or(RecordError::MissingField(key))?
        .as_str()
        .ok_or(RecordError::FieldNotString(key))
}

/// Compute the canonical `content_hash` of a record body (RCP §9.1):
/// `sha256:hex( SHA-256( LP(domain) ‖ LP(canon_version) ‖ RCP-serialize(body \ {content_hash,sig}) ) )`.
///
/// The `domain` / `canon_version` are read from the body and re-bound into the preimage; callers
/// verifying a record should additionally confirm they equal the expected constants (see
/// [`verify_content_hash`]).
pub fn compute_content_hash(record: &CanonValue) -> Result<String, RecordError> {
    if record.as_object().is_none() {
        return Err(RecordError::NotObject);
    }
    let domain = str_field(record, "domain")?.to_string();
    let canon_version = str_field(record, "canon_version")?.to_string();

    let body = record.without_keys(&["content_hash", "sig"]);
    let canon = body.serialize();

    let mut preimage = Vec::with_capacity(8 + domain.len() + canon_version.len() + canon.len());
    if !lp_str_into(&mut preimage, &domain) || !lp_str_into(&mut preimage, &canon_version) {
        return Err(RecordError::TooLong);
    }
    preimage.extend_from_slice(canon.as_bytes());
    Ok(sha256_prefixed(&preimage))
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
