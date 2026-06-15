//! Hiding commitments for low-entropy fields (RCP §9.3, threat #6).
//!
//! `commitment = sha256:hex( SHA-256( LP("feir.commit.v1") ‖ LP(field_domain) ‖ LB(nonce) ‖ LB(value) ) )`
//!
//! Nonce and value are bound as **raw byte strings** (length-prefixed), never re-encoded, so
//! there is no encoding ambiguity. The commitment hides the value (the 32-byte nonce defeats a
//! hash dictionary) and binds it (disclosure reveals `(value, nonce)` and is checkable).

use crate::hashx::{lp_into, lp_str_into, sha256_prefixed};

pub const COMMIT_TAG: &str = "feir.commit.v1";
pub const NONCE_LEN: usize = 32;

/// The closed registry of commit field domains (RCP §9.3). Derived from the containing field:
/// `input_commit` → `Input`, etc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldDomain {
    Input,
    Output,
    Rationale,
}

impl FieldDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            FieldDomain::Input => "input",
            FieldDomain::Output => "output",
            FieldDomain::Rationale => "rationale",
        }
    }

    /// Parse a domain string from the closed registry. The disclosure `field` and the FFI `domain`
    /// argument both resolve through here, so the registry stays in exactly one place.
    pub fn parse(s: &str) -> Option<FieldDomain> {
        match s {
            "input" => Some(FieldDomain::Input),
            "output" => Some(FieldDomain::Output),
            "rationale" => Some(FieldDomain::Rationale),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CommitError {
    TooLong,
    BadNonceLen(usize),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitError::TooLong => write!(f, "value or nonce too long to length-prefix"),
            CommitError::BadNonceLen(n) => write!(f, "nonce must be {NONCE_LEN} bytes, got {n}"),
        }
    }
}
impl std::error::Error for CommitError {}

/// Compute a hiding commitment over `value` under `domain`, hidden by `nonce` (32 bytes).
pub fn commit(domain: FieldDomain, value: &[u8], nonce: &[u8]) -> Result<String, CommitError> {
    if nonce.len() != NONCE_LEN {
        return Err(CommitError::BadNonceLen(nonce.len()));
    }
    let mut pre = Vec::with_capacity(32 + value.len());
    if !lp_str_into(&mut pre, COMMIT_TAG)
        || !lp_str_into(&mut pre, domain.as_str())
        || !lp_into(&mut pre, nonce)
        || !lp_into(&mut pre, value)
    {
        return Err(CommitError::TooLong);
    }
    Ok(sha256_prefixed(&pre))
}

/// Verify a disclosed `(value, nonce)` against a commitment. Recomputes the commitment and
/// compares. The commitment is public (no secret is compared), so the byte comparison short-
/// circuits on a length mismatch; the equal-length path uses a difference-accumulating compare
/// to avoid being a footgun if this helper is ever reused on secret material.
pub fn verify_commitment(
    commitment: &str,
    domain: FieldDomain,
    value: &[u8],
    nonce: &[u8],
) -> bool {
    match commit(domain, value, nonce) {
        Ok(c) => c.as_bytes().ct_eq(commitment.as_bytes()),
        Err(_) => false,
    }
}

/// Generate a fresh 32-byte nonce from the OS CSPRNG, or `None` if the CSPRNG is unavailable.
/// The FFI (`feir_random_nonce`) uses this fallible form so a CSPRNG failure becomes a clean
/// `{"error":...}` instead of a panic unwinding across the C/cgo boundary (UB in the debug
/// staticlib Go links). Only with the `std` feature — the WASM verifier never mints nonces.
#[cfg(feature = "std")]
pub fn try_random_nonce() -> Option<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).ok()?;
    Some(n)
}

/// Generate a fresh 32-byte nonce from the OS CSPRNG. Panics if the CSPRNG is unavailable; use
/// [`try_random_nonce`] across an FFI boundary where unwinding is UB.
#[cfg(feature = "std")]
pub fn random_nonce() -> [u8; NONCE_LEN] {
    try_random_nonce().expect("OS CSPRNG unavailable")
}

/// Length-independent byte comparison to avoid leaking via early-exit timing. The commitment is
/// public, but constant-time comparison is cheap and avoids a footgun if reused on secrets.
trait CtEq {
    fn ct_eq(&self, other: &Self) -> bool;
}
impl CtEq for [u8] {
    fn ct_eq(&self, other: &[u8]) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_binds_and_hides() {
        let nonce = [9u8; NONCE_LEN];
        let c = commit(FieldDomain::Input, b"transfer $900", &nonce).unwrap();
        assert!(c.starts_with("sha256:"));
        assert!(verify_commitment(
            &c,
            FieldDomain::Input,
            b"transfer $900",
            &nonce
        ));
        // wrong value, wrong domain, wrong nonce all fail
        assert!(!verify_commitment(
            &c,
            FieldDomain::Input,
            b"transfer $901",
            &nonce
        ));
        assert!(!verify_commitment(
            &c,
            FieldDomain::Output,
            b"transfer $900",
            &nonce
        ));
        assert!(!verify_commitment(
            &c,
            FieldDomain::Input,
            b"transfer $900",
            &[1u8; NONCE_LEN]
        ));
    }

    #[test]
    fn rejects_bad_nonce_len() {
        assert_eq!(
            commit(FieldDomain::Input, b"x", &[0u8; 16]),
            Err(CommitError::BadNonceLen(16))
        );
    }

    #[test]
    fn domain_separation_prevents_crossfield_reuse() {
        let nonce = [3u8; NONCE_LEN];
        let a = commit(FieldDomain::Input, b"same", &nonce).unwrap();
        let b = commit(FieldDomain::Output, b"same", &nonce).unwrap();
        assert_ne!(a, b, "same value+nonce under different domains must differ");
    }
}
