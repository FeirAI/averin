//! External anchoring of checkpoints (spec §7, threats #1/#3/#9). An anchor binds a
//! `checkpoint_hash` to a time attested by a party the customer does **not** control, so a
//! checkpoint cannot be backdated (#3) and records anchored before a key compromise stay
//! trustworthy (#9).
//!
//! Two schemes:
//! * `rfc3161` — a real RFC 3161 TimeStampToken (DER/CMS). Production path; the Go anchoring job
//!   obtains it from a third-party TSA. Wire-format verification is feature-gated (`rfc3161`,
//!   landing with the server) to keep the WASM verifier lean — until then it reports `Unsupported`.
//! * `test-anchor` — a hermetic, deterministic scheme used by fixtures/dev: an independent TSA key
//!   (distinct from the customer signing key) signs `LP(tag) ‖ LP(checkpoint_hash) ‖ LP(anchored_ts)`.
//!   It exercises the *exact* detection logic (bind hash→time under a non-customer key) without a
//!   network or ASN.1 dependency.

use crate::canon::CanonValue;
use crate::hashx::lp_str_into;
use crate::{b64, sign};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub const ANCHOR_TAG: &str = "feir.anchor.v1";

#[derive(Debug, PartialEq)]
pub enum AnchorError {
    MissingField(&'static str),
    BadScheme(String),
    BadToken(String),
    Untrusted,
    Unsupported(String),
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorError::MissingField(k) => write!(f, "anchor missing field '{k}'"),
            AnchorError::BadScheme(s) => write!(f, "unknown anchor scheme '{s}'"),
            AnchorError::BadToken(e) => write!(f, "bad anchor token: {e}"),
            AnchorError::Untrusted => {
                write!(f, "anchor token not signed by any trusted TSA key")
            }
            AnchorError::Unsupported(s) => {
                write!(f, "anchor scheme '{s}' not supported in this build")
            }
        }
    }
}
impl std::error::Error for AnchorError {}

fn anchor_preimage(checkpoint_hash: &str, anchored_ts: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(16 + checkpoint_hash.len() + anchored_ts.len());
    lp_str_into(&mut p, ANCHOR_TAG);
    lp_str_into(&mut p, checkpoint_hash);
    lp_str_into(&mut p, anchored_ts);
    p
}

/// Build a `test-anchor` block over `checkpoint_hash` at `anchored_ts`, signed by the TSA key.
pub fn make_test_anchor(
    checkpoint_hash: &str,
    anchored_ts: &str,
    tsa_sk: &SigningKey,
    tsa_key_id: &str,
) -> CanonValue {
    use ed25519_dalek::Signer;
    let sig = tsa_sk.sign(&anchor_preimage(checkpoint_hash, anchored_ts));
    CanonValue::object(vec![
        ("scheme".into(), CanonValue::string("test-anchor")),
        ("anchored_ts".into(), CanonValue::string(anchored_ts)),
        ("tsa_key_id".into(), CanonValue::string(tsa_key_id)),
        (
            "token_b64".into(),
            CanonValue::string(b64::encode(&sig.to_bytes())),
        ),
    ])
    .expect("anchor object")
}

/// Verify an anchor block binds `checkpoint_hash` and return the attested `anchored_ts`.
/// `trusted_tsa` are TSA public keys supplied out-of-band (the anchor's trust root).
pub fn verify_anchor(
    checkpoint_hash: &str,
    anchor: &CanonValue,
    trusted_tsa: &[VerifyingKey],
) -> Result<String, AnchorError> {
    let scheme = anchor
        .get("scheme")
        .and_then(|v| v.as_str())
        .ok_or(AnchorError::MissingField("scheme"))?;
    match scheme {
        "test-anchor" => {
            let anchored_ts = anchor
                .get("anchored_ts")
                .and_then(|v| v.as_str())
                .ok_or(AnchorError::MissingField("anchored_ts"))?;
            let token = anchor
                .get("token_b64")
                .and_then(|v| v.as_str())
                .ok_or(AnchorError::MissingField("token_b64"))?;
            let sig_bytes = b64::decode_fixed::<64>(token).map_err(AnchorError::BadToken)?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            let pre = anchor_preimage(checkpoint_hash, anchored_ts);
            for vk in trusted_tsa {
                if vk.verify_strict(&pre, &signature).is_ok() {
                    return Ok(anchored_ts.to_string());
                }
            }
            Err(AnchorError::Untrusted)
        }
        "rfc3161" => Err(AnchorError::Unsupported("rfc3161".into())),
        other => Err(AnchorError::BadScheme(other.to_string())),
    }
}

/// Convenience: a TSA "authority" for tests/dev (deterministic key from seed).
pub fn test_tsa_key(seed: &[u8; 32]) -> SigningKey {
    sign::signing_key_from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_binds_hash_and_time() {
        let tsa = test_tsa_key(&[200u8; 32]);
        let ch = "sha256:abababababababababababababababababababababababababababababababab";
        let ts = "2026-06-15T10:05:00.000Z";
        let anchor = make_test_anchor(ch, ts, &tsa, "tsa-1");
        let trusted = vec![tsa.verifying_key()];

        assert_eq!(verify_anchor(ch, &anchor, &trusted).unwrap(), ts);
        // wrong checkpoint_hash -> fails (token is bound to the hash)
        let ch2 = "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        assert_eq!(
            verify_anchor(ch2, &anchor, &trusted),
            Err(AnchorError::Untrusted)
        );
        // untrusted TSA key -> fails
        let other = vec![test_tsa_key(&[1u8; 32]).verifying_key()];
        assert_eq!(
            verify_anchor(ch, &anchor, &other),
            Err(AnchorError::Untrusted)
        );
    }

    #[test]
    fn rfc3161_is_explicitly_unsupported_not_silently_passed() {
        let anchor = CanonValue::parse(
            r#"{"scheme":"rfc3161","anchored_ts":"2026-06-15T10:05:00.000Z","token_b64":"AAAA"}"#,
        )
        .unwrap();
        assert!(matches!(
            verify_anchor("sha256:00", &anchor, &[]),
            Err(AnchorError::Unsupported(_))
        ));
    }
}
