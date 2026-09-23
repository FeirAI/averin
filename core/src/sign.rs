//! Ed25519 signing with domain separation (RCP §9.2). Signs the `content_hash` (a
//! collision-resistant commitment to the whole canonical body) under a per-context tag, so a
//! signature in one context can never be replayed in another.

use crate::b64;
use crate::hashx::lp_str_into;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const RECORD_SIG_TAG: &str = "averin.record.sig.v1";
pub const CHECKPOINT_SIG_TAG: &str = "averin.checkpoint.sig.v1";

pub const SIG_PREFIX: &str = "ed25519:";
pub const PUBKEY_PREFIX: &str = "ed25519pub:";

#[derive(Debug, PartialEq)]
pub enum SigError {
    BadPrefix,
    BadEncoding(String),
    BadKey,
    Invalid,
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigError::BadPrefix => write!(f, "missing/incorrect algorithm prefix"),
            SigError::BadEncoding(e) => write!(f, "bad base64url encoding: {e}"),
            SigError::BadKey => write!(f, "invalid Ed25519 key"),
            SigError::Invalid => write!(f, "signature verification failed"),
        }
    }
}
impl std::error::Error for SigError {}

/// The exact bytes an Ed25519 signature under `tag` covers. Hidden `pub` for the Lean-oracle
/// differential test (`core/tests/oracle.rs`).
#[doc(hidden)]
pub fn preimage(tag: &str, content_hash: &str) -> Vec<u8> {
    // LP(tag) ‖ utf8(content_hash)   (RCP §9.2)
    let mut pre = Vec::with_capacity(4 + tag.len() + content_hash.len());
    lp_str_into(&mut pre, tag);
    pre.extend_from_slice(content_hash.as_bytes());
    pre
}

/// Sign `content_hash` under `tag`; returns `ed25519:<base64url-no-pad>`.
pub fn sign(tag: &str, content_hash: &str, sk: &SigningKey) -> String {
    let sig = sk.sign(&preimage(tag, content_hash));
    format!("{SIG_PREFIX}{}", b64::encode(&sig.to_bytes()))
}

/// Verify a `sig` string against `content_hash` under `tag` (strict — rejects malleable forms).
pub fn verify(tag: &str, content_hash: &str, sig: &str, vk: &VerifyingKey) -> Result<(), SigError> {
    let raw = sig.strip_prefix(SIG_PREFIX).ok_or(SigError::BadPrefix)?;
    let bytes = b64::decode_fixed::<64>(raw).map_err(SigError::BadEncoding)?;
    let signature = Signature::from_bytes(&bytes);
    vk.verify_strict(&preimage(tag, content_hash), &signature)
        .map_err(|_| SigError::Invalid)
}

/// `ed25519pub:<base64url(32)>`.
pub fn encode_pubkey(vk: &VerifyingKey) -> String {
    format!("{PUBKEY_PREFIX}{}", b64::encode(vk.as_bytes()))
}

pub fn decode_pubkey(s: &str) -> Result<VerifyingKey, SigError> {
    let raw = s.strip_prefix(PUBKEY_PREFIX).ok_or(SigError::BadPrefix)?;
    let bytes = b64::decode_fixed::<32>(raw).map_err(SigError::BadEncoding)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| SigError::BadKey)
}

/// Deterministic test/dev key from a 32-byte seed. Production keys come from KMS / customer
/// custody; this is for golden vectors and fixtures.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_domain_separation() {
        let sk = signing_key_from_seed(&[42u8; 32]);
        let vk = sk.verifying_key();
        let ch = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let s = sign(RECORD_SIG_TAG, ch, &sk);
        assert!(s.starts_with("ed25519:"));
        assert!(verify(RECORD_SIG_TAG, ch, &s, &vk).is_ok());

        // wrong tag (domain) must fail — no cross-context replay
        assert_eq!(
            verify(CHECKPOINT_SIG_TAG, ch, &s, &vk),
            Err(SigError::Invalid)
        );
        // wrong content_hash must fail
        let ch2 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(verify(RECORD_SIG_TAG, ch2, &s, &vk), Err(SigError::Invalid));
    }

    #[test]
    fn pubkey_encoding_roundtrip() {
        let vk = signing_key_from_seed(&[7u8; 32]).verifying_key();
        let enc = encode_pubkey(&vk);
        assert!(enc.starts_with("ed25519pub:"));
        assert_eq!(decode_pubkey(&enc).unwrap(), vk);
        // wrong prefix, and a too-short body, both rejected as BadEncoding/BadPrefix
        assert_eq!(decode_pubkey("ed25519:AAAA"), Err(SigError::BadPrefix));
        assert!(matches!(
            decode_pubkey("ed25519pub:short"),
            Err(SigError::BadEncoding(_))
        ));
        // a 31-byte body (valid base64url, wrong length) is rejected with the byte-count message
        let short = crate::b64::encode(&[0u8; 31]);
        assert!(matches!(
            decode_pubkey(&format!("ed25519pub:{short}")),
            Err(SigError::BadEncoding(_))
        ));
    }

    #[test]
    fn rejects_tampered_signature() {
        let sk = signing_key_from_seed(&[1u8; 32]);
        let vk = sk.verifying_key();
        let ch = "sha256:abababababababababababababababababababababababababababababababab";
        let mut s = sign(RECORD_SIG_TAG, ch, &sk);
        // flip a char in the signature body
        let last = s.pop().unwrap();
        s.push(if last == 'A' { 'B' } else { 'A' });
        assert!(verify(RECORD_SIG_TAG, ch, &s, &vk).is_err());
    }
}
