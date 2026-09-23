//! Hashing primitives and the length-prefix domain-separation helpers (RCP §9).

use sha2::{Digest, Sha256};

/// Maximum byte length that fits the 4-byte big-endian length prefix.
pub const MAX_LP_LEN: usize = u32::MAX as usize;

/// `LB(b) = uint32_be(len(b)) ‖ b` (RCP §9). Appends into `out`.
/// Returns false if `b` is too long to length-prefix (practically never).
pub fn lp_into(out: &mut Vec<u8>, b: &[u8]) -> bool {
    if b.len() > MAX_LP_LEN {
        return false;
    }
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
    true
}

/// `LP(s)` — length-prefix the UTF-8 bytes of a string (RCP §9).
pub fn lp_str_into(out: &mut Vec<u8>, s: &str) -> bool {
    lp_into(out, s.as_bytes())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn hex_lower(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0xF) as usize] as char);
    }
    s
}

/// `"sha256:" ‖ lowerhex(SHA-256(data))`.
pub fn sha256_prefixed(data: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&sha256(data)))
}

/// Parse a `sha256:<64-hex>` string into 32 raw bytes (None if malformed).
pub fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    let hex = s.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Decode exactly 64 lowercase-hex chars into 32 raw bytes (None on wrong length or non-hex).
/// Shared by 32-byte signing seeds and 32-byte commitment nonces.
pub fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hex_val(bytes[2 * i])? << 4) | hex_val(bytes[2 * i + 1])?;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None, // RCP requires lowercase hex
    }
}

/// Bounded proofs over this exact code (run by `formal/run-kani.sh`). The Lean seal theorem assumes
/// `"sha256:" ‖ lowerhex(·)` is injective and that `LP` emits `uint32_be(len) ‖ b`; these discharge both
/// against the implementation.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Every byte round-trips through its two lowercase hex digits. `hex_lower` writes exactly two digits
    /// per byte and `parse_sha256`/`hex32` read exactly two per byte at fixed offsets, so with
    /// `hex_digit_is_canonical` this makes `"sha256:" ‖ hex_lower(d)` injective in `d` for every length.
    #[kani::proof]
    #[kani::unwind(4)]
    fn hex_byte_roundtrip() {
        let b: u8 = kani::any();
        let s = hex_lower(&[b]);
        let d = s.as_bytes();
        assert_eq!(d.len(), 2);
        assert_eq!((hex_val(d[0]).unwrap() << 4) | hex_val(d[1]).unwrap(), b);
    }

    /// `hex_val` accepts exactly the 16 lowercase digits, each as the unique spelling of its value, so
    /// no uppercase or other alternative spelling of a digest is ever accepted.
    #[kani::proof]
    fn hex_digit_is_canonical() {
        let c: u8 = kani::any();
        if let Some(v) = hex_val(c) {
            assert!(v < 16);
            assert_eq!(b"0123456789abcdef"[v as usize], c);
        }
    }

    /// `lp_into` appends exactly `uint32_be(len) ‖ b` (checked for every `b` of length ≤ 4).
    #[kani::proof]
    #[kani::unwind(10)]
    fn lp_into_frames_exactly() {
        let bytes: [u8; 4] = kani::any();
        let len: usize = kani::any_where(|l: &usize| *l <= 4);
        let mut out = Vec::new();
        assert!(lp_into(&mut out, &bytes[..len]));
        assert_eq!(out.len(), 4 + len);
        assert_eq!(&out[..4], &(len as u32).to_be_bytes());
        assert_eq!(&out[4..], &bytes[..len]);
    }
}
