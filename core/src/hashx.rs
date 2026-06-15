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
