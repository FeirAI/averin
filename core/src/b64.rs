//! base64url (RFC 4648 §5) **without padding**, with canonical-encoding enforcement on decode.
//! Self-contained (no external crate) to keep the WASM verifier bundle small and auditable.

const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ENC[((n >> 18) & 63) as usize] as char);
        out.push(ENC[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ENC[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ENC[(n & 63) as usize] as char);
        }
    }
    out
}

fn val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None, // padding, whitespace, and standard-base64 +/ are all rejected
    }
}

/// Decode base64url-no-pad, rejecting padding, non-alphabet chars, the invalid length `% 4 == 1`,
/// and **non-canonical** encodings (unused trailing bits must be zero) so a byte string has
/// exactly one valid encoding.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    let mut vals = Vec::with_capacity(bytes.len());
    for &c in bytes {
        vals.push(val(c).ok_or_else(|| format!("invalid base64url char {:?}", c as char))?);
    }
    let mut out = Vec::with_capacity(vals.len() / 4 * 3);
    for chunk in vals.chunks(4) {
        match chunk.len() {
            1 => return Err("invalid base64url length (% 4 == 1)".to_string()),
            2 => {
                let n = ((chunk[0] as u32) << 18) | ((chunk[1] as u32) << 12);
                if (n & 0x0000_FFFF) != 0 {
                    return Err("non-canonical base64url (nonzero trailing bits)".to_string());
                }
                out.push((n >> 16) as u8);
            }
            3 => {
                let n = ((chunk[0] as u32) << 18)
                    | ((chunk[1] as u32) << 12)
                    | ((chunk[2] as u32) << 6);
                if (n & 0x0000_00FF) != 0 {
                    return Err("non-canonical base64url (nonzero trailing bits)".to_string());
                }
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            4 => {
                let n = ((chunk[0] as u32) << 18)
                    | ((chunk[1] as u32) << 12)
                    | ((chunk[2] as u32) << 6)
                    | (chunk[3] as u32);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            _ => unreachable!(),
        }
    }
    Ok(out)
}

/// Decode and require exactly `N` bytes.
pub fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = decode(s)?;
    if v.len() != N {
        return Err(format!("expected {} bytes, got {}", N, v.len()));
    }
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert_eq!(encode(b"fooba"), "Zm9vYmE");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        for v in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0xff, 0x00, 0xab, 0xcd],
        ] {
            assert_eq!(decode(&encode(v)).unwrap(), v);
        }
        // url-safe chars
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn rejects_padding_and_noncanonical() {
        assert!(decode("Zg==").is_err()); // padding
        assert!(decode("Zm9v====").is_err());
        assert!(decode("Zg").is_ok());
        // "Zh" would decode 'f' with nonzero trailing bits -> non-canonical
        assert!(decode("Zh").is_err());
        assert!(decode("A").is_err()); // length % 4 == 1
        assert!(decode("AB+/").is_err()); // standard base64 chars rejected
    }

    #[test]
    fn fixed_length() {
        let sig = [7u8; 64];
        assert_eq!(decode_fixed::<64>(&encode(&sig)).unwrap(), sig);
        assert!(decode_fixed::<32>(&encode(&sig)).is_err());
    }
}
