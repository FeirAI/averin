//! base64url (RFC 4648 §5) **without padding**, with canonical-encoding enforcement on decode.
//! Self-contained (no external crate) to keep the WASM verifier bundle small and auditable.

const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let (symbols, len) = encode_chunk(chunk);
        for &symbol in &symbols[..len] {
            out.push(symbol as char);
        }
    }
    out
}

// The fixed-width chunk algorithm used by the public encoder and the bounded proofs.
fn encode_chunk(chunk: &[u8]) -> ([u8; 4], usize) {
    let b0 = chunk[0] as u32;
    let b1 = *chunk.get(1).unwrap_or(&0) as u32;
    let b2 = *chunk.get(2).unwrap_or(&0) as u32;
    let n = (b0 << 16) | (b1 << 8) | b2;
    let mut symbols = [0; 4];
    symbols[0] = ENC[((n >> 18) & 63) as usize];
    symbols[1] = ENC[((n >> 12) & 63) as usize];
    if chunk.len() > 1 {
        symbols[2] = ENC[((n >> 6) & 63) as usize];
    }
    if chunk.len() > 2 {
        symbols[3] = ENC[(n & 63) as usize];
    }
    (symbols, chunk.len() + 1)
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
    decode_typed(s).map_err(|err| match err {
        DecodeError::InvalidChar(c) => format!("invalid base64url char {:?}", c as char),
        DecodeError::InvalidLength => "invalid base64url length (% 4 == 1)".to_string(),
        DecodeError::NonCanonical => "non-canonical base64url (nonzero trailing bits)".to_string(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodeError {
    InvalidChar(u8),
    InvalidLength,
    NonCanonical,
}

// The public decoder and the bounded proofs both use this exact validation and decoding path.
// Error text is produced only at the public boundary, after the typed result is known.
fn decode_typed(s: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = s.as_bytes();
    let mut vals = Vec::with_capacity(bytes.len());
    for &c in bytes {
        vals.push(val(c).ok_or(DecodeError::InvalidChar(c))?);
    }
    let mut out = Vec::with_capacity(vals.len() / 4 * 3);
    for chunk in vals.chunks(4) {
        let (bytes, len) = decode_chunk(chunk)?;
        out.extend_from_slice(&bytes[..len]);
    }
    Ok(out)
}

// Values have already passed `val`; all accepted spellings are assembled from these chunks.
fn decode_chunk(chunk: &[u8]) -> Result<([u8; 3], usize), DecodeError> {
    match chunk.len() {
        1 => Err(DecodeError::InvalidLength),
        2..=4 => {
            let n = ((chunk[0] as u32) << 18)
                | ((chunk[1] as u32) << 12)
                | ((*chunk.get(2).unwrap_or(&0) as u32) << 6)
                | (*chunk.get(3).unwrap_or(&0) as u32);
            if (chunk.len() == 2 && n & 0x0000_FFFF != 0)
                || (chunk.len() == 3 && n & 0x0000_00FF != 0)
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(([(n >> 16) as u8, (n >> 8) as u8, n as u8], chunk.len() - 1))
        }
        _ => unreachable!(),
    }
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
        assert_eq!(decode("+").unwrap_err(), "invalid base64url char '+'");
        assert_eq!(decode("é").unwrap_err(), "invalid base64url char 'Ã'");
        assert_eq!(
            decode("A").unwrap_err(),
            "invalid base64url length (% 4 == 1)"
        );
        assert_eq!(
            decode("Zh").unwrap_err(),
            "non-canonical base64url (nonzero trailing bits)"
        );
    }

    #[test]
    fn fixed_length() {
        let sig = [7u8; 64];
        assert_eq!(decode_fixed::<64>(&encode(&sig)).unwrap(), sig);
        assert!(decode_fixed::<32>(&encode(&sig)).is_err());
    }
}

/// Bounded proofs of the production chunk functions (run by `formal/run-kani.sh`). The public
/// encoder and decoder apply these functions to successive chunks after alphabet validation.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// The alphabet is a bijection between the 64 accepted symbols and 0..64: `val` inverts `ENC`, and
    /// every byte `val` accepts is the `ENC` symbol of its value (padding, whitespace and the standard
    /// `+`/`/` alphabet are rejected).
    #[kani::proof]
    fn alphabet_is_a_bijection() {
        let c: u8 = kani::any();
        if let Some(v) = val(c) {
            assert!(v < 64);
            assert_eq!(ENC[v as usize], c);
        }
        let v: u8 = kani::any_where(|v: &u8| *v < 64);
        assert_eq!(val(ENC[v as usize]), Some(v));
    }

    fn unique<const N: usize>() {
        let raw: [u8; N] = kani::any();
        let mut vals = [0u8; N];
        for (i, &b) in raw.iter().enumerate() {
            let Some(v) = val(b) else {
                return;
            };
            vals[i] = v;
        }
        if let Ok((bytes, len)) = decode_chunk(&vals) {
            let (symbols, out_len) = encode_chunk(&bytes[..len]);
            assert_eq!(out_len, N);
            assert_eq!(symbols[..N], raw);
        }
    }

    /// Canonicality of the 2-symbol tail (1 byte): an accepted chunk is exactly the encoded byte —
    /// the 4 unused trailing bits must be zero. A full 4-symbol chunk has no unused bits, so with
    /// `alphabet_is_a_bijection` every byte string has exactly one accepted spelling.
    #[kani::proof]
    #[kani::solver(kissat)]
    #[kani::unwind(4)]
    fn one_byte_tail_is_canonical() {
        unique::<2>();
    }

    /// Canonicality of the 3-symbol tail (2 bytes): the 2 unused trailing bits must be zero.
    #[kani::proof]
    #[kani::solver(kissat)]
    #[kani::unwind(5)]
    fn two_byte_tail_is_canonical() {
        unique::<3>();
    }

    /// A full 4-symbol chunk (3 bytes, no unused bits): every accepted spelling is exactly the encoding
    /// of the bytes it decodes to. The public functions use these same fixed-width chunk functions, so
    /// the proof avoids symbolic heap growth while covering each chunk case.
    #[kani::proof]
    #[kani::solver(kissat)]
    #[kani::unwind(6)]
    fn full_chunk_is_canonical() {
        let raw: [u8; 4] = kani::any();
        let mut vals = [0u8; 4];
        for (i, &b) in raw.iter().enumerate() {
            let Some(v) = val(b) else {
                return;
            };
            vals[i] = v;
        }
        match decode_chunk(&vals) {
            Ok((bytes, len)) => {
                assert_eq!(len, 3);
                let (symbols, out_len) = encode_chunk(&bytes[..len]);
                assert_eq!(out_len, 4);
                assert_eq!(symbols, raw);
            }
            Err(_) => panic!("a full chunk of alphabet symbols always decodes"),
        }
    }
}
