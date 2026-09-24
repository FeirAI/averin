//! Record Canonical Profile (RCP) v1 — the byte-for-byte canonicalization engine.
//!
//! See `/spec/rcp-v1.md`. We deliberately implement our own JSON parse/serialize rather than
//! reuse a lenient library, because RCP requires behaviours general-purpose JSON does not give:
//! post-NFC **duplicate-key rejection**, **lone-surrogate rejection**, **integers only (i64)**,
//! and byte-exact escaping + UTF-16 key ordering. This module is the golden-vector contract;
//! any divergence here is threat #10 (verifier skew).

use core::cmp::Ordering;
use core::fmt;
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;

/// A value restricted to the RCP canonical model (RCP §1).
#[derive(Clone, Debug, PartialEq)]
pub enum CanonValue {
    Null,
    Bool(bool),
    /// Signed 64-bit integer. RCP forbids floats and bounds integers to i64 (RCP §3).
    Int(i64),
    /// Always already NFC-normalized (RCP §4).
    Str(String),
    Array(Vec<CanonValue>),
    /// Members in insertion order; keys are NFC-normalized and guaranteed unique (RCP §5).
    /// Serialization sorts by UTF-16 code unit (RCP §2).
    Object(Vec<(String, CanonValue)>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanonError {
    pub msg: String,
    pub pos: usize,
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RCP parse error at byte {}: {}", self.pos, self.msg)
    }
}
impl std::error::Error for CanonError {}

// Keep parser decisions independent of diagnostic formatting. The public API still constructs
// precisely the same `CanonError` text at its boundary.
#[derive(Debug)]
struct ParseError {
    message: ParseMessage,
    pos: usize,
}

#[derive(Debug)]
enum ParseMessage {
    Static(&'static str),
    Expected(u8),
    InvalidLiteral(&'static str),
    DuplicateKey(String),
}

impl ParseError {
    fn into_public(self) -> CanonError {
        let msg = match self.message {
            ParseMessage::Static(msg) => msg.to_string(),
            ParseMessage::Expected(b) => format!("expected '{}'", b as char),
            ParseMessage::InvalidLiteral(kw) => format!("invalid literal, expected '{kw}'"),
            ParseMessage::DuplicateKey(key) => {
                format!("duplicate object key after NFC normalization: {key:?}")
            }
        };
        CanonError { msg, pos: self.pos }
    }
}

impl CanonValue {
    /// Parse a JSON document under RCP v1 rules. Rejects floats, out-of-range integers,
    /// duplicate keys (post-NFC), lone surrogates, and trailing garbage.
    pub fn parse(input: &str) -> Result<CanonValue, CanonError> {
        Self::parse_typed(input).map_err(ParseError::into_public)
    }

    fn parse_typed(input: &str) -> Result<CanonValue, ParseError> {
        let mut p = Parser {
            source: input,
            s: input.as_bytes(),
            i: 0,
            depth: 0,
        };
        p.skip_ws();
        let v = p.parse_value()?;
        p.skip_ws();
        if p.i != p.s.len() {
            return Err(p.err("trailing data after top-level value"));
        }
        Ok(v)
    }

    /// Checked string constructor — NFC-normalizes (RCP §4). Preferred over `Str(..)` for
    /// programmatic building so invariants hold before serialization.
    pub fn string(s: impl Into<String>) -> CanonValue {
        CanonValue::Str(nfc(&s.into()))
    }

    /// Checked object constructor — NFC-normalizes keys and **rejects duplicates** (RCP §5).
    /// Preferred over `Object(..)` for programmatic building (e.g. checkpoint bodies).
    pub fn object(pairs: Vec<(String, CanonValue)>) -> Result<CanonValue, CanonError> {
        let mut members: Vec<(String, CanonValue)> = Vec::with_capacity(pairs.len());
        // A key set alongside the ordered members: a linear `members.iter().any(..)` per key made
        // construction quadratic in the member count (a verifier DoS on wide objects).
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for (k, v) in pairs {
            let key = nfc(&k);
            if !seen.insert(key.clone()) {
                return Err(CanonError {
                    msg: format!("duplicate object key after NFC normalization: {key:?}"),
                    pos: 0,
                });
            }
            members.push((key, v));
        }
        Ok(CanonValue::Object(members))
    }

    /// Serialize to the canonical RCP byte string (UTF-8).
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            CanonValue::Null => out.push_str("null"),
            CanonValue::Bool(true) => out.push_str("true"),
            CanonValue::Bool(false) => out.push_str("false"),
            CanonValue::Int(n) => out.push_str(&n.to_string()),
            CanonValue::Str(s) => write_string(&nfc(s), out),
            CanonValue::Array(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    it.write(out);
                }
                out.push(']');
            }
            CanonValue::Object(members) => {
                // RCP §2/§4/§5: keys are NFC-normalized here (defense in depth — the hashed
                // bytes are always canonical even if a `CanonValue` was built programmatically
                // without going through `parse`/`object`), then sorted by UTF-16 code unit.
                // Values produced by `parse` are already NFC, so this is idempotent on the
                // signing path. Duplicate keys are a caller invariant violation (use
                // `CanonValue::object`); we assert against them in debug builds.
                let keys: Vec<String> = members.iter().map(|(k, _)| nfc(k)).collect();
                let mut idx: Vec<usize> = (0..members.len()).collect();
                idx.sort_by(|&a, &b| utf16_cmp(&keys[a], &keys[b]));
                debug_assert!(
                    idx.windows(2).all(|w| keys[w[0]] != keys[w[1]]),
                    "RCP invariant: duplicate object key after NFC in serialize()"
                );
                out.push('{');
                for (n, &mi) in idx.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    write_string(&keys[mi], out);
                    out.push(':');
                    members[mi].1.write(out);
                }
                out.push('}');
            }
        }
    }

    // ---- ergonomic accessors used by record/checkpoint logic ----

    pub fn as_object(&self) -> Option<&Vec<(String, CanonValue)>> {
        match self {
            CanonValue::Object(m) => Some(m),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&CanonValue> {
        self.as_object()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            CanonValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<CanonValue>> {
        match self {
            CanonValue::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            CanonValue::Int(n) => Some(*n),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, CanonValue::Null)
    }

    /// Return a clone of this object with the given top-level keys removed (used to strip
    /// `content_hash`/`sig` before hashing — RCP §9.1).
    pub fn without_keys(&self, keys: &[&str]) -> CanonValue {
        match self {
            CanonValue::Object(m) => CanonValue::Object(
                m.iter()
                    .filter(|(k, _)| !keys.contains(&k.as_str()))
                    .cloned()
                    .collect(),
            ),
            other => other.clone(),
        }
    }
}

/// Compare two strings by their UTF-16 code-unit sequences (RFC 8785 §3.2.3 / RCP §2).
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// NFC-normalize a string (RCP §4). Idempotent on already-normalized input.
fn nfc(s: &str) -> String {
    if s.is_ascii() {
        // Every ASCII scalar is already NFC. This common production path also keeps symbolic
        // ASCII parser proofs out of the Unicode normalization tables.
        s.to_string()
    } else {
        s.nfc().collect()
    }
}

/// Write a JSON string with RCP-minimal escaping (RCP §4).
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                let b = c as u32;
                out.push(hex_digit((b >> 4) as u8));
                out.push(hex_digit((b & 0xF) as u8));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

/// Maximum array/object nesting depth. Bounds recursion so deeply-nested untrusted input cannot
/// overflow the stack (which, under `panic="abort"`, would kill the process — a DoS reachable from
/// the FFI/WASM/CLI entry points). 256 is far beyond any real record/checkpoint shape.
const MAX_DEPTH: usize = 256;

struct Parser<'a> {
    source: &'a str,
    s: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &'static str) -> ParseError {
        ParseError {
            message: ParseMessage::Static(msg),
            pos: self.i,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        // RCP/JSON insignificant whitespace: space, tab, LF, CR.
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<CanonValue, ParseError> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(CanonValue::Str(self.parse_string()?)),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.err("unexpected character")),
            None => Err(self.err("unexpected end of input")),
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), ParseError> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(ParseError {
                message: ParseMessage::Expected(b),
                pos: self.i,
            })
        }
    }

    fn parse_keyword(&mut self, kw: &'static str) -> Result<(), ParseError> {
        if self.s[self.i..].starts_with(kw.as_bytes()) {
            self.i += kw.len();
            Ok(())
        } else {
            Err(ParseError {
                message: ParseMessage::InvalidLiteral(kw),
                pos: self.i,
            })
        }
    }

    fn parse_bool(&mut self) -> Result<CanonValue, ParseError> {
        if self.peek() == Some(b't') {
            self.parse_keyword("true")?;
            Ok(CanonValue::Bool(true))
        } else {
            self.parse_keyword("false")?;
            Ok(CanonValue::Bool(false))
        }
    }

    fn parse_null(&mut self) -> Result<CanonValue, ParseError> {
        self.parse_keyword("null")?;
        Ok(CanonValue::Null)
    }

    fn parse_number(&mut self) -> Result<CanonValue, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        // integer part: 0 alone, or [1-9][0-9]*  (JSON grammar; no leading zeros)
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
            }
            Some(b'1'..=b'9') => {
                self.i += 1;
                while let Some(b'0'..=b'9') = self.peek() {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("invalid number: missing integer digits")),
        }
        // RCP §3: floats are forbidden. A fraction or exponent here is a hard error.
        if let Some(b'.') = self.peek() {
            return Err(self.err("floating-point not allowed in RCP (use integer micros)"));
        }
        if let Some(b'e') | Some(b'E') = self.peek() {
            return Err(self.err("exponent not allowed in RCP (integers only)"));
        }
        // The scanner above consumed only ASCII '-' and digits. Keep the original validated
        // string so this slice does not need a second UTF-8 validation pass. Every cursor
        // advance elsewhere is ASCII or a whole scalar, so both indices are char boundaries.
        let lexeme = &self.source[start..self.i];
        // RCP §3: `-0` is not a canonical integer spelling (consistent with rejecting `00`/`01`).
        if lexeme == "-0" {
            return Err(ParseError {
                message: ParseMessage::Static("negative zero is not a canonical integer"),
                pos: start,
            });
        }
        match lexeme.parse::<i64>() {
            Ok(n) => Ok(CanonValue::Int(n)),
            Err(_) => Err(ParseError {
                message: ParseMessage::Static("integer out of signed 64-bit range"),
                pos: start,
            }),
        }
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err("nesting depth limit exceeded"));
        }
        Ok(())
    }

    fn parse_array(&mut self) -> Result<CanonValue, ParseError> {
        self.expect(b'[')?;
        self.enter()?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(CanonValue::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
        self.depth -= 1;
        Ok(CanonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<CanonValue, ParseError> {
        self.expect(b'{')?;
        self.enter()?;
        let mut members: Vec<(String, CanonValue)> = Vec::new();
        // Duplicate detection via a key set (O(log n) per key) — a linear scan of `members` per key was
        // quadratic in the key count, so one attacker-supplied wide object stalled the verifier for seconds.
        let mut seen: BTreeSet<String> = BTreeSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            return Ok(CanonValue::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected string key"));
            }
            let key_pos = self.i;
            let key = self.parse_string()?; // already NFC-normalized
                                            // RCP §5: reject duplicate keys, checked AFTER NFC normalization.
            if !seen.insert(key.clone()) {
                return Err(ParseError {
                    message: ParseMessage::DuplicateKey(key),
                    pos: key_pos,
                });
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let val = self.parse_value()?;
            members.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
        self.depth -= 1;
        Ok(CanonValue::Object(members))
    }

    /// Parse a JSON string, decode escapes (rejecting lone surrogates and raw control chars),
    /// and NFC-normalize (RCP §4).
    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut units: Vec<u16> = Vec::new(); // collect UTF-16 to handle surrogate pairs cleanly
        loop {
            let b = self.peek().ok_or_else(|| self.err("unterminated string"))?;
            match b {
                b'"' => {
                    self.i += 1;
                    break;
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => units.push(b'"' as u16),
                        b'\\' => units.push(b'\\' as u16),
                        b'/' => units.push(b'/' as u16),
                        b'b' => units.push(0x08),
                        b'f' => units.push(0x0C),
                        b'n' => units.push(0x0A),
                        b'r' => units.push(0x0D),
                        b't' => units.push(0x09),
                        b'u' => {
                            let u = self.parse_hex4()?;
                            units.push(u);
                        }
                        _ => return Err(self.err("invalid string escape")),
                    }
                }
                0x00..=0x1F => {
                    return Err(self.err("raw control character in string (must be escaped)"));
                }
                _ => {
                    // Copy one UTF-8 scalar value; collect as UTF-16 units.
                    // next_utf8_char advances the cursor past the whole scalar value.
                    let (ch, _len) = self.next_utf8_char()?;
                    let mut buf = [0u16; 2];
                    for u in ch.encode_utf16(&mut buf) {
                        units.push(*u);
                    }
                }
            }
        }
        // Decode the UTF-16 units; a lone surrogate is invalid (RCP §4 — no U+FFFD substitution).
        let s = decode_utf16_strict(&units).map_err(|m| ParseError {
            message: ParseMessage::Static(m),
            pos: self.i,
        })?;
        // NFC normalize (RCP §4), including non-ASCII scalars and combining sequences.
        Ok(nfc(&s))
    }

    fn parse_hex4(&mut self) -> Result<u16, ParseError> {
        if self.i + 4 > self.s.len() {
            return Err(self.err("truncated \\u escape"));
        }
        let mut v: u16 = 0;
        for _ in 0..4 {
            let c = self.s[self.i];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(self.err("invalid hex digit in \\u escape")),
            };
            v = (v << 4) | d as u16;
            self.i += 1;
        }
        Ok(v)
    }

    /// Read one UTF-8 scalar value at the cursor, advancing past it. Returns (char, byte_len).
    fn next_utf8_char(&mut self) -> Result<(char, usize), ParseError> {
        let rest = &self.s[self.i..];
        // Determine length from lead byte, then validate via std.
        let lead = rest[0];
        let len = if lead < 0x80 {
            1
        } else if lead >> 5 == 0b110 {
            2
        } else if lead >> 4 == 0b1110 {
            3
        } else if lead >> 3 == 0b11110 {
            4
        } else {
            return Err(self.err("invalid UTF-8 lead byte in string"));
        };
        if self.i + len > self.s.len() {
            return Err(self.err("truncated UTF-8 sequence in string"));
        }
        let slice = &self.s[self.i..self.i + len];
        let s = std::str::from_utf8(slice).map_err(|_| self.err("invalid UTF-8 in string"))?;
        let ch = s.chars().next().unwrap();
        self.i += len;
        Ok((ch, len))
    }
}

/// Strictly decode a UTF-16 unit sequence; reject unpaired surrogates.
fn decode_utf16_strict(units: &[u16]) -> Result<String, &'static str> {
    let mut out = String::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let u = units[i];
        match u {
            0xD800..=0xDBFF => {
                // high surrogate; need a following low surrogate
                let lo = *units.get(i + 1).ok_or("unpaired high surrogate")?;
                if !(0xDC00..=0xDFFF).contains(&lo) {
                    return Err("high surrogate not followed by low surrogate");
                }
                let c = 0x10000 + (((u as u32 - 0xD800) << 10) | (lo as u32 - 0xDC00));
                out.push(char::from_u32(c).ok_or("invalid scalar value")?);
                i += 2;
            }
            0xDC00..=0xDFFF => return Err("unpaired low surrogate"),
            _ => {
                out.push(char::from_u32(u as u32).ok_or("invalid scalar value")?);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod error_compat_tests {
    use super::*;

    #[test]
    fn public_parser_errors_keep_their_text_and_position() {
        let cases = [
            ("tru", "invalid literal, expected 'true'", 0),
            ("[1", "expected ',' or ']' in array", 2),
            ("{\"x\" 1}", "expected ':'", 5),
            (
                "{\"é\":0,\"e\\u0301\":1}",
                "duplicate object key after NFC normalization: \"é\"",
                8,
            ),
            ("\"\\uD800\"", "unpaired high surrogate", 8),
        ];
        for (input, msg, pos) in cases {
            let err = CanonValue::parse(input).unwrap_err();
            assert_eq!((err.msg.as_str(), err.pos), (msg, pos), "{input}");
        }
    }

    #[test]
    fn real_nfc_normalizes_combining_sequence() {
        assert_eq!(
            CanonValue::parse("\"e\\u0301\"").unwrap(),
            CanonValue::Str("é".into())
        );
    }
}

/// Bounded proofs over this exact code (run by `formal/run-kani.sh`), complementing the unbounded Lean
/// model in `formal/lean/Averin/Canon.lean` (which proves `ser` injective): these check that the Rust
/// serializer and parser really implement that model on small inputs.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// `parse(n.to_string()) == Int(n)` and serialization writes that same spelling back, for every
    /// |n| < 10^5 (the i64 extremes are pinned by the golden vectors).
    #[kani::proof]
    #[kani::unwind(8)]
    fn integer_roundtrip() {
        let n: i64 = kani::any_where(|n: &i64| *n > -100_000 && *n < 100_000);
        let text = n.to_string();
        let v = CanonValue::parse_typed(&text).unwrap();
        assert_eq!(v, CanonValue::Int(n));
        assert_eq!(v.serialize(), text);
    }

    /// No second spelling: every ≤ 4-byte numeric literal the parser accepts is in canonical form
    /// `-?(0|[1-9][0-9]*)` with no `-0` (so `00`, `01`, `-0`, `+1`, fractions and exponents are rejected).
    #[kani::proof]
    #[kani::unwind(6)]
    fn accepted_integer_spelling_is_canonical() {
        let raw: [u8; 4] = kani::any();
        let len: usize = kani::any_where(|l: &usize| *l >= 1 && *l <= 4);
        for b in &raw[..len] {
            kani::assume(b.is_ascii_digit() || matches!(*b, b'-' | b'+' | b'.' | b'e' | b'E'));
        }
        let text = core::str::from_utf8(&raw[..len]).unwrap();
        if let Ok(CanonValue::Int(_)) = CanonValue::parse_typed(text) {
            let digits = text.strip_prefix('-').unwrap_or(text).as_bytes();
            assert!(!digits.is_empty() && digits.iter().all(|b| b.is_ascii_digit()));
            assert!(digits[0] != b'0' || digits.len() == 1, "no leading zero");
            assert!(text != "-0", "no negative zero");
        }
    }

    /// `write_string` is inverted by the parser for every string of ≤ 2 characters drawn from quotes,
    /// backslashes, every C0 control, DEL, and non-ASCII scalars through the real NFC path.
    #[kani::proof]
    #[kani::unwind(16)]
    fn string_escape_roundtrip() {
        let len: usize = kani::any_where(|l: &usize| *l <= 2);
        let mut s = String::new();
        for _ in 0..len {
            let c: char = kani::any();
            kani::assume((c as u32) < 0x80 || c == 'é' || c == '\u{1F600}');
            s.push(c);
        }
        let mut text = String::new();
        write_string(&s, &mut text);
        assert!(
            text.bytes().all(|b| b >= 0x20),
            "no raw control byte may be emitted"
        );
        assert_eq!(CanonValue::parse_typed(&text).unwrap(), CanonValue::Str(s));
    }

    fn utf16_agrees<const N: usize>() {
        let units: [u16; N] = kani::any();
        let mut reference = char::decode_utf16(units.iter().copied());
        match decode_utf16_strict(&units) {
            Ok(s) => {
                for c in s.chars() {
                    assert_eq!(reference.next().map(|r| r.ok()), Some(Some(c)));
                }
                assert!(reference.next().is_none());
            }
            Err(_) => assert!(reference.any(|r| r.is_err())),
        }
    }

    /// `decode_utf16_strict` agrees with the standard library's strict UTF-16 decoder (errors exactly on
    /// a lone surrogate, else yields the same scalars) for every 1- and 2-unit sequence — every
    /// surrogate-pair / lone-surrogate / BMP combination the decoder distinguishes.
    #[kani::proof]
    #[kani::unwind(4)]
    fn utf16_strict_matches_std() {
        utf16_agrees::<1>();
        utf16_agrees::<2>();
    }

    /// A key of one or two symbolic scalars, spelled into a caller buffer (no heap), together with the
    /// reference order key: its UTF-16 code units computed independently of `utf16_cmp`, per scalar, by
    /// `char::encode_utf16`.
    fn key<'a>(buf: &'a mut [u8; 8], units: &mut [u16; 4]) -> (&'a str, usize) {
        let c1: char = kani::any();
        let c2: char = kani::any();
        let two: bool = kani::any();
        let n1 = c1.len_utf8();
        c1.encode_utf8(&mut buf[..4]);
        let mut u = c1.encode_utf16(&mut units[..2]).len();
        let mut n = n1;
        if two {
            let n2 = c2.len_utf8();
            c2.encode_utf8(&mut buf[n1..n1 + 4]);
            u += c2.encode_utf16(&mut units[u..u + 2]).len();
            n += n2;
        }
        // SAFETY: `buf[..n]` is exactly the UTF-8 encoding of one or two scalars written just above
        // (skipping `from_utf8` keeps its validation loop out of the model).
        (unsafe { core::str::from_utf8_unchecked(&buf[..n]) }, u)
    }

    /// Key order is exactly RFC 8785 / RCP §2 order: for every pair of keys of one or two scalars,
    /// `utf16_cmp` equals the lexicographic order of their UTF-16 code units. The order is checked against
    /// that reference (not merely for antisymmetry), and one case is pinned to the BMP-above-surrogates vs
    /// astral region, where UTF-8 byte order and UTF-16 order disagree (U+E000..U+FFFF sorts AFTER every
    /// astral scalar in UTF-16, before it in UTF-8), so a byte-order `utf16_cmp` fails here with a
    /// counterexample rather than an unwinding assertion.
    #[kani::proof]
    #[kani::unwind(10)]
    fn utf16_key_order_is_exact() {
        let (mut ba, mut bb) = ([0u8; 8], [0u8; 8]);
        let (mut ua, mut ub) = ([0u16; 4], [0u16; 4]);
        let (sa, na) = key(&mut ba, &mut ua);
        let (sb, nb) = key(&mut bb, &mut ub);
        assert_eq!(utf16_cmp(sa, sb), ua[..na].cmp(&ub[..nb]));

        // Steered case: a single BMP scalar at or above U+E000 against a single astral scalar.
        let hi: char = kani::any();
        let astral: char = kani::any();
        kani::assume(('\u{E000}'..='\u{FFFF}').contains(&hi) && astral as u32 >= 0x10000);
        let (mut bh, mut bs) = ([0u8; 4], [0u8; 4]);
        let (sh, ss) = (&*hi.encode_utf8(&mut bh), &*astral.encode_utf8(&mut bs));
        assert_eq!(utf16_cmp(sh, ss), Ordering::Greater);
        assert_eq!(utf16_cmp(ss, sh), Ordering::Less);
    }

    /// Key order is transitive (so sorting members is well defined): for any three single-scalar keys,
    /// `a ≤ b` and `b ≤ c` imply `a ≤ c`, and `Equal` holds only between identical keys.
    #[kani::proof]
    #[kani::unwind(6)]
    fn utf16_key_order_is_transitive() {
        let (a, b, c): (char, char, char) = (kani::any(), kani::any(), kani::any());
        let (mut ba, mut bb, mut bc) = ([0u8; 4], [0u8; 4], [0u8; 4]);
        let (sa, sb, sc) = (
            &*a.encode_utf8(&mut ba),
            &*b.encode_utf8(&mut bb),
            &*c.encode_utf8(&mut bc),
        );
        let (ab, bc_, ac) = (utf16_cmp(sa, sb), utf16_cmp(sb, sc), utf16_cmp(sa, sc));
        if ab != Ordering::Greater && bc_ != Ordering::Greater {
            assert!(ac != Ordering::Greater);
        }
        assert_eq!(ab == Ordering::Equal, a == b);
    }

    /// The production parser core never panics on any valid UTF-8 input of ≤ 5 bytes, including
    /// real NFC. Public error text is materialized after this typed result is returned.
    #[kani::proof]
    #[kani::unwind(8)]
    fn parse_never_panics() {
        let raw: [u8; 5] = kani::any();
        let len: usize = kani::any_where(|l: &usize| *l <= 5);
        if let Ok(text) = core::str::from_utf8(&raw[..len]) {
            let _ = CanonValue::parse_typed(text);
        }
    }
}
