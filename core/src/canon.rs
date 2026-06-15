//! Record Canonical Profile (RCP) v1 — the byte-for-byte canonicalization engine.
//!
//! See `/spec/rcp-v1.md`. We deliberately implement our own JSON parse/serialize rather than
//! reuse a lenient library, because RCP requires behaviours general-purpose JSON does not give:
//! post-NFC **duplicate-key rejection**, **lone-surrogate rejection**, **integers only (i64)**,
//! and byte-exact escaping + UTF-16 key ordering. This module is the golden-vector contract;
//! any divergence here is threat #10 (verifier skew).

use core::cmp::Ordering;
use core::fmt;
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

impl CanonValue {
    /// Parse a JSON document under RCP v1 rules. Rejects floats, out-of-range integers,
    /// duplicate keys (post-NFC), lone surrogates, and trailing garbage.
    pub fn parse(input: &str) -> Result<CanonValue, CanonError> {
        let mut p = Parser {
            s: input.as_bytes(),
            i: 0,
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
        for (k, v) in pairs {
            let key = nfc(&k);
            if members.iter().any(|(existing, _)| *existing == key) {
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
    s.nfc().collect()
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

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &str) -> CanonError {
        CanonError {
            msg: msg.to_string(),
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

    fn parse_value(&mut self) -> Result<CanonValue, CanonError> {
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

    fn expect(&mut self, b: u8) -> Result<(), CanonError> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", b as char)))
        }
    }

    fn parse_keyword(&mut self, kw: &str) -> Result<(), CanonError> {
        if self.s[self.i..].starts_with(kw.as_bytes()) {
            self.i += kw.len();
            Ok(())
        } else {
            Err(self.err(&format!("invalid literal, expected '{kw}'")))
        }
    }

    fn parse_bool(&mut self) -> Result<CanonValue, CanonError> {
        if self.peek() == Some(b't') {
            self.parse_keyword("true")?;
            Ok(CanonValue::Bool(true))
        } else {
            self.parse_keyword("false")?;
            Ok(CanonValue::Bool(false))
        }
    }

    fn parse_null(&mut self) -> Result<CanonValue, CanonError> {
        self.parse_keyword("null")?;
        Ok(CanonValue::Null)
    }

    fn parse_number(&mut self) -> Result<CanonValue, CanonError> {
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
        let lexeme = std::str::from_utf8(&self.s[start..self.i]).unwrap();
        // RCP §3: `-0` is not a canonical integer spelling (consistent with rejecting `00`/`01`).
        if lexeme == "-0" {
            return Err(CanonError {
                msg: "negative zero is not a canonical integer".to_string(),
                pos: start,
            });
        }
        match lexeme.parse::<i64>() {
            Ok(n) => Ok(CanonValue::Int(n)),
            Err(_) => Err(CanonError {
                msg: "integer out of signed 64-bit range".to_string(),
                pos: start,
            }),
        }
    }

    fn parse_array(&mut self) -> Result<CanonValue, CanonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
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
        Ok(CanonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<CanonValue, CanonError> {
        self.expect(b'{')?;
        let mut members: Vec<(String, CanonValue)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
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
            if members.iter().any(|(k, _)| *k == key) {
                return Err(CanonError {
                    msg: format!("duplicate object key after NFC normalization: {key:?}"),
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
        Ok(CanonValue::Object(members))
    }

    /// Parse a JSON string, decode escapes (rejecting lone surrogates and raw control chars),
    /// and NFC-normalize (RCP §4).
    fn parse_string(&mut self) -> Result<String, CanonError> {
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
        let s = decode_utf16_strict(&units).map_err(|m| CanonError {
            msg: m,
            pos: self.i,
        })?;
        // NFC normalize (RCP §4).
        Ok(s.nfc().collect())
    }

    fn parse_hex4(&mut self) -> Result<u16, CanonError> {
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
    fn next_utf8_char(&mut self) -> Result<(char, usize), CanonError> {
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
fn decode_utf16_strict(units: &[u16]) -> Result<String, String> {
    let mut out = String::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let u = units[i];
        match u {
            0xD800..=0xDBFF => {
                // high surrogate; need a following low surrogate
                let lo = *units
                    .get(i + 1)
                    .ok_or_else(|| "unpaired high surrogate".to_string())?;
                if !(0xDC00..=0xDFFF).contains(&lo) {
                    return Err("high surrogate not followed by low surrogate".to_string());
                }
                let c = 0x10000 + (((u as u32 - 0xD800) << 10) | (lo as u32 - 0xDC00));
                out.push(char::from_u32(c).ok_or_else(|| "invalid scalar value".to_string())?);
                i += 2;
            }
            0xDC00..=0xDFFF => return Err("unpaired low surrogate".to_string()),
            _ => {
                out.push(
                    char::from_u32(u as u32).ok_or_else(|| "invalid scalar value".to_string())?,
                );
                i += 1;
            }
        }
    }
    Ok(out)
}
