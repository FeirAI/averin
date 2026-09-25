//! Record Canonical Profile (RCP) v1 — the byte-for-byte canonicalization engine.
//!
//! See `/spec/rcp-v1.md`. We deliberately implement our own JSON parse/serialize rather than
//! reuse a lenient library, because RCP requires behaviours general-purpose JSON does not give:
//! post-NFC **duplicate-key rejection**, **lone-surrogate rejection**, **integers only (i64)**,
//! and byte-exact escaping + UTF-16 key ordering. This module is the golden-vector contract;
//! any divergence here is threat #10 (verifier skew).

#[cfg(kani)]
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
        // A number at byte zero cannot start with insignificant whitespace. Route that
        // common top-level case straight to the same number parser used by parse_value.
        // Nested and all other top-level values retain the general dispatcher.
        if input
            .as_bytes()
            .first()
            .is_some_and(|b| *b == b'-' || b.is_ascii_digit())
        {
            let n = p.parse_number()?;
            p.finish_top_level()?;
            return Ok(CanonValue::Int(n));
        }
        let v = parse_top_level_general(&mut p)?;
        p.finish_top_level()?;
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
    ///
    /// Duplicate keys after NFC are a caller invariant violation (use `CanonValue::object`); they are
    /// asserted against in debug builds. The hash/seal paths reject them outright (see
    /// [`write_object`]'s result and `record::hash_body_preimage`).
    pub fn serialize(&self) -> String {
        let mut out = Vec::new();
        let unique = write_canonical(self, &mut out);
        debug_assert!(
            unique,
            "RCP invariant: duplicate object key after NFC in serialize()"
        );
        match String::from_utf8(out) {
            Ok(text) => text,
            // Every byte comes from a `String` (UTF-8) or is ASCII punctuation/escapes.
            Err(_) => panic!("RCP canonical text is always UTF-8"),
        }
    }

    // ---- ergonomic accessors used by record/checkpoint logic ----

    pub fn as_object(&self) -> Option<&Vec<(String, CanonValue)>> {
        match self {
            CanonValue::Object(m) => Some(m),
            _ => None,
        }
    }
    /// The first member whose key equals `key` (byte-for-byte; no normalization).
    pub fn get(&self, key: &str) -> Option<&CanonValue> {
        member(self, key)
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

// ---- the canonical serializer (RCP §2–§5) ----
//
// Written over bytes with explicit loops and no iterator adapters, closures, `str` formatting or
// library sorting, so that `formal/run-production-refinement.sh` extracts exactly this code with
// Charon/Aeneas and proves it against the Lean model (`formal/production`). The only opaque
// operation is `nfc` (the unicode-normalization crate, a stated trust boundary).

/// [`CanonValue::get`], as a free function so the extracted model names it outside the
/// `CanonValue` namespace (whose `Str` constructor would shadow Aeneas' `Str` type).
pub(crate) fn member<'a>(v: &'a CanonValue, key: &str) -> Option<&'a CanonValue> {
    let members = match v {
        CanonValue::Object(m) => m,
        _ => return None,
    };
    let mut i = 0;
    while i < members.len() && members[i].0.as_bytes() != key.as_bytes() {
        i += 1;
    }
    if i < members.len() {
        Some(&members[i].1)
    } else {
        None
    }
}

/// Append the canonical RCP bytes of `v` to `out` (RCP §2–§4). Returns false if some object in `v`
/// has two members whose keys coincide after NFC (RCP §5); the bytes are still written in full, so
/// `serialize` produces the same text as before for every value.
pub(crate) fn write_canonical(v: &CanonValue, out: &mut Vec<u8>) -> bool {
    match v {
        CanonValue::Null => {
            out.extend_from_slice(b"null");
            true
        }
        CanonValue::Bool(b) => {
            if *b {
                out.extend_from_slice(b"true");
            } else {
                out.extend_from_slice(b"false");
            }
            true
        }
        CanonValue::Int(n) => {
            write_int(*n, out);
            true
        }
        CanonValue::Str(s) => {
            escape_into(nfc(s).as_bytes(), out);
            true
        }
        CanonValue::Array(items) => write_array(items, out),
        CanonValue::Object(members) => write_object(members, &[], out),
    }
}

fn write_array(items: &[CanonValue], out: &mut Vec<u8>) -> bool {
    out.push(b'[');
    let mut unique = true;
    let mut i = 0;
    while i < items.len() {
        if i > 0 {
            out.push(b',');
        }
        if !write_canonical(&items[i], out) {
            unique = false;
        }
        i += 1;
    }
    out.push(b']');
    unique
}

/// Append the canonical bytes of the object `members` without the members whose (raw) key is in
/// `strip` (RCP §9.1 strips `content_hash`/`sig` this way). Keys are NFC-normalized here (defense in
/// depth — the hashed bytes are always canonical even if a `CanonValue` was built programmatically
/// without going through `parse`/`object`), then sorted by UTF-16 code unit (RCP §2). Values
/// produced by `parse` are already NFC, so this is idempotent on the signing path. Returns false on
/// a duplicate key after NFC, here or in any nested object.
#[allow(clippy::ptr_arg)]
pub(crate) fn write_object(
    members: &Vec<(String, CanonValue)>,
    strip: &[&str],
    out: &mut Vec<u8>,
) -> bool {
    let mut keep = vec![true; members.len()];
    unmark_stripped(members, strip, 0, &mut keep);
    write_members(members, &keep, out)
}

/// Clear `keep[j]` for every member whose key equals `strip[i..]`. Recursion over the (constant,
/// short) strip list rather than a loop keeps nested `&[&str]` borrows out of loop state.
#[allow(clippy::ptr_arg)]
fn unmark_stripped(
    members: &Vec<(String, CanonValue)>,
    strip: &[&str],
    i: usize,
    keep: &mut [bool],
) {
    if i < strip.len() {
        unmark_key(members, strip[i].as_bytes(), keep);
        unmark_stripped(members, strip, i + 1, keep);
    }
}

// `&Vec`, not a slice, here and in `write_members`/`write_object`: Aeneas cannot yet translate the
// indexed loops below over a slice of pairs.
#[allow(clippy::ptr_arg)]
fn unmark_key(members: &Vec<(String, CanonValue)>, key: &[u8], keep: &mut [bool]) {
    let mut j = 0;
    while j < members.len() {
        if members[j].0.as_bytes() == key {
            keep[j] = false;
        }
        j += 1;
    }
}

#[allow(clippy::ptr_arg)]
fn write_members(members: &Vec<(String, CanonValue)>, keep: &[bool], out: &mut Vec<u8>) -> bool {
    // The kept members, as NFC keys, their UTF-16 sort keys and their member index.
    let mut keys: Vec<String> = Vec::new();
    let mut units: Vec<Vec<u16>> = Vec::new();
    let mut src: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < members.len() {
        if keep[i] {
            let key = nfc(&members[i].0);
            units.push(utf16_units(key.as_bytes()));
            keys.push(key);
            src.push(i);
        }
        i += 1;
    }
    let order = sort_by_units(&units, &positions(units.len()));
    out.push(b'{');
    let mut unique = true;
    let mut n = 0;
    while n < order.len() {
        if n > 0 {
            out.push(b',');
            // Sorted, so a duplicate key is always adjacent to its twin.
            if units[order[n - 1]] == units[order[n]] {
                unique = false;
            }
        }
        escape_into(keys[order[n]].as_bytes(), out);
        out.push(b':');
        if !write_canonical(&members[src[order[n]]].1, out) {
            unique = false;
        }
        n += 1;
    }
    out.push(b'}');
    unique
}

/// `[0, 1, …, n-1]`.
fn positions(n: usize) -> Vec<usize> {
    let mut pos = Vec::with_capacity(n);
    let mut p = 0;
    while p < n {
        pos.push(p);
        p += 1;
    }
    pos
}

/// Stable merge sort of `pos` by `units[pos[_]]` in UTF-16 code-unit order (RFC 8785 §3.2.3 /
/// RCP §2): split at `(len + 1) / 2`, sort both halves, merge preferring the left run on ties.
fn sort_by_units(units: &[Vec<u16>], pos: &[usize]) -> Vec<usize> {
    if pos.len() <= 1 {
        pos.to_vec()
    } else {
        let mid = pos.len() - pos.len() / 2;
        let left = sort_by_units(units, &pos[..mid]);
        let right = sort_by_units(units, &pos[mid..]);
        merge_by_units(units, &left, &right)
    }
}

fn merge_by_units(units: &[Vec<u16>], left: &[usize], right: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(left.len() + right.len());
    let mut i = 0;
    let mut j = 0;
    while i < left.len() || j < right.len() {
        if j == right.len() || (i < left.len() && !units_lt(&units[right[j]], &units[left[i]])) {
            out.push(left[i]);
            i += 1;
        } else {
            out.push(right[j]);
            j += 1;
        }
    }
    out
}

/// Strict lexicographic order on UTF-16 code-unit sequences (a proper prefix sorts first).
fn units_lt(a: &[u16], b: &[u16]) -> bool {
    let n = if a.len() < b.len() { a.len() } else { b.len() };
    let mut i = 0;
    while i < n && a[i] == b[i] {
        i += 1;
    }
    if i < n {
        a[i] < b[i]
    } else {
        a.len() < b.len()
    }
}

/// The UTF-16 code units of UTF-8 text `s` (which is always valid: it comes from a `String`).
fn utf16_units(s: &[u8]) -> Vec<u16> {
    let mut units = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let b0 = s[i] as u32;
        let (cp, width) = if b0 < 0x80 {
            (b0, 1)
        } else if b0 < 0xE0 {
            ((b0 - 0xC0) * 0x40 + (s[i + 1] as u32 - 0x80), 2)
        } else if b0 < 0xF0 {
            (
                (b0 - 0xE0) * 0x1000 + (s[i + 1] as u32 - 0x80) * 0x40 + (s[i + 2] as u32 - 0x80),
                3,
            )
        } else {
            (
                (b0 - 0xF0) * 0x40000
                    + (s[i + 1] as u32 - 0x80) * 0x1000
                    + (s[i + 2] as u32 - 0x80) * 0x40
                    + (s[i + 3] as u32 - 0x80),
                4,
            )
        };
        if cp < 0x10000 {
            units.push(cp as u16);
        } else {
            units.push((0xD800 + (cp - 0x10000) / 0x400) as u16);
            units.push((0xDC00 + (cp - 0x10000) % 0x400) as u16);
        }
        i += width;
    }
    units
}

/// Kani adapter: the order harnesses below drive the production key order through a `&str` API.
#[cfg(kani)]
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    let (ua, ub) = (utf16_units(a.as_bytes()), utf16_units(b.as_bytes()));
    if units_lt(&ua, &ub) {
        Ordering::Less
    } else if units_lt(&ub, &ua) {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

/// Append `n` in shortest decimal, `-` for negatives (RCP §3).
fn write_int(n: i64, out: &mut Vec<u8>) {
    // |n| as u64 without overflow at i64::MIN.
    let mut u: u64 = if n < 0 {
        out.push(b'-');
        (-(n + 1)) as u64 + 1
    } else {
        n as u64
    };
    let mut digits = [0u8; 20];
    let mut k = 20;
    loop {
        k -= 1;
        digits[k] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[k..]);
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

/// Append a JSON string with RCP-minimal escaping (RCP §4). Byte-wise over UTF-8: every byte the
/// table escapes is ASCII, and every byte of a multi-byte scalar is ≥ 0x80 and copied as is, so
/// this is exactly the per-scalar escape.
fn escape_into(s: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x00..=0x1F => {
                out.extend_from_slice(b"\\u00");
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0xF));
            }
            _ => out.push(b),
        }
        i += 1;
    }
    out.push(b'"');
}

/// Kani adapter: the escape harness below drives the production escaper through a `&str`/`String` API.
#[cfg(kani)]
fn write_string(s: &str, out: &mut String) {
    let mut bytes = Vec::new();
    escape_into(s.as_bytes(), &mut bytes);
    out.push_str(core::str::from_utf8(&bytes).unwrap());
}

fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
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

// The top-level nonnumeric route also handles leading whitespace before a value.
// Numeric-first input has no leading whitespace and uses the same parse_number method
// that parse_value would select, so this helper is unreachable for that input domain.
fn parse_top_level_general(p: &mut Parser<'_>) -> Result<CanonValue, ParseError> {
    p.skip_ws();
    p.parse_value()
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

    fn finish_top_level(&mut self) -> Result<(), ParseError> {
        self.skip_ws();
        if self.i != self.s.len() {
            Err(self.err("trailing data after top-level value"))
        } else {
            Ok(())
        }
    }

    fn parse_value(&mut self) -> Result<CanonValue, ParseError> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(CanonValue::Str(self.parse_string()?)),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number().map(CanonValue::Int),
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

    fn parse_number(&mut self) -> Result<i64, ParseError> {
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
            Ok(n) => Ok(n),
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

    // Keep a copy of the prior top-level dispatch as an independent regression oracle for
    // the numeric-first fast path. Both routes call the same production parser methods.
    fn general_top_level_parse(input: &str) -> Result<CanonValue, CanonError> {
        let mut p = Parser {
            source: input,
            s: input.as_bytes(),
            i: 0,
            depth: 0,
        };
        let typed = (|| {
            p.skip_ws();
            let value = p.parse_value()?;
            p.skip_ws();
            if p.i != p.s.len() {
                return Err(p.err("trailing data after top-level value"));
            }
            Ok(value)
        })();
        typed.map_err(ParseError::into_public)
    }

    #[test]
    fn numeric_first_dispatch_matches_general_parser() {
        let check = |input: &str| {
            assert_eq!(
                CanonValue::parse(input),
                general_top_level_parse(input),
                "{input:?}"
            );
        };
        for line in include_str!("../../formal/fuzz/regressions.tsv")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
        {
            let input_hex = line.split('\t').nth(1).expect("fuzz corpus input");
            let bytes = input_hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            check(&String::from_utf8(bytes).unwrap());
        }
        for input in [
            "",
            "0",
            "-0",
            "00",
            "01",
            "-01",
            "-",
            "-x",
            "1.0",
            "1e0",
            "1E",
            "1!",
            "1 2",
            "1\n",
            " 1",
            "\t-2\r",
            "+1",
            "9223372036854775807",
            "9223372036854775808",
            "-9223372036854775808",
            "-9223372036854775809",
            "true",
            "[1]",
            "\"é\"",
            "{\"a\":1}",
        ] {
            check(input);
        }
        for n in [-99_999, -10_000, -100, -1, 0, 1, 9, 10, 100, 99_999] {
            check(&n.to_string());
        }
    }

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

    // Native complement to the key-order proofs' fail-closed growth guard (G1): utf16_units never
    // needs more than its `with_capacity(s.len())` preallocation, and yields std's UTF-16 units.
    #[test]
    fn utf16_units_fit_their_preallocation() {
        let check = |s: &str| {
            let units = utf16_units(s.as_bytes());
            assert!(units.len() <= s.len(), "{s:?}");
            assert_eq!(units, s.encode_utf16().collect::<Vec<u16>>(), "{s:?}");
        };
        let scalars: Vec<char> = (0..=0x10FFFFu32).filter_map(char::from_u32).collect();
        for c in &scalars {
            check(c.encode_utf8(&mut [0; 4]));
        }
        // Pairs over a spread of every width and the BMP/astral boundaries.
        let sample: Vec<char> = scalars
            .iter()
            .copied()
            .step_by(4099)
            .chain([
                '\0',
                '\u{7F}',
                '\u{80}',
                '\u{7FF}',
                '\u{800}',
                '\u{D7FF}',
                '\u{E000}',
                '\u{FFFF}',
                '\u{10000}',
                '\u{10FFFF}',
            ])
            .collect();
        for a in &sample {
            for b in &sample {
                check(&format!("{a}{b}"));
            }
        }
    }
}

/// Bounded proofs over this exact code (run by `formal/run-kani.sh`), complementing the unbounded Lean
/// model in `formal/lean/Averin/Canon.lean` (which proves `ser` injective): these check that the Rust
/// serializer and parser really implement that model on small inputs.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // This guard replaces only the top-level general route in integer harnesses. A proof
    // fails if the real numeric-first dispatcher ever takes it; no successful behavior is
    // supplied. The parser's number scanner and final trailing-data check remain real.
    fn reject_general_in_integer_proof(_: &mut Parser<'_>) -> Result<CanonValue, ParseError> {
        panic!("numeric spelling reached general top-level parser")
    }

    // ---- Fail-closed std-path guards and std-permitted behavior selections ----
    //
    // Each item below replaces a Rust std function only in the named harnesses that attach it
    // with `#[kani::stub]`; `formal/check-kani-success.py` holds the exact per-harness allowlist
    // and `formal/check-kani-shards.py` pins these bodies. See formal/README.md.

    /// A1, a std-permitted behavior selection. `<*const T>::align_offset` documents (Rust
    /// nightly-2026-08-21, the Kani 0.68 toolchain, library/core/src/ptr/const_ptr.rs): "It is
    /// permissible for the implementation to always return `usize::MAX`. Only your algorithm's
    /// performance can depend on getting a usable offset here, not its correctness." Selecting that
    /// answer keeps std's UTF-8 validator on its byte-at-a-time path; its word-at-a-time fast path
    /// (whose result std documents as identical) stays inside the trusted std boundary.
    fn align_offset_usize_max<T>(_: *const T, _: usize) -> usize {
        usize::MAX
    }

    /// G1, a fail-closed std-path guard. std's `Vec::push` (same toolchain,
    /// library/alloc/src/vec/mod.rs) is `if len == self.buf.capacity() { self.buf.grow_one() }`
    /// followed by writing `value` at `len` and setting the length to `len + 1`. This body asserts
    /// (never assumes) that the growth branch is not taken, then runs exactly the non-growth branch,
    /// so a proof passes only if no push on its whole domain would reallocate.
    fn push_without_growth<T, A: std::alloc::Allocator>(v: &mut Vec<T, A>, value: T) {
        let len = v.len();
        assert!(
            len < v.capacity(),
            "Vec::push reached reallocation in a no-growth proof"
        );
        // SAFETY: len < capacity, so slot `len` is allocated and unused; std's non-growth branch.
        unsafe {
            v.as_mut_ptr().add(len).write(value);
            v.set_len(len + 1);
        }
    }

    /// The exact assertion body shared by the original full-domain proof and every exhaustive
    /// decimal-width shard below. Only the input domain changes between harnesses.
    fn integer_roundtrip_case(n: i64) {
        let text = n.to_string();
        // Prove the formatter's first byte before using it to prune impossible parser paths.
        // The parse result and both round-trip equalities remain unconstrained.
        let numeric_prefix = text
            .as_bytes()
            .first()
            .is_some_and(|b| *b == b'-' || b.is_ascii_digit());
        assert!(numeric_prefix, "decimal spelling needs sign or digit");
        kani::assume(numeric_prefix);
        let parsed = CanonValue::parse_typed(&text);
        // The whole typed parse result must be exactly Int(n): an error, another variant or
        // another integer all fail here.
        assert!(matches!(&parsed, Ok(CanonValue::Int(parsed_n)) if *parsed_n == n));
        // Destruction of the harness-owned parse result is outside the property: the assertion
        // above has already read it, and production code never drops it.
        core::mem::forget(parsed);
        // Given that equality, Int(n) is the parsed value; its serialization must restore the
        // exact spelling that was parsed.
        assert!(CanonValue::Int(n).serialize() == text);
    }

    /// `parse(n.to_string()) == Int(n)` and serialization writes that same spelling back, for every
    /// |n| < 10^5 (the i64 extremes are pinned by the golden vectors). This original full-domain
    /// harness remains available for direct verification; CI can instead prove the exact union of
    /// the disjoint shards below, checked by `formal/check-kani-domains.py`.
    #[kani::proof]
    #[kani::stub(parse_top_level_general, reject_general_in_integer_proof)]
    #[kani::stub(<*const u8>::align_offset, align_offset_usize_max)]
    #[kani::unwind(8)]
    fn integer_roundtrip() {
        let n: i64 = kani::any_where(|n: &i64| *n > -100_000 && *n < 100_000);
        integer_roundtrip_case(n);
    }

    macro_rules! integer_roundtrip_shard {
        // The singleton shard is the same n == 0 domain without a symbolic i64 whose
        // formatting path would otherwise remain symbolic to CBMC.
        ($name:ident, u8, zero, 0, 0) => {
            #[kani::proof]
            #[kani::stub(parse_top_level_general, reject_general_in_integer_proof)]
            #[kani::stub(<*const u8>::align_offset, align_offset_usize_max)]
            #[kani::unwind(8)]
            fn $name() {
                integer_roundtrip_case(0);
            }
        };
        ($name:ident, $ty:ty, positive, $lo:expr, $hi:expr) => {
            #[kani::proof]
            #[kani::stub(parse_top_level_general, reject_general_in_integer_proof)]
            #[kani::stub(<*const u8>::align_offset, align_offset_usize_max)]
            #[kani::unwind(8)]
            fn $name() {
                let magnitude: $ty = kani::any_where(|m: &$ty| *m >= $lo && *m <= $hi);
                integer_roundtrip_case(magnitude as i64);
            }
        };
        ($name:ident, $ty:ty, negative, $lo:expr, $hi:expr) => {
            #[kani::proof]
            #[kani::stub(parse_top_level_general, reject_general_in_integer_proof)]
            #[kani::stub(<*const u8>::align_offset, align_offset_usize_max)]
            #[kani::unwind(8)]
            fn $name() {
                let magnitude: $ty = kani::any_where(|m: &$ty| *m >= $lo && *m <= $hi);
                integer_roundtrip_case(-(magnitude as i64));
            }
        };
    }

    // These eleven lines are the proof-domain table parsed by formal/check-kani-domains.py.
    integer_roundtrip_shard!(integer_roundtrip_zero, u8, zero, 0, 0);
    integer_roundtrip_shard!(integer_roundtrip_positive_1, u8, positive, 1, 9);
    integer_roundtrip_shard!(integer_roundtrip_positive_2, u8, positive, 10, 99);
    integer_roundtrip_shard!(integer_roundtrip_positive_3, u16, positive, 100, 999);
    integer_roundtrip_shard!(integer_roundtrip_positive_4, u16, positive, 1000, 9999);
    integer_roundtrip_shard!(integer_roundtrip_positive_5, u32, positive, 10000, 99999);
    integer_roundtrip_shard!(integer_roundtrip_negative_1, u8, negative, 1, 9);
    integer_roundtrip_shard!(integer_roundtrip_negative_2, u8, negative, 10, 99);
    integer_roundtrip_shard!(integer_roundtrip_negative_3, u16, negative, 100, 999);
    integer_roundtrip_shard!(integer_roundtrip_negative_4, u16, negative, 1000, 9999);
    integer_roundtrip_shard!(integer_roundtrip_negative_5, u32, negative, 10000, 99999);

    /// The bytes a numeric spelling harness draws from: digits, sign characters, the fraction
    /// point and both exponent markers.
    fn spelling_byte(b: u8) -> bool {
        b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E')
    }

    /// Exactly the bytes accepted by `spelling_byte`, each once.
    const SPELLING_BYTES: [u8; 15] = *b"0123456789-+.eE";

    /// `SPELLING_BYTES` is exactly the `spelling_byte` alphabet, so the per-first-byte shards
    /// below enumerate every first byte of the original domain.
    #[kani::proof]
    fn spelling_alphabet_is_exact() {
        let any_byte: u8 = kani::any();
        assert_eq!(spelling_byte(any_byte), SPELLING_BYTES.contains(&any_byte));
    }

    /// The assertion body shared by every spelling shard: a `len`-byte literal whose first byte is
    /// `first` and whose other bytes range symbolically over the whole spelling alphabet.
    fn accepted_integer_spelling_case(len: usize, first: u8) {
        let mut raw: [u8; 4] = kani::any();
        for b in &raw[1..] {
            kani::assume(spelling_byte(*b));
        }
        raw[0] = first;
        let bytes = &raw[..len];
        assert!(bytes.iter().all(|b| b.is_ascii()));
        // SAFETY: every byte was just checked to be ASCII, hence valid UTF-8
        // (skipping `from_utf8` keeps its validation loop out of the model).
        let text = unsafe { core::str::from_utf8_unchecked(bytes) };
        let parsed = CanonValue::parse_typed(text);
        if matches!(parsed, Ok(CanonValue::Int(_))) {
            let digits = text.strip_prefix('-').unwrap_or(text).as_bytes();
            assert!(!digits.is_empty() && digits.iter().all(|b| b.is_ascii_digit()));
            assert!(digits[0] != b'0' || digits.len() == 1, "no leading zero");
            assert!(text != "-0", "no negative zero");
        }
        // Destruction of the harness-owned result is outside the property.
        core::mem::forget(parsed);
    }

    /// No second spelling: every ≤ 4-byte numeric literal the parser accepts is in canonical form
    /// `-?(0|[1-9][0-9]*)` with no `-0` (so `00`, `01`, `-0`, `+1`, fractions and exponents are
    /// rejected). The original domain (length 1..=4, every byte in the spelling alphabet) is proved
    /// as the 60 disjoint shards below, one per concrete (length, first byte), so the top-level
    /// dispatch is concrete; `check-kani-shards.py` checks the table covers every pair exactly once.
    macro_rules! spelling_shard {
        ($name:ident, $len:literal, $first:literal) => {
            #[kani::proof]
            #[kani::unwind(16)]
            fn $name() {
                accepted_integer_spelling_case($len, $first);
            }
        };
    }

    // These sixty lines are the proof-domain table parsed by formal/check-kani-shards.py.
    spelling_shard!(accepted_integer_spelling_1_digit_0, 1, b'0');
    spelling_shard!(accepted_integer_spelling_1_digit_1, 1, b'1');
    spelling_shard!(accepted_integer_spelling_1_digit_2, 1, b'2');
    spelling_shard!(accepted_integer_spelling_1_digit_3, 1, b'3');
    spelling_shard!(accepted_integer_spelling_1_digit_4, 1, b'4');
    spelling_shard!(accepted_integer_spelling_1_digit_5, 1, b'5');
    spelling_shard!(accepted_integer_spelling_1_digit_6, 1, b'6');
    spelling_shard!(accepted_integer_spelling_1_digit_7, 1, b'7');
    spelling_shard!(accepted_integer_spelling_1_digit_8, 1, b'8');
    spelling_shard!(accepted_integer_spelling_1_digit_9, 1, b'9');
    spelling_shard!(accepted_integer_spelling_1_minus, 1, b'-');
    spelling_shard!(accepted_integer_spelling_1_plus, 1, b'+');
    spelling_shard!(accepted_integer_spelling_1_dot, 1, b'.');
    spelling_shard!(accepted_integer_spelling_1_e, 1, b'e');
    spelling_shard!(accepted_integer_spelling_1_upper_e, 1, b'E');
    spelling_shard!(accepted_integer_spelling_2_digit_0, 2, b'0');
    spelling_shard!(accepted_integer_spelling_2_digit_1, 2, b'1');
    spelling_shard!(accepted_integer_spelling_2_digit_2, 2, b'2');
    spelling_shard!(accepted_integer_spelling_2_digit_3, 2, b'3');
    spelling_shard!(accepted_integer_spelling_2_digit_4, 2, b'4');
    spelling_shard!(accepted_integer_spelling_2_digit_5, 2, b'5');
    spelling_shard!(accepted_integer_spelling_2_digit_6, 2, b'6');
    spelling_shard!(accepted_integer_spelling_2_digit_7, 2, b'7');
    spelling_shard!(accepted_integer_spelling_2_digit_8, 2, b'8');
    spelling_shard!(accepted_integer_spelling_2_digit_9, 2, b'9');
    spelling_shard!(accepted_integer_spelling_2_minus, 2, b'-');
    spelling_shard!(accepted_integer_spelling_2_plus, 2, b'+');
    spelling_shard!(accepted_integer_spelling_2_dot, 2, b'.');
    spelling_shard!(accepted_integer_spelling_2_e, 2, b'e');
    spelling_shard!(accepted_integer_spelling_2_upper_e, 2, b'E');
    spelling_shard!(accepted_integer_spelling_3_digit_0, 3, b'0');
    spelling_shard!(accepted_integer_spelling_3_digit_1, 3, b'1');
    spelling_shard!(accepted_integer_spelling_3_digit_2, 3, b'2');
    spelling_shard!(accepted_integer_spelling_3_digit_3, 3, b'3');
    spelling_shard!(accepted_integer_spelling_3_digit_4, 3, b'4');
    spelling_shard!(accepted_integer_spelling_3_digit_5, 3, b'5');
    spelling_shard!(accepted_integer_spelling_3_digit_6, 3, b'6');
    spelling_shard!(accepted_integer_spelling_3_digit_7, 3, b'7');
    spelling_shard!(accepted_integer_spelling_3_digit_8, 3, b'8');
    spelling_shard!(accepted_integer_spelling_3_digit_9, 3, b'9');
    spelling_shard!(accepted_integer_spelling_3_minus, 3, b'-');
    spelling_shard!(accepted_integer_spelling_3_plus, 3, b'+');
    spelling_shard!(accepted_integer_spelling_3_dot, 3, b'.');
    spelling_shard!(accepted_integer_spelling_3_e, 3, b'e');
    spelling_shard!(accepted_integer_spelling_3_upper_e, 3, b'E');
    spelling_shard!(accepted_integer_spelling_4_digit_0, 4, b'0');
    spelling_shard!(accepted_integer_spelling_4_digit_1, 4, b'1');
    spelling_shard!(accepted_integer_spelling_4_digit_2, 4, b'2');
    spelling_shard!(accepted_integer_spelling_4_digit_3, 4, b'3');
    spelling_shard!(accepted_integer_spelling_4_digit_4, 4, b'4');
    spelling_shard!(accepted_integer_spelling_4_digit_5, 4, b'5');
    spelling_shard!(accepted_integer_spelling_4_digit_6, 4, b'6');
    spelling_shard!(accepted_integer_spelling_4_digit_7, 4, b'7');
    spelling_shard!(accepted_integer_spelling_4_digit_8, 4, b'8');
    spelling_shard!(accepted_integer_spelling_4_digit_9, 4, b'9');
    spelling_shard!(accepted_integer_spelling_4_minus, 4, b'-');
    spelling_shard!(accepted_integer_spelling_4_plus, 4, b'+');
    spelling_shard!(accepted_integer_spelling_4_dot, 4, b'.');
    spelling_shard!(accepted_integer_spelling_4_e, 4, b'e');
    spelling_shard!(accepted_integer_spelling_4_upper_e, 4, b'E');

    /// Character classes of the string domain: any ASCII scalar (the symbolic byte), U+00E9 (a
    /// two-byte NFC-stable scalar with a canonical decomposition) and U+1F600 (a four-byte
    /// astral scalar encoded as a surrogate pair by `\u` escapes).
    const STRING_CLASSES: [u8; 3] = [0, 1, 2];

    fn string_escape_case(classes: &[u8], ascii: &[u8; 2]) {
        let mut s = String::new();
        for (class, a) in classes.iter().zip(ascii) {
            match class {
                0 => s.push(*a as char),
                1 => s.push('é'),
                _ => s.push('\u{1F600}'),
            }
        }
        let mut text = String::new();
        write_string(&s, &mut text);
        assert!(
            text.bytes().all(|b| b >= 0x20),
            "no raw control byte may be emitted"
        );
        let parsed = CanonValue::parse_typed(&text);
        assert!(matches!(&parsed, Ok(CanonValue::Str(parsed_s)) if *parsed_s == s));
        // Destruction of the harness-owned result is outside the property.
        core::mem::forget(parsed);
    }

    /// `write_string` is inverted by the real parser (including real NFC) for every string of at
    /// most two scalars, each any ASCII scalar (quotes, backslash, every C0 control, DEL, ...),
    /// U+00E9 or U+1F600. Length and class pattern range over all 13 cases one concrete case at a
    /// time; the ASCII scalars stay symbolic.
    #[kani::proof]
    #[kani::unwind(16)]
    fn string_escape_roundtrip() {
        let ascii: [u8; 2] = kani::any();
        kani::assume(ascii.iter().all(|a| *a < 0x80));
        string_escape_case(&[], &ascii);
        for first in STRING_CLASSES {
            string_escape_case(&[first], &ascii);
            for second in STRING_CLASSES {
                string_escape_case(&[first, second], &ascii);
            }
        }
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
    #[kani::solver(kissat)]
    #[kani::unwind(4)]
    fn utf16_strict_matches_std() {
        utf16_agrees::<1>();
        utf16_agrees::<2>();
    }

    /// A key of exactly `count` (1 or 2) symbolic scalars, spelled into a caller buffer, together with
    /// the reference order key: its UTF-16 code units computed independently of `utf16_cmp`, per
    /// scalar, by `char::encode_utf16`.
    fn key<'a>(count: usize, buf: &'a mut [u8; 8], units: &mut [u16; 4]) -> (&'a str, usize) {
        let c1: char = kani::any();
        let n1 = c1.len_utf8();
        c1.encode_utf8(&mut buf[..4]);
        let mut u = c1.encode_utf16(&mut units[..2]).len();
        let mut n = n1;
        if count == 2 {
            let c2: char = kani::any();
            let n2 = c2.len_utf8();
            c2.encode_utf8(&mut buf[n1..n1 + 4]);
            u += c2.encode_utf16(&mut units[u..u + 2]).len();
            n += n2;
        }
        // SAFETY: `buf[..n]` is exactly the UTF-8 encoding of the scalars written just above
        // (skipping `from_utf8` keeps its validation loop out of the model).
        (unsafe { core::str::from_utf8_unchecked(&buf[..n]) }, u)
    }

    /// The assertion body shared by the four scalar-count shards of `utf16_key_order_is_exact`.
    fn utf16_key_order_exact_case(count_a: usize, count_b: usize) {
        let (mut ba, mut bb) = ([0u8; 8], [0u8; 8]);
        let (mut ua, mut ub) = ([0u16; 4], [0u16; 4]);
        let (sa, na) = key(count_a, &mut ba, &mut ua);
        let (sb, nb) = key(count_b, &mut bb, &mut ub);
        assert_eq!(utf16_cmp(sa, sb), ua[..na].cmp(&ub[..nb]));
    }

    /// Key order is exactly RFC 8785 / RCP §2 order: for every pair of keys of one or two scalars,
    /// `utf16_cmp` equals the lexicographic order of their UTF-16 code units. The order is checked
    /// against that reference (not merely for antisymmetry). The original domain (each key one or two
    /// arbitrary scalars) is proved as four disjoint shards, one per concrete pair of scalar counts,
    /// plus the steered harness below; `check-kani-shards.py` checks that exact partition.
    macro_rules! key_order_shard {
        ($name:ident, $count_a:literal, $count_b:literal) => {
            #[kani::proof]
            #[kani::stub(std::vec::Vec::push, push_without_growth)]
            #[kani::unwind(6)]
            fn $name() {
                utf16_key_order_exact_case($count_a, $count_b);
            }
        };
    }

    // These four lines are the proof-domain table parsed by formal/check-kani-shards.py.
    key_order_shard!(utf16_key_order_is_exact_1_1, 1, 1);
    key_order_shard!(utf16_key_order_is_exact_1_2, 1, 2);
    key_order_shard!(utf16_key_order_is_exact_2_1, 2, 1);
    key_order_shard!(utf16_key_order_is_exact_2_2, 2, 2);

    /// The steered conjunct of `utf16_key_order_is_exact`: a single BMP scalar at or above U+E000
    /// against a single astral scalar, where UTF-8 byte order and UTF-16 order disagree (U+E000..U+FFFF
    /// sorts AFTER every astral scalar in UTF-16, before it in UTF-8), so a byte-order `utf16_cmp`
    /// fails here with a counterexample rather than an unwinding assertion.
    #[kani::proof]
    #[kani::stub(std::vec::Vec::push, push_without_growth)]
    #[kani::unwind(6)]
    fn utf16_key_order_is_exact_steered() {
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
    #[kani::stub(std::vec::Vec::push, push_without_growth)]
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
            let parsed = CanonValue::parse_typed(text);
            // Destruction of the harness-owned result is outside the property.
            core::mem::forget(parsed);
        }
    }
}
