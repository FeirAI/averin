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

impl CanonValue {
    /// Parse a JSON document under RCP v1 rules. Rejects floats, out-of-range integers,
    /// duplicate keys (post-NFC), lone surrogates, and trailing garbage.
    pub fn parse(input: &str) -> Result<CanonValue, CanonError> {
        parse_document(input).map_err(ParseFault::into_error)
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
    s.nfc().collect()
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

// ---- the parser (RCP §1–§5) ----
//
// Written, like the serializer, in the subset that `formal/run-production-refinement.sh` extracts with
// Charon/Aeneas: the cursor is an explicit byte index, loops keep their outcome in state variables
// instead of returning early, and a failure is a `ParseFault` that `CanonValue::parse` renders into a
// `CanonError` only at the public boundary. `formal/production` proves that `parse_document` returns
// (a value or a `ParseFault`) for every input: no panic, overflow or out-of-bounds index, and it
// terminates. The only opaque call is `nfc`.

/// Why the parser stopped; `message` is the public `CanonError` text.
pub(crate) enum ParseError {
    TrailingData,
    UnexpectedChar,
    UnexpectedEnd,
    LiteralTrue,
    LiteralFalse,
    LiteralNull,
    MissingDigits,
    Fraction,
    Exponent,
    NegativeZero,
    OutOfRange,
    DepthLimit,
    ArrayDelimiter,
    ExpectedKey,
    ObjectDelimiter,
    UnterminatedString,
    UnterminatedEscape,
    InvalidEscape,
    RawControl,
    TruncatedUnicodeEscape,
    InvalidHexDigit,
    Utf8Lead,
    Utf8Truncated,
    Utf8Invalid,
    UnpairedHigh,
    HighNotLow,
    InvalidScalar,
    UnpairedLow,
}

impl ParseError {
    fn message(&self) -> &'static str {
        match self {
            ParseError::TrailingData => "trailing data after top-level value",
            ParseError::UnexpectedChar => "unexpected character",
            ParseError::UnexpectedEnd => "unexpected end of input",
            ParseError::LiteralTrue => "invalid literal, expected 'true'",
            ParseError::LiteralFalse => "invalid literal, expected 'false'",
            ParseError::LiteralNull => "invalid literal, expected 'null'",
            ParseError::MissingDigits => "invalid number: missing integer digits",
            ParseError::Fraction => "floating-point not allowed in RCP (use integer micros)",
            ParseError::Exponent => "exponent not allowed in RCP (integers only)",
            ParseError::NegativeZero => "negative zero is not a canonical integer",
            ParseError::OutOfRange => "integer out of signed 64-bit range",
            ParseError::DepthLimit => "nesting depth limit exceeded",
            ParseError::ArrayDelimiter => "expected ',' or ']' in array",
            ParseError::ExpectedKey => "expected string key",
            ParseError::ObjectDelimiter => "expected ',' or '}' in object",
            ParseError::UnterminatedString => "unterminated string",
            ParseError::UnterminatedEscape => "unterminated escape",
            ParseError::InvalidEscape => "invalid string escape",
            ParseError::RawControl => "raw control character in string (must be escaped)",
            ParseError::TruncatedUnicodeEscape => "truncated \\u escape",
            ParseError::InvalidHexDigit => "invalid hex digit in \\u escape",
            ParseError::Utf8Lead => "invalid UTF-8 lead byte in string",
            ParseError::Utf8Truncated => "truncated UTF-8 sequence in string",
            ParseError::Utf8Invalid => "invalid UTF-8 in string",
            ParseError::UnpairedHigh => "unpaired high surrogate",
            ParseError::HighNotLow => "high surrogate not followed by low surrogate",
            ParseError::InvalidScalar => "invalid scalar value",
            ParseError::UnpairedLow => "unpaired low surrogate",
        }
    }
}

/// A parse failure and its byte offset.
pub(crate) enum ParseFault {
    At(ParseError, usize),
    /// `expected '<byte>'`.
    Expected(u8, usize),
    /// A key equal after NFC to an earlier key of the same object (RCP §5), at its opening quote.
    DuplicateKey(String, usize),
}

impl ParseFault {
    fn into_error(self) -> CanonError {
        match self {
            ParseFault::At(e, pos) => CanonError {
                msg: e.message().to_string(),
                pos,
            },
            ParseFault::Expected(b, pos) => CanonError {
                msg: format!("expected '{}'", b as char),
                pos,
            },
            ParseFault::DuplicateKey(key, pos) => CanonError {
                msg: format!("duplicate object key after NFC normalization: {key:?}"),
                pos,
            },
        }
    }
}

/// [`CanonValue::parse`] before rendering the error: one value, surrounded by optional whitespace.
pub(crate) fn parse_document(input: &str) -> Result<CanonValue, ParseFault> {
    let s = input.as_bytes();
    let i = skip_ws(s, 0);
    match parse_value(s, i, 0) {
        Ok((v, j)) => {
            let k = skip_ws(s, j);
            if k != s.len() {
                Err(ParseFault::At(ParseError::TrailingData, k))
            } else {
                Ok(v)
            }
        }
        Err(e) => Err(e),
    }
}

fn is_ws(b: u8) -> bool {
    // RCP/JSON insignificant whitespace: space, tab, LF, CR.
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

#[allow(clippy::manual_is_ascii_check)] // `u8::is_ascii_digit` is not in the extracted subset
fn is_digit(b: u8) -> bool {
    matches!(b, b'0'..=b'9')
}

/// Whether the byte at `i` exists and is `b`.
fn at(s: &[u8], i: usize, b: u8) -> bool {
    i < s.len() && s[i] == b
}

fn skip_ws(s: &[u8], i: usize) -> usize {
    let mut i = i;
    while i < s.len() && is_ws(s[i]) {
        i += 1;
    }
    i
}

fn expect(s: &[u8], i: usize, b: u8) -> Result<usize, ParseFault> {
    if at(s, i, b) {
        Ok(i + 1)
    } else {
        Err(ParseFault::Expected(b, i))
    }
}

/// The value starting at `i`, and the offset just past it. `depth` counts the enclosing arrays and
/// objects.
fn parse_value(s: &[u8], i: usize, depth: usize) -> Result<(CanonValue, usize), ParseFault> {
    if i >= s.len() {
        return Err(ParseFault::At(ParseError::UnexpectedEnd, i));
    }
    let b = s[i];
    if b == b'{' {
        parse_object(s, i, depth)
    } else if b == b'[' {
        parse_array(s, i, depth)
    } else if b == b'"' {
        match parse_string(s, i) {
            Ok((t, j)) => Ok((CanonValue::Str(t), j)),
            Err(e) => Err(e),
        }
    } else if b == b't' {
        parse_literal(
            s,
            i,
            b"true",
            ParseError::LiteralTrue,
            CanonValue::Bool(true),
        )
    } else if b == b'f' {
        parse_literal(
            s,
            i,
            b"false",
            ParseError::LiteralFalse,
            CanonValue::Bool(false),
        )
    } else if b == b'n' {
        parse_literal(s, i, b"null", ParseError::LiteralNull, CanonValue::Null)
    } else if b == b'-' || is_digit(b) {
        parse_number(s, i)
    } else {
        Err(ParseFault::At(ParseError::UnexpectedChar, i))
    }
}

fn parse_literal(
    s: &[u8],
    i: usize,
    kw: &[u8],
    err: ParseError,
    v: CanonValue,
) -> Result<(CanonValue, usize), ParseFault> {
    // `s[i..].starts_with(kw)`, for `i <= s.len()`.
    let mut k = 0;
    if s.len() - i >= kw.len() {
        while k < kw.len() && s[i + k] == kw[k] {
            k += 1;
        }
    }
    if k == kw.len() {
        Ok((v, i + k))
    } else {
        Err(ParseFault::At(err, i))
    }
}

fn parse_number(s: &[u8], start: usize) -> Result<(CanonValue, usize), ParseFault> {
    let mut i = start;
    let negative = at(s, i, b'-');
    if negative {
        i += 1;
    }
    let digits = i;
    // integer part: 0 alone, or [1-9][0-9]*  (JSON grammar; no leading zeros)
    if at(s, i, b'0') {
        i += 1;
    } else if i < s.len() && is_digit(s[i]) {
        i += 1;
        while i < s.len() && is_digit(s[i]) {
            i += 1;
        }
    } else {
        return Err(ParseFault::At(ParseError::MissingDigits, i));
    }
    // RCP §3: floats are forbidden. A fraction or exponent here is a hard error.
    if at(s, i, b'.') {
        return Err(ParseFault::At(ParseError::Fraction, i));
    }
    if at(s, i, b'e') || at(s, i, b'E') {
        return Err(ParseFault::At(ParseError::Exponent, i));
    }
    // RCP §3: `-0` is not a canonical integer spelling (consistent with rejecting `00`/`01`).
    if negative && i - digits == 1 && s[digits] == b'0' {
        return Err(ParseFault::At(ParseError::NegativeZero, start));
    }
    match decimal_i64(s, digits, i, negative) {
        Some(n) => Ok((CanonValue::Int(n), i)),
        None => Err(ParseFault::At(ParseError::OutOfRange, start)),
    }
}

/// The integer spelled by the ASCII digits `s[from..to]`, negated if `negative`, or `None` outside
/// the signed 64-bit range (what `str::parse::<i64>` returns for `-?digits`).
fn decimal_i64(s: &[u8], from: usize, to: usize, negative: bool) -> Option<i64> {
    // The magnitude, bounded by the sign's limit (|i64::MIN| = i64::MAX + 1).
    let limit: u64 = if negative {
        9_223_372_036_854_775_808
    } else {
        9_223_372_036_854_775_807
    };
    let mut mag: u64 = 0;
    let mut in_range = true;
    let mut k = from;
    while k < to {
        let d = (s[k] - b'0') as u64;
        if mag > (limit - d) / 10 {
            in_range = false;
        } else {
            mag = mag * 10 + d;
        }
        k += 1;
    }
    if !in_range {
        None
    } else if !negative {
        Some(mag as i64)
    } else if mag == limit {
        Some(i64::MIN)
    } else {
        Some(-(mag as i64))
    }
}

fn parse_array(s: &[u8], i: usize, depth: usize) -> Result<(CanonValue, usize), ParseFault> {
    let mut i = expect(s, i, b'[')?;
    if depth >= MAX_DEPTH {
        return Err(ParseFault::At(ParseError::DepthLimit, i));
    }
    let mut items = Vec::new();
    i = skip_ws(s, i);
    if at(s, i, b']') {
        return Ok((CanonValue::Array(items), i + 1));
    }
    let mut fault = None;
    let mut open = true;
    while open {
        i = skip_ws(s, i);
        match parse_value(s, i, depth + 1) {
            Ok((v, j)) => {
                items.push(v);
                i = skip_ws(s, j);
                if at(s, i, b',') {
                    i += 1;
                } else if at(s, i, b']') {
                    i += 1;
                    open = false;
                } else {
                    fault = Some(ParseFault::At(ParseError::ArrayDelimiter, i));
                    open = false;
                }
            }
            Err(e) => {
                fault = Some(e);
                open = false;
            }
        }
    }
    match fault {
        Some(e) => Err(e),
        None => Ok((CanonValue::Array(items), i)),
    }
}

fn parse_object(s: &[u8], i: usize, depth: usize) -> Result<(CanonValue, usize), ParseFault> {
    let mut i = expect(s, i, b'{')?;
    if depth >= MAX_DEPTH {
        return Err(ParseFault::At(ParseError::DepthLimit, i));
    }
    let mut members: Vec<(String, CanonValue)> = Vec::new();
    i = skip_ws(s, i);
    if at(s, i, b'}') {
        return Ok((CanonValue::Object(members), i + 1));
    }
    // Every key parsed so far (already NFC-normalized), in input order: its bytes widened to `u16`
    // (a sort key for `sort_by_units`; only equality matters here), the offset of its opening quote
    // and its text, for the duplicate check below.
    let mut units: Vec<Vec<u16>> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let mut fault = None;
    let mut open = true;
    while open {
        i = skip_ws(s, i);
        if !at(s, i, b'"') {
            fault = Some(ParseFault::At(ParseError::ExpectedKey, i));
            open = false;
        } else {
            let key_pos = i;
            match parse_string(s, i) {
                Ok((key, j)) => {
                    units.push(widen(key.as_bytes()));
                    starts.push(key_pos);
                    keys.push(key.clone());
                    i = skip_ws(s, j);
                    match expect(s, i, b':') {
                        Ok(j) => {
                            i = skip_ws(s, j);
                            match parse_value(s, i, depth + 1) {
                                Ok((v, j)) => {
                                    members.push((key, v));
                                    i = skip_ws(s, j);
                                    if at(s, i, b',') {
                                        i += 1;
                                    } else if at(s, i, b'}') {
                                        i += 1;
                                        open = false;
                                    } else {
                                        fault =
                                            Some(ParseFault::At(ParseError::ObjectDelimiter, i));
                                        open = false;
                                    }
                                }
                                Err(e) => {
                                    fault = Some(e);
                                    open = false;
                                }
                            }
                        }
                        Err(e) => {
                            fault = Some(e);
                            open = false;
                        }
                    }
                }
                Err(e) => {
                    fault = Some(e);
                    open = false;
                }
            }
        }
    }
    // RCP §5: a key equal after NFC to an earlier key is rejected, at its opening quote. The first
    // such key is found once the loop stops (`first_repeat`, O(n log n)); it precedes every later
    // fault, so reporting it first is what stopping at it would report.
    let dup = first_repeat(&units);
    if dup < units.len() {
        return Err(ParseFault::DuplicateKey(keys[dup].clone(), starts[dup]));
    }
    match fault {
        Some(e) => Err(e),
        None => Ok((CanonValue::Object(members), i)),
    }
}

/// The least index whose key equals an earlier key, or `units.len()` if the keys are distinct.
/// `sort_by_units` is stable, so in each run of equal keys the positions increase and every one but
/// the first repeats an earlier key.
#[allow(clippy::ptr_arg)]
fn first_repeat(units: &Vec<Vec<u16>>) -> usize {
    let order = sort_by_units(units, &positions(units.len()));
    let mut first = units.len();
    let mut n = 1;
    while n < order.len() {
        if units[order[n - 1]] == units[order[n]] && order[n] < first {
            first = order[n];
        }
        n += 1;
    }
    first
}

/// `s`, one `u16` per byte: equal exactly when the byte strings are equal.
fn widen(s: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        out.push(s[i] as u16);
        i += 1;
    }
    out
}

/// Parse a JSON string, decode escapes (rejecting lone surrogates and raw control chars),
/// and NFC-normalize (RCP §4).
fn parse_string(s: &[u8], i: usize) -> Result<(String, usize), ParseFault> {
    let mut i = expect(s, i, b'"')?;
    let mut units: Vec<u16> = Vec::new(); // collect UTF-16 to handle surrogate pairs cleanly
    let mut fault = None;
    let mut open = true;
    while open {
        if i >= s.len() {
            fault = Some(ParseFault::At(ParseError::UnterminatedString, i));
            open = false;
        } else {
            let b = s[i];
            if b == b'"' {
                i += 1;
                open = false;
            } else if b == b'\\' {
                i += 1;
                if i >= s.len() {
                    fault = Some(ParseFault::At(ParseError::UnterminatedEscape, i));
                    open = false;
                } else {
                    let e = s[i];
                    i += 1;
                    if e == b'u' {
                        match parse_hex4(s, i) {
                            Ok((u, j)) => {
                                units.push(u);
                                i = j;
                            }
                            Err(f) => {
                                fault = Some(f);
                                open = false;
                            }
                        }
                    } else {
                        let u = short_escape(e);
                        if u < 0x80 {
                            units.push(u);
                        } else {
                            fault = Some(ParseFault::At(ParseError::InvalidEscape, i));
                            open = false;
                        }
                    }
                }
            } else if b < 0x20 {
                fault = Some(ParseFault::At(ParseError::RawControl, i));
                open = false;
            } else {
                // One UTF-8 scalar value, collected as UTF-16 units.
                match next_utf8_char(s, i) {
                    Ok((c, len)) => {
                        push_utf16(&mut units, c);
                        i += len;
                    }
                    Err(f) => {
                        fault = Some(f);
                        open = false;
                    }
                }
            }
        }
    }
    if let Some(f) = fault {
        return Err(f);
    }
    // Decode the UTF-16 units; a lone surrogate is invalid (RCP §4 — no U+FFFD substitution).
    match decode_utf16_strict(&units) {
        // NFC normalize (RCP §4). Through `nfc` (not `s.nfc()` inline) so the Kani harnesses can stub
        // the Unicode tables and check the escape decoder itself.
        Ok(t) => Ok((nfc(&t), i)),
        Err(e) => Err(ParseFault::At(e, i)),
    }
}

/// The code unit of a one-character escape `\e`, or `0xFFFF` if `e` is not one.
fn short_escape(e: u8) -> u16 {
    match e {
        b'"' => 0x22,
        b'\\' => 0x5C,
        b'/' => 0x2F,
        b'b' => 0x08,
        b'f' => 0x0C,
        b'n' => 0x0A,
        b'r' => 0x0D,
        b't' => 0x09,
        _ => 0xFFFF,
    }
}

/// The value of a hex digit, or 16 if `c` is not one.
fn hex_value(c: u8) -> u16 {
    match c {
        b'0'..=b'9' => (c - b'0') as u16,
        b'a'..=b'f' => (c - b'a' + 10) as u16,
        b'A'..=b'F' => (c - b'A' + 10) as u16,
        _ => 16,
    }
}

/// The four hex digits of a `\u` escape at `i` (`i <= s.len()`), and the offset past them.
fn parse_hex4(s: &[u8], i: usize) -> Result<(u16, usize), ParseFault> {
    if s.len() - i < 4 {
        return Err(ParseFault::At(ParseError::TruncatedUnicodeEscape, i));
    }
    let d0 = hex_value(s[i]);
    if d0 > 15 {
        return Err(ParseFault::At(ParseError::InvalidHexDigit, i));
    }
    let d1 = hex_value(s[i + 1]);
    if d1 > 15 {
        return Err(ParseFault::At(ParseError::InvalidHexDigit, i + 1));
    }
    let d2 = hex_value(s[i + 2]);
    if d2 > 15 {
        return Err(ParseFault::At(ParseError::InvalidHexDigit, i + 2));
    }
    let d3 = hex_value(s[i + 3]);
    if d3 > 15 {
        return Err(ParseFault::At(ParseError::InvalidHexDigit, i + 3));
    }
    Ok((d0 * 0x1000 + d1 * 0x100 + d2 * 0x10 + d3, i + 4))
}

/// Read one UTF-8 scalar value at `i < s.len()`. Returns (scalar, byte_len).
fn next_utf8_char(s: &[u8], i: usize) -> Result<(u32, usize), ParseFault> {
    // Determine length from lead byte, then validate.
    let lead = s[i];
    let len = if lead < 0x80 {
        1
    } else if lead >> 5 == 0b110 {
        2
    } else if lead >> 4 == 0b1110 {
        3
    } else if lead >> 3 == 0b11110 {
        4
    } else {
        return Err(ParseFault::At(ParseError::Utf8Lead, i));
    };
    if s.len() - i < len {
        return Err(ParseFault::At(ParseError::Utf8Truncated, i));
    }
    match utf8_scalar(s, i, len) {
        Some(c) => Ok((c, len)),
        None => Err(ParseFault::At(ParseError::Utf8Invalid, i)),
    }
}

fn is_continuation(b: u8) -> bool {
    matches!(b, 0x80..=0xBF)
}

/// The scalar value of `s[i..i + len]` if it is exactly one well-formed UTF-8 sequence (Unicode
/// Table 3-7: what `str::from_utf8` accepts), given its lead byte `s[i]` announces `len` bytes and
/// `i + len <= s.len()`.
fn utf8_scalar(s: &[u8], i: usize, len: usize) -> Option<u32> {
    let b0 = s[i] as u32;
    if len == 1 {
        return Some(b0);
    }
    let b1 = s[i + 1];
    if len == 2 {
        if b0 >= 0xC2 && is_continuation(b1) {
            return Some((b0 - 0xC0) * 0x40 + (b1 as u32 - 0x80));
        }
        return None;
    }
    let b2 = s[i + 2];
    // The second byte's range depends on the lead (no overlongs, surrogates or scalars > U+10FFFF).
    let lo: u8 = if b0 == 0xE0 {
        0xA0
    } else if b0 == 0xF0 {
        0x90
    } else {
        0x80
    };
    let hi: u8 = if b0 == 0xED {
        0x9F
    } else if b0 == 0xF4 {
        0x8F
    } else {
        0xBF
    };
    if b1 < lo || b1 > hi || !is_continuation(b2) {
        return None;
    }
    if len == 3 {
        return Some((b0 - 0xE0) * 0x1000 + (b1 as u32 - 0x80) * 0x40 + (b2 as u32 - 0x80));
    }
    let b3 = s[i + 3];
    if b0 > 0xF4 || !is_continuation(b3) {
        return None;
    }
    Some(
        (b0 - 0xF0) * 0x40000
            + (b1 as u32 - 0x80) * 0x1000
            + (b2 as u32 - 0x80) * 0x40
            + (b3 as u32 - 0x80),
    )
}

/// Append the UTF-16 code units of the scalar value `c`.
fn push_utf16(units: &mut Vec<u16>, c: u32) {
    if c < 0x10000 {
        units.push(c as u16);
    } else {
        units.push((0xD800 + (c - 0x10000) / 0x400) as u16);
        units.push((0xDC00 + (c - 0x10000) % 0x400) as u16);
    }
}

/// Append the UTF-8 encoding of the scalar value `c`.
fn push_utf8(out: &mut Vec<u8>, c: u32) {
    if c < 0x80 {
        out.push(c as u8);
    } else if c < 0x800 {
        out.push((0xC0 + c / 0x40) as u8);
        out.push((0x80 + c % 0x40) as u8);
    } else if c < 0x10000 {
        out.push((0xE0 + c / 0x1000) as u8);
        out.push((0x80 + c / 0x40 % 0x40) as u8);
        out.push((0x80 + c % 0x40) as u8);
    } else {
        out.push((0xF0 + c / 0x40000) as u8);
        out.push((0x80 + c / 0x1000 % 0x40) as u8);
        out.push((0x80 + c / 0x40 % 0x40) as u8);
        out.push((0x80 + c % 0x40) as u8);
    }
}

/// Strictly decode a UTF-16 unit sequence; reject unpaired surrogates.
#[allow(clippy::manual_range_contains)] // range `contains` is not in the extracted subset
fn decode_utf16_strict(units: &[u16]) -> Result<String, ParseError> {
    let mut out: Vec<u8> = Vec::with_capacity(units.len());
    let mut fault = ParseError::InvalidScalar;
    let mut ok = true;
    let mut i = 0;
    while ok && i < units.len() {
        let u = units[i] as u32;
        if u >= 0xD800 && u <= 0xDBFF {
            // high surrogate; need a following low surrogate
            if i + 1 >= units.len() {
                fault = ParseError::UnpairedHigh;
                ok = false;
            } else {
                let lo = units[i + 1] as u32;
                if lo < 0xDC00 || lo > 0xDFFF {
                    fault = ParseError::HighNotLow;
                    ok = false;
                } else {
                    push_utf8(&mut out, 0x10000 + (u - 0xD800) * 0x400 + (lo - 0xDC00));
                    i += 2;
                }
            }
        } else if u >= 0xDC00 && u <= 0xDFFF {
            fault = ParseError::UnpairedLow;
            ok = false;
        } else {
            push_utf8(&mut out, u);
            i += 1;
        }
    }
    if !ok {
        return Err(fault);
    }
    // Always valid: every scalar was encoded above (the original `String::push` could not fail either).
    match String::from_utf8(out) {
        Ok(t) => Ok(t),
        Err(_) => Err(ParseError::InvalidScalar),
    }
}

/// Bounded proofs over this exact code (run by `formal/run-kani.sh`), complementing the unbounded Lean
/// model in `formal/lean/Averin/Canon.lean` (which proves `ser` injective): these check that the Rust
/// serializer and parser really implement that model on small inputs.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn nfc_identity(s: &str) -> String {
        s.to_string()
    }

    /// `parse(n.to_string()) == Int(n)` and serialization writes that same spelling back, for every
    /// |n| < 10^5 (the i64 extremes are pinned by the golden vectors).
    #[kani::proof]
    #[kani::unwind(8)]
    fn integer_roundtrip() {
        let n: i64 = kani::any_where(|n: &i64| *n > -100_000 && *n < 100_000);
        let text = n.to_string();
        let v = CanonValue::parse(&text).unwrap();
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
        if let Ok(CanonValue::Int(_)) = CanonValue::parse(text) {
            let digits = text.strip_prefix('-').unwrap_or(text).as_bytes();
            assert!(!digits.is_empty() && digits.iter().all(|b| b.is_ascii_digit()));
            assert!(digits[0] != b'0' || digits.len() == 1, "no leading zero");
            assert!(text != "-0", "no negative zero");
        }
    }

    /// `write_string` is inverted by the parser for every string of ≤ 2 characters drawn from quotes,
    /// backslashes, every C0 control, DEL, and non-ASCII scalars (NFC stubbed to the identity; the
    /// escaper and the escape decoder are what is checked).
    #[kani::proof]
    #[kani::stub(nfc, nfc_identity)]
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
        assert_eq!(CanonValue::parse(&text).unwrap(), CanonValue::Str(s));
    }

    fn utf16_agrees<const N: usize>() {
        let units: [u16; N] = kani::any();
        let std_ok = char::decode_utf16(units.iter().copied()).all(|r| r.is_ok());
        match decode_utf16_strict(&units) {
            Ok(s) => {
                assert!(std_ok);
                let mut theirs = char::decode_utf16(units.iter().copied());
                for c in s.chars() {
                    assert_eq!(theirs.next().map(|r| r.ok()), Some(Some(c)));
                }
                assert!(theirs.next().is_none());
            }
            Err(_) => assert!(!std_ok),
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

    /// The parser never panics on any input of ≤ 5 bytes (NFC stubbed): every rejection is a `CanonError`.
    #[kani::proof]
    #[kani::stub(nfc, nfc_identity)]
    #[kani::unwind(8)]
    fn parse_never_panics() {
        let raw: [u8; 5] = kani::any();
        let len: usize = kani::any_where(|l: &usize| *l <= 5);
        if let Ok(text) = core::str::from_utf8(&raw[..len]) {
            let _ = CanonValue::parse(text);
        }
    }
}
