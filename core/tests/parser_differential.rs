//! Differential test for the extractable parser rewrite (formal/production, parser panic-freedom).
//!
//! `reference` is the parser exactly as it was before that rewrite (core/src/canon.rs at 9513a97,
//! `CanonValue::parse` and the `Parser` it drove), copied here only as a test oracle. Production
//! `CanonValue::parse` must return the identical `Result` (value, or error message and offset) on the
//! fuzz corpus, the committed regressions, and a large generated corpus of valid, near-valid and
//! random inputs.
use averin_decision_core::canon::{CanonError, CanonValue};

#[allow(dead_code, clippy::all)]
mod reference {
    use super::{CanonError, CanonValue};
    use std::collections::BTreeSet;
    use unicode_normalization::UnicodeNormalization;

    fn nfc(s: &str) -> String {
        s.nfc().collect()
    }

    pub fn parse(input: &str) -> Result<CanonValue, CanonError> {
        let mut p = Parser {
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

    /// Maximum array/object nesting depth. Bounds recursion so deeply-nested untrusted input cannot
    /// overflow the stack (which, under `panic="abort"`, would kill the process — a DoS reachable from
    /// the FFI/WASM/CLI entry points). 256 is far beyond any real record/checkpoint shape.
    const MAX_DEPTH: usize = 256;

    struct Parser<'a> {
        s: &'a [u8],
        i: usize,
        depth: usize,
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

        fn enter(&mut self) -> Result<(), CanonError> {
            self.depth += 1;
            if self.depth > MAX_DEPTH {
                return Err(self.err("nesting depth limit exceeded"));
            }
            Ok(())
        }

        fn parse_array(&mut self) -> Result<CanonValue, CanonError> {
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

        fn parse_object(&mut self) -> Result<CanonValue, CanonError> {
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
            self.depth -= 1;
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
            // NFC normalize (RCP §4). Through `nfc` (not `s.nfc()` inline) so the Kani harnesses can stub
            // the Unicode tables and check the escape decoder itself.
            Ok(nfc(&s))
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
                        char::from_u32(u as u32)
                            .ok_or_else(|| "invalid scalar value".to_string())?,
                    );
                    i += 1;
                }
            }
        }
        Ok(out)
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Fragments that exercise every parser branch: literals and their prefixes, integer spellings at
/// and beyond the i64 limits, fractions/exponents, escapes (valid, invalid, truncated, surrogate
/// pairs and lone halves), raw controls, multi-byte scalars and NFC-colliding keys.
const ATOMS: &[&str] = &[
    "null",
    "true",
    "false",
    "nul",
    "tru",
    "fals",
    "nulll",
    "0",
    "-0",
    "00",
    "01",
    "-",
    "-01",
    "7",
    "-7",
    "123456789",
    "9223372036854775807",
    "9223372036854775808",
    "-9223372036854775808",
    "-9223372036854775809",
    "99999999999999999999",
    "1.5",
    "1e3",
    "1E3",
    "0.",
    "-a",
    "\"\"",
    "\"plain\"",
    "\"é\"",
    "\"e\\u0301\"",
    "\"\\u00e9\"",
    "\"\\uD83D\\uDE00\"",
    "\"\\ud83d\\ude00\"",
    "\"\\uD83D\"",
    "\"\\uDE00\"",
    "\"\\uD83Dx\"",
    "\"\\uD83D\\u0041\"",
    "\"\\uD83D😀\"",
    "\"\\u12\"",
    "\"\\u12G4\"",
    "\"\\x\"",
    "\"\\b\\f\\n\\r\\t\\/\\\\\\\"\"",
    "\"\\u0000\"",
    "\"a\u{1}b\"",
    "\"𝄞\"",
    "\"\u{FFFF}\u{E000}\u{10FFFF}\"",
    "\"Å\"",
    "\"A\u{30A}\"",
    "\"\\",
    "\"abc",
    "[]",
    "{}",
];

const KEYS: &[&str] = &[
    "\"a\"",
    "\"b\"",
    "\"é\"",
    "\"e\\u0301\"",
    "\"\\u00e9\"",
    "\"Å\"",
    "\"A\\u030A\"",
    "\"\u{212B}\"",
    "\"\"",
    "\"𝄞\"",
    "\"\\uD834\\uDD1E\"",
    "\"z\"",
    "\"\\uD800\"",
    "\"a",
];

const WS: &[&str] = &["", "", "", " ", "\n", "\t", "\r", "  "];

fn ws(r: &mut Rng) -> &'static str {
    WS[r.pick(WS.len())]
}

fn doc(r: &mut Rng, depth: usize, out: &mut String) {
    if depth == 0 || r.pick(3) == 0 {
        out.push_str(ATOMS[r.pick(ATOMS.len())]);
        return;
    }
    let n = r.pick(5);
    if r.pick(2) == 0 {
        out.push('[');
        for k in 0..n {
            if k > 0 {
                out.push_str(ws(r));
                out.push(',');
            }
            out.push_str(ws(r));
            doc(r, depth - 1, out);
        }
        out.push_str(ws(r));
        out.push(']');
    } else {
        out.push('{');
        for k in 0..n {
            if k > 0 {
                out.push(',');
            }
            out.push_str(ws(r));
            out.push_str(KEYS[r.pick(KEYS.len())]);
            out.push_str(ws(r));
            out.push(':');
            out.push_str(ws(r));
            doc(r, depth - 1, out);
        }
        out.push_str(ws(r));
        out.push('}');
    }
}

const NOISE: &[&str] = &[
    "{", "}", "[", "]", ",", ":", "\"", "\\", "u", "0", "1", "-", ".", "e", "t", "n", " ", "\u{1}",
    "é", "😀", "\u{301}", "x",
];

/// A random edit of a generated document: truncate, delete, duplicate or insert a fragment.
fn mutate(r: &mut Rng, s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return NOISE[r.pick(NOISE.len())].to_string();
    }
    let at = r.pick(chars.len() + 1);
    let mut out: String = chars[..at].iter().collect();
    match r.pick(4) {
        0 => {}
        1 => out.extend(chars[(at + 1).min(chars.len())..].iter()),
        2 => {
            out.push_str(NOISE[r.pick(NOISE.len())]);
            out.extend(chars[at..].iter());
        }
        _ => {
            out.extend(chars[at..].iter());
            out.extend(chars[at..].iter());
        }
    }
    out
}

fn same(input: &str) {
    let want = reference::parse(input);
    let got = CanonValue::parse(input);
    assert_eq!(got, want, "parser rewrite differs on {input:?}");
}

fn from_hex(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    for pair in b.chunks(2) {
        let d = |c: u8| (c as char).to_digit(16).unwrap() as u8;
        out.push((d(pair[0]) << 4) | d(pair[1]));
    }
    String::from_utf8(out).ok()
}

fn corpus(text: &str) -> usize {
    let mut n = 0;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(input) = line.split('\t').nth(1).and_then(from_hex) {
            same(&input);
            n += 1;
        }
    }
    n
}

#[test]
fn rewrite_matches_reference_on_regressions_and_corpus() {
    let n = corpus(include_str!("../../formal/fuzz/regressions.tsv"));
    assert!(n > 0);
    // `formal/run-fuzz.sh`'s generated corpus, when a path is given (the gate passes it).
    if let Ok(path) = std::env::var("DIFF_CORPUS") {
        let text = std::fs::read_to_string(&path).expect("DIFF_CORPUS");
        let m = corpus(&text);
        assert!(m > 0);
        println!("differential: {m} corpus cases from {path}");
    }
}

#[test]
fn rewrite_matches_reference_on_boundaries() {
    for d in [255, 256, 257, 300] {
        same(&format!("{}0{}", "[".repeat(d), "]".repeat(d)));
        same(&format!("{}{}", "{\"a\":".repeat(d), "}".repeat(d)));
        same(&format!("{}1{}", "{\"a\":".repeat(d), "}".repeat(d)));
        same(&"[".repeat(d));
    }
    same(&format!("\"{}\"", "e".repeat(16_384)));
    same(&format!("{{\"{}\":0}}", "k".repeat(8_192)));
    // A wide object whose only repeat is the last key, and one whose repeat is followed by an error.
    let wide: Vec<String> = (0..5000).map(|k| format!("\"k{k}\":{k}")).collect();
    same(&format!("{{{}}}", wide.join(",")));
    same(&format!("{{{},\"k17\":0}}", wide.join(",")));
    same(&format!("{{{},\"k17\":[1,}}", wide.join(",")));
    same("{\"a\":1,\"a\":{\"b\":1,\"b\":2}}");
    same("{\"a\":{\"b\":1,\"b\":2},\"a\":1}");
    same("{\"é\":1,\"e\\u0301\":{\"x\" 1}}");
    same("{\"b\":1,\"a\":2,\"b\":3,\"a\":4}");
    for n in [0i64, 1, -1, i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1] {
        same(&n.to_string());
    }
    for s in [
        "9223372036854775808",
        "-9223372036854775809",
        "18446744073709551616",
        "-",
        "-x",
    ] {
        same(s);
    }
    for c in 0u32..0x800 {
        if let Some(ch) = char::from_u32(c) {
            same(&format!("\"{ch}\""));
            same(&format!("\"\\u{c:04x}\""));
            same(&format!("{ch}"));
        }
    }
    for c in (0xD700u32..0xE100)
        .chain(0xFFF0..0x10010)
        .chain(0x10FFF0..0x110000)
    {
        same(&format!("\"\\u{:04X}\"", c & 0xFFFF));
        if let Some(ch) = char::from_u32(c) {
            same(&format!("\"{ch}\""));
        }
    }
}

#[test]
fn rewrite_matches_reference_on_generated_corpus() {
    let cases: usize = std::env::var("DIFF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let mut r = Rng(0x5eed_2026_0925);
    let (mut accepted, mut rejected) = (0usize, 0usize);
    for _ in 0..cases {
        let mut s = String::new();
        s.push_str(ws(&mut r));
        let depth = 1 + r.pick(5);
        doc(&mut r, depth, &mut s);
        s.push_str(ws(&mut r));
        let input = match r.pick(3) {
            0 => s,
            1 => mutate(&mut r, &s),
            _ => {
                let t = mutate(&mut r, &s);
                mutate(&mut r, &t)
            }
        };
        same(&input);
        if CanonValue::parse(&input).is_ok() {
            accepted += 1;
        } else {
            rejected += 1;
        }
        // Short noise strings over the parser's significant bytes.
        let mut noise = String::new();
        for _ in 0..r.pick(8) {
            noise.push_str(NOISE[r.pick(NOISE.len())]);
        }
        same(&noise);
    }
    println!("differential: {cases} generated documents ({accepted} accepted, {rejected} rejected) + {cases} noise strings");
    assert!(accepted > cases / 20 && rejected > cases / 20);
}

/// Parse with both parsers, require identical results, and return the error message and offset.
fn rejected(input: &str) -> (String, usize) {
    same(input);
    let e = CanonValue::parse(input).expect_err("must reject");
    (e.msg, e.pos)
}

const DUP: &str = "duplicate object key after NFC normalization";

#[test]
fn deferred_duplicate_check_reports_what_the_online_check_did() {
    // A duplicate followed by a syntax error in the same object: the duplicate, at its quote.
    for tail in ["2 \"x\"}", "}", "2,}", "2", "2,\"b\"", "[1 2]}"] {
        let (msg, pos) = rejected(&format!("{{\"a\":1,\"a\":{tail}"));
        assert!(msg.starts_with(DUP), "{tail}: {msg}");
        assert_eq!(pos, 7);
    }
    // A duplicate followed by an error inside its (nested) value.
    for value in [
        "[1,}",
        "{\"b\":tru}",
        "\"\\uD800\"",
        "-0",
        "[[[",
        "{\"b\":1,\"b\":2}",
    ] {
        let (msg, pos) = rejected(&format!("{{\"a\":1,\"a\":{value}}}"));
        assert!(
            msg.starts_with(DUP) && msg.ends_with("\"a\""),
            "{value}: {msg}"
        );
        assert_eq!(pos, 7, "{value}: the outer duplicate wins");
    }
    // An inner error before the outer duplicate: the inner error wins.
    let (msg, pos) = rejected("{\"a\":{\"b\":1,\"b\":2},\"a\":1}");
    assert!(msg.starts_with(DUP) && msg.ends_with("\"b\""), "{msg}");
    assert_eq!(pos, 12);
    let (msg, pos) = rejected("{\"a\":[1,],\"a\":1}");
    assert_eq!((msg.as_str(), pos), ("unexpected character", 8));
    // The earliest repeat wins among several, whatever the key order.
    let (msg, pos) = rejected("{\"b\":1,\"a\":2,\"b\":3,\"a\":4}");
    assert!(msg.ends_with("\"b\"") && pos == 13, "{msg} {pos}");
    let (msg, pos) = rejected("{\"b\":1,\"a\":2,\"a\":3,\"b\":4}");
    assert!(msg.ends_with("\"a\"") && pos == 13, "{msg} {pos}");
    // NFC-equivalent keys (composed, decomposed raw and escaped): reported as the normalized key.
    for (k1, k2) in [
        ("é", "e\u{301}"),
        ("é", "e\\u0301"),
        ("\\u00e9", "é"),
        ("Å", "\u{212B}"),
    ] {
        let input = format!("{{\"{k1}\":1,\"{k2}\":2}}");
        let (msg, pos) = rejected(&input);
        assert!(msg.starts_with(DUP), "{input}: {msg}");
        assert_eq!(pos, k1.len() + 6, "{input}");
    }
    // Duplicates at the depth limit: an object at depth 256 is parsed and its duplicate reported;
    // at 257 the depth error comes first.
    for d in [255usize, 256] {
        let input = format!(
            "{}{{\"a\":1,\"a\":2}}{}",
            "[".repeat(d - 1),
            "]".repeat(d - 1)
        );
        let (msg, _) = rejected(&input);
        assert!(msg.starts_with(DUP), "depth {d}: {msg}");
    }
    let input = format!("{}{{\"a\":1,\"a\":2}}{}", "[".repeat(256), "]".repeat(256));
    assert_eq!(rejected(&input).0, "nesting depth limit exceeded");
    // A duplicate whose value nests past the limit: the duplicate still wins.
    let input = format!("{{\"a\":1,\"a\":{}0{}}}", "[".repeat(300), "]".repeat(300));
    assert_eq!(rejected(&input), (format!("{DUP}: \"a\""), 7));
    // Trailing garbage after an object with a duplicate: the duplicate.
    for t in [" x", "}", ",", "{}", "\"a\""] {
        let (msg, pos) = rejected(&format!("{{\"a\":1,\"a\":2}}{t}"));
        assert!(msg.starts_with(DUP) && pos == 7, "{t}: {msg}");
    }
}
