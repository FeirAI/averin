//! Deterministic RCP differential campaign. No third-party JSON parser is an oracle: the
//! accepted/rejected classes below come from spec/rcp-v1.md, and the C ABI must agree.
use averin_decision_core::{b64, canon::CanonValue, ffi};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::{CStr, CString},
    fs,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

const ATOMS: &[&str] = &[
    "null",
    "true",
    "false",
    "0",
    "-1",
    "9223372036854775807",
    "-9223372036854775808",
    "\"plain\"",
    "\"e\\u0301\"",
    "\"\\uD83D\\uDE00\"",
    "\"\\b\\t\\n\\f\\r\\u0000\"",
    "\"\\\\\\\"/\"",
    "\"𝄞\"",
];

fn valid(r: &mut Rng, depth: usize) -> String {
    if depth == 0 || r.pick(3) == 0 {
        return ATOMS[r.pick(ATOMS.len())].to_string();
    }
    if r.pick(2) == 0 {
        format!(
            "[{}, {},{}]",
            valid(r, depth - 1),
            valid(r, depth - 1),
            valid(r, depth - 1)
        )
    } else {
        // Deliberately unsorted: RCP orders these by UTF-16 code units.
        format!(
            "{{\"z\":{},\"𝄞\":{},\"a\":{}}}",
            valid(r, depth - 1),
            valid(r, depth - 1),
            valid(r, depth - 1)
        )
    }
}

fn invalid(r: &mut Rng) -> String {
    match r.pick(7) {
        0 => format!("{}!", valid(r, 2)),
        1 => format!("[{},]", valid(r, 2)),
        2 => format!("{{\"k\":{},\"k\":{}}}", valid(r, 2), valid(r, 2)),
        3 => format!("[{}", valid(r, 2)),
        4 => format!("{}e0", r.next() % 1_000_000),
        5 => format!("\"\\uD800{}\"", r.next() % 1_000_000),
        _ => INVALID[r.pick(INVALID.len())].to_string(),
    }
}

const INVALID: &[&str] = &[
    "-0",
    "00",
    "01",
    "-01",
    "+1",
    "1.0",
    "1e0",
    "9223372036854775808",
    "-9223372036854775809",
    "\"\\uD800\"",
    "\"\\uDC00\"",
    "\"\\uD800x\"",
    "\"\\u12\"",
    "\"\\x00\"",
    "\"raw\nnewline\"",
    "[1,]",
    "{\"a\":1,}",
    "{\"a\":1,\"a\":2}",
    "{\"é\":1,\"e\\u0301\":2}",
    "true false",
    "null!",
    "[",
    "{",
    "\"",
    "\"\\",
    "{\"x\" 1}",
    "[1 2]",
];

fn from_hex(s: &str) -> String {
    let mut out = Vec::new();
    for pair in s.as_bytes().chunks_exact(2) {
        let d = |b: u8| (b as char).to_digit(16).expect("corpus hex digit") as u8;
        out.push((d(pair[0]) << 4) | d(pair[1]));
    }
    assert_eq!(s.len() % 2, 0, "corpus hex width");
    String::from_utf8(out).expect("corpus UTF-8")
}

fn check(input: &str, accepted: bool, expected: Option<&str>) -> String {
    let parsed = std::panic::catch_unwind(|| CanonValue::parse(input))
        .unwrap_or_else(|_| panic!("RCP parser panicked on {input:?}"));
    assert_eq!(parsed.is_ok(), accepted, "RCP acceptance for {input:?}");
    let canonical = match parsed {
        Ok(v) => {
            let s = v.serialize();
            assert_eq!(
                CanonValue::parse(&s)
                    .expect("canonical output reparses")
                    .serialize(),
                s
            );
            if let Some(want) = expected {
                assert_eq!(s, want, "canonical bytes for {input:?}");
            }
            s
        }
        Err(_) => "!".to_string(),
    };
    // The cgo/staticlib entrypoint is NUL-terminated. A raw interior NUL needs the Go
    // wrapper's guard; it cannot safely be supplied to this C-string interface.
    if !input.contains('\0') {
        let c = CString::new(input).unwrap();
        let ptr = unsafe { ffi::averin_rcp_canonicalize(c.as_ptr()) };
        assert!(!ptr.is_null(), "native C ABI returned null for {input:?}");
        let got = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        unsafe { ffi::averin_string_free(ptr) };
        if accepted {
            assert_eq!(got, canonical, "native C ABI for {input:?}");
        } else {
            assert!(
                got.starts_with("ERROR:"),
                "native C ABI accepted {input:?}: {got}"
            );
        }
    }
    canonical
}

fn emit(out: &mut String, input: &str, accepted: bool, expected: Option<&str>) {
    let canonical = check(input, accepted, expected);
    let hex = |s: &str| {
        s.as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    out.push_str(if accepted { "A" } else { "R" });
    out.push('\t');
    out.push_str(&hex(input));
    out.push('\t');
    out.push_str(&hex(&canonical));
    out.push('\n');
}

#[test]
fn seeded_rcp_campaign() {
    let seed = env::var("FUZZ_SEED")
        .unwrap_or_else(|_| "20260923".into())
        .parse::<u64>()
        .expect("FUZZ_SEED must be decimal u64");
    let cases = env::var("FUZZ_CASES")
        .unwrap_or_else(|_| "128".into())
        .parse::<usize>()
        .expect("FUZZ_CASES must be decimal usize");
    assert!((1..=50_000).contains(&cases));
    let mut r = Rng(seed.max(1));
    let mut out = String::new();
    for line in include_str!("../../formal/fuzz/regressions.tsv").lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t');
        let accepted = match fields.next().unwrap() {
            "A" => true,
            "R" => false,
            _ => panic!("bad corpus kind"),
        };
        let input = from_hex(fields.next().expect("corpus input"));
        let expected = fields.next().map(from_hex);
        assert!(fields.next().is_none(), "extra corpus field");
        emit(&mut out, &input, accepted, expected.as_deref());
    }
    // These exceed the short symbolic domains. Depth 256 is allowed; 257 is rejected.
    emit(
        &mut out,
        &format!("{}0{}", "[".repeat(256), "]".repeat(256)),
        true,
        None,
    );
    emit(
        &mut out,
        &format!("{}0{}", "[".repeat(257), "]".repeat(257)),
        false,
        None,
    );
    emit(&mut out, &format!("\"{}\"", "e".repeat(16_384)), true, None);
    emit(
        &mut out,
        &format!("{{\"{}\":0}}", "k".repeat(8_192)),
        true,
        None,
    );
    // Nonzero unused bits in a one- or two-byte tail are forbidden even when all
    // symbols belong to the base64url alphabet.
    assert!(b64::decode("Zh").is_err());
    assert!(b64::decode("Zm9").is_err());
    for i in 0..cases {
        if i % 2 == 0 {
            let depth = 1 + r.pick(4);
            emit(&mut out, &valid(&mut r, depth), true, None);
        } else {
            emit(&mut out, &invalid(&mut r), false, None);
        }
        // Separate base64url byte stream: round-trip arbitrary lengths, and reject forbidden
        // alphabet/padding. The RCP corpus remains focused on the JSON parser.
        let bytes: Vec<u8> = (0..r.pick(65)).map(|_| r.next() as u8).collect();
        let encoded = b64::encode(&bytes);
        assert_eq!(b64::decode(&encoded).unwrap(), bytes);
        assert!(b64::decode(&format!("{encoded}=")).is_err());
    }
    let digest = Sha256::digest(out.as_bytes());
    println!(
        "RCP fuzz seed={seed} generated={cases} corpus_lines={} sha256={digest:x}",
        out.lines().count()
    );
    if let Ok(path) = env::var("FUZZ_OUTPUT") {
        fs::write(path, out).expect("write corpus");
    }
}
