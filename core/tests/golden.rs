//! Golden-vector acceptance tests (M0.4 / threat #10). The committed `/spec/golden-vectors`
//! are the cross-implementation contract; this asserts the Rust core reproduces them
//! byte-for-byte, and that RCP rejection rules hold.

use averin_decision_core::authority::{preimage_v3, subject_digest};
use averin_decision_core::canon::CanonValue;
use averin_decision_core::hashx::hex_lower;
use averin_decision_core::record::compute_content_hash;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec")
        .join("golden-vectors")
}

fn read_manifest(name: &str) -> CanonValue {
    let p = vectors_dir().join(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    CanonValue::parse(&text).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    fn v(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex digit"),
        }
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| (v(p[0]) << 4) | v(p[1]))
        .collect()
}

#[test]
fn canon_golden_vectors_reproduce_byte_for_byte() {
    let manifest = read_manifest("canon.json");
    let cases = manifest.get("cases").unwrap().as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case.get("name").unwrap().as_str().unwrap();
        // input_hex is the authoritative, byte-preserved source (immune to manifest re-NFC).
        let input_hex = case.get("input_hex").unwrap().as_str().unwrap();
        let input_bytes = decode_hex(input_hex);
        let input = std::str::from_utf8(&input_bytes).expect("input utf8");
        let expected_hex = case.get("canonical_hex").unwrap().as_str().unwrap();

        let parsed = CanonValue::parse(input)
            .unwrap_or_else(|e| panic!("case {name}: input should parse: {e}"));
        let out = parsed.serialize();
        assert_eq!(
            hex_lower(out.as_bytes()),
            expected_hex,
            "case {name}: canonical bytes diverged\n got: {out}",
        );
    }
}

#[test]
fn record_content_hash_golden() {
    let m = read_manifest("record-basic.json");
    let input_hex = m.get("input_hex").unwrap().as_str().unwrap();
    let input = String::from_utf8(decode_hex(input_hex)).unwrap();
    let expected_canon_hex = m.get("canonical_hex").unwrap().as_str().unwrap();
    let expected_ch = m.get("content_hash").unwrap().as_str().unwrap();

    let rec = CanonValue::parse(&input).expect("record parses");
    assert_eq!(hex_lower(rec.serialize().as_bytes()), expected_canon_hex);
    assert_eq!(compute_content_hash(&rec).unwrap(), expected_ch);
}

#[test]
fn authority_subject_v3_matches_govder_vector() {
    let vector = read_manifest("authority-subject-v3.json");
    let record = vector.get("record").unwrap();
    let digest = vector.get("subject_digest").unwrap().as_str().unwrap();
    assert_eq!(subject_digest(record).unwrap(), digest);
    let actual = preimage_v3(
        "human_signed",
        "p1",
        "r1",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        digest,
    )
    .unwrap();
    assert_eq!(
        hex_lower(&actual),
        vector.get("preimage_hex").unwrap().as_str().unwrap()
    );
}

#[test]
fn sdk_prepared_v3_record_matches_govder_subject_bytes() {
    let vector = read_manifest("authority-sdk-v3.json");
    let record = vector.get("prepared_record").unwrap();
    assert_eq!(
        subject_digest(record).unwrap(),
        vector.get("subject_digest").unwrap().as_str().unwrap()
    );
    let draft = vector.get("draft_record").unwrap();
    assert!(
        subject_digest(draft).is_err(),
        "draft is not signable before preparation"
    );
}

// ---- RCP rejection rules (negative vectors) ----

fn rejects(input: &str, why: &str) {
    let r = CanonValue::parse(input);
    assert!(r.is_err(), "expected rejection ({why}) but parsed: {input}");
}

#[test]
fn rcp_rejects_floats_and_exponents() {
    rejects(r#"{"a":1.5}"#, "fraction");
    rejects(r#"{"a":1e3}"#, "exponent");
    rejects(r#"{"a":1E3}"#, "exponent");
    rejects(r#"{"a":-0.0}"#, "negative float");
}

#[test]
fn rcp_rejects_out_of_range_integers() {
    rejects(r#"{"a":9223372036854775808}"#, "i64 max + 1");
    rejects(r#"{"a":-9223372036854775809}"#, "i64 min - 1");
    // boundaries are accepted
    assert!(CanonValue::parse(r#"{"a":9223372036854775807}"#).is_ok());
    assert!(CanonValue::parse(r#"{"a":-9223372036854775808}"#).is_ok());
}

#[test]
fn rcp_rejects_leading_zeros() {
    rejects(r#"{"a":01}"#, "leading zero");
    rejects(r#"{"a":00}"#, "leading zero");
    rejects(r#"{"a":-01}"#, "leading zero negative");
}

#[test]
fn rcp_rejects_negative_zero() {
    rejects(r#"{"a":-0}"#, "negative zero is non-canonical");
    rejects(r#"[-0]"#, "negative zero in array");
    // plain zero is fine and canonicalizes to "0"
    let v = CanonValue::parse(r#"{"a":0}"#).unwrap();
    assert_eq!(v.serialize(), r#"{"a":0}"#);
}

#[test]
fn serializer_is_canonical_regardless_of_construction() {
    // A hand-built Str holding a decomposed (non-NFC) value must still serialize as NFC,
    // so the hashed bytes are canonical even off the parse path.
    let decomposed = CanonValue::Str("e\u{0301}".to_string()); // e + combining acute
    assert_eq!(decomposed.serialize(), "\"\u{00e9}\""); // precomposed é
                                                        // The checked constructor normalizes up front and rejects duplicate keys.
    assert_eq!(CanonValue::string("e\u{0301}").serialize(), "\"\u{00e9}\"");
    let dup = CanonValue::object(vec![
        ("\u{00e9}".to_string(), CanonValue::Int(1)),
        ("e\u{0301}".to_string(), CanonValue::Int(2)),
    ]);
    assert!(dup.is_err(), "object() must reject post-NFC duplicate keys");
}

#[test]
fn rcp_rejects_duplicate_keys() {
    rejects(r#"{"a":1,"a":2}"#, "literal duplicate");
}

#[test]
fn rcp_rejects_post_nfc_duplicate_keys() {
    // "é" (precomposed U+00E9) and "é" (decomposed) normalize to the same NFC key.
    rejects("{\"\u{00e9}\":1,\"e\u{0301}\":2}", "post-NFC duplicate");
}

#[test]
fn rcp_rejects_lone_surrogates() {
    rejects(r#"{"a":"\uD800"}"#, "lone high surrogate");
    rejects(r#"{"a":"\uDC00"}"#, "lone low surrogate");
    rejects(r#"{"a":"\uD800x"}"#, "high surrogate then non-surrogate");
    // a valid surrogate pair is accepted
    assert!(CanonValue::parse(r#"{"a":"😀"}"#).is_ok());
}

#[test]
fn rcp_rejects_raw_control_chars_in_strings() {
    rejects("{\"a\":\"\u{01}\"}", "raw control char");
}

#[test]
fn rcp_rejects_trailing_data() {
    rejects(r#"{} {}"#, "trailing object");
    rejects(r#"{}x"#, "trailing garbage");
}

#[test]
fn rcp_rejects_excessive_nesting_no_stack_overflow() {
    // Deeply nested untrusted input must error, not overflow the stack (DoS under panic=abort).
    let deep_arr = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
    assert!(
        CanonValue::parse(&deep_arr).is_err(),
        "deep array must be rejected"
    );
    let deep_obj = format!(
        "{}{}",
        r#"{"a":"#.repeat(5000),
        "1".to_string() + &"}".repeat(5000)
    );
    assert!(
        CanonValue::parse(&deep_obj).is_err(),
        "deep object must be rejected"
    );
    // a modestly nested doc (well under the limit) still parses
    let ok = format!("{}{}", "[".repeat(50), "]".repeat(50));
    assert!(CanonValue::parse(&ok).is_ok());
}

#[test]
fn nfc_equivalent_inputs_have_equal_content_hash() {
    // Two byte-different inputs that are NFC-equivalent must canonicalize and hash identically.
    let composed = "{\"domain\":\"flightrecorder.record.v2\",\"canon_version\":\"rcp-1\",\"note\":\"\u{00e9}\"}";
    let decomposed = "{\"domain\":\"flightrecorder.record.v2\",\"canon_version\":\"rcp-1\",\"note\":\"e\u{0301}\"}";
    assert_ne!(composed.as_bytes(), decomposed.as_bytes());
    let a = CanonValue::parse(composed).unwrap();
    let b = CanonValue::parse(decomposed).unwrap();
    assert_eq!(a.serialize(), b.serialize());
    assert_eq!(
        compute_content_hash(&a).unwrap(),
        compute_content_hash(&b).unwrap()
    );
}

#[test]
fn unicode17_combining_mark_has_pinned_nfc_result() {
    // U+1ADD acquired combining class 220 after Unicode 15. Go 1.25's x/text
    // tables treat it as class 0, so Go-only NFC checks would accept this
    // spelling even though the shipped Rust RCP core composes a + acute.
    let raw = "a\u{1add}\u{301}";
    let canonical = "\u{e1}\u{1add}";
    assert_ne!(raw, canonical);
    assert_eq!(
        CanonValue::parse(r#""a\u1add\u0301""#).unwrap().as_str(),
        Some(canonical)
    );
    assert_eq!(CanonValue::string(raw).as_str(), Some(canonical));
}

// Plan 009: the v2 revocation tree preimages, root and proofs are the shared Go/Rust contract
// (server/internal/broker TestRevocationV2GoldenVector writes and checks the same file).
#[test]
fn revocation_v2_golden_vector() {
    use averin_decision_core::verify::{
        revocation_entry_v2, revocation_entry_v2_preimage, revocation_key_v2,
        revocation_key_v2_preimage, revocation_merkle_root_v2, revocation_state_digest_v2,
        revocation_state_v2_preimage, RevState,
    };
    let v = read_manifest("revocation-v2.json");
    let s = |c: &CanonValue, k: &str| c.get(k).unwrap().as_str().unwrap().to_string();
    let keys = v.get("key_cases").unwrap().as_array().unwrap();
    assert_eq!(keys.len(), 3);
    for c in keys {
        let g = s(c, "grant_id");
        assert_eq!(
            hex_lower(&revocation_key_v2_preimage(&g)),
            s(c, "preimage_hex"),
            "{g}"
        );
        assert_eq!(hex_lower(&revocation_key_v2(&g)), s(c, "key_hex"), "{g}");
    }
    for c in v.get("state_cases").unwrap().as_array().unwrap() {
        let (mode, cutoff) = (s(c, "mode"), c.get("cutoff").unwrap().as_int().unwrap());
        assert_eq!(
            hex_lower(&revocation_state_v2_preimage(&mode, cutoff)),
            s(c, "preimage_hex")
        );
        assert_eq!(
            hex_lower(&revocation_state_digest_v2(&mode, cutoff)),
            s(c, "digest_hex")
        );
    }
    let e = v.get("entry_case").unwrap();
    let arr32 = |h: String| -> [u8; 32] { decode_hex(&h).try_into().unwrap() };
    let (key, state) = (arr32(s(e, "key_hex")), arr32(s(e, "state_hex")));
    assert_eq!(
        hex_lower(&revocation_entry_v2_preimage(&key, &state)),
        s(e, "preimage_hex")
    );
    assert_eq!(
        hex_lower(&revocation_entry_v2(&key, &state)),
        s(e, "entry_hex")
    );
    let tree = v.get("tree").unwrap();
    let entries: Vec<(String, RevState)> = tree
        .get("entries")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let st = match s(x, "mode").as_str() {
                "total" => RevState::Total,
                _ => RevState::Prospective(x.get("cutoff_order").unwrap().as_int().unwrap()),
            };
            (s(x, "grant_id"), st)
        })
        .collect();
    let refs: Vec<(&str, RevState)> = entries.iter().map(|(g, st)| (g.as_str(), *st)).collect();
    assert_eq!(revocation_merkle_root_v2(&refs), s(tree, "root"));
    assert_eq!(
        tree.get("leaf_count").unwrap().as_int().unwrap() as usize,
        entries.len() + 2
    );
}
