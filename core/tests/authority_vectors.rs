//! vectors/authority-v3.v1.json is OWNED by averin (repackaged from formal/oracle and
//! spec/golden-vectors by scripts/vectors/gen_authority_v3.py) and copied byte for byte into govder,
//! which signs authority proofs. This test checks the Rust implementation reproduces every vector,
//! so the file cannot drift from what averin actually computes.

use averin_decision_core::authority::{preimage_v3, subject_digest};
use averin_decision_core::canon::CanonValue;
use averin_decision_core::hashx::hex_lower;
use std::path::PathBuf;

fn vectors() -> CanonValue {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vectors")
        .join("authority-v3.v1.json");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    CanonValue::parse(&text).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

#[test]
fn canon_json_vectors_serialize_to_the_pinned_bytes() {
    let v = vectors();
    let cases = v.get("canon_json").and_then(|c| c.as_array()).expect("canon_json");
    assert!(cases.len() >= 7);
    for c in cases {
        let name = c.get("name").and_then(|x| x.as_str()).unwrap();
        let input = c.get("input").and_then(|x| x.as_str()).unwrap();
        let want = c.get("canonical_hex").and_then(|x| x.as_str()).unwrap();
        let parsed = CanonValue::parse(input).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(hex_lower(parsed.serialize().as_bytes()), want, "{name}");
    }
}

#[test]
fn subject_v3_digest_and_preimage_match_the_pinned_bytes() {
    let v = vectors();
    let s = v.get("subject_v3").expect("subject_v3");
    let g = |k: &str| s.get(k).and_then(|x| x.as_str()).unwrap().to_string();
    let record = s.get("record").unwrap();
    let digest = subject_digest(record).unwrap();
    assert_eq!(digest, g("subject_digest"));
    let pre = preimage_v3(&g("source"), &g("project_id"), &g("record_id"), &g("evidence_hash"), &digest).unwrap();
    assert_eq!(hex_lower(&pre), g("preimage_hex"));
}
