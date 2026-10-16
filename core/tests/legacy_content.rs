//! AVE-02: the verifier tells the reader how many records of a bundle carry prompt or answer text in the
//! clear (`extensions.content_preview`), which no retention purge can erase.

use averin_decision_core::canon::CanonValue;
use averin_decision_core::record::compute_content_hash;
use averin_decision_core::sign::{sign, signing_key_from_seed, RECORD_SIG_TAG};
use averin_decision_core::verify::verify_bundle;
use std::path::PathBuf;

fn fixture() -> CanonValue {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec/fixtures/bundle-valid.json");
    CanonValue::parse(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// Re-seal every record of the fixture under k0 with `extensions` set by `ext` (None = leave as is).
fn with_extensions(ext: Option<CanonValue>, only_first: bool) -> CanonValue {
    let b = fixture();
    let sk = signing_key_from_seed(&[0u8; 32]);
    let mut records = b.get("records").unwrap().as_array().unwrap().clone();
    for (i, r) in records.iter_mut().enumerate() {
        if only_first && i > 0 {
            break;
        }
        let Some(e) = ext.clone() else { break };
        let CanonValue::Object(mut m) = r.without_keys(&["content_hash", "sig", "extensions"])
        else {
            panic!()
        };
        m.push(("extensions".into(), e));
        let body = CanonValue::Object(m);
        let ch = compute_content_hash(&body).unwrap();
        let sig = sign(RECORD_SIG_TAG, &ch, &sk);
        let CanonValue::Object(mut m) = body else {
            panic!()
        };
        m.push(("content_hash".into(), CanonValue::Str(ch)));
        m.push(("sig".into(), CanonValue::Str(sig)));
        *r = CanonValue::Object(m);
    }
    let mut m = b.as_object().unwrap().clone();
    m.retain(|(k, _)| k != "records");
    m.push(("records".into(), CanonValue::Array(records)));
    CanonValue::Object(m)
}

fn preview() -> CanonValue {
    CanonValue::object(vec![(
        "content_preview".into(),
        CanonValue::object(vec![("input".into(), CanonValue::string("a card number"))]).unwrap(),
    )])
    .unwrap()
}

#[test]
fn a_bundle_with_signed_cleartext_text_is_counted() {
    let r = verify_bundle(&with_extensions(Some(preview()), true));
    assert_eq!(r.cleartext_content_records, 1);
    assert!(averin_decision_core::verify::report_to_json(&r)
        .contains("\"cleartext_content_records\":1"));
}

#[test]
fn a_bundle_without_it_reports_zero() {
    assert_eq!(verify_bundle(&fixture()).cleartext_content_records, 0);
    let other = CanonValue::object(vec![(
        "framework".into(),
        CanonValue::object(vec![("name".into(), CanonValue::string("x"))]).unwrap(),
    )])
    .unwrap();
    assert_eq!(
        verify_bundle(&with_extensions(Some(other), true)).cleartext_content_records,
        0
    );
}
