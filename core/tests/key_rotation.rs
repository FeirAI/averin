//! AVE-04: signed key-rotation statements. The fixture bundle is sealed by key `k0` (seed [0;32]); the tests
//! treat `k0` as the SUCCESSOR and a second key as the retiring recording key an auditor pinned earlier.

use averin_decision_core::canon::CanonValue;
use averin_decision_core::hashx::sha256_prefixed;
use averin_decision_core::sign::{encode_pubkey, sign, signing_key_from_seed};
use averin_decision_core::verify::{
    verify_bundle_with, TrustLevel, TrustedKey, VerifyOptions, VerifyReport, KEY_ROTATION_SIG_TAG,
};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

const ROTATED_AT: &str = "2026-07-01T00:00:00.000Z";

fn fixture() -> CanonValue {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec/fixtures/bundle-valid.json");
    CanonValue::parse(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn obj(pairs: Vec<(&str, CanonValue)>) -> CanonValue {
    CanonValue::object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()).unwrap()
}

fn s(v: &str) -> CanonValue {
    CanonValue::string(v)
}

fn old_sk() -> SigningKey {
    signing_key_from_seed(&[9u8; 32])
}

fn new_sk() -> SigningKey {
    signing_key_from_seed(&[0u8; 32])
}

fn key_ref(id: &str, sk: &SigningKey) -> CanonValue {
    obj(vec![
        ("signing_key_id", s(id)),
        ("key_epoch", CanonValue::Int(0)),
        ("public_key", s(&encode_pubkey(&sk.verifying_key()))),
    ])
}

/// A statement body (no signatures yet).
fn body(reason: &str) -> Vec<(String, CanonValue)> {
    vec![
        ("kind".into(), s("key_rotation")),
        ("old_key".into(), key_ref("k-old", &old_sk())),
        ("new_key".into(), key_ref("k0", &new_sk())),
        ("rotated_at".into(), s(ROTATED_AT)),
        ("reason".into(), s(reason)),
    ]
}

fn digest(members: &[(String, CanonValue)]) -> String {
    sha256_prefixed(CanonValue::Object(members.to_vec()).serialize().as_bytes())
}

fn statement(reason: &str, old_signer: Option<&SigningKey>, new_signer: &SigningKey) -> CanonValue {
    let mut m = body(reason);
    let d = digest(&m);
    m.push((
        "sig_new".into(),
        s(&sign(KEY_ROTATION_SIG_TAG, &d, new_signer)),
    ));
    if let Some(o) = old_signer {
        m.push(("sig_old".into(), s(&sign(KEY_ROTATION_SIG_TAG, &d, o))));
    }
    CanonValue::Object(m)
}

fn bundle_with(rotations: Vec<CanonValue>, old_status: &str) -> CanonValue {
    let b = fixture();
    let mut keys = b.get("keys").unwrap().as_array().unwrap().clone();
    keys.push(obj(vec![
        ("signing_key_id", s("k-old")),
        ("key_epoch", CanonValue::Int(0)),
        ("public_key", s(&encode_pubkey(&old_sk().verifying_key()))),
        ("key_status", s(old_status)),
        ("status_changed_at", s(ROTATED_AT)),
    ]));
    let mut m = b.as_object().unwrap().clone();
    m.retain(|(k, _)| k != "keys");
    m.push(("keys".into(), CanonValue::Array(keys)));
    if !rotations.is_empty() {
        m.push(("key_rotations".into(), CanonValue::Array(rotations)));
    }
    CanonValue::Object(m)
}

fn pin(sk: &SigningKey, status: Option<&str>, at: Option<&str>) -> VerifyOptions {
    VerifyOptions {
        trusted_keys: Some(vec![TrustedKey {
            vk: sk.verifying_key(),
            status: status.map(Into::into),
            status_changed_at: at.map(Into::into),
        }]),
        ..Default::default()
    }
}

fn all_proven(r: &VerifyReport) -> bool {
    !r.record_trust.is_empty()
        && r.record_trust
            .iter()
            .all(|t| t.trust == TrustLevel::IntegrityProven)
}

fn none_proven(r: &VerifyReport) -> bool {
    r.record_trust
        .iter()
        .all(|t| t.trust == TrustLevel::Untrusted)
}

#[test]
fn scheduled_handover_carries_a_pinned_old_key_to_its_successor() {
    let b = bundle_with(
        vec![statement("scheduled", Some(&old_sk()), &new_sk())],
        "retired",
    );
    let r = verify_bundle_with(&b, &pin(&old_sk(), None, None));
    assert!(r.ok, "{:?}", r.issues);
    assert_eq!((r.key_rotations_total, r.key_rotations_verified), (1, 1));
    assert_eq!(r.key_rotations_chain_trusted, 1);
    assert!(all_proven(&r));
}

#[test]
fn control_without_the_statement_the_successor_is_not_trusted() {
    let b = bundle_with(vec![], "retired");
    let r = verify_bundle_with(&b, &pin(&old_sk(), None, None));
    assert_eq!(r.key_rotations_chain_trusted, 0);
    assert!(
        none_proven(&r),
        "the successor must not be trusted on its own say-so"
    );
}

#[test]
fn without_external_pinning_the_statement_changes_nothing() {
    let b = bundle_with(
        vec![statement("scheduled", Some(&old_sk()), &new_sk())],
        "retired",
    );
    let r = verify_bundle_with(&b, &VerifyOptions::default());
    assert!(!r.keys_externally_pinned);
    assert_eq!(r.key_rotations_chain_trusted, 0);
}

#[test]
fn an_old_key_the_auditor_marked_compromised_hands_over_nothing() {
    let b = bundle_with(
        vec![statement("scheduled", Some(&old_sk()), &new_sk())],
        "retired",
    );
    let r = verify_bundle_with(&b, &pin(&old_sk(), Some("compromised"), Some(ROTATED_AT)));
    assert_eq!(r.key_rotations_chain_trusted, 0);
    assert!(none_proven(&r));
}

#[test]
fn a_bundle_cannot_launder_trust_by_calling_a_compromised_key_active() {
    // the bundle lists the old key as compromised: worst-of wins even if the auditor pinned it plain
    let b = bundle_with(
        vec![statement("scheduled", Some(&old_sk()), &new_sk())],
        "compromised",
    );
    let r = verify_bundle_with(&b, &pin(&old_sk(), None, None));
    assert_eq!(r.key_rotations_chain_trusted, 0);
    assert!(none_proven(&r));
}

#[test]
fn a_compromise_rotation_links_the_keys_but_extends_no_trust() {
    let b = bundle_with(
        vec![statement("compromise", None, &new_sk())],
        "compromised",
    );
    let r = verify_bundle_with(&b, &pin(&old_sk(), None, None));
    assert_eq!((r.key_rotations_total, r.key_rotations_verified), (1, 1));
    assert_eq!(r.key_rotations_chain_trusted, 0);
    assert!(none_proven(&r));
    // the auditor pins the successor directly: its records are proven
    let direct = verify_bundle_with(&b, &pin(&new_sk(), None, None));
    assert!(all_proven(&direct));
}

#[test]
fn a_scheduled_statement_without_the_old_keys_signature_is_refused() {
    let b = bundle_with(vec![statement("scheduled", None, &new_sk())], "retired");
    let r = verify_bundle_with(&b, &pin(&old_sk(), None, None));
    assert!(!r.ok);
    assert_eq!(r.key_rotations_verified, 0);
    assert!(
        r.issues.iter().any(|i| i.contains("sig_old")),
        "{:?}",
        r.issues
    );
    assert!(none_proven(&r));
}

#[test]
fn a_statement_signed_by_the_wrong_old_key_is_refused() {
    let thief = signing_key_from_seed(&[77u8; 32]);
    let b = bundle_with(
        vec![statement("scheduled", Some(&thief), &new_sk())],
        "retired",
    );
    let r = verify_bundle_with(&b, &pin(&old_sk(), None, None));
    assert!(!r.ok);
    assert_eq!(r.key_rotations_chain_trusted, 0);
}

#[test]
fn editing_a_signed_statement_breaks_both_signatures() {
    let mut st = statement("scheduled", Some(&old_sk()), &new_sk())
        .as_object()
        .unwrap()
        .clone();
    for (k, v) in st.iter_mut() {
        if k == "rotated_at" {
            *v = s("2026-07-02T00:00:00.000Z");
        }
    }
    let b = bundle_with(vec![CanonValue::Object(st)], "retired");
    let r = verify_bundle_with(&b, &pin(&old_sk(), None, None));
    assert!(!r.ok);
    assert_eq!(r.key_rotations_chain_trusted, 0);
}

#[test]
fn an_unknown_field_or_a_key_missing_from_the_bundle_is_refused() {
    let mut st = statement("scheduled", Some(&old_sk()), &new_sk())
        .as_object()
        .unwrap()
        .clone();
    st.push(("extra".into(), s("x")));
    let b = bundle_with(vec![CanonValue::Object(st)], "retired");
    assert!(!verify_bundle_with(&b, &pin(&old_sk(), None, None)).ok);

    // statement names a key the bundle does not list
    let b = fixture();
    let mut m = b.as_object().unwrap().clone();
    m.push((
        "key_rotations".into(),
        CanonValue::Array(vec![statement("scheduled", Some(&old_sk()), &new_sk())]),
    ));
    let r = verify_bundle_with(&CanonValue::Object(m), &pin(&old_sk(), None, None));
    assert!(!r.ok);
    assert!(
        r.issues.iter().any(|i| i.contains("not listed")),
        "{:?}",
        r.issues
    );
}

#[test]
fn the_report_json_carries_the_rotation_counts() {
    let b = bundle_with(
        vec![statement("scheduled", Some(&old_sk()), &new_sk())],
        "retired",
    );
    let r = verify_bundle_with(&b, &pin(&old_sk(), None, None));
    let j = averin_decision_core::verify::report_to_json(&r);
    assert!(j.contains("\"key_rotations_chain_trusted\":1"), "{j}");
}

#[test]
fn a_statement_not_signed_by_the_new_key_is_refused() {
    // a compromise statement needs only the successor's signature, so that signature must really be the successor's
    let thief = signing_key_from_seed(&[77u8; 32]);
    let b = bundle_with(vec![statement("compromise", None, &thief)], "compromised");
    let r = verify_bundle_with(&b, &pin(&new_sk(), None, None));
    assert!(!r.ok);
    assert_eq!(r.key_rotations_verified, 0);
    assert!(
        r.issues.iter().any(|i| i.contains("sig_new")),
        "{:?}",
        r.issues
    );
}

#[test]
fn a_successor_that_is_also_a_pinned_role_key_is_not_trusted() {
    let b = bundle_with(
        vec![statement("scheduled", Some(&old_sk()), &new_sk())],
        "retired",
    );
    let mut opts = pin(&old_sk(), None, None);
    opts.resource_authority_keys = vec![new_sk().verifying_key()];
    let r = verify_bundle_with(&b, &opts);
    assert_eq!(r.key_rotations_chain_trusted, 0);
    assert!(
        r.issues.iter().any(|i| i.contains("role")),
        "{:?}",
        r.issues
    );
    assert!(none_proven(&r));
}
