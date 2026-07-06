//! Signing + commitment golden vectors (M1.3/M1.4). Ed25519 is deterministic (RFC 8032), so
//! `sig` must reproduce byte-for-byte from the seed; commitments must reproduce from value+nonce.

use averin_decision_core::canon::CanonValue;
use averin_decision_core::commit::{commit, verify_commitment, FieldDomain};
use averin_decision_core::record::{seal, verify_sealed, verify_signature};
use averin_decision_core::sign::{decode_pubkey, signing_key_from_seed};
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec")
        .join("golden-vectors")
}

fn manifest() -> CanonValue {
    let p = vectors_dir().join("sign-vectors.json");
    let text = std::fs::read_to_string(&p).unwrap();
    CanonValue::parse(&text).unwrap()
}

fn decode_hex(s: &str) -> Vec<u8> {
    fn v(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex"),
        }
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| (v(p[0]) << 4) | v(p[1]))
        .collect()
}

#[test]
fn signing_vector_reproduces_and_verifies() {
    let m = manifest();
    let seed: [u8; 32] = decode_hex(m.get("seed_hex").unwrap().as_str().unwrap())
        .try_into()
        .unwrap();
    let body_text = m.get("record_body").unwrap().as_str().unwrap();
    let expected_ch = m.get("content_hash").unwrap().as_str().unwrap();
    let expected_sig = m.get("sig").unwrap().as_str().unwrap();
    let pubkey = m.get("pubkey").unwrap().as_str().unwrap();

    let sk = signing_key_from_seed(&seed);
    let body = CanonValue::parse(body_text).unwrap();
    let sealed = seal(&body, &sk).unwrap();

    // deterministic reproduction
    assert_eq!(
        sealed.get("content_hash").unwrap().as_str().unwrap(),
        expected_ch
    );
    assert_eq!(
        sealed.get("sig").unwrap().as_str().unwrap(),
        expected_sig,
        "Ed25519 sig must reproduce byte-for-byte"
    );

    // verifies under the published public key
    let vk = decode_pubkey(pubkey).unwrap();
    assert!(verify_sealed(&sealed, &vk).is_ok());

    // tamper: change a body field -> content_hash check fails
    let tampered_text = body_text.replace("billing-agent", "evil-agent");
    let tampered = seal_unsigned_then_swap(&tampered_text, &sealed);
    assert!(verify_sealed(&tampered, &vk).is_err());
}

/// Build a record with a tampered body but the ORIGINAL content_hash/sig (simulating an attacker
/// editing the body after sealing) — verification must reject it.
fn seal_unsigned_then_swap(tampered_body: &str, sealed: &CanonValue) -> CanonValue {
    let body = CanonValue::parse(tampered_body).unwrap();
    let ch = sealed.get("content_hash").unwrap().clone();
    let sig = sealed.get("sig").unwrap().clone();
    let CanonValue::Object(mut m) = body else {
        panic!()
    };
    m.push(("content_hash".to_string(), ch));
    m.push(("sig".to_string(), sig));
    CanonValue::Object(m)
}

#[test]
fn verify_sealed_rejects_unknown_top_level_field() {
    let m = manifest();
    let body = CanonValue::parse(m.get("record_body").unwrap().as_str().unwrap()).unwrap();
    let sk = signing_key_from_seed(&[5u8; 32]);
    // attacker smuggles a semantically-meaningful field that was never schema-validated, then
    // (since they hold this dev key) re-seals so hash+sig are valid — shape check must still reject.
    let CanonValue::Object(mut members) = body else {
        panic!()
    };
    members.push((
        "ui_status".to_string(),
        CanonValue::Str("approved".to_string()),
    ));
    let smuggled = CanonValue::Object(members);
    let sealed = seal(&smuggled, &sk).unwrap();
    let vk = sk.verifying_key();
    // content_hash + signature alone would pass; verify_sealed rejects the unknown field.
    assert!(verify_signature(&sealed, &vk).is_ok());
    let err = verify_sealed(&sealed, &vk).unwrap_err();
    assert!(
        format!("{err}").contains("unknown top-level field"),
        "got: {err}"
    );
}

#[test]
fn verify_sealed_accepts_optional_record_kind() {
    // leria integration: the OPTIONAL typed top-level `record_kind` is in ALLOWED_TOP_KEYS, so a
    // record carrying it (a SIBLING of event_type, not a replacement) seals AND verifies — it must
    // NOT raise UnknownField. Both closed-set values are exercised; record_kind is signed (covered by
    // content_hash/sig — canon iterates object keys), so a verify over a chain containing it passes.
    let m = manifest();
    let sk = signing_key_from_seed(&[7u8; 32]);
    let vk = sk.verifying_key();
    for kind in ["budget-exhausted", "chargeback-posted"] {
        let body = CanonValue::parse(m.get("record_body").unwrap().as_str().unwrap()).unwrap();
        let CanonValue::Object(mut members) = body else {
            panic!()
        };
        members.push(("record_kind".to_string(), CanonValue::Str(kind.to_string())));
        let sealed = seal(&CanonValue::Object(members), &sk).unwrap();
        // record_kind is part of the signed body and survives the seal verbatim.
        assert_eq!(
            sealed.get("record_kind").unwrap().as_str().unwrap(),
            kind,
            "record_kind must be preserved through the seal preimage"
        );
        // verify_sealed must PASS (shape + content_hash + sig) — no UnknownField on record_kind.
        verify_sealed(&sealed, &vk)
            .unwrap_or_else(|e| panic!("record_kind={kind} should verify, got: {e}"));
    }
}

#[test]
fn wrong_key_fails_signature() {
    let m = manifest();
    let body = CanonValue::parse(m.get("record_body").unwrap().as_str().unwrap()).unwrap();
    let sk = signing_key_from_seed(&[0u8; 32]);
    let sealed = seal(&body, &sk).unwrap();
    let other_vk = signing_key_from_seed(&[99u8; 32]).verifying_key();
    assert!(verify_signature(&sealed, &other_vk).is_err());
}

#[test]
fn commitment_vector_reproduces() {
    let m = manifest();
    let c = m.get("commitment").unwrap();
    let value_hex = c.get("value_hex").unwrap().as_str().unwrap();
    let nonce_hex = c.get("nonce_hex").unwrap().as_str().unwrap();
    let expected = c.get("commitment").unwrap().as_str().unwrap();

    let value = decode_hex(value_hex);
    let nonce = decode_hex(nonce_hex);
    let computed = commit(FieldDomain::Input, &value, &nonce).unwrap();
    assert_eq!(computed, expected, "commitment must reproduce");
    assert!(verify_commitment(
        expected,
        FieldDomain::Input,
        &value,
        &nonce
    ));
}
