//! SB-29: `record::seal` must reject every body that `verify_sealed` would reject on top-level
//! shape, `domain` or `canon_version`, so that `seal(b) == Ok` implies `verify_sealed(seal(b))`
//! succeeds. Deterministic generator (no proptest dependency): every single defect on the golden
//! body, then pseudo-random combinations of defects from a fixed seed.

use averin_decision_core::canon::CanonValue;
use averin_decision_core::record::{
    seal, seal_shape_violations, seal_with_mode, verify_sealed, SealShapeMode, ALLOWED_TOP_KEYS,
    REQUIRED_TOP_KEYS,
};
use averin_decision_core::sign::signing_key_from_seed;

fn golden_body() -> Vec<(String, CanonValue)> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec/golden-vectors/sign-vectors.json");
    let m = CanonValue::parse(&std::fs::read_to_string(p).unwrap()).unwrap();
    let body = CanonValue::parse(m.get("record_body").unwrap().as_str().unwrap()).unwrap();
    match body {
        CanonValue::Object(members) => members,
        _ => panic!("golden record_body is not an object"),
    }
}

#[derive(Clone, Debug)]
enum Defect {
    UnknownKey(&'static str),
    DropKey(&'static str),
    Domain(&'static str),
    CanonVersion(&'static str),
    DomainNotString,
    DropDomain,
    ContentHashPresent,
    AddAllowedKey(&'static str),
}

fn apply(members: &mut Vec<(String, CanonValue)>, d: &Defect) {
    let set = |m: &mut Vec<(String, CanonValue)>, k: &str, v: CanonValue| {
        if let Some(slot) = m.iter_mut().find(|(n, _)| n == k) {
            slot.1 = v;
        } else {
            m.push((k.to_string(), v));
        }
    };
    match d {
        Defect::UnknownKey(k) => set(members, k, CanonValue::string("x")),
        Defect::DropKey(k) => members.retain(|(n, _)| n != k),
        Defect::Domain(v) => set(members, "domain", CanonValue::string(*v)),
        Defect::CanonVersion(v) => set(members, "canon_version", CanonValue::string(*v)),
        Defect::DomainNotString => set(members, "domain", CanonValue::Int(2)),
        Defect::DropDomain => members.retain(|(n, _)| n != "domain"),
        Defect::ContentHashPresent => set(members, "content_hash", CanonValue::string("sha256:00")),
        Defect::AddAllowedKey(k) => set(members, k, CanonValue::Null),
    }
}

fn all_defects() -> Vec<Defect> {
    let mut v = vec![
        Defect::UnknownKey("ui_status"),
        Defect::UnknownKey("Domain"),
        Defect::UnknownKey(""),
        Defect::Domain("flightrecorder.record.v1"),
        Defect::Domain(""),
        Defect::Domain("flightrecorder.checkpoint.v2"),
        Defect::CanonVersion("rcp-2"),
        Defect::CanonVersion(""),
        Defect::DomainNotString,
        Defect::DropDomain,
        Defect::ContentHashPresent,
    ];
    v.extend(REQUIRED_TOP_KEYS.iter().map(|k| Defect::DropKey(k)));
    v.extend(ALLOWED_TOP_KEYS.iter().map(|k| Defect::AddAllowedKey(k)));
    v
}

fn body_with(defects: &[Defect]) -> CanonValue {
    let mut m = golden_body();
    for d in defects {
        apply(&mut m, d);
    }
    CanonValue::Object(m)
}

fn check_implication(body: &CanonValue, what: &str) -> bool {
    let sk = signing_key_from_seed(&[9u8; 32]);
    let vk = sk.verifying_key();
    match seal(body, &sk) {
        Ok(sealed) => {
            assert_eq!(
                verify_sealed(&sealed, &vk),
                Ok(()),
                "seal accepted a body verify_sealed rejects ({what}): {}",
                body.serialize()
            );
            true
        }
        Err(_) => false,
    }
}

#[test]
fn golden_body_seals_and_verifies() {
    assert!(check_implication(&body_with(&[]), "golden"));
}

#[test]
fn every_single_defect_keeps_the_implication() {
    let mut rejected = 0;
    for d in all_defects() {
        if !check_implication(&body_with(std::slice::from_ref(&d)), &format!("{d:?}")) {
            rejected += 1;
        }
    }
    // Not vacuous: unknown keys, dropped required keys and wrong domains must really be refused.
    assert!(rejected >= 20, "only {rejected} defect bodies were refused");
}

#[test]
fn named_defects_are_refused() {
    let sk = signing_key_from_seed(&[9u8; 32]);
    for d in [
        Defect::UnknownKey("ui_status"),
        Defect::DropKey("record_id"),
        Defect::Domain("flightrecorder.record.v1"),
        Defect::CanonVersion("rcp-2"),
    ] {
        assert!(
            seal(&body_with(std::slice::from_ref(&d)), &sk).is_err(),
            "{d:?} must be refused"
        );
    }
}

#[test]
fn random_defect_combinations_keep_the_implication() {
    let defects = all_defects();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let (mut ok, mut refused) = (0, 0);
    for _ in 0..600 {
        let n = (next() % 4) as usize;
        let picked: Vec<Defect> = (0..n)
            .map(|_| defects[(next() % defects.len() as u64) as usize].clone())
            .collect();
        if check_implication(&body_with(&picked), &format!("{picked:?}")) {
            ok += 1;
        } else {
            refused += 1;
        }
    }
    assert!(
        ok > 0 && refused > 0,
        "generator is one-sided: {ok} ok, {refused} refused"
    );
}

#[test]
fn non_object_body_is_refused() {
    let sk = signing_key_from_seed(&[9u8; 32]);
    assert!(seal(&CanonValue::Null, &sk).is_err());
    assert!(seal(&CanonValue::Int(1), &sk).is_err());
}

#[test]
fn shadow_mode_seals_a_bad_body_and_counts_it() {
    let sk = signing_key_from_seed(&[9u8; 32]);
    let bad = body_with(&[Defect::UnknownKey("ui_status")]);
    let before = seal_shape_violations();
    let sealed = seal_with_mode(&bad, &sk, SealShapeMode::Shadow).expect("shadow seals anyway");
    assert!(seal_shape_violations() > before);
    assert!(verify_sealed(&sealed, &sk.verifying_key()).is_err());
    let good_before = seal_shape_violations();
    seal_with_mode(&body_with(&[]), &sk, SealShapeMode::Shadow).unwrap();
    assert_eq!(seal_shape_violations(), good_before);
    assert!(seal_with_mode(&bad, &sk, SealShapeMode::Enforce).is_err());
}
