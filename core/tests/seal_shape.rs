//! SB-29: `record::seal` must reject every body that `verify_sealed` would reject on top-level
//! shape, `domain` or `canon_version`, so that `seal(b) == Ok` implies `verify_sealed(seal(b))`
//! succeeds; likewise `checkpoint::seal_checkpoint` against `verify_checkpoint_sealed` (the
//! `checkpoint_*` tests). Deterministic generator (no proptest dependency): every single defect on
//! the golden body, then pseudo-random combinations of defects from a fixed seed.

use averin_decision_core::canon::CanonValue;
use averin_decision_core::checkpoint::{
    checkpoint_body, seal_checkpoint, seal_checkpoint_with_mode, verify_checkpoint_sealed,
};
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
            // The shipped path serializes the sealed record and verifiers parse it back.
            let reparsed = CanonValue::parse(&sealed.serialize()).expect("sealed record reparses");
            assert_eq!(
                verify_sealed(&reparsed, &vk),
                Ok(()),
                "serialize/parse round trip of a sealed record fails verify_sealed ({what})"
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

/// The shadow-mode tests read and bump the process-wide `seal_shape_violations` counter, shared by
/// records and checkpoints; they hold this lock so a parallel test cannot move it in between.
static SHADOW_COUNTER: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn shadow_mode_seals_a_bad_body_and_counts_it() {
    let _guard = SHADOW_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
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

/// Mechanical guard: the only public seal entry points in core/src are the checked ones. The old
/// public, doc-hidden `seal_unchecked_for_tests` bypass is gone; tests that need a record every
/// verifier rejects build it from the public hash and sign primitives (`hostile_seal` in sign.rs and
/// adversarial.rs), as a hostile key holder could.
#[test]
fn only_checked_seal_entry_points_are_public() {
    const ALLOWED: [&str; 5] = [
        "seal",
        "seal_with_mode",
        "seal_shape_violations",
        "seal_checkpoint",
        "seal_checkpoint_with_mode",
    ];
    fn walk(dir: &std::path::Path, hits: &mut Vec<String>, seen: &mut usize) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, hits, seen);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).unwrap();
                for (i, l) in text.lines().enumerate() {
                    let Some(rest) = l.trim_start().strip_prefix("pub fn seal") else {
                        continue;
                    };
                    let tail: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    let name = format!("seal{tail}");
                    *seen += 1;
                    if !ALLOWED.contains(&name.as_str()) {
                        hits.push(format!("{}:{}: {name}", p.display(), i + 1));
                    }
                }
            }
        }
    }
    let (mut hits, mut seen) = (Vec::new(), 0);
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut hits,
        &mut seen,
    );
    assert!(
        hits.is_empty(),
        "public seal entry point outside the checked set: {hits:?}"
    );
    // Not vacuous: the scan must find every allowed entry point.
    assert_eq!(
        seen,
        ALLOWED.len(),
        "expected exactly the checked public seal functions"
    );
}

// ---- checkpoints: the checkpoint half of SB-29 (backlog AV-04) ---------------------------------
//
// `checkpoint::seal_checkpoint` must reject every body that `verify_checkpoint_sealed` would reject on
// its per-checkpoint pins (`domain` and `canon_version`), so that `seal_checkpoint(b) == Ok` implies
// `verify_checkpoint_sealed(seal_checkpoint(b))` succeeds. Same generator shape as the record half:
// every single defect on a golden checkpoint body, then seeded random combinations.

fn golden_checkpoint() -> Vec<(String, CanonValue)> {
    let key = CanonValue::object(vec![
        ("signing_key_id".into(), CanonValue::string("k0")),
        ("key_epoch".into(), CanonValue::Int(0)),
        (
            "key_valid_from".into(),
            CanonValue::string("2026-01-01T00:00:00.000Z"),
        ),
        ("key_status".into(), CanonValue::string("active")),
    ])
    .unwrap();
    let head = format!("sha256:{}", "ab".repeat(32));
    match checkpoint_body(
        "cp-p-0",
        "p",
        0,
        None,
        &[head],
        1,
        "2026-01-01T00:00:00.000Z",
        key,
    )
    .unwrap()
    {
        CanonValue::Object(members) => members,
        _ => panic!("checkpoint_body is not an object"),
    }
}

const CHECKPOINT_BODY_KEYS: &[&str] = &[
    "schema_version",
    "checkpoint_id",
    "project_id",
    "checkpoint_seq",
    "prev_checkpoint_hash",
    "frontier",
    "record_count",
    "created_ts",
    "key",
];

#[derive(Clone, Debug)]
enum CpDefect {
    Domain(&'static str),
    CanonVersion(&'static str),
    DomainNotString,
    CanonVersionNotString,
    DropDomain,
    DropCanonVersion,
    HashPresent,
    SigPresent,
    AnchorPresent,
    ExtraKey(&'static str),
    DropKey(&'static str),
}

fn cp_apply(members: &mut Vec<(String, CanonValue)>, d: &CpDefect) {
    let set = |m: &mut Vec<(String, CanonValue)>, k: &str, v: CanonValue| {
        if let Some(slot) = m.iter_mut().find(|(n, _)| n == k) {
            slot.1 = v;
        } else {
            m.push((k.to_string(), v));
        }
    };
    match d {
        CpDefect::Domain(v) => set(members, "domain", CanonValue::string(*v)),
        CpDefect::CanonVersion(v) => set(members, "canon_version", CanonValue::string(*v)),
        CpDefect::DomainNotString => set(members, "domain", CanonValue::Int(2)),
        CpDefect::CanonVersionNotString => set(members, "canon_version", CanonValue::Null),
        CpDefect::DropDomain => members.retain(|(n, _)| n != "domain"),
        CpDefect::DropCanonVersion => members.retain(|(n, _)| n != "canon_version"),
        CpDefect::HashPresent => set(members, "checkpoint_hash", CanonValue::string("sha256:00")),
        CpDefect::SigPresent => set(members, "sig", CanonValue::string("ed25519:00")),
        CpDefect::AnchorPresent => set(members, "anchor", CanonValue::string("x")),
        CpDefect::ExtraKey(k) => set(members, k, CanonValue::string("x")),
        CpDefect::DropKey(k) => members.retain(|(n, _)| n != k),
    }
}

fn cp_all_defects() -> Vec<CpDefect> {
    let mut v = vec![
        CpDefect::Domain("flightrecorder.record.v2"),
        CpDefect::Domain("flightrecorder.checkpoint.v1"),
        CpDefect::Domain("Flightrecorder.checkpoint.v2"),
        CpDefect::Domain(""),
        CpDefect::CanonVersion("rcp-2"),
        CpDefect::CanonVersion(""),
        CpDefect::DomainNotString,
        CpDefect::CanonVersionNotString,
        CpDefect::DropDomain,
        CpDefect::DropCanonVersion,
        CpDefect::HashPresent,
        CpDefect::SigPresent,
        CpDefect::AnchorPresent,
        CpDefect::ExtraKey("broker_grant_head"),
        CpDefect::ExtraKey("ui_status"),
    ];
    v.extend(CHECKPOINT_BODY_KEYS.iter().map(|k| CpDefect::DropKey(k)));
    v
}

fn checkpoint_with(defects: &[CpDefect]) -> CanonValue {
    let mut m = golden_checkpoint();
    for d in defects {
        cp_apply(&mut m, d);
    }
    CanonValue::Object(m)
}

fn checkpoint_implication(body: &CanonValue, what: &str) -> bool {
    let sk = signing_key_from_seed(&[9u8; 32]);
    let vk = sk.verifying_key();
    match seal_checkpoint(body, &sk) {
        Ok(sealed) => {
            assert_eq!(
                verify_checkpoint_sealed(&sealed, &vk),
                Ok(()),
                "seal_checkpoint accepted a body verify_checkpoint_sealed rejects ({what}): {}",
                body.serialize()
            );
            let reparsed =
                CanonValue::parse(&sealed.serialize()).expect("sealed checkpoint reparses");
            assert_eq!(
                verify_checkpoint_sealed(&reparsed, &vk),
                Ok(()),
                "serialize/parse round trip of a sealed checkpoint fails verify_checkpoint_sealed ({what})"
            );
            true
        }
        Err(_) => false,
    }
}

#[test]
fn checkpoint_golden_body_seals_and_verifies() {
    assert!(checkpoint_implication(&checkpoint_with(&[]), "golden"));
}

#[test]
fn checkpoint_every_single_defect_keeps_the_implication() {
    let mut rejected = 0;
    for d in cp_all_defects() {
        if !checkpoint_implication(
            &checkpoint_with(std::slice::from_ref(&d)),
            &format!("{d:?}"),
        ) {
            rejected += 1;
        }
    }
    // Not vacuous: the four wrong domains, two wrong canon_versions, two non-strings and two drops.
    assert!(rejected >= 10, "only {rejected} defect bodies were refused");
}

#[test]
fn checkpoint_named_defects_are_refused() {
    let sk = signing_key_from_seed(&[9u8; 32]);
    for d in [
        CpDefect::Domain("flightrecorder.record.v2"),
        CpDefect::Domain("flightrecorder.checkpoint.v1"),
        CpDefect::CanonVersion("rcp-2"),
    ] {
        assert!(
            seal_checkpoint(&checkpoint_with(std::slice::from_ref(&d)), &sk).is_err(),
            "{d:?} must be refused"
        );
    }
}

#[test]
fn checkpoint_random_defect_combinations_keep_the_implication() {
    let defects = cp_all_defects();
    let mut x: u64 = 0xD1B5_4A32_D192_ED03;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let (mut ok, mut refused) = (0, 0);
    for _ in 0..600 {
        let n = (next() % 4) as usize;
        let picked: Vec<CpDefect> = (0..n)
            .map(|_| defects[(next() % defects.len() as u64) as usize].clone())
            .collect();
        if checkpoint_implication(&checkpoint_with(&picked), &format!("{picked:?}")) {
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
fn checkpoint_shadow_mode_seals_a_bad_body_and_counts_it() {
    let _guard = SHADOW_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    let sk = signing_key_from_seed(&[9u8; 32]);
    let vk = sk.verifying_key();
    let bad = checkpoint_with(&[CpDefect::Domain("flightrecorder.record.v2")]);
    let before = seal_shape_violations();
    let sealed =
        seal_checkpoint_with_mode(&bad, &sk, SealShapeMode::Shadow).expect("shadow seals anyway");
    assert_eq!(seal_shape_violations(), before + 1);
    assert!(verify_checkpoint_sealed(&sealed, &vk).is_err());
    let good =
        seal_checkpoint_with_mode(&checkpoint_with(&[]), &sk, SealShapeMode::Shadow).unwrap();
    assert_eq!(
        seal_shape_violations(),
        before + 1,
        "a conforming body is not counted"
    );
    assert_eq!(verify_checkpoint_sealed(&good, &vk), Ok(()));
    assert!(seal_checkpoint_with_mode(&bad, &sk, SealShapeMode::Enforce).is_err());
    assert_eq!(seal_shape_violations(), before + 1, "enforce never counts");
}
