//! feir-ops#16: the verifier enforces canonical sets (`causal_prev_hashes`, checkpoint `frontier`) and the
//! closed member sets of the nested objects (RCP §6, §7, §10; decision-record.schema.json and
//! checkpoint.schema.json `additionalProperties:false`). `extensions` and the checkpoint `anchor` stay open.
//!
//! Bundles are built the way a hostile key holder would build them: hash and sign with the public
//! primitives, because `seal` refuses every body here (SB-29). Every new rejection is checked at three
//! levels: the per-object function (`verify_sealed` / `verify_checkpoint_sealed`), `verify_bundle_with`
//! with keys pinned and unpinned, and the shared cross-implementation vectors
//! (`spec/fixtures/canonical-shape-vectors.json`, replayed by the WASM and cgo tests too).

use averin_decision_core::anchor::{make_test_anchor, test_tsa_key};
use averin_decision_core::canon::CanonValue;
use averin_decision_core::checkpoint::{
    attach_anchor, checkpoint_body, compute_checkpoint_hash, validate_checkpoint_shape,
    verify_checkpoint_sealed, CheckpointError, ALLOWED_CHECKPOINT_KEYS,
    ALLOWED_CHECKPOINT_KEY_BLOCK_KEYS, ALLOWED_GRANT_HEAD_KEYS,
};
use averin_decision_core::record::{
    compute_content_hash, validate_record_shape, verify_sealed, RecordError,
    ALLOWED_AUTHORITY_KEYS, ALLOWED_COMMIT_KEYS, ALLOWED_CONTENT_KEYS, ALLOWED_KEY_BLOCK_KEYS,
    ALLOWED_POLICY_SNAPSHOT_REF_KEYS, ALLOWED_TOKENS_KEYS, COMMIT_FIELDS,
};
use averin_decision_core::sign::{
    encode_pubkey, sign, signing_key_from_seed, CHECKPOINT_SIG_TAG, RECORD_SIG_TAG,
};
use averin_decision_core::verify::{
    claim_verdict, report_to_canon, verify_bundle, verify_bundle_with, verify_bundle_with_json,
    ClaimVerdict, TrustedKey, VerifyOptions, VerifyReport,
};
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::path::PathBuf;

const PROJECT: &str = "proj-canon";
const TS: &str = "2026-06-15T10:00:00.000Z";

type Members = Vec<(String, CanonValue)>;

fn sk() -> SigningKey {
    signing_key_from_seed(&[0u8; 32])
}

fn parse(s: &str) -> CanonValue {
    CanonValue::parse(s).unwrap()
}

fn set(m: &mut Members, k: &str, v: CanonValue) {
    if let Some(slot) = m.iter_mut().find(|(n, _)| n == k) {
        slot.1 = v;
    } else {
        m.push((k.to_string(), v));
    }
}

fn key_block() -> CanonValue {
    parse(
        r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active","key_valid_from":"2026-01-01T00:00:00.000Z"}"#,
    )
}

/// A conforming record body (no hash or signature yet).
fn body(n: usize, session: &str, parents: &[String]) -> Members {
    let plist = parents
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(",");
    let v = parse(&format!(
        r#"{{"action":"db.query","agent_id":"a","agent_ts":"{TS}","agent_version":"1","canon_version":"rcp-1",
        "causal_prev_hashes":[{plist}],"display_seq":{n},"domain":"flightrecorder.record.v2","event_type":"tool_call",
        "key":{{"key_epoch":0,"key_status":"active","key_valid_from":"2026-01-01T00:00:00.000Z","signing_key_id":"k0"}},
        "observed_via":"sdk","parent_span_id":null,"project_id":"{PROJECT}","received_ts":"{TS}","record_id":"r{n}",
        "schema_version":"2","session_id":"{session}","span_id":"s{n}","status":"ok"}}"#
    ));
    v.as_object().unwrap().clone()
}

/// What a hostile key holder does: hash and sign any body with the public primitives.
fn hostile_seal(m: &Members) -> CanonValue {
    let b = CanonValue::Object(m.clone());
    let ch = compute_content_hash(&b).unwrap();
    let sig = sign(RECORD_SIG_TAG, &ch, &sk());
    let CanonValue::Object(mut out) = b.without_keys(&["content_hash", "sig"]) else {
        panic!()
    };
    out.push(("content_hash".into(), CanonValue::Str(ch)));
    out.push(("sig".into(), CanonValue::Str(sig)));
    CanonValue::Object(out)
}

fn hash(v: &CanonValue) -> String {
    v.get("content_hash").unwrap().as_str().unwrap().to_string()
}

/// Seal a checkpoint body with the public primitives (the body may break the shape rules).
fn hostile_cp(m: &Members) -> CanonValue {
    let b = CanonValue::Object(m.clone());
    let ch = compute_checkpoint_hash(&b).unwrap();
    let sig = sign(CHECKPOINT_SIG_TAG, &ch, &sk());
    let CanonValue::Object(mut out) = b.without_keys(&["checkpoint_hash", "sig", "anchor"]) else {
        panic!()
    };
    out.push(("checkpoint_hash".into(), CanonValue::Str(ch)));
    out.push(("sig".into(), CanonValue::Str(sig)));
    if let Some(a) = m.iter().find(|(k, _)| k == "anchor") {
        out.push(a.clone());
    }
    CanonValue::Object(out)
}

/// A conforming checkpoint body over `frontier` (as given: this helper does not sort it).
fn cp_members(frontier: &[String], count: i64) -> Members {
    let mut m = checkpoint_body("cp0", PROJECT, 0, None, &[], count, TS, key_block())
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    set(
        &mut m,
        "frontier",
        CanonValue::Array(frontier.iter().cloned().map(CanonValue::Str).collect()),
    );
    m
}

fn bundle(records: Vec<CanonValue>, cps: Vec<CanonValue>) -> CanonValue {
    CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::string("1")),
        ("project_id".into(), CanonValue::string(PROJECT)),
        (
            "keys".into(),
            parse(&format!(
                r#"[{{"key_epoch":0,"key_status":"active","public_key":"{}","signing_key_id":"k0"}}]"#,
                encode_pubkey(&sk().verifying_key())
            )),
        ),
        ("records".into(), CanonValue::Array(records)),
        ("checkpoints".into(), CanonValue::Array(cps)),
        ("disclosures".into(), CanonValue::Array(vec![])),
    ])
    .unwrap()
}

/// Two roots A and B, and a merge record C naming both. `edit` rewrites C's body before it is signed and
/// `parents` orders its parent list. One checkpoint, frontier `[C]`.
fn merge_bundle(
    parents: impl Fn(&str, &str) -> Vec<String>,
    edit: impl Fn(&mut Members),
) -> CanonValue {
    let a = hostile_seal(&body(0, "sa", &[]));
    let b = hostile_seal(&body(1, "sb", &[]));
    let mut c = body(2, "sc", &parents(&hash(&a), &hash(&b)));
    edit(&mut c);
    let c = hostile_seal(&c);
    let cp = hostile_cp(&cp_members(&[hash(&c)], 3));
    bundle(vec![a, b, c], vec![cp])
}

fn sorted_pair(a: &str, b: &str) -> Vec<String> {
    let mut v = vec![a.to_string(), b.to_string()];
    v.sort();
    v
}

/// Two independent roots A and B, both heads. `edit` rewrites the checkpoint body (frontier sorted
/// ascending before the edit) before it is signed.
fn heads_bundle(edit: impl Fn(&mut Members)) -> CanonValue {
    let a = hostile_seal(&body(0, "sa", &[]));
    let b = hostile_seal(&body(1, "sb", &[]));
    let mut m = cp_members(&sorted_pair(&hash(&a), &hash(&b)), 2);
    edit(&mut m);
    bundle(vec![a, b], vec![hostile_cp(&m)])
}

fn pinned() -> VerifyOptions {
    VerifyOptions {
        trusted_keys: Some(vec![TrustedKey::from(sk().verifying_key())]),
        ..Default::default()
    }
}

fn notes_and_issues(r: &VerifyReport) -> String {
    let mut all: Vec<String> = r.issues.clone();
    for t in &r.record_trust {
        all.extend(t.notes.iter().cloned());
    }
    all.join(" | ")
}

/// The report both with and without pinned keys: `ok` false, FAIL headline, the given counts, and `reason`
/// named in a note or an issue.
fn assert_rejected(
    b: &CanonValue,
    records_proven: usize,
    checkpoints_verified: usize,
    reason: &str,
) {
    for (label, r) in [
        ("pinned", verify_bundle_with(b, &pinned())),
        ("unpinned", verify_bundle(b)),
    ] {
        assert!(!r.ok, "{label}: must not be ok: {}", notes_and_issues(&r));
        assert_eq!(
            r.records_proven,
            records_proven,
            "{label}: {}",
            notes_and_issues(&r)
        );
        assert_eq!(
            r.checkpoints_verified,
            checkpoints_verified,
            "{label}: {}",
            notes_and_issues(&r)
        );
        assert!(
            notes_and_issues(&r).contains(reason),
            "{label}: expected {reason:?} in {}",
            notes_and_issues(&r)
        );
        assert_eq!(
            claim_verdict(&report_to_canon(&r)),
            ClaimVerdict::Fail,
            "{label}"
        );
    }
}

fn assert_accepted(b: &CanonValue, records_proven: usize, checkpoints_verified: usize) {
    for (label, r) in [
        ("pinned", verify_bundle_with(b, &pinned())),
        ("unpinned", verify_bundle(b)),
    ] {
        assert!(r.ok, "{label}: {}", notes_and_issues(&r));
        assert_eq!(r.records_proven, records_proven, "{label}");
        assert_eq!(r.checkpoints_verified, checkpoints_verified, "{label}");
    }
}

#[test]
fn the_baseline_bundles_verify() {
    assert_accepted(&merge_bundle(sorted_pair, |_| {}), 3, 1);
    assert_accepted(&heads_bundle(|_| {}), 2, 1);
}

// ---- R1: causal_prev_hashes ------------------------------------------------------------------------

fn rec_with_parents(parents: &[&str]) -> CanonValue {
    let p: Vec<String> = parents.iter().map(|s| s.to_string()).collect();
    hostile_seal(&body(0, "s", &p))
}

#[test]
fn r1_byte_order_is_the_order() {
    let nine = format!("sha256:9{}", "0".repeat(63));
    let a = format!("sha256:a{}", "0".repeat(63));
    // 0x39 < 0x61: digit before letter is ascending, the reverse is not.
    let ok = rec_with_parents(&[&nine, &a]);
    assert_eq!(validate_record_shape(&ok), Ok(()));
    assert_eq!(verify_sealed(&ok, &sk().verifying_key()), Ok(()));
    let rev = rec_with_parents(&[&a, &nine]);
    let want = Err(RecordError::NonCanonicalSet("causal_prev_hashes"));
    assert_eq!(validate_record_shape(&rev), want);
    assert_eq!(verify_sealed(&rev, &sk().verifying_key()), want);
    // empty and single parent sets conform
    assert_eq!(validate_record_shape(&rec_with_parents(&[])), Ok(()));
    assert_eq!(validate_record_shape(&rec_with_parents(&[&a])), Ok(()));
}

#[test]
fn r1_duplicate_parents_are_rejected() {
    let a = format!("sha256:a{}", "0".repeat(63));
    assert_eq!(
        validate_record_shape(&rec_with_parents(&[&a, &a])),
        Err(RecordError::NonCanonicalSet("causal_prev_hashes"))
    );
}

#[test]
fn r1_in_a_bundle_the_record_is_untrusted_and_the_verdict_fails() {
    let rev = |a: &str, b: &str| {
        let mut v = sorted_pair(a, b);
        v.reverse();
        v
    };
    let dup = |a: &str, _b: &str| vec![a.to_string(), a.to_string()];
    for p in [
        Box::new(rev) as Box<dyn Fn(&str, &str) -> Vec<String>>,
        Box::new(dup),
    ] {
        let b = merge_bundle(&*p, |_| {});
        // C is not proven; the checkpoint still verifies (its own shape is fine).
        assert_rejected(&b, 2, 1, "is not a canonical set");
        let r = verify_bundle_with(&b, &pinned());
        let c = &r.record_trust[2];
        assert!(!c.integrity_ok, "the offending record has no integrity");
    }
}

// ---- R3: nested closed member sets -----------------------------------------------------------------

/// (field path as set on the record, allowed members, builder that wraps an object into the record field).
struct Obj {
    name: &'static str,
    allowed: &'static [&'static str],
    /// Put `inner` (an object) where the closed set applies.
    put: fn(&mut Members, CanonValue),
}

fn put_top(field: &'static str) -> impl Fn(&mut Members, CanonValue) {
    move |m, v| set(m, field, v)
}

fn put_authority(m: &mut Members, v: CanonValue) {
    set(m, "authority", v);
}
fn put_snapshot_ref(m: &mut Members, v: CanonValue) {
    set(
        m,
        "authority",
        CanonValue::object(vec![("policy_snapshot_ref".into(), v)]).unwrap(),
    );
}
fn put_key(m: &mut Members, v: CanonValue) {
    set(m, "key", v);
}
fn put_content(m: &mut Members, v: CanonValue) {
    set(m, "content", v);
}
fn put_tokens(m: &mut Members, v: CanonValue) {
    set(m, "tokens", v);
}
fn put_input(m: &mut Members, v: CanonValue) {
    put_top("input_commit")(m, v);
}
fn put_output(m: &mut Members, v: CanonValue) {
    put_top("output_commit")(m, v);
}
fn put_rationale(m: &mut Members, v: CanonValue) {
    put_top("rationale_commit")(m, v);
}
fn put_credential(m: &mut Members, v: CanonValue) {
    put_top("credential_commit")(m, v);
}

fn objects() -> Vec<Obj> {
    vec![
        Obj {
            name: "authority",
            allowed: ALLOWED_AUTHORITY_KEYS,
            put: put_authority,
        },
        Obj {
            name: "authority.policy_snapshot_ref",
            allowed: ALLOWED_POLICY_SNAPSHOT_REF_KEYS,
            put: put_snapshot_ref,
        },
        Obj {
            name: "key",
            allowed: ALLOWED_KEY_BLOCK_KEYS,
            put: put_key,
        },
        Obj {
            name: "content",
            allowed: ALLOWED_CONTENT_KEYS,
            put: put_content,
        },
        Obj {
            name: "tokens",
            allowed: ALLOWED_TOKENS_KEYS,
            put: put_tokens,
        },
        Obj {
            name: "input_commit",
            allowed: ALLOWED_COMMIT_KEYS,
            put: put_input,
        },
        Obj {
            name: "output_commit",
            allowed: ALLOWED_COMMIT_KEYS,
            put: put_output,
        },
        Obj {
            name: "rationale_commit",
            allowed: ALLOWED_COMMIT_KEYS,
            put: put_rationale,
        },
        Obj {
            name: "credential_commit",
            allowed: ALLOWED_COMMIT_KEYS,
            put: put_credential,
        },
    ]
}

fn object_of(members: &[&str], extra: Option<&str>) -> CanonValue {
    let mut v: Vec<(String, CanonValue)> = members
        .iter()
        .map(|k| (k.to_string(), CanonValue::string("x")))
        .collect();
    if let Some(e) = extra {
        v.push((e.to_string(), CanonValue::string("x")));
    }
    CanonValue::object(v).unwrap()
}

/// The `key` object must still resolve to the pinned key (`k0` epoch 0) for the bundle-level checks.
fn key_obj(extra: Option<&str>, all: bool) -> CanonValue {
    if all {
        let mut v = vec![
            ("signing_key_id".to_string(), CanonValue::string("k0")),
            ("key_epoch".to_string(), CanonValue::Int(0)),
            ("key_status".to_string(), CanonValue::string("active")),
        ];
        for k in ALLOWED_KEY_BLOCK_KEYS {
            if !v.iter().any(|(n, _)| n == k) {
                v.push((k.to_string(), CanonValue::string("x")));
            }
        }
        return CanonValue::object(v).unwrap();
    }
    let CanonValue::Object(mut v) = key_block() else {
        panic!()
    };
    if let Some(e) = extra {
        v.push((e.to_string(), CanonValue::string("x")));
    }
    CanonValue::Object(v)
}

fn inner(o: &Obj, extra: Option<&str>, all: bool) -> CanonValue {
    if o.name == "key" {
        return key_obj(extra, all);
    }
    if all {
        object_of(o.allowed, extra)
    } else {
        object_of(&o.allowed[..1], extra)
    }
}

#[test]
fn r3_one_unknown_member_in_each_object_is_rejected() {
    for o in objects() {
        let mut m = body(0, "s", &[]);
        (o.put)(&mut m, inner(&o, Some("bogus"), false));
        let rec = hostile_seal(&m);
        let want = Err(RecordError::UnknownMember {
            object: o.name.to_string(),
            key: "bogus".to_string(),
        });
        assert_eq!(validate_record_shape(&rec), want, "{}", o.name);
        assert_eq!(
            verify_sealed(&rec, &sk().verifying_key()),
            want,
            "{}",
            o.name
        );
        // in a bundle: the head record C loses its integrity and the verdict is FAIL
        let b = merge_bundle(sorted_pair, |c| (o.put)(c, inner(&o, Some("bogus"), false)));
        assert_rejected(&b, 2, 1, "unknown member 'bogus'");
    }
}

#[test]
fn r3_every_allowed_member_is_accepted() {
    // Catches a list that is too narrow: each object carries ALL of its schema members.
    for o in objects() {
        let mut m = body(0, "s", &[]);
        (o.put)(&mut m, inner(&o, None, true));
        let rec = hostile_seal(&m);
        assert_eq!(validate_record_shape(&rec), Ok(()), "{}", o.name);
        assert_eq!(
            verify_sealed(&rec, &sk().verifying_key()),
            Ok(()),
            "{}",
            o.name
        );
    }
}

#[test]
fn r3_member_names_are_case_sensitive() {
    let mut m = body(0, "s", &[]);
    set(
        &mut m,
        "authority",
        CanonValue::object(vec![("Source".into(), CanonValue::string("x"))]).unwrap(),
    );
    assert_eq!(
        validate_record_shape(&hostile_seal(&m)),
        Err(RecordError::UnknownMember {
            object: "authority".into(),
            key: "Source".into()
        })
    );
}

#[test]
fn r3_rotation_prev_key_sig_is_a_record_key_member_not_a_checkpoint_one() {
    let mut m = body(0, "s", &[]);
    let CanonValue::Object(mut k) = key_block() else {
        panic!()
    };
    k.push(("rotation_prev_key_sig".into(), CanonValue::string("x")));
    set(&mut m, "key", CanonValue::Object(k.clone()));
    assert_eq!(validate_record_shape(&hostile_seal(&m)), Ok(()));
    // the checkpoint key block has no such member
    let mut cp = cp_members(&[], 0);
    set(&mut cp, "key", CanonValue::Object(k));
    assert_eq!(
        validate_checkpoint_shape(&CanonValue::Object(cp)),
        Err(RecordError::UnknownMember {
            object: "checkpoint key".into(),
            key: "rotation_prev_key_sig".into()
        })
    );
}

#[test]
fn r3_extensions_stay_open_and_non_objects_behave_as_before() {
    let mut m = body(0, "s", &[]);
    set(
        &mut m,
        "extensions",
        parse(r#"{"anything":{"goes":[1,{"deep":null}]},"Mixed":"Case"}"#),
    );
    assert_eq!(validate_record_shape(&hostile_seal(&m)), Ok(()));
    // a non-object authority hides no member: the closed-member rule does not apply (D11)
    let mut m = body(0, "s", &[]);
    set(&mut m, "authority", CanonValue::string("not an object"));
    assert_eq!(validate_record_shape(&hostile_seal(&m)), Ok(()));
}

// ---- R2, R4, R5: checkpoints -----------------------------------------------------------------------

fn hash_pair() -> (String, String) {
    let a = hash(&hostile_seal(&body(0, "sa", &[])));
    let b = hash(&hostile_seal(&body(1, "sb", &[])));
    (a, b)
}

fn strs(v: &[&str]) -> CanonValue {
    CanonValue::Array(v.iter().map(|s| CanonValue::string(*s)).collect())
}

#[test]
fn r2_frontier_byte_order_and_duplicates() {
    let nine = format!("sha256:9{}", "0".repeat(63));
    let a = format!("sha256:a{}", "0".repeat(63));
    let vk = sk().verifying_key();
    let ok = hostile_cp(&cp_members(&[nine.clone(), a.clone()], 2));
    assert_eq!(validate_checkpoint_shape(&ok), Ok(()));
    assert_eq!(verify_checkpoint_sealed(&ok, &vk), Ok(()));
    let want = RecordError::NonCanonicalSet("frontier");
    for f in [vec![a.clone(), nine.clone()], vec![a.clone(), a.clone()]] {
        let bad = hostile_cp(&cp_members(&f, 2));
        assert_eq!(validate_checkpoint_shape(&bad), Err(want.clone()));
        assert_eq!(
            verify_checkpoint_sealed(&bad, &vk),
            Err(CheckpointError::Shape(want.clone()))
        );
    }
    // empty and single-member frontiers conform
    assert_eq!(
        validate_checkpoint_shape(&hostile_cp(&cp_members(&[], 0))),
        Ok(())
    );
    assert_eq!(
        validate_checkpoint_shape(&hostile_cp(&cp_members(&[a], 1))),
        Ok(())
    );
}

#[test]
fn r2_in_a_bundle_the_checkpoint_is_not_verified() {
    let (a, b) = hash_pair();
    let rev = [a.clone().max(b.clone()), a.clone().min(b.clone())];
    let b1 = heads_bundle(|m| {
        set(
            m,
            "frontier",
            CanonValue::Array(rev.iter().cloned().map(CanonValue::Str).collect()),
        )
    });
    assert_rejected(&b1, 2, 0, "checkpoint 0 invalid: checkpoint shape");
    let dup = heads_bundle(|m| {
        set(
            m,
            "frontier",
            CanonValue::Array(vec![CanonValue::Str(a.clone()); 2]),
        )
    });
    assert_rejected(&dup, 2, 0, "is not a canonical set");
}

#[test]
fn r4_unknown_top_level_checkpoint_member() {
    let b = heads_bundle(|m| set(m, "ui_status", CanonValue::string("x")));
    assert_rejected(&b, 2, 0, "unknown member 'ui_status' in checkpoint");
    // an unknown member is rejected even when it is null
    let b = heads_bundle(|m| set(m, "extensions", CanonValue::Null));
    assert_rejected(&b, 2, 0, "unknown member 'extensions' in checkpoint");
}

#[test]
fn r5_unknown_member_in_key_and_grant_heads() {
    let b = heads_bundle(|m| {
        let CanonValue::Object(mut k) = key_block() else {
            panic!()
        };
        k.push(("bogus".into(), CanonValue::Int(1)));
        set(m, "key", CanonValue::Object(k));
    });
    assert_rejected(&b, 2, 0, "unknown member 'bogus' in checkpoint key");
    let b = heads_bundle(|m| {
        set(m, "broker_grant_head", parse(r#"{"max_seq":1,"bogus":1}"#));
    });
    assert_rejected(&b, 2, 0, "unknown member 'bogus' in broker_grant_head");
    let b = heads_bundle(|m| {
        set(
            m,
            "broker_grant_heads",
            parse(r#"{"b1":{"max_seq":1},"b2":{"zzz":1}}"#),
        );
    });
    assert_rejected(&b, 2, 0, "unknown member 'zzz' in broker_grant_heads entry");
}

#[test]
fn checkpoint_positives_broker_heads_and_open_anchor() {
    // broker_grant_heads keyed by two arbitrary broker ids, each with every grant-head member
    let one = format!(
        r#"{{"max_seq":1,"prior_head_hash":"sha256:{}","cumulative_root":"sha256:{}"}}"#,
        "0".repeat(64),
        "1".repeat(64)
    );
    let b = heads_bundle(|m| {
        set(
            m,
            "broker_grant_heads",
            parse(&format!(r#"{{"broker-A":{one},"broker-Z":{one}}}"#)),
        );
        set(m, "broker_grant_head", parse(&one));
    });
    let r = verify_bundle(&b);
    assert_eq!(r.checkpoints_verified, 1, "{}", notes_and_issues(&r));
    // every key-block and checkpoint member admitted
    for k in ALLOWED_CHECKPOINT_KEY_BLOCK_KEYS {
        assert!(!k.is_empty());
    }
    // anchor: open. tsa_key_id and an unknown extra member are admitted
    let tsa = test_tsa_key(&[7u8; 32]);
    let cp = cp_members(
        &{
            let (a, b) = hash_pair();
            sorted_pair(&a, &b)
        },
        2,
    );
    let sealed = hostile_cp(&cp);
    let h = sealed
        .get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let anchor = make_test_anchor(&h, "2026-06-15T10:05:00.000Z", &tsa, "test-tsa");
    let CanonValue::Object(mut am) = anchor else {
        panic!()
    };
    am.push(("surplus".into(), CanonValue::string("open by design")));
    let anchored = attach_anchor(&sealed, CanonValue::Object(am));
    assert_eq!(validate_checkpoint_shape(&anchored), Ok(()));
    assert_eq!(
        verify_checkpoint_sealed(&anchored, &sk().verifying_key()),
        Ok(())
    );
}

#[test]
fn an_anchored_checkpoint_that_breaks_the_set_rule_does_not_count_as_anchored() {
    let tsa = test_tsa_key(&[7u8; 32]);
    let (a, b) = hash_pair();
    let rev = [a.clone().max(b.clone()), a.clone().min(b.clone())];
    let ra = hostile_seal(&body(0, "sa", &[]));
    let rb = hostile_seal(&body(1, "sb", &[]));
    let build = |frontier: &[String]| {
        let sealed = hostile_cp(&cp_members(frontier, 2));
        let h = sealed
            .get("checkpoint_hash")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let anchor = make_test_anchor(&h, "2026-06-15T10:05:00.000Z", &tsa, "test-tsa");
        bundle(
            vec![ra.clone(), rb.clone()],
            vec![attach_anchor(&sealed, anchor)],
        )
    };
    let opts = VerifyOptions {
        trusted_tsa_keys: vec![tsa.verifying_key()],
        ..pinned()
    };
    let good = verify_bundle_with(&build(&sorted_pair(&a, &b)), &opts);
    assert_eq!(good.checkpoints_anchored, 1, "{}", notes_and_issues(&good));
    let bad = verify_bundle_with(&build(&rev), &opts);
    assert_eq!(bad.checkpoints_verified, 0);
    assert_eq!(
        bad.checkpoints_anchored, 0,
        "an unverified checkpoint honors no anchor"
    );
    assert!(!bad.ok);
}

// ---- segments --------------------------------------------------------------------------------------

#[test]
fn a_segment_whose_carried_base_checkpoint_has_an_unsorted_frontier_fails() {
    use averin_decision_core::segment::split_bundle;
    // Month one: two independent roots (frontier of two). Month two: each root gets a child.
    let (r0, r1) = (
        hostile_seal(&{
            let mut m = body(0, "sa", &[]);
            set(
                &mut m,
                "received_ts",
                CanonValue::string("2026-06-10T10:00:00.000Z"),
            );
            m
        }),
        hostile_seal(&{
            let mut m = body(1, "sb", &[]);
            set(
                &mut m,
                "received_ts",
                CanonValue::string("2026-06-10T10:01:00.000Z"),
            );
            m
        }),
    );
    let child = |n: usize, sess: &str, parent: &CanonValue| {
        let mut m = body(n, sess, &[hash(parent)]);
        set(
            &mut m,
            "received_ts",
            CanonValue::string("2026-07-10T10:00:00.000Z"),
        );
        hostile_seal(&m)
    };
    let (c0, c1) = (child(2, "sa", &r0), child(3, "sb", &r1));
    let build = |unsort_base: bool| {
        let mut f1 = sorted_pair(&hash(&r0), &hash(&r1));
        if unsort_base {
            f1.reverse();
        }
        let mut m1 = cp_members(&f1, 2);
        set(
            &mut m1,
            "created_ts",
            CanonValue::string("2026-06-28T12:00:00.000Z"),
        );
        let cp1 = hostile_cp(&m1);
        let mut m2 = checkpoint_body(
            "cp1",
            PROJECT,
            1,
            Some(cp1.get("checkpoint_hash").unwrap().as_str().unwrap()),
            &[hash(&c0), hash(&c1)],
            4,
            "2026-07-28T12:00:00.000Z",
            key_block(),
        )
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
        set(&mut m2, "checkpoint_id", CanonValue::string("cp1"));
        let cp2 = hostile_cp(&m2);
        bundle(
            vec![r0.clone(), r1.clone(), c0.clone(), c1.clone()],
            vec![cp1, cp2],
        )
    };
    let whole_ok = verify_bundle_with(&build(false), &pinned());
    assert!(whole_ok.ok, "{}", notes_and_issues(&whole_ok));
    let segs = split_bundle(&build(false)).expect("split of the conforming history");
    let july = &segs.iter().find(|(m, _)| m == "2026-07").unwrap().1;
    let r = verify_bundle_with(july, &pinned());
    assert!(r.ok, "conforming July segment: {}", notes_and_issues(&r));
    // The same history with an unsorted base frontier: whole history and any month carrying that base fail.
    let bad_whole = verify_bundle_with(&build(true), &pinned());
    assert!(!bad_whole.ok);
    assert!(
        notes_and_issues(&bad_whole).contains("checkpoint 0 invalid: checkpoint shape"),
        "{}",
        notes_and_issues(&bad_whole)
    );
    if let Ok(segs) = split_bundle(&build(true)) {
        for (m, s) in segs {
            let r = verify_bundle_with(&s, &pinned());
            assert!(
                !r.ok,
                "segment {m} carrying a non-canonical checkpoint must fail"
            );
        }
    }
}

// ---- spec parity: every list equals its schema `properties` set ------------------------------------

fn schema(file: &str) -> CanonValue {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec")
        .join(file);
    CanonValue::parse(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn prop_keys(root: &CanonValue, path: &[&str]) -> BTreeSet<String> {
    let mut v = root;
    for step in path {
        v = v
            .get(step)
            .unwrap_or_else(|| panic!("schema path {path:?}: no {step}"));
    }
    v.get("properties")
        .and_then(|p| p.as_object())
        .unwrap_or_else(|| panic!("schema path {path:?}: no properties"))
        .iter()
        .map(|(k, _)| k.clone())
        .collect()
}

fn set_of(l: &[&str]) -> BTreeSet<String> {
    l.iter().map(|s| s.to_string()).collect()
}

#[test]
fn every_list_equals_its_schema_member_set() {
    let rec = schema("decision-record.schema.json");
    assert_eq!(
        prop_keys(&rec, &["properties", "authority"]),
        set_of(ALLOWED_AUTHORITY_KEYS)
    );
    assert_eq!(
        prop_keys(
            &rec,
            &[
                "properties",
                "authority",
                "properties",
                "policy_snapshot_ref"
            ]
        ),
        set_of(ALLOWED_POLICY_SNAPSHOT_REF_KEYS)
    );
    assert_eq!(
        prop_keys(&rec, &["properties", "key"]),
        set_of(ALLOWED_KEY_BLOCK_KEYS)
    );
    assert_eq!(
        prop_keys(&rec, &["properties", "content"]),
        set_of(ALLOWED_CONTENT_KEYS)
    );
    assert_eq!(
        prop_keys(&rec, &["properties", "tokens"]),
        set_of(ALLOWED_TOKENS_KEYS)
    );
    assert_eq!(
        prop_keys(&rec, &["$defs", "commit"]),
        set_of(ALLOWED_COMMIT_KEYS)
    );
    for f in COMMIT_FIELDS {
        let r = rec
            .get("properties")
            .unwrap()
            .get(f)
            .unwrap()
            .get("$ref")
            .unwrap();
        assert_eq!(
            r.as_str(),
            Some("#/$defs/commit"),
            "{f} must reference the commit definition"
        );
    }
    // each of these objects is closed in the schema
    for path in [
        vec!["properties", "authority"],
        vec!["properties", "key"],
        vec!["properties", "content"],
        vec!["properties", "tokens"],
        vec!["$defs", "commit"],
    ] {
        let mut v = &rec;
        for s in &path {
            v = v.get(s).unwrap();
        }
        assert_eq!(
            v.get("additionalProperties"),
            Some(&CanonValue::Bool(false)),
            "{path:?}"
        );
    }

    let cp = schema("checkpoint.schema.json");
    assert_eq!(prop_keys(&cp, &[]), set_of(ALLOWED_CHECKPOINT_KEYS));
    assert_eq!(
        prop_keys(&cp, &["properties", "key"]),
        set_of(ALLOWED_CHECKPOINT_KEY_BLOCK_KEYS)
    );
    assert_eq!(
        prop_keys(&cp, &["$defs", "grant_head"]),
        set_of(ALLOWED_GRANT_HEAD_KEYS)
    );
    let props = cp.get("properties").unwrap();
    assert_eq!(
        props
            .get("broker_grant_head")
            .unwrap()
            .get("$ref")
            .unwrap()
            .as_str(),
        Some("#/$defs/grant_head")
    );
    assert_eq!(
        props
            .get("broker_grant_heads")
            .unwrap()
            .get("additionalProperties")
            .unwrap()
            .get("$ref")
            .unwrap()
            .as_str(),
        Some("#/$defs/grant_head")
    );
    // the anchor is open by design (D3)
    assert_eq!(
        props.get("anchor").unwrap().get("additionalProperties"),
        Some(&CanonValue::Bool(true))
    );
    assert!(prop_keys(&cp, &["properties", "anchor"]).contains("tsa_key_id"));
}

// ---- cross-implementation vectors ------------------------------------------------------------------

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec/fixtures/canonical-shape-vectors.json")
}

/// (name, bundle) rows: one per rule, plus the positives.
fn vector_rows() -> Vec<(String, CanonValue)> {
    let mut rows: Vec<(String, CanonValue)> = Vec::new();
    let mut add = |n: &str, b: CanonValue| rows.push((n.to_string(), b));
    add("baseline_merge", merge_bundle(sorted_pair, |_| {}));
    add("baseline_two_heads", heads_bundle(|_| {}));
    add(
        "r1_parents_unsorted",
        merge_bundle(
            |a, b| {
                let mut v = sorted_pair(a, b);
                v.reverse();
                v
            },
            |_| {},
        ),
    );
    add(
        "r1_parents_duplicated",
        merge_bundle(|a, _| vec![a.to_string(), a.to_string()], |_| {}),
    );
    for o in objects() {
        add(
            &format!("r3_unknown_member_in_{}", o.name.replace('.', "_")),
            merge_bundle(sorted_pair, |c| (o.put)(c, inner(&o, Some("bogus"), false))),
        );
    }
    add(
        "r3_extensions_open",
        merge_bundle(sorted_pair, |c| {
            set(
                c,
                "extensions",
                parse(r#"{"any":{"thing":[1,2,{"x":null}]}}"#),
            )
        }),
    );
    let (a, b) = hash_pair();
    let rev = [a.clone().max(b.clone()), a.clone().min(b.clone())];
    add(
        "r2_frontier_unsorted",
        heads_bundle(|m| {
            set(
                m,
                "frontier",
                CanonValue::Array(rev.iter().cloned().map(CanonValue::Str).collect()),
            )
        }),
    );
    add(
        "r2_frontier_duplicated",
        heads_bundle(|m| {
            set(
                m,
                "frontier",
                CanonValue::Array(vec![CanonValue::Str(a.clone()); 2]),
            )
        }),
    );
    add(
        "r4_checkpoint_unknown_member",
        heads_bundle(|m| set(m, "ui_status", strs(&["x"]))),
    );
    add(
        "r5_checkpoint_key_unknown_member",
        heads_bundle(|m| {
            let CanonValue::Object(mut k) = key_block() else {
                panic!()
            };
            k.push(("bogus".into(), CanonValue::Int(1)));
            set(m, "key", CanonValue::Object(k));
        }),
    );
    add(
        "r5_broker_grant_heads_entry_unknown_member",
        heads_bundle(|m| {
            set(
                m,
                "broker_grant_heads",
                parse(r#"{"b1":{"max_seq":1,"zzz":1}}"#),
            )
        }),
    );
    add(
        "r5_broker_grant_heads_two_brokers_ok",
        heads_bundle(|m| {
            set(
                m,
                "broker_grant_heads",
                parse(r#"{"broker-A":{"max_seq":1},"broker-Z":{"max_seq":2}}"#),
            )
        }),
    );
    rows
}

fn opts_json() -> String {
    format!(
        r#"{{"signing_keys":["{}"]}}"#,
        encode_pubkey(&sk().verifying_key())
    )
}

fn expect_of(r: &CanonValue) -> (bool, i64, i64) {
    (
        matches!(r.get("ok"), Some(CanonValue::Bool(true))),
        r.get("records_proven").unwrap().as_int().unwrap(),
        r.get("checkpoints_verified").unwrap().as_int().unwrap(),
    )
}

/// The intended outcome of each row, pinned to literals so the vector file is not circular.
fn intended(name: &str) -> (bool, i64, i64, &'static str) {
    match name {
        "baseline_merge" | "r3_extensions_open" => (true, 3, 1, ""),
        "baseline_two_heads" | "r5_broker_grant_heads_two_brokers_ok" => (true, 2, 1, ""),
        "r1_parents_unsorted" | "r1_parents_duplicated" => (false, 2, 1, "is not a canonical set"),
        "r2_frontier_unsorted" | "r2_frontier_duplicated" => {
            (false, 2, 0, "checkpoint 0 invalid: checkpoint shape")
        }
        "r4_checkpoint_unknown_member" => (false, 2, 0, "unknown member 'ui_status' in checkpoint"),
        "r5_checkpoint_key_unknown_member" => {
            (false, 2, 0, "unknown member 'bogus' in checkpoint key")
        }
        "r5_broker_grant_heads_entry_unknown_member" => (
            false,
            2,
            0,
            "unknown member 'zzz' in broker_grant_heads entry",
        ),
        n if n.starts_with("r3_unknown_member_in_") => (false, 2, 1, "unknown member 'bogus'"),
        other => panic!("no intended outcome for {other}"),
    }
}

#[test]
fn vector_rows_have_the_intended_outcomes() {
    for (name, b) in vector_rows() {
        let (ok, proven, cps, reason) = intended(&name);
        let r = verify_bundle_with(&b, &pinned());
        assert_eq!(r.ok, ok, "{name}: {}", notes_and_issues(&r));
        assert_eq!(r.records_proven as i64, proven, "{name}");
        assert_eq!(r.checkpoints_verified as i64, cps, "{name}");
        assert!(
            notes_and_issues(&r).contains(reason),
            "{name}: {}",
            notes_and_issues(&r)
        );
    }
}

/// Writer (opt-in): AVERIN_WRITE_CANONICAL_SHAPE_VECTORS=<path>. Bundles are signed by the TEST-ONLY seed-0
/// key (the key of spec/fixtures/bundle-valid.json); never pin it in a deployment.
#[test]
fn write_canonical_shape_vectors() {
    let Ok(path) = std::env::var("AVERIN_WRITE_CANONICAL_SHAPE_VECTORS") else {
        return;
    };
    let rows: Vec<CanonValue> = vector_rows()
        .into_iter()
        .map(|(name, b)| {
            let (ok, proven, cps, reason) = intended(&name);
            CanonValue::object(vec![
                ("name".into(), CanonValue::string(&name)),
                ("bundle_json".into(), CanonValue::string(b.serialize())),
                ("opts_json".into(), CanonValue::string(opts_json())),
                ("expected_ok".into(), CanonValue::Bool(ok)),
                ("expected_records_proven".into(), CanonValue::Int(proven)),
                ("expected_checkpoints_verified".into(), CanonValue::Int(cps)),
                ("expected_reason".into(), CanonValue::string(reason)),
            ])
            .unwrap()
        })
        .collect();
    std::fs::write(path, CanonValue::Array(rows).serialize() + "\n").unwrap();
}

#[test]
fn the_vector_file_replays_natively() {
    let text =
        std::fs::read_to_string(vector_path()).expect("run the writer to create the vectors");
    let rows = parse(&text);
    let rows = rows.as_array().unwrap();
    assert_eq!(
        rows.len(),
        vector_rows().len(),
        "vector file is stale: re-run the writer"
    );
    for row in rows {
        let name = row.get("name").unwrap().as_str().unwrap();
        let out = verify_bundle_with_json(
            row.get("bundle_json").unwrap().as_str().unwrap(),
            row.get("opts_json").unwrap().as_str().unwrap(),
        );
        let rep = parse(&out);
        let (ok, proven, cps) = expect_of(&rep);
        assert_eq!(
            ok,
            matches!(row.get("expected_ok"), Some(CanonValue::Bool(true))),
            "{name}"
        );
        assert_eq!(
            proven,
            row.get("expected_records_proven")
                .unwrap()
                .as_int()
                .unwrap(),
            "{name}"
        );
        assert_eq!(
            cps,
            row.get("expected_checkpoints_verified")
                .unwrap()
                .as_int()
                .unwrap(),
            "{name}"
        );
        let reason = row.get("expected_reason").unwrap().as_str().unwrap();
        assert!(
            out.contains(reason),
            "{name}: reason {reason:?} not in report"
        );
        // the file agrees with the intended literals
        let (iok, ip, ic, ir) = intended(name);
        assert_eq!((ok, proven, cps, reason), (iok, ip, ic, ir), "{name}");
    }
}
