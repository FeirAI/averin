//! AVE-01: month segments. A project built over three months is split into one checkable bundle per
//! month, each chained to the previous month's last checkpoint. The tests pin what a month proves on its own
//! (integrity, its own checkpoint chain, the link to its base), what only the chain of months proves (the base is the
//! previous head, parents that point before a base exist), and that dropping, reordering or relabeling a month
//! fails closed.

use averin_decision_core::anchor::{make_test_anchor, test_tsa_key};
use averin_decision_core::canon::CanonValue;
use averin_decision_core::checkpoint::{attach_anchor, checkpoint_body, seal_checkpoint};
use averin_decision_core::record::seal;
use averin_decision_core::segment::{split_bundle, ChainState};
use averin_decision_core::sign::signing_key_from_seed;
use averin_decision_core::verify::{
    report_to_canon, verify_bundle_with, TrustLevel, TrustedKey, VerifyOptions, VerifyReport,
};
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;

const PROJECT: &str = "proj-seg";

fn sk() -> SigningKey {
    signing_key_from_seed(&[0u8; 32])
}

fn parse(s: &str) -> CanonValue {
    CanonValue::parse(s).unwrap()
}

fn key_block() -> CanonValue {
    parse(
        r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active","key_valid_from":"2026-01-01T00:00:00.000Z"}"#,
    )
}

fn record(n: usize, session: &str, parents: &[String], ts: &str) -> CanonValue {
    let plist = parents
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(",");
    let body = parse(&format!(
        r#"{{"action":"db.query","agent_id":"a","agent_ts":"{ts}","agent_version":"1","canon_version":"rcp-1",
        "causal_prev_hashes":[{plist}],"display_seq":{n},"domain":"flightrecorder.record.v2","event_type":"tool_call",
        "key":{{"key_epoch":0,"key_status":"active","key_valid_from":"2026-01-01T00:00:00.000Z","signing_key_id":"k0"}},
        "observed_via":"sdk","parent_span_id":null,"project_id":"{PROJECT}","received_ts":"{ts}","record_id":"r{n}",
        "schema_version":"2","session_id":"{session}","span_id":"s{n}","status":"ok"}}"#
    ));
    seal(&body, &sk()).unwrap()
}

fn hash(v: &CanonValue) -> String {
    v.get("content_hash").unwrap().as_str().unwrap().to_string()
}

/// Three months. Each record's parents are all current heads (as the server stamps them), except the first
/// record of month three, which also names a record of month one that is no longer a head (a forced parent such as a
/// `use_outcome` naming its intent), so month three has one parent that points before its base.
struct Project {
    records: Vec<CanonValue>,
    checkpoints: Vec<CanonValue>,
}

fn build() -> Project {
    let months = [
        ("2026-06", vec!["sess-A", "sess-B", "sess-A"]),
        ("2026-07", vec!["sess-A", "sess-A"]),
        ("2026-08", vec!["sess-B", "sess-A", "sess-B"]),
    ];
    let mut records: Vec<CanonValue> = Vec::new();
    let mut checkpoints: Vec<CanonValue> = Vec::new();
    let mut heads: BTreeSet<String> = BTreeSet::new();
    let mut month1_nonhead = String::new();
    let mut n = 0usize;
    for (mi, (month, sessions)) in months.iter().enumerate() {
        for (j, sess) in sessions.iter().enumerate() {
            let ts = format!("{month}-10T10:0{j}:00.000Z");
            let mut parents: Vec<String> = heads.iter().cloned().collect();
            if mi == 2 && j == 0 {
                parents.push(month1_nonhead.clone());
            }
            parents.sort();
            parents.dedup();
            let r = record(n, sess, &parents, &ts);
            for p in &parents {
                heads.remove(p);
            }
            heads.insert(hash(&r));
            if mi == 0 && j == 0 {
                month1_nonhead = hash(&r);
            }
            records.push(r);
            n += 1;
        }
        let prev = checkpoints.last().map(|c: &CanonValue| {
            c.get("checkpoint_hash")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        });
        let frontier: Vec<String> = heads.iter().cloned().collect();
        let body = checkpoint_body(
            &format!("cp{mi}"),
            PROJECT,
            mi as i64,
            prev.as_deref(),
            &frontier,
            records.len() as i64,
            &format!("{month}-28T12:00:00.000Z"),
            key_block(),
        )
        .unwrap();
        checkpoints.push(seal_checkpoint(&body, &sk()).unwrap());
    }
    Project {
        records,
        checkpoints,
    }
}

fn keys() -> CanonValue {
    parse(&format!(
        r#"[{{"key_epoch":0,"key_status":"active","public_key":"{}","signing_key_id":"k0"}}]"#,
        averin_decision_core::sign::encode_pubkey(&sk().verifying_key())
    ))
}

fn whole(p: &Project) -> CanonValue {
    CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::string("1")),
        ("project_id".into(), CanonValue::string(PROJECT)),
        ("keys".into(), keys()),
        ("records".into(), CanonValue::Array(p.records.clone())),
        (
            "checkpoints".into(),
            CanonValue::Array(p.checkpoints.clone()),
        ),
    ])
    .unwrap()
}

fn pinned() -> VerifyOptions {
    VerifyOptions {
        trusted_keys: Some(vec![TrustedKey::from(sk().verifying_key())]),
        ..Default::default()
    }
}

fn with_pin(pin: &str) -> VerifyOptions {
    VerifyOptions {
        segment_base_pin: Some(pin.to_string()),
        ..pinned()
    }
}

fn segments() -> Vec<(String, CanonValue)> {
    split_bundle(&whole(&build())).expect("split")
}

fn set(b: &CanonValue, key: &str, v: CanonValue) -> CanonValue {
    let mut m = b.as_object().unwrap().clone();
    m.retain(|(k, _)| k != key);
    m.push((key.to_string(), v));
    CanonValue::Object(m)
}

fn arr(b: &CanonValue, k: &str) -> Vec<CanonValue> {
    b.get(k).unwrap().as_array().unwrap().clone()
}

fn seg_field(b: &CanonValue, k: &str) -> CanonValue {
    b.get("segment").unwrap().get(k).unwrap().clone()
}

fn issues(r: &VerifyReport) -> String {
    r.issues.join(" | ")
}

#[test]
fn the_whole_history_fixture_verifies_and_splits_into_three_months() {
    let p = build();
    let w = whole(&p);
    let r = verify_bundle_with(&w, &pinned());
    assert!(r.ok, "{}", issues(&r));
    assert!(
        r.segment.is_none(),
        "a whole-history bundle has no segment section"
    );

    let segs = segments();
    let months: Vec<&str> = segs.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(months, ["2026-06", "2026-07", "2026-08"]);
    let counts: Vec<usize> = segs.iter().map(|(_, b)| arr(b, "records").len()).collect();
    assert_eq!(counts, [3, 2, 3]);
    // the base is carried first, then the month's own checkpoints
    assert_eq!(arr(&segs[0].1, "checkpoints").len(), 1);
    assert_eq!(arr(&segs[1].1, "checkpoints").len(), 2);
}

#[test]
fn every_month_verifies_alone_and_links_to_the_previous_head() {
    let segs = segments();
    let mut pin = "genesis".to_string();
    for (i, (month, b)) in segs.iter().enumerate() {
        let r = verify_bundle_with(b, &with_pin(&pin));
        assert!(r.ok, "{month}: {}", issues(&r));
        let sg = r.segment.as_ref().expect("segment section");
        assert_eq!(&sg.month, month);
        assert_eq!(sg.link, if i == 0 { "genesis" } else { "base_pinned" });
        assert!(r
            .record_trust
            .iter()
            .all(|t| t.trust == TrustLevel::IntegrityProven));
        assert_eq!(r.checkpoints_verified, r.checkpoints_total);
        pin = sg.head_checkpoint_hash.clone().unwrap();
    }
    // the final head is the whole history's latest checkpoint
    let p = build();
    assert_eq!(
        pin,
        p.checkpoints
            .last()
            .unwrap()
            .get("checkpoint_hash")
            .unwrap()
            .as_str()
            .unwrap()
    );
}

#[test]
fn an_unpinned_base_is_consistent_but_reports_it_is_unpinned() {
    let segs = segments();
    let r = verify_bundle_with(&segs[1].1, &pinned());
    assert!(r.ok, "{}", issues(&r));
    assert_eq!(r.segment.unwrap().link, "base_unpinned");
}

#[test]
fn a_month_reports_what_it_could_not_evaluate_and_the_head_count() {
    let segs = segments();
    let r = verify_bundle_with(&segs[2].1, &pinned());
    let sg = r.segment.unwrap();
    // month three has a parent that points before its base, so its record set is only bounded by the chain
    assert_eq!(
        sg.not_evaluated,
        [
            "broker_grant_log",
            "federation_heads",
            "record_completeness"
        ]
    );
    assert_eq!(sg.head_record_count, 8);
    let second = verify_bundle_with(&segs[1].1, &pinned()).segment.unwrap();
    assert_eq!(
        second.not_evaluated,
        ["broker_grant_log", "federation_heads"]
    );
    assert_eq!(r.broker_trust, "assumed");
    // the first month evaluates everything a whole bundle does
    let first = verify_bundle_with(&segs[0].1, &pinned()).segment.unwrap();
    assert!(first.not_evaluated.is_empty());
}

#[test]
fn a_wrong_base_pin_fails() {
    let segs = segments();
    let r = verify_bundle_with(
        &segs[1].1,
        &with_pin(&format!("sha256:{}", "ab".repeat(32))),
    );
    assert!(!r.ok);
    assert!(issues(&r).contains("expected"), "{}", issues(&r));
    // pinning "genesis" on a month that has a base fails too
    let r = verify_bundle_with(&segs[1].1, &with_pin("genesis"));
    assert!(!r.ok);
    // and a pin on a whole-history bundle is refused rather than ignored
    let r = verify_bundle_with(&whole(&build()), &with_pin("genesis"));
    assert!(!r.ok);
    assert!(issues(&r).contains("not a month segment"), "{}", issues(&r));
}

#[test]
fn a_month_with_a_missing_record_fails_the_count_and_the_dag() {
    let segs = segments();
    let b = &segs[1].1;
    let mut recs = arr(b, "records");
    recs.remove(0);
    let r = verify_bundle_with(&set(b, "records", CanonValue::Array(recs)), &pinned());
    assert!(!r.ok);
    assert!(!r.chain_ok, "{}", issues(&r));
}

#[test]
fn a_month_with_an_extra_record_fails() {
    let segs = segments();
    let extra = segs[0].1.get("records").unwrap().as_array().unwrap()[0].clone();
    let b = &segs[1].1;
    let mut recs = arr(b, "records");
    // an earlier month's record smuggled in is a record the month's checkpoints do not account for
    recs.push(record(99, "sess-Z", &[], "2026-07-11T10:00:00.000Z"));
    recs.push(extra);
    let r = verify_bundle_with(&set(b, "records", CanonValue::Array(recs)), &pinned());
    assert!(!r.ok);
}

#[test]
fn a_base_that_is_not_carried_or_not_first_fails() {
    let segs = segments();
    let b = &segs[1].1;
    // drop the carried base checkpoint
    let cps = arr(b, "checkpoints");
    let r = verify_bundle_with(
        &set(b, "checkpoints", CanonValue::Array(cps[1..].to_vec())),
        &pinned(),
    );
    assert!(!r.ok);
    assert!(issues(&r).contains("not carried"), "{}", issues(&r));
    // claim a different base seq
    let seg = set(&seg_obj(b), "base_seq", CanonValue::Int(0));
    let seg = set(
        &seg,
        "base_checkpoint_hash",
        CanonValue::string(format!("sha256:{}", "cd".repeat(32))),
    );
    let r = verify_bundle_with(&set(b, "segment", seg), &pinned());
    assert!(!r.ok);
}

fn seg_obj(b: &CanonValue) -> CanonValue {
    b.get("segment").unwrap().clone()
}

#[test]
fn a_tampered_base_checkpoint_fails_its_signature() {
    let segs = segments();
    let b = &segs[1].1;
    let mut cps = arr(b, "checkpoints");
    cps[0] = set(&cps[0], "record_count", CanonValue::Int(99));
    let r = verify_bundle_with(&set(b, "checkpoints", CanonValue::Array(cps)), &pinned());
    assert!(!r.ok);
    assert!(
        r.checkpoints_verified < r.checkpoints_total,
        "{}",
        issues(&r)
    );
}

#[test]
fn a_wrong_base_record_count_fails() {
    let segs = segments();
    let b = &segs[2].1;
    let seg = set(&seg_obj(b), "base_record_count", CanonValue::Int(4));
    let r = verify_bundle_with(&set(b, "segment", seg), &pinned());
    assert!(!r.ok);
    assert!(issues(&r).contains("base_record_count"), "{}", issues(&r));
}

#[test]
fn the_month_label_must_match_the_checkpoints_dates() {
    let segs = segments();
    let b = &segs[1].1;
    let seg = set(&seg_obj(b), "month", CanonValue::string("2026-09"));
    let r = verify_bundle_with(&set(b, "segment", seg), &pinned());
    assert!(!r.ok);
    assert!(
        issues(&r).contains("outside segment month"),
        "{}",
        issues(&r)
    );
    for bad in ["2026-13", "26-07", "2026/07", ""] {
        let seg = set(&seg_obj(b), "month", CanonValue::string(bad));
        let r = verify_bundle_with(&set(b, "segment", seg), &pinned());
        assert!(!r.ok, "month {bad:?} accepted");
    }
}

#[test]
fn an_unknown_segment_format_fails() {
    let segs = segments();
    let b = &segs[1].1;
    let seg = set(
        &seg_obj(b),
        "format",
        CanonValue::string("averin.segment.v2"),
    );
    let r = verify_bundle_with(&set(b, "segment", seg), &pinned());
    assert!(!r.ok);
}

#[test]
fn a_segment_with_no_checkpoint_after_its_base_fails() {
    let segs = segments();
    let b = &segs[1].1;
    let cps = arr(b, "checkpoints");
    // keep only the base and drop the month's own checkpoints; the month label then names nothing
    let r = verify_bundle_with(
        &set(b, "checkpoints", CanonValue::Array(cps[..1].to_vec())),
        &pinned(),
    );
    assert!(!r.ok);
}

#[test]
fn a_first_month_cannot_start_mid_chain() {
    let segs = segments();
    // month two's bundle relabeled as a genesis segment: its first checkpoint has seq 1, not 0
    let b = &segs[1].1;
    let seg = set(&seg_obj(b), "base_seq", CanonValue::Null);
    let seg = set(&seg, "base_checkpoint_hash", CanonValue::Null);
    let seg = set(&seg, "base_record_count", CanonValue::Int(0));
    let r = verify_bundle_with(&set(b, "segment", seg), &pinned());
    assert!(!r.ok);
}

#[test]
fn only_the_month_two_parent_pointing_before_the_base_is_counted() {
    let segs = segments();
    let r = verify_bundle_with(&segs[2].1, &pinned());
    assert!(r.ok, "{}", issues(&r));
    assert_eq!(r.segment.unwrap().earlier_parent_refs, 1);
    for i in [0, 1] {
        assert_eq!(
            verify_bundle_with(&segs[i].1, &pinned())
                .segment
                .unwrap()
                .earlier_parent_refs,
            0
        );
    }
}

fn run_chain(bundles: &[CanonValue]) -> ChainState {
    let mut chain = ChainState::new();
    for b in bundles {
        let r = verify_bundle_with(b, &with_pin(&chain.next_pin()));
        chain.absorb(b, &report_to_canon(&r));
    }
    chain
}

#[test]
fn the_chain_of_all_three_months_is_ok() {
    let segs = segments();
    let bundles: Vec<CanonValue> = segs.into_iter().map(|(_, b)| b).collect();
    let chain = run_chain(&bundles);
    assert!(chain.is_ok(), "{:?}", chain.issues);
    assert_eq!((chain.months, chain.records), (3, 8));
    assert_eq!(chain.head_record_count(), 8);
}

#[test]
fn the_chain_with_a_month_removed_fails() {
    let segs = segments();
    let chain = run_chain(&[segs[0].1.clone(), segs[2].1.clone()]);
    assert!(!chain.is_ok());
    assert!(
        chain
            .issues
            .iter()
            .any(|i| i.contains("is not the previous")),
        "{:?}",
        chain.issues
    );
}

#[test]
fn the_chain_out_of_order_fails() {
    let segs = segments();
    let chain = run_chain(&[segs[1].1.clone(), segs[0].1.clone()]);
    assert!(!chain.is_ok());
}

#[test]
fn a_parent_before_the_base_must_exist_in_an_earlier_month() {
    let segs = segments();
    // month three alone, with no earlier month in the walk: its forced parent names nothing seen
    let mut chain = ChainState::new();
    let r = verify_bundle_with(&segs[2].1, &pinned());
    chain.absorb(&segs[2].1, &report_to_canon(&r));
    assert!(!chain.is_ok());
    assert!(
        chain.issues.iter().any(|i| i.contains("name no record")),
        "{:?}",
        chain.issues
    );
    // the full walk resolves it
    let all: Vec<CanonValue> = segs.into_iter().map(|(_, b)| b).collect();
    assert!(run_chain(&all).is_ok());
}

#[test]
fn a_base_anchored_by_a_trusted_timestamp_is_reported() {
    let segs = segments();
    let tsa = test_tsa_key(&[200u8; 32]);
    let b = &segs[1].1;
    let mut cps = arr(b, "checkpoints");
    let h = cps[0]
        .get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    cps[0] = attach_anchor(
        &cps[0],
        make_test_anchor(&h, "2026-06-29T00:00:00.000Z", &tsa, "tsa-1"),
    );
    let b2 = set(b, "checkpoints", CanonValue::Array(cps));
    let mut opts = pinned();
    opts.trusted_tsa_keys = vec![tsa.verifying_key()];
    let r = verify_bundle_with(&b2, &opts);
    assert!(r.ok, "{}", issues(&r));
    assert!(r.segment.unwrap().base_anchored);
    // without the pinned TSA the anchor does not count
    let r = verify_bundle_with(&b2, &pinned());
    assert!(!r.segment.unwrap().base_anchored);
}

#[test]
fn split_refuses_months_that_go_backwards_and_unaccounted_records() {
    let mut p = build();
    // reseal checkpoint 2 dated before checkpoint 1
    let prev = p.checkpoints[1]
        .get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let frontier: Vec<String> = p.checkpoints[2]
        .get("frontier")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect();
    let body = checkpoint_body(
        "cp2",
        PROJECT,
        2,
        Some(&prev),
        &frontier,
        8,
        "2026-05-28T12:00:00.000Z",
        key_block(),
    )
    .unwrap();
    p.checkpoints[2] = seal_checkpoint(&body, &sk()).unwrap();
    let e = split_bundle(&whole(&p)).unwrap_err();
    assert!(e.contains("backwards"), "{e}");

    // a record no checkpoint commits
    let mut p = build();
    p.records
        .push(record(50, "sess-X", &[], "2026-08-11T10:00:00.000Z"));
    let e = split_bundle(&whole(&p)).unwrap_err();
    assert!(e.contains("committed by no checkpoint"), "{e}");
}

#[test]
fn a_verified_segment_report_serializes_the_segment_section() {
    let segs = segments();
    let r = verify_bundle_with(&segs[1].1, &pinned());
    let canon = report_to_canon(&r);
    let sg = canon.get("segment").expect("segment section");
    assert_eq!(sg.get("month").unwrap().as_str(), Some("2026-07"));
    assert_eq!(sg.get("link").unwrap().as_str(), Some("base_unpinned"));
    assert_eq!(seg_field(&segs[1].1, "month").as_str(), Some("2026-07"));
    // a whole-history report has no such key
    let w = report_to_canon(&verify_bundle_with(&whole(&build()), &pinned()));
    assert!(w.get("segment").is_none());
}

// ---- the CLI: split a whole-history bundle, then check the months with `chain` ----

fn cli(args: &[&std::ffi::OsStr]) -> (String, i32, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_averin-verify"))
        .args(args)
        .output()
        .expect("run averin-verify");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let word = stdout
        .lines()
        .find_map(|l| l.strip_prefix("RESULT: "))
        .map(|r| {
            r.split(|c: char| !c.is_ascii_uppercase())
                .next()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    (word, out.status.code().expect("exit code"), stdout)
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("averin-segments-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn cli_splits_a_bundle_and_chains_its_months() {
    let dir = scratch("cli");
    let whole_path = dir.join("whole.json");
    std::fs::write(&whole_path, whole(&build()).serialize()).unwrap();
    let out = dir.join("months");
    let (_, code, stdout) = cli(&["split".as_ref(), whole_path.as_os_str(), out.as_os_str()]);
    assert_eq!(code, 0, "{stdout}");
    let files: Vec<std::path::PathBuf> = stdout.lines().map(std::path::PathBuf::from).collect();
    assert_eq!(files.len(), 3);
    assert!(files[0].ends_with("proj-seg-2026-06.json"));

    let opts = dir.join("opts.json");
    std::fs::write(
        &opts,
        format!(
            r#"{{"signing_keys":["{}"]}}"#,
            averin_decision_core::sign::encode_pubkey(&sk().verifying_key())
        ),
    )
    .unwrap();
    let mut args: Vec<&std::ffi::OsStr> =
        vec!["chain".as_ref(), "--opts".as_ref(), opts.as_os_str()];
    args.extend(files.iter().map(|f| f.as_os_str()));
    let (word, code, stdout) = cli(&args);
    assert_eq!((word.as_str(), code), ("PASS", 0), "{stdout}");
    assert!(stdout.contains("3 month(s), 8 records"), "{stdout}");

    // keys not pinned: consistent, never a PASS
    let mut args: Vec<&std::ffi::OsStr> = vec!["chain".as_ref()];
    args.extend(files.iter().map(|f| f.as_os_str()));
    let (word, code, _) = cli(&args);
    assert_eq!((word.as_str(), code), ("CONSISTENT", 2));

    // a month missing from the walk fails
    let args: Vec<&std::ffi::OsStr> = vec![
        "chain".as_ref(),
        "--opts".as_ref(),
        opts.as_os_str(),
        files[0].as_os_str(),
        files[2].as_os_str(),
    ];
    let (word, code, stdout) = cli(&args);
    assert_eq!((word.as_str(), code), ("FAIL", 1), "{stdout}");

    // the single-bundle command shows the segment line and the not-checked-here notice
    let (_, _, stdout) = cli(&["bundle".as_ref(), files[1].as_os_str(), opts.as_os_str()]);
    assert!(stdout.contains("MONTH 2026-07"), "{stdout}");
    assert!(
        stdout.contains("Earlier months are NOT checked here"),
        "{stdout}"
    );
    // ... and a month whose record set only the chain can bound says so
    let (_, _, stdout) = cli(&["bundle".as_ref(), files[2].as_os_str(), opts.as_os_str()]);
    assert!(
        stdout.contains("RECORD COMPLETENESS NOT EVALUATED"),
        "{stdout}"
    );
    assert!(
        !cli(&["bundle".as_ref(), files[1].as_os_str(), opts.as_os_str()])
            .2
            .contains("RECORD COMPLETENESS NOT EVALUATED")
    );
    let _ = std::fs::remove_dir_all(dir);
}

// ---- cross-month references (a use or outcome naming a grant or intent from an earlier month) ----

fn hand_segment(
    month: &str,
    base: Option<&str>,
    head: &str,
    head_count: i64,
    record_id: &str,
    unresolved: &str,
) -> (CanonValue, CanonValue) {
    let ch = format!(
        "sha256:{}",
        format!("{:02x}", record_id.len() + month.len()).repeat(32)
    );
    let (bs, bh, bc) = match base {
        Some(h) => ("1".to_string(), format!("\"{h}\""), "1"),
        None => ("null".to_string(), "null".to_string(), "0"),
    };
    let bundle = parse(&format!(
        r#"{{"project_id":"p","records":[{{"content_hash":"{ch}","record_id":"{record_id}","causal_prev_hashes":[]}}],
        "checkpoints":[],"segment":{{"format":"averin.segment.v1","month":"{month}","base_seq":{bs},"base_checkpoint_hash":{bh},"base_record_count":{bc}}}}}"#
    ));
    let report = parse(&format!(
        r#"{{"ok":true,"segment":{{"month":"{month}","link":"base_pinned","head_checkpoint_hash":"{head}","head_record_count":{head_count},
        "unresolved_cross_month":[{unresolved}]}}}}"#
    ));
    (bundle, report)
}

#[test]
fn the_chain_resolves_cross_month_references_against_earlier_months_only() {
    let h1 = format!("sha256:{}", "11".repeat(32));
    let h2 = format!("sha256:{}", "22".repeat(32));
    let ref_json =
        |kind: &str, id: &str| format!(r#"{{"kind":"{kind}","record_id":"u1","ref":"{id}"}}"#);

    // the grant g1 is held by month one: the use in month two resolves
    let (b1, r1) = hand_segment("2026-06", None, &h1, 1, "g1", "");
    let (b2, r2) = hand_segment("2026-07", Some(&h1), &h2, 2, "u1", &ref_json("use", "g1"));
    let mut chain = ChainState::new();
    chain.absorb(&b1, &r1);
    chain.absorb(&b2, &r2);
    assert!(chain.is_ok(), "{:?}", chain.issues);

    // month one does not hold it: the same use is unresolved and the chain fails
    let (b1x, r1x) = hand_segment("2026-06", None, &h1, 1, "other", "");
    let mut chain = ChainState::new();
    chain.absorb(&b1x, &r1x);
    chain.absorb(&b2, &r2);
    assert!(!chain.is_ok());
    assert!(
        chain
            .issues
            .iter()
            .any(|i| i.contains("no earlier month holds")),
        "{:?}",
        chain.issues
    );

    // naming a record of its own month does not resolve a cross-month reference
    let (b2s, r2s) = hand_segment(
        "2026-07",
        Some(&h1),
        &h2,
        2,
        "g1",
        &ref_json("use_outcome", "g1"),
    );
    let mut chain = ChainState::new();
    chain.absorb(&b1x, &r1x);
    chain.absorb(&b2s, &r2s);
    assert!(!chain.is_ok());
}

// ---- rules a month shares with a whole-history bundle ----

#[test]
fn a_whole_history_bundle_with_a_missing_record_still_fails_as_a_broken_link() {
    // The relaxation that lets a month point before its base must not reach a bundle with no base.
    let p = build();
    let mut recs = p.records.clone();
    recs.remove(0); // the first record is the parent of the second
    let b = CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::string("1")),
        ("project_id".into(), CanonValue::string(PROJECT)),
        ("keys".into(), keys()),
        ("records".into(), CanonValue::Array(recs)),
        (
            "checkpoints".into(),
            CanonValue::Array(p.checkpoints.clone()),
        ),
    ])
    .unwrap();
    let r = verify_bundle_with(&b, &pinned());
    assert!(!r.ok);
    assert!(!r.dag_ok, "{}", issues(&r));
    // and the same hole in a first-month segment (no base) is a DAG failure too
    let first = segments().remove(0).1;
    let mut recs = arr(&first, "records");
    recs.remove(0);
    let r = verify_bundle_with(&set(&first, "records", CanonValue::Array(recs)), &pinned());
    assert!(!r.dag_ok, "{}", issues(&r));
}

#[test]
fn an_intermediate_checkpoint_naming_a_head_the_month_does_not_carry_fails() {
    // Month two with an extra checkpoint in the middle whose frontier names a record that exists nowhere. The
    // latest checkpoint is honest, so only the per-checkpoint frontier rule can catch it.
    let segs = segments();
    let b = &segs[1].1;
    let cps = arr(b, "checkpoints");
    let (base, last) = (&cps[0], &cps[1]);
    let base_hash = base
        .get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let bogus = format!("sha256:{}", "ee".repeat(32));
    let mid_body = checkpoint_body(
        "cp-mid",
        PROJECT,
        1,
        Some(&base_hash),
        &[bogus],
        4,
        "2026-07-20T12:00:00.000Z",
        key_block(),
    )
    .unwrap();
    let mid = seal_checkpoint(&mid_body, &sk()).unwrap();
    let mid_hash = mid
        .get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let frontier: Vec<String> = last
        .get("frontier")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect();
    let last_body = checkpoint_body(
        "cp-last",
        PROJECT,
        2,
        Some(&mid_hash),
        &frontier,
        5,
        "2026-07-28T12:00:00.000Z",
        key_block(),
    )
    .unwrap();
    let last2 = seal_checkpoint(&last_body, &sk()).unwrap();
    let r = verify_bundle_with(
        &set(
            b,
            "checkpoints",
            CanonValue::Array(vec![base.clone(), mid, last2]),
        ),
        &pinned(),
    );
    assert!(!r.ok);
    assert!(issues(&r).contains("OMISSION"), "{}", issues(&r));
}

// ---- committed fixtures: the same three months, for the browser verifier's skew test ----

/// `spec/fixtures/segment-<month>.json` are the three months of `build()` as `split_bundle` cuts them. A drift
/// fails here; `AVERIN_WRITE_FIXTURES=1 cargo test --test segments committed_segment_fixtures` rewrites them.
#[test]
fn committed_segment_fixtures_match_the_builder() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../spec/fixtures");
    for (month, bundle) in segments() {
        let path = dir.join(format!("segment-{month}.json"));
        let want = bundle.serialize() + "\n";
        if std::env::var("AVERIN_WRITE_FIXTURES").is_ok() {
            std::fs::write(&path, &want).unwrap();
        }
        let have = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{}: {e} (run with AVERIN_WRITE_FIXTURES=1)", path.display())
        });
        assert_eq!(have, want, "{} drifted from the builder", path.display());
    }
}

// ---- single-month completeness: a dropped record must not hide behind an earlier month's record ----

/// Month one is a chain r0 <- r1 <- r2 (frontier [r2]). Month two is a, b(a), c(b, a), d(c) with a naming the base
/// frontier r2, and, when `forced_old`, also the old non-frontier r0 (a `use_outcome` naming its intent).
fn two_month_project(forced_old: bool) -> Vec<(String, CanonValue)> {
    let mut records: Vec<CanonValue> = Vec::new();
    let mut prev: Vec<String> = Vec::new();
    for n in 0..3 {
        let r = record(n, "sess-A", &prev, &format!("2026-06-10T10:0{n}:00.000Z"));
        prev = vec![hash(&r)];
        records.push(r);
    }
    let (r0, r2) = (hash(&records[0]), hash(&records[2]));
    let mut a_parents = vec![r2.clone()];
    if forced_old {
        a_parents.push(r0);
    }
    a_parents.sort();
    let a = record(3, "sess-A", &a_parents, "2026-07-10T10:00:00.000Z");
    let b = record(4, "sess-A", &[hash(&a)], "2026-07-10T10:01:00.000Z");
    let mut c_parents = vec![hash(&a), hash(&b)];
    c_parents.sort();
    let c = record(5, "sess-A", &c_parents, "2026-07-10T10:02:00.000Z");
    let d = record(6, "sess-A", &[hash(&c)], "2026-07-10T10:03:00.000Z");
    let frontiers = [
        (vec![r2], 3i64, "2026-06-28"),
        (vec![hash(&d)], 7, "2026-07-28"),
    ];
    records.extend([a, b, c, d]);
    let mut cps: Vec<CanonValue> = Vec::new();
    for (i, (frontier, count, day)) in frontiers.iter().enumerate() {
        let prev_hash = cps.last().map(|c: &CanonValue| {
            c.get("checkpoint_hash")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        });
        let body = checkpoint_body(
            &format!("cp{i}"),
            PROJECT,
            i as i64,
            prev_hash.as_deref(),
            frontier,
            *count,
            &format!("{day}T12:00:00.000Z"),
            key_block(),
        )
        .unwrap();
        cps.push(seal_checkpoint(&body, &sk()).unwrap());
    }
    split_bundle(&whole(&Project {
        records,
        checkpoints: cps,
    }))
    .expect("split")
}

fn drop_and_add(month: &CanonValue, drop_id: &str, add: CanonValue) -> CanonValue {
    let mut recs: Vec<CanonValue> = arr(month, "records")
        .into_iter()
        .filter(|r| r.get("record_id").unwrap().as_str() != Some(drop_id))
        .collect();
    recs.push(add);
    set(month, "records", CanonValue::Array(recs))
}

fn find_record(month: &CanonValue, id: &str) -> CanonValue {
    arr(month, "records")
        .into_iter()
        .find(|r| r.get("record_id").unwrap().as_str() == Some(id))
        .unwrap()
}

#[test]
fn an_honest_two_month_project_verifies_alone_and_in_chain() {
    for forced in [false, true] {
        let segs = two_month_project(forced);
        let r = verify_bundle_with(&segs[1].1, &with_pin(&hash_of_cp(&segs[0].1)));
        assert!(r.ok, "{}", issues(&r));
        let sg = r.segment.unwrap();
        // without a forced old parent every parent is in the month or the base frontier: completeness is exact
        assert_eq!(sg.earlier_parent_refs, usize::from(forced));
        assert_eq!(sg.earlier_parent_ref_hashes.len(), usize::from(forced));
        assert_eq!(
            sg.not_evaluated.iter().any(|x| x == "record_completeness"),
            forced
        );
        assert!(run_chain(&[segs[0].1.clone(), segs[1].1.clone()]).is_ok());
    }
}

fn hash_of_cp(month: &CanonValue) -> String {
    let cps = arr(month, "checkpoints");
    cps.last()
        .unwrap()
        .get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn a_dropped_record_replaced_by_a_base_frontier_record_fails_the_month() {
    // shape (a): drop b, add r2 (the base frontier member a references). Count and heads still match.
    let segs = two_month_project(false);
    let r2 = find_record(&segs[0].1, "r2");
    let attacked = drop_and_add(&segs[1].1, "r4", r2);
    let r = verify_bundle_with(&attacked, &with_pin(&hash_of_cp(&segs[0].1)));
    assert!(!r.ok);
    assert!(!r.chain_ok);
    assert!(issues(&r).contains("already commits"), "{}", issues(&r));
}

#[test]
fn a_dropped_record_replaced_by_an_old_record_is_reported_incomplete_and_the_chain_catches_it() {
    // shape (b): a also names old r0; drop b, add r0. One month cannot tell, so it must not claim completeness.
    let segs = two_month_project(true);
    let pin = hash_of_cp(&segs[0].1);
    let honest = verify_bundle_with(&segs[1].1, &with_pin(&pin))
        .segment
        .unwrap();
    let r0 = find_record(&segs[0].1, "r0");
    let attacked = drop_and_add(&segs[1].1, "r4", r0);
    let r = verify_bundle_with(&attacked, &with_pin(&pin));
    let sg = r.segment.clone().unwrap();
    assert!(sg.not_evaluated.iter().any(|x| x == "record_completeness"));
    assert_eq!(sg.earlier_parent_refs, honest.earlier_parent_refs);
    assert_ne!(
        sg.earlier_parent_ref_hashes, honest.earlier_parent_ref_hashes,
        "the dropped record's hash must be visible"
    );
    assert!(sg
        .earlier_parent_ref_hashes
        .contains(&hash(&find_record(&segs[1].1, "r4"))));
    // the chain, which knows every earlier month, refuses it
    let chain = run_chain(&[segs[0].1.clone(), attacked]);
    assert!(!chain.is_ok(), "{:?}", chain.issues);
    assert!(chain.issues.iter().any(|i| i.contains("name no record")));
}
