//! AVE-01, round-2 lead decision: a month bundle refuses records an earlier month already holds, and a cross-month
//! hard violation (a use with no matching grant, a second use of a single-use grant) reaches the verdict exactly as in
//! a whole-history check. The differential at the bottom is the contract: verifying the months in sequence gives the
//! same verdict as verifying the concatenated history, on honest and on hostile histories, for the default claim and
//! for `authorized`.
//!
//! The histories are real: a signed broker grant, resource-signed uses, signed checkpoints, split by month with
//! `split_bundle` (a month is the checkpoint's `created_ts`).

use averin_decision_core::authority::sign_evidence;
use averin_decision_core::canon::CanonValue;
use averin_decision_core::checkpoint::{checkpoint_body, seal_checkpoint};
use averin_decision_core::hashx::sha256_prefixed;
use averin_decision_core::record::seal;
use averin_decision_core::segment::{split_bundle, ChainState};
use averin_decision_core::sign::{encode_pubkey, signing_key_from_seed};
use averin_decision_core::verify::{
    claim_verdict, report_to_canon, verify_bundle_with, ClaimPolicy, ClaimVerdict, RequestedClaim,
    TrustedKey, VerifyOptions,
};
use ed25519_dalek::SigningKey;

const PROJECT: &str = "proj-001";
const CNF: &str = "ed25519-AgentKid0";
const ACTION: &str = "db.query:orders-ro";
const RESOURCE: &str = "orders-db";
const ISSUED: i64 = 1_718_445_600;
const EXP: i64 = 1_718_449_200;
const USED: i64 = 1_718_445_700;

fn rec_key() -> SigningKey {
    signing_key_from_seed(&[0u8; 32])
}
fn res_key() -> SigningKey {
    signing_key_from_seed(&[3u8; 32])
}

fn parse(s: &str) -> CanonValue {
    CanonValue::parse(s).unwrap()
}

fn hash(v: &CanonValue) -> String {
    v.get("content_hash").unwrap().as_str().unwrap().to_string()
}

fn grant_evidence(gid: &str, scope: &str) -> CanonValue {
    CanonValue::object(vec![
        ("kind".into(), CanonValue::string("grant")),
        ("grant_id".into(), CanonValue::string(gid)),
        ("action".into(), CanonValue::string(ACTION)),
        ("resource_id".into(), CanonValue::string(RESOURCE)),
        ("scope_class".into(), CanonValue::string(scope)),
        ("cnf_kid".into(), CanonValue::string(CNF)),
        (
            "credential_binding".into(),
            CanonValue::string(sha256_prefixed(b"test-credential-binding")),
        ),
        ("issued_at".into(), CanonValue::Int(ISSUED)),
        ("exp".into(), CanonValue::Int(EXP)),
    ])
    .unwrap()
}

fn seal_grant(gid: &str, scope: &str, prev: &[String]) -> CanonValue {
    let ge = grant_evidence(gid, scope);
    let eh = sha256_prefixed(ge.serialize().as_bytes());
    let esig = sign_evidence("gateway_enforced", PROJECT, gid, &eh, &rec_key());
    let prev_json =
        CanonValue::Array(prev.iter().map(|p| CanonValue::string(p.clone())).collect()).serialize();
    let body = format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{gid}","project_id":"{PROJECT}","agent_id":"agent","agent_version":"averin-broker",
        "session_id":"s","span_id":"sp-{gid}","parent_span_id":null,"causal_prev_hashes":{prev_json},"display_seq":0,
        "agent_ts":"2026-06-15T10:00:00.000Z","received_ts":"2026-06-15T10:00:00.000Z",
        "event_type":"credential_grant","action":"{ACTION}","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"credential_broker","grant_type":"id-jag","grant_id":"{gid}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "extensions":{{"broker":{{"kind":"grant","grant_evidence":{ge}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#,
        ge = ge.serialize(),
    );
    seal(&parse(&body), &rec_key()).unwrap()
}

/// A resource-signed use of `gid`. `jti` is the grant id for a single-use grant; `n` makes the nonce distinct.
fn seal_use(record_id: &str, gid: &str, jti: &str, n: i64, prev: &[String]) -> CanonValue {
    let used_at = USED + n;
    let nonce = format!("nonce-{used_at}");
    let ue = CanonValue::object(vec![
        ("kind".into(), CanonValue::string("use")),
        ("grant_id".into(), CanonValue::string(gid)),
        ("action".into(), CanonValue::string(ACTION)),
        ("resource_id".into(), CanonValue::string(RESOURCE)),
        ("jti".into(), CanonValue::string(jti)),
        ("nonce".into(), CanonValue::string(nonce.clone())),
        (
            "pop_challenge_hash".into(),
            CanonValue::string(sha256_prefixed(b"pop")),
        ),
        ("cnf_kid".into(), CanonValue::string(CNF)),
        (
            "ledger_commitment".into(),
            CanonValue::string(averin_decision_core::verify::ledger_commitment(
                jti, &nonce, used_at,
            )),
        ),
        ("used_at".into(), CanonValue::Int(used_at)),
    ])
    .unwrap();
    let eh = sha256_prefixed(ue.serialize().as_bytes());
    let esig = sign_evidence("gateway_enforced", PROJECT, record_id, &eh, &res_key());
    let prev_json =
        CanonValue::Array(prev.iter().map(|p| CanonValue::string(p.clone())).collect()).serialize();
    let body = format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{record_id}","project_id":"{PROJECT}","agent_id":"averin-resource","agent_version":"averin-resource",
        "session_id":"s","span_id":"sp-{record_id}","parent_span_id":null,"causal_prev_hashes":{prev_json},"display_seq":1,
        "agent_ts":"2026-06-15T10:00:05.000Z","received_ts":"2026-06-15T10:00:05.000Z",
        "event_type":"tool_call","action":"{ACTION}","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"tool_gateway","grant_id":"{gid}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "extensions":{{"broker":{{"kind":"use","grant_id":"{gid}","resource_id":"{RESOURCE}","use_evidence":{ue}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#,
        ue = ue.serialize(),
    );
    seal(&parse(&body), &rec_key()).unwrap()
}

/// A plain (non-broker) record, to give a month something to commit.
fn plain(n: usize, prev: &[String]) -> CanonValue {
    let plist = prev
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(",");
    let body = parse(&format!(
        r#"{{"action":"db.query","agent_id":"a","agent_ts":"2026-06-15T10:00:00.000Z","agent_version":"1","canon_version":"rcp-1",
        "causal_prev_hashes":[{plist}],"display_seq":{n},"domain":"flightrecorder.record.v2","event_type":"tool_call",
        "key":{{"key_epoch":0,"key_status":"active","key_valid_from":"2026-06-01T00:00:00.000Z","signing_key_id":"k0"}},
        "observed_via":"sdk","parent_span_id":null,"project_id":"{PROJECT}","received_ts":"2026-06-15T10:00:00.000Z","record_id":"plain-{n}",
        "schema_version":"2","session_id":"s","span_id":"ps{n}","status":"ok"}}"#
    ));
    seal(&body, &rec_key()).unwrap()
}

/// `months[i]` is the linear chain of records month `i` adds (each record's parent is the one before it); one
/// checkpoint at the end of each month. Returns the whole-history bundle.
fn history(months: &[(&str, Vec<CanonValue>)]) -> CanonValue {
    let mut records: Vec<CanonValue> = Vec::new();
    let mut cps: Vec<CanonValue> = Vec::new();
    for (i, (day, recs)) in months.iter().enumerate() {
        records.extend(recs.iter().cloned());
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
            &[hash(records.last().unwrap())],
            records.len() as i64,
            &format!("{day}T12:00:00.000Z"),
            parse(r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active"}"#),
        )
        .unwrap();
        cps.push(seal_checkpoint(&body, &rec_key()).unwrap());
    }
    let key_entry = CanonValue::object(vec![
        ("signing_key_id".into(), CanonValue::string("k0")),
        ("key_epoch".into(), CanonValue::Int(0)),
        (
            "public_key".into(),
            CanonValue::string(encode_pubkey(&rec_key().verifying_key())),
        ),
        ("key_status".into(), CanonValue::string("active")),
    ])
    .unwrap();
    CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::string("1")),
        ("project_id".into(), CanonValue::string(PROJECT)),
        ("keys".into(), CanonValue::Array(vec![key_entry])),
        ("records".into(), CanonValue::Array(records)),
        ("checkpoints".into(), CanonValue::Array(cps)),
    ])
    .unwrap()
}

fn opts(requested: RequestedClaim, pin: Option<&str>) -> VerifyOptions {
    VerifyOptions {
        trusted_keys: Some(vec![TrustedKey::from(rec_key().verifying_key())]),
        broker_authority_keys: vec![rec_key().verifying_key()],
        resource_authority_keys: vec![res_key().verifying_key()],
        claim_policy: ClaimPolicy {
            requested,
            ..Default::default()
        },
        segment_base_pin: pin.map(String::from),
        ..Default::default()
    }
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

/// The months in sequence, as `averin-verify chain` runs them.
fn run_chain(months: &[CanonValue], requested: RequestedClaim) -> (ChainState, ClaimVerdict) {
    let mut chain = ChainState::new();
    for m in months {
        let pin = chain.next_pin();
        let r = verify_bundle_with(m, &opts(requested, Some(&pin)));
        chain.absorb(m, &report_to_canon(&r));
    }
    let verdict = chain
        .finish_with(|whole| {
            Some(report_to_canon(&verify_bundle_with(
                whole,
                &opts(requested, None),
            )))
        })
        .verdict;
    (chain, verdict)
}

fn whole_verdict(whole: &CanonValue, requested: RequestedClaim) -> ClaimVerdict {
    claim_verdict(&report_to_canon(&verify_bundle_with(
        whole,
        &opts(requested, None),
    )))
}

fn months_of(whole: &CanonValue) -> Vec<CanonValue> {
    split_bundle(whole)
        .expect("split")
        .into_iter()
        .map(|(_, b)| b)
        .collect()
}

const CLAIMS: [RequestedClaim; 2] = [RequestedClaim::Integrity, RequestedClaim::Authorized];

/// Grant g1 and a first use in June; the second use of g1 (a single-use or a reusable grant) in July.
fn two_uses(scope: &str) -> CanonValue {
    let g = seal_grant("g1", scope, &[]);
    let u1 = seal_use("use-1", "g1", "g1", 0, &[hash(&g)]);
    let u2 = seal_use("use-2", "g1", "g1", 1, &[hash(&u1)]);
    history(&[("2026-06-28", vec![g, u1]), ("2026-07-28", vec![u2])])
}

/// June holds a grant and a use of it; July holds a use of a grant no month holds.
fn ghost_use() -> CanonValue {
    let g = seal_grant("g1", "session_grant", &[]);
    let u1 = seal_use("use-1", "g1", "g1", 0, &[hash(&g)]);
    let u2 = seal_use("use-2", "ghost", "ghost", 1, &[hash(&u1)]);
    history(&[("2026-06-28", vec![g, u1]), ("2026-07-28", vec![u2])])
}

fn honest_reusable() -> CanonValue {
    two_uses("session_grant")
}

// ---- the differential: months in sequence == the concatenated history ----

#[test]
fn the_honest_cross_month_history_chains_to_the_whole_histories_verdict() {
    let whole = honest_reusable();
    for claim in CLAIMS {
        let w = whole_verdict(&whole, claim);
        assert_ne!(
            w,
            ClaimVerdict::Fail,
            "the honest history must verify whole"
        );
        let (chain, v) = run_chain(&months_of(&whole), claim);
        assert!(chain.is_ok(), "{:?}", chain.issues);
        assert_eq!(v, w, "claim {claim:?}");
    }
}

#[test]
fn a_second_use_of_a_single_use_grant_in_a_later_month_reaches_the_whole_histories_verdict() {
    let whole = two_uses("single_operation");
    let months = months_of(&whole);
    for claim in CLAIMS {
        let w = whole_verdict(&whole, claim);
        let (_chain, v) = run_chain(&months, claim);
        assert_eq!(v, w, "claim {claim:?}");
    }
    // the whole history refutes it (the second use of a single-use grant is a violation), so no month sequence may pass
    let w = whole_verdict(&whole, RequestedClaim::Authorized);
    assert_eq!(w, ClaimVerdict::Fail, "whole history: {w:?}");
    let (chain, v) = run_chain(&months, RequestedClaim::Authorized);
    assert!(
        chain.is_ok(),
        "the chain links fine; the history is what fails"
    );
    assert_eq!(v, ClaimVerdict::Fail);
    // and the default claim does not hide it either
    assert_eq!(
        run_chain(&months, RequestedClaim::Integrity).1,
        whole_verdict(&whole, RequestedClaim::Integrity)
    );
}

#[test]
fn a_use_in_a_later_month_with_no_matching_grant_reaches_the_whole_histories_verdict() {
    let whole = ghost_use();
    let months = months_of(&whole);
    for claim in CLAIMS {
        let w = whole_verdict(&whole, claim);
        let (chain, v) = run_chain(&months, claim);
        assert_eq!(v, w, "claim {claim:?}");
        // the chain itself also names the missing grant
        assert!(
            chain.issues.iter().any(|i| i.contains("ghost")),
            "{:?}",
            chain.issues
        );
    }
    assert_eq!(
        run_chain(&months, RequestedClaim::Authorized).1,
        ClaimVerdict::Fail
    );
}

// ---- no reuse across months ----

#[test]
fn a_month_that_carries_a_record_an_earlier_month_already_holds_is_refused() {
    // July's own record x is replaced by June's use-1 (same count, same checkpoint)
    let g = seal_grant("g1", "session_grant", &[]);
    let u1 = seal_use("use-1", "g1", "g1", 0, &[hash(&g)]);
    let x = plain(1, &[hash(&u1)]);
    let whole = history(&[("2026-06-28", vec![g, u1.clone()]), ("2026-07-28", vec![x])]);
    let months = months_of(&whole);
    let attacked = set(&months[1], "records", CanonValue::Array(vec![u1]));
    let (chain, v) = run_chain(&[months[0].clone(), attacked], RequestedClaim::Integrity);
    assert!(!chain.is_ok());
    assert!(
        chain
            .issues
            .iter()
            .any(|i| i.contains("already absorbed from an earlier month")),
        "{:?}",
        chain.issues
    );
    assert_eq!(v, ClaimVerdict::Fail);
}

#[test]
fn a_month_that_repeats_an_earlier_record_id_with_other_content_is_refused() {
    let g = seal_grant("g1", "session_grant", &[]);
    let u1 = seal_use("use-1", "g1", "g1", 0, &[hash(&g)]);
    let u2 = seal_use("use-2", "g1", "g1", 1, &[hash(&u1)]);
    let whole = history(&[
        ("2026-06-28", vec![g, u1.clone()]),
        ("2026-07-28", vec![u2]),
    ]);
    let months = months_of(&whole);
    // a different use that wears June's record_id
    let imposter = seal_use("use-1", "g1", "g1", 7, &[hash(&u1)]);
    assert_ne!(hash(&imposter), hash(&u1));
    let attacked = set(&months[1], "records", CanonValue::Array(vec![imposter]));
    let (chain, v) = run_chain(&[months[0].clone(), attacked], RequestedClaim::Integrity);
    assert!(
        chain
            .issues
            .iter()
            .any(|i| i.contains("already absorbed from an earlier month")),
        "{:?}",
        chain.issues
    );
    assert_eq!(v, ClaimVerdict::Fail);
}

#[test]
fn an_honest_split_carries_no_record_twice() {
    let whole = honest_reusable();
    let months = months_of(&whole);
    let mut seen = std::collections::BTreeSet::new();
    for m in &months {
        for r in arr(m, "records") {
            assert!(seen.insert(hash(&r)), "split carried a record twice");
        }
    }
    assert_eq!(seen.len(), arr(&whole, "records").len());
}

// ---- the concatenation itself ----

#[test]
fn the_rebuilt_whole_history_is_the_original_up_to_the_unsplit_members() {
    let whole = honest_reusable();
    let (chain, _) = run_chain(&months_of(&whole), RequestedClaim::Integrity);
    let rebuilt = chain.whole_bundle().expect("rebuilt");
    assert_eq!(arr(&rebuilt, "records"), arr(&whole, "records"));
    assert_eq!(arr(&rebuilt, "checkpoints"), arr(&whole, "checkpoints"));
    assert!(rebuilt.get("segment").is_none());
    assert_eq!(
        run_chain(&months_of(&whole), RequestedClaim::Integrity).1,
        whole_verdict(&rebuilt, RequestedClaim::Integrity)
    );
}

#[test]
fn a_chain_with_no_month_has_no_whole_and_fails() {
    let chain = ChainState::new();
    assert!(chain.whole_bundle().is_none());
    let v = chain.finish_with(|_| None);
    assert_eq!(v.verdict, ClaimVerdict::Fail);
}

#[test]
fn a_whole_history_too_large_to_verify_in_one_piece_is_capped_at_insufficient_never_passed() {
    // the months are fine and link; the verifier cannot take the concatenation, so the cross-month rules were not run
    let whole = honest_reusable();
    let months = months_of(&whole);
    let mut chain = ChainState::new();
    for m in &months {
        let pin = chain.next_pin();
        let r = verify_bundle_with(m, &opts(RequestedClaim::Integrity, Some(&pin)));
        chain.absorb(m, &report_to_canon(&r));
    }
    assert!(chain.is_ok(), "{:?}", chain.issues);
    let v = chain.finish_with(|_| None);
    assert_eq!(v.verdict, ClaimVerdict::Insufficient);
    assert!(v.whole.is_none());
}

// ---- the CLI ----

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

fn chain_cli(whole: &CanonValue, requested: &str, name: &str) -> (String, i32, String) {
    let dir = std::env::temp_dir().join(format!("averin-xmonth-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut files = Vec::new();
    for (m, b) in split_bundle(whole).unwrap() {
        let p = dir.join(format!("{m}.json"));
        std::fs::write(&p, b.serialize()).unwrap();
        files.push(p);
    }
    let pk = |k: &SigningKey| encode_pubkey(&k.verifying_key());
    let opts = dir.join("opts.json");
    std::fs::write(
        &opts,
        format!(
            r#"{{"signing_keys":["{r}"],"broker_authority_keys":["{r}"],"resource_authority_keys":["{s}"],"claim_policy":{{"requested":"{requested}"}}}}"#,
            r = pk(&rec_key()),
            s = pk(&res_key())
        ),
    )
    .unwrap();
    let mut args: Vec<&std::ffi::OsStr> =
        vec!["chain".as_ref(), "--opts".as_ref(), opts.as_os_str()];
    args.extend(files.iter().map(|f| f.as_os_str()));
    let out = cli(&args);
    let _ = std::fs::remove_dir_all(dir);
    out
}

#[test]
fn the_chain_command_fails_a_cross_month_double_use_and_agrees_with_the_whole_history() {
    let (word, code, stdout) = chain_cli(&two_uses("single_operation"), "authorized", "double");
    assert_eq!((word.as_str(), code), ("FAIL", 1), "{stdout}");
    assert!(stdout.contains("whole history"), "{stdout}");
    // the same history with a reusable grant is fine, and the command says its word is the whole history's
    let (word, code, stdout) = chain_cli(&honest_reusable(), "integrity", "honest");
    assert_eq!(code, if word == "PASS" { 0 } else { 2 }, "{stdout}");
    assert!(
        word == "PASS" || word == "CONSISTENT",
        "honest cross-month history: {stdout}"
    );
    assert!(
        stdout.contains("The verdict is the whole history's"),
        "{stdout}"
    );
}

#[test]
fn the_chain_command_fails_a_use_whose_grant_no_month_holds() {
    let (word, code, stdout) = chain_cli(&ghost_use(), "integrity", "ghost");
    assert_eq!((word.as_str(), code), ("FAIL", 1), "{stdout}");
    assert!(stdout.contains("ghost"), "{stdout}");
}

#[test]
fn a_chain_whose_months_were_not_pinned_to_each_others_heads_fails_though_the_whole_verifies() {
    // every month verified with no base pin: each month is fine, the concatenation is the honest history, and the
    // chain still refuses it because nobody said month two follows month one
    let whole = honest_reusable();
    assert_ne!(
        whole_verdict(&whole, RequestedClaim::Integrity),
        ClaimVerdict::Fail
    );
    let mut chain = ChainState::new();
    for m in months_of(&whole) {
        let r = verify_bundle_with(&m, &opts(RequestedClaim::Integrity, None));
        chain.absorb(&m, &report_to_canon(&r));
    }
    assert!(!chain.is_ok());
    let v = chain.finish_with(|w| {
        Some(report_to_canon(&verify_bundle_with(
            w,
            &opts(RequestedClaim::Integrity, None),
        )))
    });
    assert_eq!(v.verdict, ClaimVerdict::Fail);
}
