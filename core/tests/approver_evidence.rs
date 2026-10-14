//! XV-11: approver identity in the signed evidence of a govder approval record.
//!
//! vectors/approver-evidence.v1.json is OWNED by averin (independent Python reference,
//! scripts/vectors/gen_approver_evidence.py) and copied byte for byte into govder, whose signer
//! commits the same evidence. For a v3 govder record the verifier re-derives the evidence from the
//! record's own fields, `decided_by` and the sign-off set included, and reports an issue when the
//! signed evidence_hash differs. These tests build REAL v3 records (valid subject digest, valid
//! signature under a pinned key) so the only thing that can fail is the evidence binding.

use averin_decision_core::authority::{
    sign_evidence, sign_evidence_v3, AuthorityTrust, SUBJECT_PROJECTION,
};
use averin_decision_core::canon::CanonValue;
use averin_decision_core::hashx::sha256_prefixed;
use averin_decision_core::record::seal;
use averin_decision_core::sign::{encode_pubkey, signing_key_from_seed};
use averin_decision_core::verify::{verify_bundle_with, VerifyOptions};
use std::path::PathBuf;

fn vectors() -> CanonValue {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vectors")
        .join("approver-evidence.v1.json");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    CanonValue::parse(&text).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

fn s(v: &CanonValue, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap().to_string()
}

/// The vector case's record JSON, with `evidence_hash` as given and the authority proof profile
/// requested (`v3` carries the subject projection; `v2` carries neither).
fn record_json(case: &CanonValue, evidence_hash: &str, v3: bool) -> String {
    let proof = if v3 {
        format!(r#""proof_version":"v3","subject_projection":"{SUBJECT_PROJECTION}","#)
    } else {
        String::new()
    };
    format!(
        r#"{{
        "schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"govder-v3-{eid}","project_id":"{tenant}","session_id":"tenant:{tenant}",
        "agent_id":"{agent}","agent_version":"unknown","span_id":"span-1","parent_span_id":null,
        "agent_ts":"{at}","event_type":"approval_gate","action":"approval","observed_via":"sdk",
        "status":"{status}",
        "authority":{{"source":"human_signed","enforcement_point":"sdk",{proof}"evidence_hash":"{eh}"}},
        "extensions":{{"govder":{{"v":"1.0.0","type":"approval","event_id":"{eid}","outcome":"{outcome}",
            "occurred_at":"{at}","links":{{"trace_id":"","span_id":""}},"body":{body}}}}},
        "received_ts":"{at}","display_seq":1,"causal_prev_hashes":[],
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}
    }}"#,
        eid = s(case, "event_id"),
        tenant = s(case, "tenant_id"),
        agent = s(case, "agent_id"),
        at = s(case, "occurred_at"),
        outcome = s(case, "outcome"),
        status = if s(case, "outcome") == "ok" {
            "ok"
        } else {
            "blocked"
        },
        body = case.get("body").unwrap().serialize(),
        eh = evidence_hash,
    )
}

/// Seal `unsigned` as govder would (authority signature under `authority_key`, then the
/// recorder's own seal), put it in a one-record bundle and verify it with the authority key pinned.
fn verify_signed(
    case: &CanonValue,
    evidence_hash: &str,
    v3: bool,
) -> (AuthorityTrust, Vec<String>, Vec<String>) {
    verify_signed_with(case, evidence_hash, v3, false, None)
}

/// As `verify_signed`, with the AVE-10 approver-binding policy chosen by the caller.
fn verify_signed_with(
    case: &CanonValue,
    evidence_hash: &str,
    v3: bool,
    require_approver_binding: bool,
    approver_binding_since: Option<&str>,
) -> (AuthorityTrust, Vec<String>, Vec<String>) {
    let (bundle, authority_key) = build_bundle(case, evidence_hash, v3);
    let report = verify_bundle_with(
        &bundle,
        &VerifyOptions {
            trusted_authority_keys: vec![authority_key.verifying_key()],
            require_approver_binding,
            approver_binding_since: approver_binding_since.map(str::to_string),
            ..Default::default()
        },
    );
    (
        report.record_trust[0].authority,
        report.issues,
        report.record_trust[0].notes.clone(),
    )
}

fn build_bundle(
    case: &CanonValue,
    evidence_hash: &str,
    v3: bool,
) -> (CanonValue, ed25519_dalek::SigningKey) {
    let authority_key = signing_key_from_seed(&[7u8; 32]);
    let seal_key = signing_key_from_seed(&[0u8; 32]);
    let unsigned = CanonValue::parse(&record_json(case, evidence_hash, v3)).unwrap();
    let signed_json = if v3 {
        let (digest, sig) = sign_evidence_v3(&unsigned, &authority_key).unwrap();
        unsigned.serialize().replace(
            &format!("\"evidence_hash\":\"{evidence_hash}\""),
            &format!(
                "\"evidence_hash\":\"{evidence_hash}\",\"subject_digest\":\"{digest}\",\"evidence_sig\":\"{sig}\""
            ),
        )
    } else {
        let sig = sign_evidence(
            "human_signed",
            &s(case, "tenant_id"),
            &format!("govder-v3-{}", s(case, "event_id")),
            evidence_hash,
            &authority_key,
        );
        unsigned.serialize().replace(
            &format!("\"evidence_hash\":\"{evidence_hash}\""),
            &format!("\"evidence_hash\":\"{evidence_hash}\",\"evidence_sig\":\"{sig}\""),
        )
    };
    let rec = seal(&CanonValue::parse(&signed_json).unwrap(), &seal_key).unwrap();
    let key_entry = CanonValue::object(vec![
        ("signing_key_id".into(), CanonValue::string("k0")),
        ("key_epoch".into(), CanonValue::Int(0)),
        (
            "public_key".into(),
            CanonValue::string(encode_pubkey(&seal_key.verifying_key())),
        ),
        ("key_status".into(), CanonValue::string("active")),
    ])
    .unwrap();
    let bundle = CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::string("1")),
        (
            "project_id".into(),
            CanonValue::string(s(case, "tenant_id")),
        ),
        ("keys".into(), CanonValue::Array(vec![key_entry])),
        ("records".into(), CanonValue::Array(vec![rec])),
        ("checkpoints".into(), CanonValue::Array(vec![])),
    ])
    .unwrap();
    (bundle, authority_key)
}

fn rederive_issue(issues: &[String]) -> bool {
    issues
        .iter()
        .any(|i| i.contains("not re-derivable") && i.contains("govder"))
}

fn cases(v: &CanonValue) -> Vec<CanonValue> {
    let c = v.get("cases").and_then(|c| c.as_array()).unwrap().clone();
    assert!(c.len() >= 7, "approver evidence vectors shrank");
    c
}

/// The pinned evidence hash for every case re-derives from the record's own fields.
#[test]
fn v3_approval_evidence_rederives_from_the_pinned_vectors() {
    let v = vectors();
    let mut named = 0;
    for case in cases(&v) {
        let name = s(&case, "name");
        // The vector's own bytes hash to the vector's hash (reference check on this side too).
        assert_eq!(
            sha256_prefixed(s(&case, "evidence_canonical").as_bytes()),
            s(&case, "evidence_hash"),
            "{name}: vector hash"
        );
        let (trust, issues, _) = verify_signed(&case, &s(&case, "evidence_hash"), true);
        assert_eq!(trust, AuthorityTrust::Verified, "{name}");
        assert!(
            !rederive_issue(&issues),
            "{name}: the signed evidence must re-derive, got {issues:?}"
        );
        if case.get("body").and_then(|b| b.get("decided_by")).is_some() {
            named += 1;
        }
    }
    assert!(named >= 6);
}

/// A signer that commits to a DIFFERENT decider than the record names (the record is otherwise
/// fully valid: subject digest and signature check out) is caught by re-derivation.
#[test]
fn v3_evidence_naming_a_different_decider_is_refused() {
    let v = vectors();
    for case in cases(&v) {
        let Some(decider) = case
            .get("body")
            .and_then(|b| b.get("decided_by"))
            .and_then(|d| d.as_str())
            .filter(|d| !d.is_empty())
        else {
            continue;
        };
        let name = s(&case, "name");
        let canonical = s(&case, "evidence_canonical");
        let forged = canonical.replace(
            &format!("\"decided_by\":\"{decider}\""),
            "\"decided_by\":\"mallory@acme.test\"",
        );
        assert_ne!(forged, canonical, "{name}: no-op mutation");
        let (trust, issues, _) = verify_signed(&case, &sha256_prefixed(forged.as_bytes()), true);
        assert_eq!(
            trust,
            AuthorityTrust::Verified,
            "{name}: signature is valid"
        );
        assert!(
            rederive_issue(&issues),
            "{name}: evidence naming mallory over a record naming {decider} must not re-derive, got {issues:?}"
        );
    }
}

/// History stays valid. A record whose body carries an approver but whose signed evidence is the
/// pre-XV-11 field set (decided_by and the sign-off set omitted: a record sealed before approver
/// binding) re-derives under the historical spelling, raises NO issue, and says in its notes that the
/// approver identity is not committed by the evidence.
#[test]
fn v3_evidence_without_the_approver_members_is_history_with_a_note() {
    let v = vectors();
    let mut checked = 0;
    for case in cases(&v) {
        let body = case.get("body").unwrap();
        let named = body
            .get("decided_by")
            .and_then(|d| d.as_str())
            .is_some_and(|d| !d.is_empty());
        if !named {
            continue;
        }
        let (trust, issues, notes) = verify_signed(
            &case,
            &sha256_prefixed(legacy_evidence(&case).as_bytes()),
            true,
        );
        assert_eq!(trust, AuthorityTrust::Verified, "{}", s(&case, "name"));
        assert!(
            !rederive_issue(&issues),
            "{}: a pre-XV-11 record must stay valid history, got {issues:?}",
            s(&case, "name")
        );
        assert!(
            notes
                .iter()
                .any(|n| n.contains("predates approver binding")),
            "{}: the record must say its approver identity is not bound, notes: {notes:?}",
            s(&case, "name")
        );
        checked += 1;
    }
    assert!(checked >= 6);
}

/// The historical field set of a vector case (no decided_by, no sign-off digest), canonical.
fn legacy_evidence(case: &CanonValue) -> String {
    format!(
        "{{\"agent_id\":{},\"event_id\":{},\"event_type\":\"approval\",\"occurred_at\":{},\"outcome\":{},\"tenant_id\":{}}}",
        CanonValue::string(s(case, "agent_id")).serialize(),
        CanonValue::string(s(case, "event_id")).serialize(),
        CanonValue::string(s(case, "occurred_at")).serialize(),
        CanonValue::string(s(case, "outcome")).serialize(),
        CanonValue::string(s(case, "tenant_id")).serialize(),
    )
}

/// Dropping or reordering the sign-off set after signing changes the evidence and is refused, even
/// if the signer's evidence is the one the vector pins.
#[test]
fn v3_evidence_binds_the_ordered_sign_off_set() {
    let v = vectors();
    let case = cases(&v)
        .into_iter()
        .find(|c| s(c, "name") == "two-person-recipe-row-0")
        .unwrap();
    let reordered = cases(&v)
        .into_iter()
        .find(|c| s(c, "name") == "order-matters")
        .unwrap();
    // Evidence signed for the (alice, bob) order, record body sealed in the (bob, alice) order.
    let (_, issues, _) = verify_signed(&reordered, &s(&case, "evidence_hash"), true);
    assert!(
        rederive_issue(&issues),
        "reordered set re-derived: {issues:?}"
    );
    assert_ne!(s(&case, "evidence_hash"), s(&reordered, "evidence_hash"));
}

/// A historical v2 (legacy-unbound) govder record keeps its original field set: the approver
/// members are v3 only, so already-signed v2 bytes still re-derive.
#[test]
fn v2_records_keep_the_historical_field_set() {
    let v = vectors();
    let case = cases(&v)
        .into_iter()
        .find(|c| s(c, "name") == "single-approver")
        .unwrap();
    let legacy = legacy_evidence(&case);
    let (trust, issues, _) = verify_signed(&case, &sha256_prefixed(legacy.as_bytes()), false);
    assert_eq!(trust, AuthorityTrust::LegacyUnbound);
    assert!(
        !rederive_issue(&issues),
        "v2 record must still re-derive: {issues:?}"
    );
}

fn binding_issue(issues: &[String]) -> bool {
    issues.iter().any(|i| {
        i.contains("approver binding is required") && i.contains("does not commit who approved")
    })
}

fn unbound_cases(v: &CanonValue) -> Vec<CanonValue> {
    cases(v)
        .into_iter()
        .filter(|c| {
            c.get("body")
                .and_then(|b| b.get("decided_by"))
                .and_then(|d| d.as_str())
                .is_some_and(|d| !d.is_empty())
        })
        .collect()
}

/// AVE-10: with the policy on, an approval whose signed evidence leaves out who approved is an issue
/// (the verdict fails). With it off (the default) the same record stays history with a note.
#[test]
fn ave10_unbound_approval_fails_when_binding_is_required() {
    let v = vectors();
    let mut checked = 0;
    for case in unbound_cases(&v) {
        let hash = sha256_prefixed(legacy_evidence(&case).as_bytes());
        let name = s(&case, "name");
        let (_, off, _) = verify_signed_with(&case, &hash, true, false, None);
        assert!(
            !binding_issue(&off),
            "{name}: policy off must not raise it: {off:?}"
        );
        let (trust, on, notes) = verify_signed_with(&case, &hash, true, true, None);
        assert_eq!(
            trust,
            AuthorityTrust::Verified,
            "{name}: the signature itself is fine"
        );
        assert!(
            binding_issue(&on),
            "{name}: policy on must raise the issue, got {on:?}"
        );
        assert!(
            notes
                .iter()
                .any(|n| n.contains("predates approver binding")),
            "{name}: the note stays: {notes:?}"
        );
        checked += 1;
    }
    assert!(checked >= 6);
}

/// AVE-10: a properly bound approval raises nothing under the strict policy.
#[test]
fn ave10_bound_approval_passes_when_binding_is_required() {
    let v = vectors();
    for case in cases(&v) {
        let (trust, issues, _) =
            verify_signed_with(&case, &s(&case, "evidence_hash"), true, true, None);
        assert_eq!(trust, AuthorityTrust::Verified, "{}", s(&case, "name"));
        assert!(
            !binding_issue(&issues) && !rederive_issue(&issues),
            "{}: bound evidence must be clean under the strict policy, got {issues:?}",
            s(&case, "name")
        );
    }
}

/// AVE-10 cutover: a record received before `approver_binding_since` stays history, one received at or
/// after it fails. The vector records are received at their `occurred_at`.
#[test]
fn ave10_cutover_separates_history_from_new_records() {
    let v = vectors();
    for case in unbound_cases(&v) {
        let hash = sha256_prefixed(legacy_evidence(&case).as_bytes());
        let at = s(&case, "occurred_at");
        let name = s(&case, "name");
        let (_, issues, _) =
            verify_signed_with(&case, &hash, true, true, Some("9999-01-01T00:00:00.000Z"));
        assert!(
            !binding_issue(&issues),
            "{name}: before the cutover it is history: {issues:?}"
        );
        let (_, issues, _) = verify_signed_with(&case, &hash, true, true, Some(&at));
        assert!(
            binding_issue(&issues),
            "{name}: received exactly at the cutover must fail: {issues:?}"
        );
        let (_, issues, _) =
            verify_signed_with(&case, &hash, true, true, Some("0001-01-01T00:00:00.000Z"));
        assert!(
            binding_issue(&issues),
            "{name}: after the cutover it must fail: {issues:?}"
        );
    }
}

/// AVE-10 through the JSON opts path the server, the CLI and the browser verifier use: the policy is read
/// from opts.json, a wrong type or a cutover without the policy is an error, never a silent default.
#[test]
fn ave10_policy_is_read_from_json_options() {
    use averin_decision_core::verify::verify_bundle_with_json;
    let v = vectors();
    let case = unbound_cases(&v).remove(0);
    let hash = sha256_prefixed(legacy_evidence(&case).as_bytes());
    let (bundle, key) = build_bundle(&case, &hash, true);
    let text = bundle.serialize();
    let pk = encode_pubkey(&key.verifying_key());
    let run = |extra: &str| {
        let opts = format!("{{\"authority_keys\":[\"{pk}\"]{extra}}}");
        CanonValue::parse(&verify_bundle_with_json(&text, &opts))
            .unwrap()
            .serialize()
    };
    assert!(!run("").contains("approver binding is required"));
    assert!(run(",\"require_approver_binding\":true").contains("approver binding is required"));
    assert!(run(",\"require_approver_binding\":\"yes\"").contains("must be a boolean"));
    assert!(
        run(",\"approver_binding_since\":\"2026-01-01T00:00:00.000Z\"")
            .contains("needs require_approver_binding")
    );
    assert!(
        run(",\"require_approver_binding\":true,\"approver_binding_since\":\"yesterday\"")
            .contains("canonical timestamp")
    );
    assert!(!run(",\"require_approver_binding\":true,\"approver_binding_since\":\"9999-01-01T00:00:00.000Z\"").contains("approver binding is required"));
}

/// AVE-10 on the command line: `averin-verify bundle` fails an approval that does not commit who
/// approved, says why and counts it, unless `--allow-unbound-approvers` accepts it as history; a bound
/// approval is untouched.
#[test]
fn ave10_cli_fails_unbound_approval_and_shows_the_reason() {
    use std::process::Command;
    let v = vectors();
    let case = unbound_cases(&v).remove(0);
    let dir = std::env::temp_dir().join(format!("averin-ave10-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let run = |hash: &str, extra: &[&str]| {
        let (bundle, key) = build_bundle(&case, hash, true);
        let b = dir.join("bundle.json");
        let o = dir.join("opts.json");
        std::fs::write(&b, bundle.serialize()).unwrap();
        std::fs::write(
            &o,
            format!(
                "{{\"authority_keys\":[\"{}\"]}}",
                encode_pubkey(&key.verifying_key())
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_averin-verify"))
            .arg("bundle")
            .arg(&b)
            .arg(&o)
            .args(extra)
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let unbound = sha256_prefixed(legacy_evidence(&case).as_bytes());
    // The one-record fixture has no checkpoint, so the verdict is FAIL either way; what the policy adds is
    // the issue line and the count, which is what these assertions pin.
    let (code, out) = run(&unbound, &[]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("RESULT: FAIL"), "{out}");
    assert!(
        out.contains("approver binding is required"),
        "reason shown:\n{out}"
    );
    assert!(
        out.contains("approvals not committing the approver: 1"),
        "count shown:\n{out}"
    );

    let (_, out) = run(&unbound, &["--allow-unbound-approvers"]);
    assert!(
        !out.contains("approver binding is required"),
        "opt-out accepts history:\n{out}"
    );
    assert!(
        out.contains("approvals not committing the approver: 1"),
        "still counted:\n{out}"
    );
    assert!(out.contains("--allow-unbound-approvers"), "{out}");

    let (_, out) = run(&s(&case, "evidence_hash"), &[]);
    assert!(
        !out.contains("approver binding is required"),
        "a bound approval is untouched:\n{out}"
    );
    assert!(
        !out.contains("approvals not committing the approver"),
        "{out}"
    );
}

/// A copy of the single-approver vector whose body is `body_json` (the evidence stays the historical
/// field set, which is also what govder seals when a decision has no decider).
fn case_with_body(v: &CanonValue, body_json: &str) -> CanonValue {
    let base = cases(v).into_iter().next().unwrap();
    let mut pairs = Vec::new();
    for k in [
        "event_id",
        "agent_id",
        "tenant_id",
        "outcome",
        "occurred_at",
    ] {
        pairs.push((k.to_string(), CanonValue::string(s(&base, k))));
    }
    pairs.push(("body".to_string(), CanonValue::parse(body_json).unwrap()));
    CanonValue::object(pairs).unwrap()
}

fn names_no_approver_issue(issues: &[String]) -> bool {
    issues
        .iter()
        .any(|i| i.contains("approver binding is required") && i.contains("names no approver"))
}

/// AVE-10: a decided govder approval that names no approver at all (decided_by absent or empty, no
/// sign-offs) fails under the strict policy, even though its signed evidence matches. A pending
/// record, which has no decider by design, stays clean.
#[test]
fn ave10_decided_approval_naming_nobody_fails_when_binding_is_required() {
    let v = vectors();
    for (name, body) in [
        ("decided_by absent", r#"{"status":"approved"}"#),
        ("decided_by empty", r#"{"status":"approved","decided_by":""}"#),
        ("denied, none", r#"{"status":"denied"}"#),
        (
            "empty sign_offs",
            r#"{"status":"approved","sign_offs":[]}"#,
        ),
    ] {
        let case = case_with_body(&v, body);
        let hash = sha256_prefixed(legacy_evidence(&case).as_bytes());
        let (_, off, notes) = verify_signed_with(&case, &hash, true, false, None);
        assert!(!names_no_approver_issue(&off), "{name}: policy off: {off:?}");
        assert!(
            notes.iter().any(|n| n.contains("names no approver")),
            "{name}: the note is always there: {notes:?}"
        );
        let (trust, on, _) = verify_signed_with(&case, &hash, true, true, None);
        assert_eq!(trust, AuthorityTrust::Verified, "{name}");
        assert!(
            names_no_approver_issue(&on),
            "{name}: policy on must raise the issue, got {on:?}"
        );
    }
    for (name, body) in [
        ("pending", r#"{"status":"pending"}"#),
        ("expired", r#"{"status":"expired"}"#),
    ] {
        let case = case_with_body(&v, body);
        let hash = sha256_prefixed(legacy_evidence(&case).as_bytes());
        let (_, on, notes) = verify_signed_with(&case, &hash, true, true, None);
        assert!(
            !names_no_approver_issue(&on) && !notes.iter().any(|n| n.contains("names no approver")),
            "{name}: exempt: {on:?} {notes:?}"
        );
    }
}
