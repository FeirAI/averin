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
    let report = verify_bundle_with(
        &bundle,
        &VerifyOptions {
            trusted_authority_keys: vec![authority_key.verifying_key()],
            ..Default::default()
        },
    );
    (
        report.record_trust[0].authority,
        report.issues,
        report.record_trust[0].notes.clone(),
    )
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
