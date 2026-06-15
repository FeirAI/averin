//! Adversarial acceptance gates (spec §15/§17). Derives tampered / omitted / forked / backdated /
//! compromised-key variants from the valid bundle fixture and asserts the offline verifier detects
//! each: #1 omission, #2 fork, #3 backdating, #4 key pinning, #7 subset-frontier, #8 dup-collapse,
//! #9 key compromise, plus integrity tamper.

use feir_decision_core::anchor::{make_test_anchor, test_tsa_key};
use feir_decision_core::canon::CanonValue;
use feir_decision_core::checkpoint::{attach_anchor, checkpoint_body, seal_checkpoint};
use feir_decision_core::sign::signing_key_from_seed;
use feir_decision_core::verify::{
    verify_bundle, verify_bundle_with, TrustLevel, TrustedKey, VerifyOptions,
};
use std::path::PathBuf;

fn fixture() -> CanonValue {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec")
        .join("fixtures")
        .join("bundle-valid.json");
    CanonValue::parse(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn arr(b: &CanonValue, k: &str) -> Vec<CanonValue> {
    b.get(k)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn rebuild(
    keys: Vec<CanonValue>,
    records: Vec<CanonValue>,
    checkpoints: Vec<CanonValue>,
) -> CanonValue {
    CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::string("1")),
        ("project_id".into(), CanonValue::string("proj-001")),
        ("keys".into(), CanonValue::Array(keys)),
        ("records".into(), CanonValue::Array(records)),
        ("checkpoints".into(), CanonValue::Array(checkpoints)),
    ])
    .unwrap()
}

fn change_field(obj: &CanonValue, key: &str, val: CanonValue) -> CanonValue {
    let mut m = obj.as_object().unwrap().clone();
    let mut found = false;
    for (k, v) in m.iter_mut() {
        if k == key {
            *v = val.clone();
            found = true;
        }
    }
    if !found {
        m.push((key.to_string(), val));
    }
    CanonValue::Object(m)
}

fn checkpoint_hash(cp: &CanonValue) -> String {
    cp.get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn credential_grant_verifies_to_gateway_enforced_under_pinned_broker_key() {
    use feir_decision_core::authority::sign_evidence;
    use feir_decision_core::hashx::sha256_prefixed;
    use feir_decision_core::record::seal;
    use feir_decision_core::sign::encode_pubkey;

    let sk = signing_key_from_seed(&[0u8; 32]); // the broker recording key == the record signing key
    let vk = sk.verifying_key();
    let record_id = "grant-1";
    // Canonical grant_evidence (ADR 0003 R1): evidence_hash is re-derived from THIS payload. The
    // record embeds it at extensions.broker.grant_evidence; the verifier confirms the signed
    // evidence_hash == sha256(RCP-canonicalize(grant_evidence)) before counting the grant verified.
    let grant_evidence = CanonValue::object(vec![
        ("kind".into(), CanonValue::string("grant")),
        ("grant_id".into(), CanonValue::string(record_id)),
        ("action".into(), CanonValue::string("db.query:orders-ro")),
        ("resource_id".into(), CanonValue::string("orders-db")),
        ("scope_class".into(), CanonValue::string("single_operation")),
        ("agent_id".into(), CanonValue::string("agent")),
        ("cnf_kid".into(), CanonValue::string("ed25519-AgentKid0")),
        ("issued_at".into(), CanonValue::Int(1_718_445_600)),
        ("exp".into(), CanonValue::Int(1_718_445_660)),
    ])
    .unwrap();
    let evidence_hash = sha256_prefixed(grant_evidence.serialize().as_bytes());
    let evidence_sig = sign_evidence("gateway_enforced", record_id, &evidence_hash, &sk);
    // Build a grant body with a given extensions.broker inner body + authority (evidence_hash/sig).
    let mk_body = |broker_inner: &str, eh: &str, esig: &str| {
        format!(
            r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{record_id}","project_id":"proj-001","agent_id":"agent","agent_version":"feir-broker",
        "session_id":"s","span_id":"sp","parent_span_id":null,"causal_prev_hashes":[],"display_seq":0,
        "agent_ts":"2026-06-15T10:00:00.000Z","received_ts":"2026-06-15T10:00:00.000Z",
        "event_type":"credential_grant","action":"db.query:orders-ro","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"credential_broker","grant_type":"id-jag",
            "grant_id":"{record_id}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "extensions":{{"broker":{{{broker_inner}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#
        )
    };
    let ge_inner = |ge: &CanonValue| format!(r#""grant_evidence":{}"#, ge.serialize());
    let body = mk_body(&ge_inner(&grant_evidence), &evidence_hash, &evidence_sig);
    let grant = seal(&CanonValue::parse(&body).unwrap(), &sk).unwrap();
    let key_entry = CanonValue::object(vec![
        ("signing_key_id".into(), CanonValue::string("k0")),
        ("key_epoch".into(), CanonValue::Int(0)),
        ("public_key".into(), CanonValue::string(encode_pubkey(&vk))),
        ("key_status".into(), CanonValue::string("active")),
    ])
    .unwrap();
    let bundle = CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::string("1")),
        ("project_id".into(), CanonValue::string("proj-001")),
        ("keys".into(), CanonValue::Array(vec![key_entry])),
        ("records".into(), CanonValue::Array(vec![grant.clone()])),
        ("checkpoints".into(), CanonValue::Array(vec![])),
    ])
    .unwrap();
    let pinned = || VerifyOptions {
        trusted_authority_keys: vec![vk],
        ..Default::default()
    };

    // Without pinning the authority key, the grant is counted but NOT verified (declared/unverifiable).
    let r = verify_bundle(&bundle);
    assert_eq!(r.grant_total, 1);
    assert_eq!(r.grant_verified, 0);

    // A body-tampered grant must NOT count as verified even though its authority evidence is intact:
    // changing `action` after sealing breaks content_hash (Untrusted), and grant_verified is gated on
    // the record being integrity-proven, not just authority-verified.
    let tampered = change_field(&grant, "action", CanonValue::string("db.delete:everything"));
    let tampered_bundle = change_field(&bundle, "records", CanonValue::Array(vec![tampered]));
    let rt = verify_bundle_with(&tampered_bundle, &pinned());
    assert_eq!(rt.grant_total, 1);
    assert_eq!(
        rt.grant_verified, 0,
        "a body-tampered grant must not be 'verified' just because its evidence_sig is intact"
    );

    // A verbatim-duplicated grant is counted ONCE (deduped by content_hash), not double-counted.
    let dup_bundle = change_field(
        &bundle,
        "records",
        CanonValue::Array(vec![grant.clone(), grant.clone()]),
    );
    let rd = verify_bundle_with(&dup_bundle, &pinned());
    assert_eq!(rd.grant_total, 1, "a duplicated grant must be deduped");
    assert_eq!(rd.grant_verified, 1);

    // Pinning the broker recording key elevates the grant to gateway_enforced (Tier-A complete).
    let r2 = verify_bundle_with(&bundle, &pinned());
    assert_eq!(r2.grant_total, 1);
    assert_eq!(r2.grant_verified, 1);

    // The report JSON surfaces the Tier-A verdict.
    let json = feir_decision_core::verify::report_to_json(&r2);
    assert!(
        json.contains(r#""grant_accountability":"complete""#),
        "{json}"
    );
    assert!(json.contains(r#""broker_trust":"assumed""#));
    assert!(json.contains(r#""action_completeness":"not_claimed""#)); // no coverage_manifest here

    // R1 (ADR 0003): a grant whose embedded grant_evidence DIVERGES from the signed evidence_hash must
    // NOT verify, even though the record seals correctly and the evidence_sig is valid. The authority
    // commits to the real evidence (hash(E1)); the embedded payload is E2 (action swapped). The
    // verifier re-derives hash(E2) != hash(E1) and refuses to count it, surfacing a fail-closed issue —
    // closing the "AuthorityTrust::Verified proves the signer committed to the match fields" gap.
    let e2 = change_field(
        &grant_evidence,
        "action",
        CanonValue::string("db.delete:everything"),
    );
    let diverged_body = mk_body(&ge_inner(&e2), &evidence_hash, &evidence_sig);
    let diverged = seal(&CanonValue::parse(&diverged_body).unwrap(), &sk).unwrap();
    let diverged_bundle = change_field(&bundle, "records", CanonValue::Array(vec![diverged]));
    let r1 = verify_bundle_with(&diverged_bundle, &pinned());
    assert_eq!(r1.grant_total, 1);
    assert_eq!(
        r1.grant_verified, 0,
        "a grant whose grant_evidence does not re-derive its signed evidence_hash must not verify (R1)"
    );
    assert!(
        r1.issues.iter().any(|i| i.contains("not re-derivable")),
        "expected an R1 re-derivation issue, got: {:?}",
        r1.issues
    );

    // R1 fail-closed on ABSENT payload: a grant with valid (pinned) authority but NO embedded
    // grant_evidence is as unacceptable as a divergent one — the verifier cannot confirm the signed
    // evidence_hash commits to any match fields, so it must NOT count and must surface the issue.
    let no_ge_body = mk_body(r#""issuance_status":"recorded""#, &evidence_hash, &evidence_sig);
    let no_ge = seal(&CanonValue::parse(&no_ge_body).unwrap(), &sk).unwrap();
    let no_ge_bundle = change_field(&bundle, "records", CanonValue::Array(vec![no_ge]));
    let r_absent = verify_bundle_with(&no_ge_bundle, &pinned());
    assert_eq!(r_absent.grant_total, 1);
    assert_eq!(
        r_absent.grant_verified, 0,
        "a grant with no embedded grant_evidence must not verify (R1 fail-closed)"
    );
    assert!(
        r_absent.issues.iter().any(|i| i.contains("not re-derivable")),
        "expected an R1 absent-payload issue, got: {:?}",
        r_absent.issues
    );

    // A forged gateway_enforced grant (agent-claimed, no real broker key) does NOT elevate: re-sign
    // the evidence with a DIFFERENT key, pin only the real broker key.
    let imposter = signing_key_from_seed(&[7u8; 32]);
    let bad_sig = sign_evidence("gateway_enforced", record_id, &evidence_hash, &imposter);
    let bad_body = body.replace(&evidence_sig, &bad_sig);
    let bad_grant = seal(&CanonValue::parse(&bad_body).unwrap(), &sk).unwrap();
    let bad_bundle = change_field(&bundle, "records", CanonValue::Array(vec![bad_grant]));
    let r3 = verify_bundle_with(&bad_bundle, &pinned());
    assert_eq!(r3.grant_total, 1);
    assert_eq!(
        r3.grant_verified, 0,
        "a grant not signed by the pinned broker key must not verify"
    );

    // verify_bundle_with_json fails CLOSED on a malformed pinned key (no silent drop to unpinned).
    let report = feir_decision_core::verify::verify_bundle_with_json(
        &bundle.serialize(),
        r#"{"authority_keys":["not-a-key"]}"#,
    );
    assert!(
        report.contains(r#""ok":false"#) && report.contains("authority_keys[0]"),
        "malformed pinned key should be a fail-closed error: {report}"
    );
}

#[test]
fn valid_bundle_verifies_clean() {
    let b = fixture();
    let r = verify_bundle(&b);
    assert!(r.ok, "valid bundle should verify; issues: {:?}", r.issues);
    assert_eq!(r.records_total, 3);
    assert_eq!(r.records_proven, 3);
    assert!(r
        .record_trust
        .iter()
        .all(|t| t.trust == TrustLevel::IntegrityProven));
    assert!(r.dag_ok && r.chain_ok);
    assert_eq!(r.checkpoints_verified, 2);
    assert_eq!(r.dag_heads, 2); // two session heads
    assert!(r.first_broken_link.is_none());
    // r2 discloses its committed `input` AND `output`; the verifier confirms both against the sealed
    // commitments (two domains, end to end).
    assert_eq!(r.disclosures_total, 2);
    assert_eq!(r.disclosures_verified, 2);
}

// disclosures is a top-level bundle array; mutate the `input` entry (disclosures[0]) and splice back.
fn with_disclosure(b: &CanonValue, field: &str, val: CanonValue) -> CanonValue {
    let mut disc = arr(b, "disclosures");
    disc[0] = change_field(&disc[0], field, val);
    change_field(b, "disclosures", CanonValue::Array(disc))
}

#[test]
fn tampered_disclosure_value_is_detected() {
    // Threat #6: the exporter reveals a DIFFERENT value than was committed for `input`. The
    // nonce/commitment are unchanged, so the recomputed commitment no longer matches — caught, the
    // bundle fails, and only the untouched `output` disclosure still verifies.
    let b = fixture();
    // base64url of "SELECT * FROM accounts -- doctored" (not the committed value).
    let bad = with_disclosure(
        &b,
        "value_b64",
        CanonValue::string("U0VMRUNUICogRlJPTSBhY2NvdW50cyAtLSBkb2N0b3JlZA"),
    );
    let r = verify_bundle(&bad);
    assert!(!r.ok, "a mismatched disclosure must fail the bundle");
    assert_eq!(
        r.disclosures_verified, 1,
        "output still verifies; input does not"
    );
    assert!(
        r.issues.iter().any(|i| i.contains("does not match")),
        "expected commitment-mismatch issue, got: {:?}",
        r.issues
    );
}

#[test]
fn disclosure_against_wrong_present_field_is_detected() {
    // The `field` selects BOTH the commitment slot (`<field>_commit`) AND the commitment domain. Take
    // the (value, nonce) that legitimately opens `input_commit` but relabel it `output`: the verifier
    // recomputes commit(Output, input_value, input_nonce) against `output_commit` and it must NOT
    // match. Proves field→domain is bound, not just value equality. (Single disclosure so the
    // duplicate-(record,field) guard doesn't fire against the real output disclosure.)
    let b = fixture();
    let input_disc = arr(&b, "disclosures")
        .into_iter()
        .find(|d| d.get("field").and_then(|v| v.as_str()) == Some("input"))
        .expect("fixture has an input disclosure");
    let cross = change_field(&input_disc, "field", CanonValue::string("output"));
    let bad = change_field(&b, "disclosures", CanonValue::Array(vec![cross]));
    let r = verify_bundle(&bad);
    assert!(!r.ok);
    assert_eq!(r.disclosures_verified, 0);
    assert!(
        r.issues.iter().any(|i| i.contains("does not match")),
        "got: {:?}",
        r.issues
    );
}

#[test]
fn disclosure_for_uncommitted_field_is_rejected() {
    // r2 has no `rationale_commit`; a disclosure naming `rationale` has nothing to check against.
    let b = fixture();
    let bad = with_disclosure(&b, "field", CanonValue::string("rationale"));
    let r = verify_bundle(&bad);
    assert!(!r.ok);
    assert!(
        r.issues
            .iter()
            .any(|i| i.contains("no rationale_commit.commitment")),
        "got: {:?}",
        r.issues
    );
}

#[test]
fn duplicate_disclosure_for_same_field_is_rejected() {
    // Two disclosures for the same (record_id, field) are redundant at best, contradictory at worst
    // (one commitment cannot open to two values). The second is flagged, failing the bundle.
    let b = fixture();
    let input_disc = arr(&b, "disclosures")
        .into_iter()
        .find(|d| d.get("field").and_then(|v| v.as_str()) == Some("input"))
        .expect("fixture has an input disclosure");
    let dup = vec![input_disc.clone(), input_disc];
    let bad = change_field(&b, "disclosures", CanonValue::Array(dup));
    let r = verify_bundle(&bad);
    assert!(!r.ok);
    assert!(
        r.issues.iter().any(|i| i.contains("duplicate disclosure")),
        "got: {:?}",
        r.issues
    );
}

#[test]
fn disclosure_with_malformed_nonce_is_rejected() {
    let b = fixture();
    let bad = with_disclosure(&b, "nonce_hex", CanonValue::string("not-64-hex-chars"));
    let r = verify_bundle(&bad);
    assert!(!r.ok);
    assert!(
        r.issues.iter().any(|i| i.contains("nonce must be 64")),
        "got: {:?}",
        r.issues
    );
}

#[test]
fn disclosure_referencing_unknown_record_is_rejected() {
    let b = fixture();
    let bad = with_disclosure(&b, "record_id", CanonValue::string("does-not-exist"));
    let r = verify_bundle(&bad);
    assert!(!r.ok);
    assert!(
        r.issues
            .iter()
            .any(|i| i.contains("no record 'does-not-exist'")),
        "got: {:?}",
        r.issues
    );
}

#[test]
fn disclosures_null_is_treated_as_absent() {
    // An SDK serializing an empty Option as JSON null must not brick an otherwise-valid bundle.
    let b = fixture();
    let nulled = change_field(&b, "disclosures", CanonValue::Null);
    let r = verify_bundle(&nulled);
    assert!(
        r.ok,
        "null disclosures == no disclosures; issues: {:?}",
        r.issues
    );
    assert_eq!(r.disclosures_total, 0);
}

#[test]
fn tamper_a_record_body_is_detected() {
    // Attacker edits a signed field but cannot re-sign (no key): content_hash no longer matches.
    let b = fixture();
    let keys = arr(&b, "keys");
    let mut records = arr(&b, "records");
    records[2] = change_field(&records[2], "action", CanonValue::string("rm -rf /"));
    let bad = rebuild(keys, records, arr(&b, "checkpoints"));

    let r = verify_bundle(&bad);
    assert!(!r.ok);
    let t = &r.record_trust[2];
    assert!(!t.integrity_ok, "tampered record must fail integrity");
    assert_eq!(t.trust, TrustLevel::Untrusted);
}

#[test]
fn omitted_session_is_detected_via_checkpoint_frontier() {
    // Threat #1: drop session B (record r2, a committed frontier head) but keep the checkpoints.
    let b = fixture();
    let keys = arr(&b, "keys");
    let records: Vec<CanonValue> = arr(&b, "records")
        .into_iter()
        .filter(|r| r.get("record_id").and_then(|v| v.as_str()) != Some("r2"))
        .collect();
    assert_eq!(records.len(), 2);
    let bad = rebuild(keys, records, arr(&b, "checkpoints"));

    let r = verify_bundle(&bad);
    assert!(!r.ok, "omission must fail verification");
    assert!(!r.chain_ok);
    let broken = r.first_broken_link.unwrap_or_default() + &r.issues.join(" ");
    assert!(
        broken.contains("OMISSION"),
        "expected omission detection, got: {broken}"
    );
}

#[test]
fn forked_history_is_detected() {
    // Threat #2: a second, distinct checkpoint at seq 0 signed by the SAME (known test) key.
    let b = fixture();
    let sk = signing_key_from_seed(&[0u8; 32]); // matches the fixture generator
    let key_block =
        CanonValue::parse(r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active"}"#)
            .unwrap();
    // reuse the real frontier so the fork itself (not a missing head) is what trips detection
    let frontier: Vec<String> = arr(&b, "checkpoints")[0]
        .get("frontier")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect();
    let forkbody = checkpoint_body(
        "cp0-fork",
        "proj-001",
        0,
        None,
        &frontier,
        3,
        "2026-06-15T11:11:11.000Z", // different time -> distinct checkpoint_hash
        key_block,
    )
    .unwrap();
    let fork = seal_checkpoint(&forkbody, &sk).unwrap();

    let mut checkpoints = arr(&b, "checkpoints");
    checkpoints.push(fork);
    let bad = rebuild(arr(&b, "keys"), arr(&b, "records"), checkpoints);

    let r = verify_bundle(&bad);
    assert!(!r.ok);
    let broken = r.first_broken_link.unwrap_or_default() + &r.issues.join(" ");
    assert!(
        broken.contains("FORK"),
        "expected fork detection, got: {broken}"
    );
}

#[test]
fn subset_frontier_leaving_a_head_uncovered_is_detected() {
    // Threat #7/#1: latest checkpoint frontier covers only ONE of two real heads. Even with every
    // record present, the frontier-vs-heads equality check must reject it (so anchoring this
    // frontier later can guarantee completeness).
    let b = fixture();
    let sk = signing_key_from_seed(&[0u8; 32]);
    let key_block =
        CanonValue::parse(r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active"}"#)
            .unwrap();
    let cps = arr(&b, "checkpoints");
    let cp0h = cps[0]
        .get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let one_head = cps[0].get("frontier").unwrap().as_array().unwrap()[0]
        .as_str()
        .unwrap()
        .to_string();
    let body = checkpoint_body(
        "cp1",
        "proj-001",
        1,
        Some(&cp0h),
        &[one_head], // omit the second head
        3,
        "2026-06-15T10:05:00.000Z",
        key_block,
    )
    .unwrap();
    let cp1 = seal_checkpoint(&body, &sk).unwrap();
    let bad = rebuild(
        arr(&b, "keys"),
        arr(&b, "records"),
        vec![cps[0].clone(), cp1],
    );

    let r = verify_bundle(&bad);
    assert!(!r.ok);
    let broken = r.first_broken_link.unwrap_or_default() + &r.issues.join(" ");
    assert!(
        broken.contains("frontier"),
        "expected frontier-vs-heads mismatch, got: {broken}"
    );
}

#[test]
fn out_of_band_key_pinning_governs_authenticity() {
    // Threat #4: the bundle's own key list is attacker-supplied. With the CORRECT pinned key the
    // bundle is authentic; with a WRONG pinned key nothing is trusted (no silent authenticity).
    let b = fixture();
    let correct = signing_key_from_seed(&[0u8; 32]).verifying_key();
    let wrong = signing_key_from_seed(&[7u8; 32]).verifying_key();

    let ok = verify_bundle_with(
        &b,
        &VerifyOptions {
            trusted_keys: Some(vec![correct.into()]),
            ..Default::default()
        },
    );
    assert!(ok.ok && ok.keys_externally_pinned);

    let bad = verify_bundle_with(
        &b,
        &VerifyOptions {
            trusted_keys: Some(vec![wrong.into()]),
            ..Default::default()
        },
    );
    assert!(!bad.ok);
    assert!(bad
        .record_trust
        .iter()
        .all(|t| t.trust == TrustLevel::Untrusted));
}

#[test]
fn missing_public_key_is_not_silently_trusted() {
    // No keys -> signatures unverifiable -> nothing is IntegrityProven, bundle not ok.
    let b = fixture();
    let bad = rebuild(vec![], arr(&b, "records"), arr(&b, "checkpoints"));
    let r = verify_bundle(&bad);
    assert!(!r.ok);
    assert_eq!(r.records_proven, 0);
    assert!(r
        .record_trust
        .iter()
        .all(|t| t.trust == TrustLevel::Untrusted));
}

/// Anchor cp1 (the latest checkpoint) at `anchored_ts` with the test TSA. The bundle key entry is
/// LYINGLY marked compromised in the far past (2020) to prove that under pinning the auditor's
/// authoritative compromise time — not the bundle's claim — governs the upgrade.
fn compromised_bundle(anchored_ts: &str) -> (CanonValue, ed25519_dalek::VerifyingKey) {
    let b = fixture();
    let tsa = test_tsa_key(&[200u8; 32]);
    let mut checkpoints = arr(&b, "checkpoints");
    let cp1 = &checkpoints[1];
    let anchor = make_test_anchor(&checkpoint_hash(cp1), anchored_ts, &tsa, "tsa-1");
    checkpoints[1] = attach_anchor(cp1, anchor);

    let mut keys = arr(&b, "keys");
    keys[0] = change_field(&keys[0], "key_status", CanonValue::string("compromised"));
    keys[0] = change_field(
        &keys[0],
        "status_changed_at",
        CanonValue::string("2020-01-01T00:00:00.000Z"), // bundle lie — ignored under pinning
    );
    (
        rebuild(keys, arr(&b, "records"), checkpoints),
        tsa.verifying_key(),
    )
}

fn pinned_compromised(changed_at: &str) -> TrustedKey {
    TrustedKey {
        vk: signing_key_from_seed(&[0u8; 32]).verifying_key(),
        status: Some("compromised".to_string()),
        status_changed_at: Some(changed_at.to_string()),
    }
}

#[test]
fn compromised_key_anchored_before_compromise_stays_trusted() {
    // Threat #9: auditor knows (out-of-band) the key was compromised at 10:10, but every record was
    // committed in a checkpoint anchored at 10:02 (before). Those records remain IntegrityProven.
    let (b, tsa_vk) = compromised_bundle("2026-06-15T10:02:00.000Z");
    let r = verify_bundle_with(
        &b,
        &VerifyOptions {
            trusted_keys: Some(vec![pinned_compromised("2026-06-15T10:10:00.000Z")]),
            trusted_tsa_keys: vec![tsa_vk],
            ..Default::default()
        },
    );
    assert!(
        r.ok,
        "anchored-before-compromise should pass; issues: {:?}",
        r.issues
    );
    assert_eq!(r.records_proven, 3);
    assert!(r
        .record_trust
        .iter()
        .all(|t| t.trust == TrustLevel::IntegrityProven));
}

#[test]
fn compromised_key_not_anchored_before_compromise_is_untrusted() {
    // Same setup, but the auditor's authoritative compromise time (10:01) is BEFORE the anchor
    // (10:02) — so no record is anchored before the compromise; all downgrade to Untrusted.
    let (b, tsa_vk) = compromised_bundle("2026-06-15T10:02:00.000Z");
    let r = verify_bundle_with(
        &b,
        &VerifyOptions {
            trusted_keys: Some(vec![pinned_compromised("2026-06-15T10:01:00.000Z")]),
            trusted_tsa_keys: vec![tsa_vk],
            ..Default::default()
        },
    );
    assert!(!r.ok);
    assert_eq!(r.records_proven, 0);
    let broken = r.first_broken_link.unwrap_or_default() + &r.issues.join(" ");
    assert!(
        broken.contains("threat #9"),
        "expected compromise downgrade, got: {broken}"
    );
}

#[test]
fn future_dated_bundle_compromise_cannot_upgrade_under_pinning() {
    // Threat #4/#9: an attacker future-dates the BUNDLE's compromise claim to try to upgrade. Under
    // pinning the bundle's status_changed_at is ignored; with no auditor-supplied compromise time,
    // the compromised key cannot be upgraded -> Untrusted.
    let (b, tsa_vk) = compromised_bundle("2026-06-15T10:02:00.000Z");
    let correct = signing_key_from_seed(&[0u8; 32]).verifying_key();
    let r = verify_bundle_with(
        &b,
        &VerifyOptions {
            trusted_keys: Some(vec![correct.into()]), // no authoritative compromise time
            trusted_tsa_keys: vec![tsa_vk],
            ..Default::default()
        },
    );
    assert!(!r.ok, "bundle's future-dated compromise must not upgrade");
    assert_eq!(r.records_proven, 0);
}

#[test]
fn backdated_anchor_time_is_detected() {
    // Threat #3: cp0 anchored at 10:05 but cp1 (later seq) anchored at 10:02 — anchor time went
    // backwards, which an un-forgeable TSA timestamp cannot do. Detected.
    let b = fixture();
    let tsa = test_tsa_key(&[200u8; 32]);
    let mut checkpoints = arr(&b, "checkpoints");
    let a0 = make_test_anchor(
        &checkpoint_hash(&checkpoints[0]),
        "2026-06-15T10:05:00.000Z",
        &tsa,
        "t",
    );
    let a1 = make_test_anchor(
        &checkpoint_hash(&checkpoints[1]),
        "2026-06-15T10:02:00.000Z",
        &tsa,
        "t",
    );
    checkpoints[0] = attach_anchor(&checkpoints[0], a0);
    checkpoints[1] = attach_anchor(&checkpoints[1], a1);
    let bad = rebuild(arr(&b, "keys"), arr(&b, "records"), checkpoints);

    let r = verify_bundle_with(
        &bad,
        &VerifyOptions {
            trusted_keys: None,
            trusted_tsa_keys: vec![tsa.verifying_key()],
            ..Default::default()
        },
    );
    assert!(!r.ok);
    let broken = r.first_broken_link.unwrap_or_default() + &r.issues.join(" ");
    assert!(
        broken.contains("backdating"),
        "expected backdating detection, got: {broken}"
    );
}

/// End-to-end: a REAL RFC 3161 TimeStampToken (CMS/DER, ECDSA P-256) anchoring the latest
/// checkpoint flows through the bundle verifier and salvages a later-compromised key (#9).
/// Requires the `test-tsa` feature (exposes the in-Rust mini-TSA token builder).
#[cfg(feature = "test-tsa")]
#[test]
fn real_rfc3161_anchor_salvages_compromised_key_in_bundle() {
    use feir_decision_core::b64;
    use feir_decision_core::rfc3161::make_test_token;

    let b = fixture();
    let mut checkpoints = arr(&b, "checkpoints");
    let cp1h = checkpoint_hash(&checkpoints[1]);
    // The TSA stamps a token over the checkpoint_hash string at 10:02 (before the 10:10 compromise).
    let (token_der, tsa_spki) =
        make_test_token(cp1h.as_bytes(), "2026-06-15T10:02:00.000Z", &[5u8; 32]);
    let anchor = CanonValue::object(vec![
        ("scheme".into(), CanonValue::string("rfc3161")),
        (
            "token_b64".into(),
            CanonValue::string(b64::encode(&token_der)),
        ),
    ])
    .unwrap();
    checkpoints[1] = attach_anchor(&checkpoints[1], anchor);

    let mut keys = arr(&b, "keys");
    keys[0] = change_field(&keys[0], "key_status", CanonValue::string("compromised"));
    keys[0] = change_field(
        &keys[0],
        "status_changed_at",
        CanonValue::string("2020-01-01T00:00:00.000Z"), // bundle lie, ignored under pinning
    );
    let bundle = rebuild(keys, arr(&b, "records"), checkpoints);

    let r = verify_bundle_with(
        &bundle,
        &VerifyOptions {
            trusted_keys: Some(vec![pinned_compromised("2026-06-15T10:10:00.000Z")]),
            trusted_tsa_spki: vec![tsa_spki],
            ..Default::default()
        },
    );
    assert!(
        r.ok,
        "real rfc3161 anchored-before-compromise should pass; issues: {:?}",
        r.issues
    );
    assert_eq!(r.records_proven, 3);
    assert!(r.checkpoints_anchored >= 1);

    // An UNtrusted TSA SPKI must not salvage anything.
    let (_t, other_spki) = make_test_token(b"x", "2026-06-15T10:02:00.000Z", &[6u8; 32]);
    let r2 = verify_bundle_with(
        &bundle,
        &VerifyOptions {
            trusted_keys: Some(vec![pinned_compromised("2026-06-15T10:10:00.000Z")]),
            trusted_tsa_spki: vec![other_spki],
            ..Default::default()
        },
    );
    assert!(!r2.ok, "untrusted TSA must not salvage the compromised key");
}

#[cfg(feature = "test-tsa")]
#[test]
fn valid_anchor_on_unverified_checkpoint_does_not_upgrade() {
    // Threat: pair a valid TSA token with a checkpoint whose OWN signature fails. The anchor binds
    // the (unchanged) checkpoint_hash, but because the checkpoint isn't authenticated its frontier
    // is attacker-controlled — so it must NOT contribute to the #9 anchored-before upgrade.
    use feir_decision_core::b64;
    use feir_decision_core::rfc3161::make_test_token;

    let b = fixture();
    let mut checkpoints = arr(&b, "checkpoints");
    let cp1h = checkpoint_hash(&checkpoints[1]);
    let (token_der, tsa_spki) =
        make_test_token(cp1h.as_bytes(), "2026-06-15T10:02:00.000Z", &[5u8; 32]);
    let anchor = CanonValue::object(vec![
        ("scheme".into(), CanonValue::string("rfc3161")),
        (
            "token_b64".into(),
            CanonValue::string(b64::encode(&token_der)),
        ),
    ])
    .unwrap();
    let mut cp1 = attach_anchor(&checkpoints[1], anchor);
    // corrupt the checkpoint signature (hash unchanged -> anchor still binds, but sig fails)
    cp1 = change_field(
        &cp1,
        "sig",
        CanonValue::string(format!("ed25519:{}", "A".repeat(86))),
    );
    checkpoints[1] = cp1;

    let mut keys = arr(&b, "keys");
    keys[0] = change_field(&keys[0], "key_status", CanonValue::string("compromised"));
    keys[0] = change_field(
        &keys[0],
        "status_changed_at",
        CanonValue::string("2020-01-01T00:00:00.000Z"),
    );
    let bundle = rebuild(keys, arr(&b, "records"), checkpoints);

    let r = verify_bundle_with(
        &bundle,
        &VerifyOptions {
            trusted_keys: Some(vec![pinned_compromised("2026-06-15T10:10:00.000Z")]),
            trusted_tsa_spki: vec![tsa_spki],
            ..Default::default()
        },
    );
    assert!(!r.ok, "unverified checkpoint must not pass");
    assert_eq!(
        r.records_proven, 0,
        "anchor on an unverified checkpoint must not upgrade compromised records"
    );
}
