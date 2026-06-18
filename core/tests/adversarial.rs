//! Adversarial acceptance gates (spec §15/§17). Derives tampered / omitted / forked / backdated /
//! compromised-key variants from the valid bundle fixture and asserts the offline verifier detects
//! each: #1 omission, #2 fork, #3 backdating, #4 key pinning, #7 subset-frontier, #8 dup-collapse,
//! #9 key compromise, plus integrity tamper.

use feir_decision_core::anchor::{make_test_anchor, test_tsa_key};
use feir_decision_core::authority::sign_evidence;
use feir_decision_core::canon::CanonValue;
use feir_decision_core::checkpoint::{attach_anchor, checkpoint_body, seal_checkpoint};
use feir_decision_core::hashx::sha256_prefixed;
use feir_decision_core::record::seal;
use feir_decision_core::sign::{encode_pubkey, signing_key_from_seed};
use feir_decision_core::verify::{
    cnf_kid, cosig_approval_challenge, report_to_json, verify_bundle, verify_bundle_with, TrustLevel,
    TrustedKey, VerifyOptions, VerifyReport,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
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
    let evidence_sig = sign_evidence("gateway_enforced", "proj-001", record_id, &evidence_hash, &sk);
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
    // The broker role discriminator (kind=grant) + enforcement_point=credential_broker classify this
    // record to the BROKER role (R2); grant_evidence carries the R1 re-derivable payload.
    let ge_inner = |ge: &CanonValue| format!(r#""kind":"grant","grant_evidence":{}"#, ge.serialize());
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
    // R2: a grant elevates ONLY under the BROKER authority key set, not the generic or resource sets.
    let pinned = || VerifyOptions {
        broker_authority_keys: vec![vk],
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

    // R1 fail-closed on ABSENT payload: a broker-role grant (kind=grant) with valid (pinned) authority
    // but NO embedded grant_evidence is as unacceptable as a divergent one — the verifier cannot
    // confirm the signed evidence_hash commits to any match fields, so it must NOT count + surface it.
    let no_ge_body = mk_body(r#""kind":"grant""#, &evidence_hash, &evidence_sig);
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

    // MUST-FIX 1 divergence: a grant whose embedded grant_evidence.kind says "use" while the record's
    // extensions.broker.kind says "grant" must fail closed — even though the evidence_hash re-derives
    // (the broker signed the "use"-kinded payload), the role label and the signed payload disagree.
    let ge_use = change_field(&grant_evidence, "kind", CanonValue::string("use"));
    let eh_use = sha256_prefixed(ge_use.serialize().as_bytes());
    let esig_use = sign_evidence("gateway_enforced", "proj-001", record_id, &eh_use, &sk);
    let kind_div_body = mk_body(
        &format!(r#""kind":"grant","grant_evidence":{}"#, ge_use.serialize()),
        &eh_use,
        &esig_use,
    );
    let kind_div = seal(&CanonValue::parse(&kind_div_body).unwrap(), &sk).unwrap();
    let kind_div_bundle = change_field(&bundle, "records", CanonValue::Array(vec![kind_div]));
    let r_kind = verify_bundle_with(&kind_div_bundle, &pinned());
    assert_eq!(r_kind.grant_total, 1);
    assert_eq!(
        r_kind.grant_verified, 0,
        "a grant whose grant_evidence.kind diverges from the role discriminator must not verify"
    );
    assert!(
        r_kind.issues.iter().any(|i| i.contains("diverges from the extensions.broker.kind")),
        "expected a kind-divergence issue, got: {:?}",
        r_kind.issues
    );

    // R2 role separation: the SAME broker key pinned in the WRONG role (resource, not broker) must NOT
    // elevate the grant — a grant only verifies under broker_authority_keys.
    let as_resource = VerifyOptions {
        resource_authority_keys: vec![vk],
        ..Default::default()
    };
    let r_wrongrole = verify_bundle_with(&bundle, &as_resource);
    assert_eq!(r_wrongrole.grant_total, 1);
    assert_eq!(
        r_wrongrole.grant_verified, 0,
        "a grant must not elevate under a key pinned only in the resource role (R2)"
    );

    // R2 rule 4: a credential_grant whose (kind, enforcement_point) does NOT classify to the broker
    // role (here kind is an unrecognized value) is a fail-closed verification failure, not counted.
    let mislabeled_body = mk_body(r#""kind":"bogus""#, &evidence_hash, &evidence_sig);
    let mislabeled = seal(&CanonValue::parse(&mislabeled_body).unwrap(), &sk).unwrap();
    let mislabeled_bundle = change_field(&bundle, "records", CanonValue::Array(vec![mislabeled]));
    let r_mis = verify_bundle_with(&mislabeled_bundle, &pinned());
    assert_eq!(r_mis.grant_total, 1);
    assert_eq!(r_mis.grant_verified, 0, "a mislabeled grant must not verify (R2)");
    assert!(
        r_mis
            .issues
            .iter()
            .any(|i| i.contains("not a recognized broker/resource role")
                || i.contains("does not classify to the broker role")),
        "expected an R2 role-classification issue, got: {:?}",
        r_mis.issues
    );

    // R2 disjointness: a key pinned in BOTH broker and resource sets is a fatal config error — the
    // verifier aborts before evaluating any record (no "clean" verdict on an ambiguous key universe).
    let conflicting = VerifyOptions {
        broker_authority_keys: vec![vk],
        resource_authority_keys: vec![vk],
        ..Default::default()
    };
    let r_conflict = verify_bundle_with(&bundle, &conflicting);
    assert!(!r_conflict.ok);
    assert_eq!(
        r_conflict.grant_total, 0,
        "a fatal config error must abort before counting any grant"
    );
    assert_eq!(
        r_conflict.records_total, 0,
        "the disjointness abort must happen BEFORE any record is evaluated"
    );
    assert!(
        r_conflict.issues.iter().any(|i| i.contains("must be disjoint")),
        "expected a disjointness fatal-config issue, got: {:?}",
        r_conflict.issues
    );

    // A forged gateway_enforced grant (agent-claimed, no real broker key) does NOT elevate: re-sign
    // the evidence with a DIFFERENT key, pin only the real broker key.
    let imposter = signing_key_from_seed(&[7u8; 32]);
    let bad_sig = sign_evidence("gateway_enforced", "proj-001", record_id, &evidence_hash, &imposter);
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
fn non_canonical_anchor_time_is_rejected() {
    // F9 hardening: an anchored_ts that is not a canonical RCP timestamp (here: no milliseconds) breaks the
    // lexical==chronological ordering the backdating check relies on, so it must be flagged rather than
    // silently mis-ordered — matching how the rest of the file gates string-time comparisons.
    let b = fixture();
    let tsa = test_tsa_key(&[200u8; 32]);
    let mut checkpoints = arr(&b, "checkpoints");
    let a = make_test_anchor(&checkpoint_hash(&checkpoints[1]), "2026-06-15T10:05:00Z", &tsa, "t");
    checkpoints[1] = attach_anchor(&checkpoints[1], a);
    let bad = rebuild(arr(&b, "keys"), arr(&b, "records"), checkpoints);
    let r = verify_bundle_with(
        &bad,
        &VerifyOptions {
            trusted_keys: None,
            trusted_tsa_keys: vec![tsa.verifying_key()],
            ..Default::default()
        },
    );
    assert!(!r.ok, "a non-canonical anchor time must fail the bundle");
    assert!(
        r.issues.iter().any(|i| i.contains("not a canonical RCP timestamp")),
        "issues: {:?}",
        r.issues
    );
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

// ---- Tier-B use<->grant join fixtures (ADR 0003 step 5) ----
//
// A grant + use + ANCHORED checkpoint, so both records are CLOSED (committed by a verified anchored
// checkpoint, R3). The record key (k0) seals all records; the broker authority is that same key
// (self-host); the resource authority is a DISTINCT key (R2). Negative variants drop/duplicate/diverge
// to exercise the match predicate.

fn content_hash_of(rec: &CanonValue) -> String {
    rec.get("content_hash").unwrap().as_str().unwrap().to_string()
}

fn grant_evidence(
    gid: &str,
    action: &str,
    resource: &str,
    scope: &str,
    cnf_kid: &str,
    issued: i64,
    exp: i64,
) -> CanonValue {
    CanonValue::object(vec![
        ("kind".into(), CanonValue::string("grant")),
        ("grant_id".into(), CanonValue::string(gid)),
        ("action".into(), CanonValue::string(action)),
        ("resource_id".into(), CanonValue::string(resource)),
        ("scope_class".into(), CanonValue::string(scope)),
        ("cnf_kid".into(), CanonValue::string(cnf_kid)),
        // credential_binding binds the grant to the minted capability descriptor + (D2) is read by the
        // verifier to reconstruct the use PoP challenge. The real broker carries it; the fixed test
        // value below is fine for non-D2 cases (uses without cnf_pub/use_sig stay shim_asserted).
        (
            "credential_binding".into(),
            CanonValue::string(sha256_prefixed(b"test-credential-binding")),
        ),
        ("issued_at".into(), CanonValue::Int(issued)),
        ("exp".into(), CanonValue::Int(exp)),
    ])
    .unwrap()
}

fn use_evidence(
    gid: &str,
    action: &str,
    resource: &str,
    jti: &str,
    cnf_kid: &str,
    used_at: i64,
) -> CanonValue {
    // a distinct nonce per use (keyed on used_at) so multi-use fixtures don't trip the D3 nonce-replay
    // check; tests that WANT a replay reuse the same used_at.
    use_evidence_n(gid, action, resource, jti, cnf_kid, used_at, &format!("nonce-{used_at}"))
}

fn use_evidence_n(
    gid: &str,
    action: &str,
    resource: &str,
    jti: &str,
    cnf_kid: &str,
    used_at: i64,
    nonce: &str,
) -> CanonValue {
    CanonValue::object(vec![
        ("kind".into(), CanonValue::string("use")),
        ("grant_id".into(), CanonValue::string(gid)),
        ("action".into(), CanonValue::string(action)),
        ("resource_id".into(), CanonValue::string(resource)),
        ("jti".into(), CanonValue::string(jti)),
        ("nonce".into(), CanonValue::string(nonce)),
        (
            "pop_challenge_hash".into(),
            CanonValue::string(sha256_prefixed(b"pop")),
        ),
        ("cnf_kid".into(), CanonValue::string(cnf_kid)),
        (
            // the real re-derivable ledger_commitment (D3): sha256(LP(tag)‖LP(jti)‖LP(nonce)‖BE8(used_at))
            "ledger_commitment".into(),
            CanonValue::string(feir_decision_core::verify::ledger_commitment(jti, nonce, used_at)),
        ),
        ("used_at".into(), CanonValue::Int(used_at)),
    ])
    .unwrap()
}

fn seal_grant(rec_sk: &SigningKey, broker_sk: &SigningKey, record_id: &str, ge: &CanonValue) -> CanonValue {
    let eh = sha256_prefixed(ge.serialize().as_bytes());
    let esig = sign_evidence("gateway_enforced", "proj-001", record_id, &eh, broker_sk);
    let action = ge.get("action").unwrap().as_str().unwrap();
    let body = format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{record_id}","project_id":"proj-001","agent_id":"agent","agent_version":"feir-broker",
        "session_id":"s","span_id":"sp-{record_id}","parent_span_id":null,"causal_prev_hashes":[],"display_seq":0,
        "agent_ts":"2026-06-15T10:00:00.000Z","received_ts":"2026-06-15T10:00:00.000Z",
        "event_type":"credential_grant","action":"{action}","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"credential_broker","grant_type":"id-jag","grant_id":"{record_id}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "extensions":{{"broker":{{"kind":"grant","grant_evidence":{ge}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#,
        ge = ge.serialize(),
    );
    seal(&CanonValue::parse(&body).unwrap(), rec_sk).unwrap()
}

// seal_use_full seals a resource-role use receipt with explicit enforcement_point + signed
// evidence_hash, so tests can exercise role-mislabel (enforcement_point) and R1 tamper (eh != hash(ue)).
#[allow(clippy::too_many_arguments)]
fn seal_use_full(
    rec_sk: &SigningKey,
    res_sk: &SigningKey,
    record_id: &str,
    prev: &[String],
    top_action: &str,
    enforcement_point: &str,
    ue: &CanonValue,
    eh: &str,
) -> CanonValue {
    let esig = sign_evidence("gateway_enforced", "proj-001", record_id, eh, res_sk);
    let gid = ue.get("grant_id").unwrap().as_str().unwrap();
    let resource = ue.get("resource_id").unwrap().as_str().unwrap();
    let prev_json = CanonValue::Array(prev.iter().map(|p| CanonValue::string(p.clone())).collect()).serialize();
    let body = format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{record_id}","project_id":"proj-001","agent_id":"feir-resource","agent_version":"feir-resource",
        "session_id":"s","span_id":"sp-{record_id}","parent_span_id":null,"causal_prev_hashes":{prev_json},"display_seq":1,
        "agent_ts":"2026-06-15T10:00:05.000Z","received_ts":"2026-06-15T10:00:05.000Z",
        "event_type":"tool_call","action":"{top_action}","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"{enforcement_point}","grant_id":"{gid}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "extensions":{{"broker":{{"kind":"use","grant_id":"{gid}","resource_id":"{resource}","use_evidence":{ue}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#,
        ue = ue.serialize(),
    );
    seal(&CanonValue::parse(&body).unwrap(), rec_sk).unwrap()
}

// seal_use is the well-formed wrapper: tool_gateway enforcement_point + evidence_hash == hash(ue).
// top_action is the (human-echo) action — EQUAL to use_evidence.action for a well-formed use, or
// DIFFERENT to exercise MUST-FIX 1 divergence.
fn seal_use(
    rec_sk: &SigningKey,
    res_sk: &SigningKey,
    record_id: &str,
    prev: &[String],
    top_action: &str,
    ue: &CanonValue,
) -> CanonValue {
    let eh = sha256_prefixed(ue.serialize().as_bytes());
    seal_use_full(rec_sk, res_sk, record_id, prev, top_action, "tool_gateway", ue, &eh)
}

// D5: a two-phase use_intent — a resource record whose broker kind AND use_evidence.kind are "use_intent",
// carrying the same PoP-validated use_evidence as a one-phase use (the match predicate runs on it).
fn seal_intent(rec_sk: &SigningKey, res_sk: &SigningKey, record_id: &str, prev: &[String], top_action: &str, ue: &CanonValue) -> CanonValue {
    let ue = change_field(ue, "kind", CanonValue::string("use_intent"));
    let eh = sha256_prefixed(ue.serialize().as_bytes());
    let esig = sign_evidence("gateway_enforced", "proj-001", record_id, &eh, res_sk);
    let gid = ue.get("grant_id").unwrap().as_str().unwrap();
    let resource = ue.get("resource_id").unwrap().as_str().unwrap();
    let prev_json = CanonValue::Array(prev.iter().map(|p| CanonValue::string(p.clone())).collect()).serialize();
    let body = format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{record_id}","project_id":"proj-001","agent_id":"feir-resource","agent_version":"feir-resource",
        "session_id":"s","span_id":"sp-{record_id}","parent_span_id":null,"causal_prev_hashes":{prev_json},"display_seq":1,
        "agent_ts":"2026-06-15T10:00:05.000Z","received_ts":"2026-06-15T10:00:05.000Z",
        "event_type":"tool_call","action":"{top_action}","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"tool_gateway","grant_id":"{gid}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "extensions":{{"broker":{{"kind":"use_intent","grant_id":"{gid}","resource_id":"{resource}","use_evidence":{ue}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#,
        ue = ue.serialize(),
    );
    seal(&CanonValue::parse(&body).unwrap(), rec_sk).unwrap()
}

// D5: a use_outcome completing an intent. The SIGNED use_outcome payload carries grant_id + intent_ref
// (what the verifier reads, bound by evidence_hash); the UNSIGNED sibling extensions.broker.intent_ref is
// set separately to `sibling_ref` so a test can DIVERGE them. `auth_sk` signs the evidence (a non-resource
// key models a FORGED outcome).
fn seal_outcome(rec_sk: &SigningKey, auth_sk: &SigningKey, record_id: &str, prev: &[String], signed_ref: &str, sibling_ref: &str, gid: &str) -> CanonValue {
    seal_outcome_k(rec_sk, auth_sk, record_id, prev, "use_outcome", signed_ref, sibling_ref, gid)
}

// seal_outcome with an explicit SIGNED-payload `kind`. The signed `intent_hash` (the before-act ordering
// binding) defaults to the first causal parent (the honest convention: an outcome's DAG parent IS its
// intent); `seal_outcome_full` overrides it to model a relay backfilling the top-level edge.
#[allow(clippy::too_many_arguments)]
fn seal_outcome_k(rec_sk: &SigningKey, auth_sk: &SigningKey, record_id: &str, prev: &[String], payload_kind: &str, signed_ref: &str, sibling_ref: &str, gid: &str) -> CanonValue {
    let signed_hash = prev.first().cloned().unwrap_or_default();
    seal_outcome_full(rec_sk, auth_sk, record_id, prev, payload_kind, signed_ref, sibling_ref, gid, &signed_hash)
}

// seal_outcome with an explicit SIGNED-payload `intent_hash` — to model a relay that re-seals a valid
// resource-signed payload (whose signed intent_hash names intent A or nothing) while backfilling the
// top-level causal_prev_hashes to point at a different (later) intent.
#[allow(clippy::too_many_arguments)]
fn seal_outcome_full(rec_sk: &SigningKey, auth_sk: &SigningKey, record_id: &str, prev: &[String], payload_kind: &str, signed_ref: &str, sibling_ref: &str, gid: &str, signed_intent_hash: &str) -> CanonValue {
    let outcome = CanonValue::object(vec![
        ("grant_id".into(), CanonValue::string(gid)),
        ("intent_hash".into(), CanonValue::string(signed_intent_hash)),
        ("intent_ref".into(), CanonValue::string(signed_ref)),
        ("kind".into(), CanonValue::string(payload_kind)),
        ("status".into(), CanonValue::string("ok")),
    ])
    .unwrap();
    let eh = sha256_prefixed(outcome.serialize().as_bytes());
    let esig = sign_evidence("gateway_enforced", "proj-001", record_id, &eh, auth_sk);
    let prev_json = CanonValue::Array(prev.iter().map(|p| CanonValue::string(p.clone())).collect()).serialize();
    let body = format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{record_id}","project_id":"proj-001","agent_id":"feir-resource","agent_version":"feir-resource",
        "session_id":"s","span_id":"sp-{record_id}","parent_span_id":null,"causal_prev_hashes":{prev_json},"display_seq":2,
        "agent_ts":"2026-06-15T10:00:06.000Z","received_ts":"2026-06-15T10:00:06.000Z",
        "event_type":"tool_call","action":"{ACTION}","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"tool_gateway","grant_id":"{gid}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "extensions":{{"broker":{{"kind":"use_outcome","grant_id":"{gid}","intent_ref":"{sibling_ref}","use_outcome":{outcome}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#,
        outcome = outcome.serialize(),
    );
    seal(&CanonValue::parse(&body).unwrap(), rec_sk).unwrap()
}

fn checkpoint_over(rec_sk: &SigningKey, frontier: &[String], record_count: i64, anchor_with: Option<&SigningKey>) -> CanonValue {
    let key_block =
        CanonValue::parse(r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active"}"#).unwrap();
    let body = checkpoint_body(
        "cp0",
        "proj-001",
        0,
        None,
        frontier,
        record_count,
        "2026-06-15T10:10:00.000Z",
        key_block,
    )
    .unwrap();
    let cp = seal_checkpoint(&body, rec_sk).unwrap();
    match anchor_with {
        Some(tsa) => {
            let anchor = make_test_anchor(&checkpoint_hash(&cp), "2026-06-15T10:10:01.000Z", tsa, "tsa-1");
            attach_anchor(&cp, anchor)
        }
        None => cp,
    }
}

fn tier_b_bundle(rec_vk: &VerifyingKey, records: Vec<CanonValue>, checkpoints: Vec<CanonValue>) -> CanonValue {
    let key_entry = CanonValue::object(vec![
        ("signing_key_id".into(), CanonValue::string("k0")),
        ("key_epoch".into(), CanonValue::Int(0)),
        ("public_key".into(), CanonValue::string(encode_pubkey(rec_vk))),
        ("key_status".into(), CanonValue::string("active")),
    ])
    .unwrap();
    rebuild(vec![key_entry], records, checkpoints)
}

fn pinned_roles(broker_vk: VerifyingKey, resource_vk: VerifyingKey, tsa_vk: VerifyingKey) -> VerifyOptions {
    VerifyOptions {
        broker_authority_keys: vec![broker_vk],
        resource_authority_keys: vec![resource_vk],
        trusted_tsa_keys: vec![tsa_vk],
        ..Default::default()
    }
}

const GID: &str = "grant-1";
const CNF: &str = "ed25519-AgentKid0";
const ACTION: &str = "db.query:orders-ro";
const RESOURCE: &str = "orders-db";
const ISSUED: i64 = 1_718_445_600;
const EXP: i64 = 1_718_449_200;
const USED: i64 = 1_718_445_700;

#[test]
fn tier_b_use_matches_closed_grant() {
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let ge = grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP);
    let grant = seal_grant(&rec, &rec, GID, &ge);
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED); // jti == grant_id (single-use)
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(
        &bundle,
        &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()),
    );
    assert!(r.ok, "happy path should verify; issues: {:?}", r.issues);
    assert_eq!(r.grant_verified, 1);
    assert_eq!(r.uses_total, 1);
    assert_eq!(r.uses_matched, 1);
    assert_eq!(r.uses_action_unverified, 1); // R6: no taxonomy -> demonstrator artifact
    // this fixture's use carries no cnf_pub/use_sig, so it stays `shim_asserted` (D2): matched but the
    // PoP is NOT independently re-run.
    assert_eq!(r.uses_pop_reverified, 0);
    assert_eq!(r.unmatched_violation, 0);
    assert_eq!(r.unmatched_pending, 0);
    assert_eq!(r.grants_unused, 0);
    // the new Tier-B fields are present in the canonical report JSON (WASM/Go consumers read these).
    let json = feir_decision_core::verify::report_to_json(&r);
    assert!(json.contains(r#""action_completeness":"not_claimed""#)); // no coverage_manifest
    for field in [
        r#""uses_total":1"#,
        r#""uses_matched":1"#,
        r#""uses_action_unverified":1"#,
        r#""unmatched_violation":0"#,
        r#""unmatched_pending":0"#,
        r#""grants_unused":0"#,
    ] {
        assert!(json.contains(field), "report JSON missing {field}: {json}");
    }
}

#[test]
fn tier_b_grant_id_equivocation_without_d6_is_a_violation() {
    // F8: a grant_id bound to two distinct grant records (distinct content_hash via distinct record_ids)
    // is broker equivocation flagged ALWAYS — even with NO D6 head (broker_trust only 'assumed'), so a
    // forged collision is surfaced rather than silently first-wins-collapsed. The honest producer emits
    // record_id == grant_id, so this covers the forged-distinct-record_id case the duplicate-record_id
    // guard misses.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let ge = grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP);
    let g1 = seal_grant(&rec, &rec, "rec-A", &ge); // distinct record_ids -> distinct content_hash, one grant_id
    let g2 = seal_grant(&rec, &rec, "rec-B", &ge);
    let mut frontier = vec![content_hash_of(&g1), content_hash_of(&g2)];
    frontier.sort();
    let cp = checkpoint_over(&rec, &frontier, 2, Some(&tsa)); // NO broker_grant_head -> no D6
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a grant_id collision must fail the bundle even without D6");
    assert_eq!(r.broker_trust, "assumed", "no head -> assumed (the F8 flag is independent of D6)");
    assert!(
        r.issues.iter().any(|i| i.contains("equivocated credential identity")),
        "issues: {:?}",
        r.issues
    );
}

#[test]
fn tier_b_grant_id_equivocation_unanchored_is_a_violation() {
    // Adversarial-review finding (GLM/Codex substitute): the original F8 ran inside the closed-gated grant
    // ACCOUNTING loop, so a D6-absent equivocation committed only by a verified-but-UNANCHORED checkpoint
    // was NOT closed -> F8 skipped it, yet grant counting (un-gated) reported ok:true + grant_verified=2 over
    // one equivocated grant_id. The injectivity check must run over ALL verified broker grants, independent of
    // anchoring (the F8 commit's "ALWAYS" guarantee). Same as the test above but the checkpoint is UNANCHORED.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let ge = grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP);
    let g1 = seal_grant(&rec, &rec, "rec-A", &ge);
    let g2 = seal_grant(&rec, &rec, "rec-B", &ge);
    let mut frontier = vec![content_hash_of(&g1), content_hash_of(&g2)];
    frontier.sort();
    let cp = checkpoint_over(&rec, &frontier, 2, None); // UNANCHORED (no TSA) — the gap GLM found
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "an UNANCHORED grant_id equivocation must still fail the bundle (F8 always-on, independent of anchoring)");
    assert!(
        r.issues.iter().any(|i| i.contains("equivocated credential identity")),
        "issues: {:?}",
        r.issues
    );
}

// ---- M1 (ADR 0005): bounded_reuse / N-Use ----

// build a bounded_reuse grant capped at `n` uses of the standard (ACTION, RESOURCE).
fn bounded_grant(rec: &SigningKey, n: i64) -> CanonValue {
    let ge = change_field(
        &grant_evidence(GID, ACTION, RESOURCE, "bounded_reuse", CNF, ISSUED, EXP),
        "use_limit",
        CanonValue::Int(n),
    );
    seal_grant(rec, rec, GID, &ge)
}

// build a bounded_reuse use receipt at sequence number `usn`, with `used_at` driving a distinct nonce.
fn bounded_use(rec: &SigningKey, res: &SigningKey, rid: &str, grant_hash: &str, usn: i64, used_at: i64) -> CanonValue {
    let ue = change_field(
        &use_evidence(GID, ACTION, RESOURCE, GID, CNF, used_at), // jti == grant_id (M1 keeps this)
        "use_sequence_number",
        CanonValue::Int(usn),
    );
    seal_use(rec, res, rid, &[grant_hash.to_string()], ACTION, &ue)
}

#[test]
fn tier_b_bounded_reuse_within_cap_verifies() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = bounded_grant(&rec, 2);
    let gh = content_hash_of(&grant);
    let u1 = bounded_use(&rec, &res, "use-1", &gh, 1, USED);
    let u2 = bounded_use(&rec, &res, "use-2", &gh, 2, USED + 100);
    let mut frontier = vec![content_hash_of(&u1), content_hash_of(&u2)];
    frontier.sort();
    let cp = checkpoint_over(&rec, &frontier, 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, u1, u2], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "N uses within the cap should verify; issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 2, "both uses join the bounded_reuse grant");
    assert_eq!(r.bounded_reuse_grants, 1);
    assert_eq!(r.bounded_reuse_overspent, 0);
    assert_eq!(r.bounded_reuse_seq_replays, 0);
    assert_eq!(r.unmatched_violation, 0);
    assert_eq!(r.grants_unused, 0);
    let json = feir_decision_core::verify::report_to_json(&r);
    for field in [r#""bounded_reuse_grants":1"#, r#""bounded_reuse_overspent":0"#, r#""bounded_reuse_seq_replays":0"#] {
        assert!(json.contains(field), "report JSON missing {field}: {json}");
    }
}

#[test]
fn tier_b_bounded_reuse_overspend_is_a_violation() {
    // use_limit=1 but the receipt claims use_sequence_number=2 (outside [1,1]).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = bounded_grant(&rec, 1);
    let gh = content_hash_of(&grant);
    let u = bounded_use(&rec, &res, "use-1", &gh, 2, USED);
    let cp = checkpoint_over(&rec, &[content_hash_of(&u)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, u], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "an out-of-range use_sequence_number must fail the bundle");
    assert_eq!(r.bounded_reuse_overspent, 1);
    assert_eq!(r.uses_matched, 0);
    assert!(r.issues.iter().any(|i| i.contains("overspend")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_bounded_reuse_sequence_replay_is_a_violation() {
    // use_limit=2, but TWO receipts claim use_sequence_number=1 (distinct nonces, so it is a USN replay,
    // not a D3 nonce replay) — the second is rejected as a seq-replay.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = bounded_grant(&rec, 2);
    let gh = content_hash_of(&grant);
    let u1 = bounded_use(&rec, &res, "use-1", &gh, 1, USED);
    let u2 = bounded_use(&rec, &res, "use-2", &gh, 1, USED + 100); // same usn, different nonce
    let mut frontier = vec![content_hash_of(&u1), content_hash_of(&u2)];
    frontier.sort();
    let cp = checkpoint_over(&rec, &frontier, 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, u1, u2], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a replayed use_sequence_number must fail the bundle");
    assert_eq!(r.bounded_reuse_seq_replays, 1);
    assert_eq!(r.uses_matched, 1, "the first usn=1 matches; the second is the replay");
    assert!(r.issues.iter().any(|i| i.contains("seq-replay")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_bounded_reuse_without_use_limit_fails_closed() {
    // a bounded_reuse grant that declares NO use_limit is fail-closed (an unbounded "bounded" grant must
    // not be honored); a use against it then reads as action-without-credential.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let ge = grant_evidence(GID, ACTION, RESOURCE, "bounded_reuse", CNF, ISSUED, EXP); // no use_limit
    let grant = seal_grant(&rec, &rec, GID, &ge);
    let gh = content_hash_of(&grant);
    let u = bounded_use(&rec, &res, "use-1", &gh, 1, USED);
    let cp = checkpoint_over(&rec, &[content_hash_of(&u)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, u], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a bounded_reuse grant with no use_limit must fail closed");
    assert_eq!(r.bounded_reuse_grants, 0, "the malformed grant is not indexed");
    assert!(r.issues.iter().any(|i| i.contains("use_limit must be >= 1")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_action_without_credential_is_a_violation() {
    // A closed use receipt with NO matching closed grant — action without a credential.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED);
    let use_rec = seal_use(&rec, &res, "use-1", &[], ACTION, &ue); // no causal parent (no grant)
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 1, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![use_rec], vec![cp]);
    let r = verify_bundle_with(
        &bundle,
        &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()),
    );
    assert!(!r.ok);
    assert_eq!(r.uses_total, 1);
    assert_eq!(r.unmatched_violation, 1);
    assert_eq!(r.uses_matched, 0);
    assert!(r.issues.iter().any(|i| i.contains("action without a credential")), "{:?}", r.issues);
}

#[test]
fn tier_b_single_use_double_spend_is_a_violation() {
    // Two closed receipts for the SAME single-use grant_id (both jti == grant_id) — the second is a
    // double-spend caught by the per-grant_id rule (R5 rev 4), regardless of jti.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let ge = grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP);
    let grant = seal_grant(&rec, &rec, GID, &ge);
    let gch = content_hash_of(&grant);
    let u1 = seal_use(&rec, &res, "use-1", std::slice::from_ref(&gch), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let u2 = seal_use(&rec, &res, "use-2", std::slice::from_ref(&gch), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED + 1));
    let cp = checkpoint_over(&rec, &[content_hash_of(&u1), content_hash_of(&u2)], 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, u1, u2], vec![cp]);
    let r = verify_bundle_with(
        &bundle,
        &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()),
    );
    assert!(!r.ok);
    assert_eq!(r.uses_total, 2);
    assert_eq!(r.uses_matched, 1);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("double-spend")), "{:?}", r.issues);
}

#[test]
fn tier_b_jti_rebinding_is_a_violation() {
    // A single_operation use whose jti != grant_id (R5 canonical binding) is rejected.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, RESOURCE, "some-other-jti", CNF, USED);
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(
        &bundle,
        &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()),
    );
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("jti == grant_id")), "{:?}", r.issues);
}

#[test]
fn tier_b_action_substitution_is_a_violation() {
    // The use's evidence action (consistently top + payload) does not match the grant's action.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, "db.delete:everything", RESOURCE, GID, CNF, USED);
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], "db.delete:everything", &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(
        &bundle,
        &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()),
    );
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("does not match grant")), "{:?}", r.issues);
}

#[test]
fn tier_b_top_level_action_divergence_is_a_violation() {
    // MUST-FIX 1: a use whose top-level action echo diverges from use_evidence.action is a hard failure.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED);
    // payload action is ACTION, but the top-level echo lies as something else
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], "db.delete:everything", &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(
        &bundle,
        &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()),
    );
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("diverges from use_evidence.action")), "{:?}", r.issues);
}

#[test]
fn tier_b_unanchored_use_is_pending_not_a_violation() {
    // R3: a use NOT committed by a verified ANCHORED checkpoint is in-flight (pending), never a
    // violation — the bundle is still clean.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED);
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, None); // NOT anchored
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(
        &bundle,
        &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()),
    );
    assert!(r.ok, "an unanchored (pending) use must not fail the bundle; issues: {:?}", r.issues);
    assert_eq!(r.uses_total, 1);
    assert_eq!(r.unmatched_pending, 1);
    assert_eq!(r.uses_matched, 0);
    assert_eq!(r.unmatched_violation, 0);
}

#[test]
fn tier_b_cnf_kid_mismatch_is_a_violation() {
    // The use's cnf_kid (the PoP key id) must equal the grant's — a use bound to a different key fails.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, "ed25519-DifferentKid", USED);
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("does not match grant")), "{:?}", r.issues);
}

#[test]
fn tier_b_resource_mismatch_is_a_violation() {
    // A use whose resource_id is not the grant's resource is a violation.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, "payments-db", GID, CNF, USED);
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
}

#[test]
fn tier_b_use_at_expiry_is_a_violation() {
    // The window is [issued_at, exp): a use AT exp is expired (matches the resource shim's rejection).
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, EXP); // used_at == exp
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert_eq!(r.uses_matched, 0);
}

#[test]
fn tier_b_unused_grant_is_counted() {
    // Two closed single-use grants, one use against grant-1 → grant-2 is grants_unused.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let g1 = seal_grant(&rec, &rec, "grant-1", &grant_evidence("grant-1", ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let g2 = seal_grant(&rec, &rec, "grant-2", &grant_evidence("grant-2", ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence("grant-1", ACTION, RESOURCE, "grant-1", CNF, USED);
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&g1)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&g2), content_hash_of(&use_rec)], 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 1);
    assert_eq!(r.grants_unused, 1);
}

#[test]
fn tier_b_reusable_grant_permits_multiple_uses() {
    // A session_grant (not single_operation) is exercised by multiple uses with NO per-grant_id cap —
    // each is a matched (taxonomy-unverified, R6) use, not a double-spend.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "session_grant", CNF, ISSUED, EXP));
    let gch = content_hash_of(&grant);
    let u1 = seal_use(&rec, &res, "use-1", std::slice::from_ref(&gch), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let u2 = seal_use(&rec, &res, "use-2", std::slice::from_ref(&gch), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED + 1));
    let cp = checkpoint_over(&rec, &[content_hash_of(&u1), content_hash_of(&u2)], 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, u1, u2], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "a reusable grant's multiple uses must not be a violation; issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 2);
    assert_eq!(r.uses_action_unverified, 2);
    assert_eq!(r.unmatched_violation, 0);
    assert_eq!(r.grants_unused, 0);
}

#[test]
fn tier_b_incomplete_grant_evidence_fails_closed() {
    // A verified, closed broker grant whose grant_evidence omits a match field (here cnf_kid) is
    // surfaced as a fail-closed issue — NOT silently skipped (which would mask its use as "no grant").
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    // grant_evidence WITHOUT cnf_kid
    let ge = CanonValue::object(vec![
        ("kind".into(), CanonValue::string("grant")),
        ("grant_id".into(), CanonValue::string(GID)),
        ("action".into(), CanonValue::string(ACTION)),
        ("resource_id".into(), CanonValue::string(RESOURCE)),
        ("scope_class".into(), CanonValue::string("single_operation")),
        ("issued_at".into(), CanonValue::Int(ISSUED)),
        ("exp".into(), CanonValue::Int(EXP)),
    ])
    .unwrap();
    let grant = seal_grant(&rec, &rec, GID, &ge);
    let cp = checkpoint_over(&rec, &[content_hash_of(&grant)], 1, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert!(r.issues.iter().any(|i| i.contains("incomplete grant_evidence")), "{:?}", r.issues);
}

#[test]
fn tier_b_tampered_use_evidence_is_a_violation() {
    // R1 (use side): a use whose authority.evidence_hash does NOT re-derive from the embedded
    // use_evidence is not validatable — even though it seals and its authority verifies.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let real_ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED);
    let eh_real = sha256_prefixed(real_ue.serialize().as_bytes());
    // embed a DIFFERENT use_evidence (used_at changed) but sign/authority the REAL eh -> divergence
    let embedded = change_field(&real_ue, "used_at", CanonValue::Int(USED + 99));
    let use_rec = seal_use_full(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, "tool_gateway", &embedded, &eh_real);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("not validatable")), "{:?}", r.issues);
}

#[test]
fn tier_b_use_signed_by_broker_key_does_not_elevate() {
    // R2 (use side of role confusion): a use whose evidence is signed by the BROKER/record key (not the
    // resource key) does not elevate — a resource-role record only verifies under resource keys.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED);
    // sign the use evidence with `rec` (the broker/record key), NOT `res`
    let use_rec = seal_use(&rec, &rec, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    // pin the REAL resource key as the resource role; the broker-signed use must fail to elevate
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert_eq!(r.uses_matched, 0);
    assert!(r.issues.iter().any(|i| i.contains("not validatable")), "{:?}", r.issues);
}

#[test]
fn tier_b_use_side_mislabel_fails_closed() {
    // R2 rule 4 (use direction): a record carrying extensions.broker.kind="use" but enforcement_point
    // "credential_broker" classifies to NO role — a fail-closed verification failure surfaced as an
    // issue, never a silent drop.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED);
    let eh = sha256_prefixed(ue.serialize().as_bytes());
    let mislabeled = seal_use_full(&rec, &res, "use-1", &[], ACTION, "credential_broker", &ue, &eh);
    let cp = checkpoint_over(&rec, &[content_hash_of(&mislabeled)], 1, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![mislabeled], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert!(
        r.issues.iter().any(|i| i.contains("not a recognized broker/resource role")),
        "expected a use-side role-classification issue, got: {:?}",
        r.issues
    );
}

// verify_mangled_use builds a closed, re-derivable use (so it reaches the carried-field gates) whose
// use_evidence is mutated by `mutate`, and returns the report — for testing the MUST-FIX 4 field gates.
fn verify_mangled_use(
    mutate: impl Fn(&CanonValue) -> CanonValue,
) -> feir_decision_core::verify::VerifyReport {
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = mutate(&use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()))
}

#[test]
fn tier_b_malformed_pop_challenge_hash_is_a_violation() {
    let r = verify_mangled_use(|ue| change_field(ue, "pop_challenge_hash", CanonValue::string("not-a-hash")));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("pop_challenge_hash")), "{:?}", r.issues);
}

#[test]
fn tier_b_malformed_ledger_commitment_is_a_violation() {
    let r = verify_mangled_use(|ue| change_field(ue, "ledger_commitment", CanonValue::string("nope")));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("ledger_commitment")), "{:?}", r.issues);
}

#[test]
fn tier_b_empty_nonce_is_a_violation() {
    let r = verify_mangled_use(|ue| change_field(ue, "nonce", CanonValue::string("")));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("nonce")), "{:?}", r.issues);
}

#[test]
fn tier_b_use_evidence_kind_divergence_is_a_violation() {
    let r = verify_mangled_use(|ue| change_field(ue, "kind", CanonValue::string("grant")));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("use_evidence.kind")), "{:?}", r.issues);
}

#[test]
fn tier_b_replayed_nonce_across_receipts_is_a_violation() {
    // D3: two closed receipts for the same resource with the SAME PoP nonce — a replay/duplicate
    // submission caught independently of the per-grant_id rule (here a reusable grant, no per-id cap).
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "session_grant", CNF, ISSUED, EXP));
    let gch = content_hash_of(&grant);
    let u1 = seal_use(&rec, &res, "use-1", std::slice::from_ref(&gch), ACTION, &use_evidence_n(GID, ACTION, RESOURCE, GID, CNF, USED, "dup-nonce"));
    let u2 = seal_use(&rec, &res, "use-2", std::slice::from_ref(&gch), ACTION, &use_evidence_n(GID, ACTION, RESOURCE, GID, CNF, USED + 1, "dup-nonce"));
    let cp = checkpoint_over(&rec, &[content_hash_of(&u1), content_hash_of(&u2)], 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, u1, u2], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert_eq!(r.uses_matched, 1);
    assert!(r.issues.iter().any(|i| i.contains("replayed across closed receipts")), "{:?}", r.issues);
}

#[test]
fn tier_b_ledger_commitment_mismatch_is_a_violation() {
    // D3: a use whose ledger_commitment is a VALID sha256 but does NOT re-derive from (jti, nonce,
    // used_at) — caught by the re-derivation check (distinct from the well-formed-format gate).
    let r = verify_mangled_use(|ue| change_field(ue, "ledger_commitment", CanonValue::string(sha256_prefixed(b"wrong-ledger"))));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("does not re-derive")), "{:?}", r.issues);
}

// ---- Cross-language preimage golden vectors ----
// `spec/golden-vectors/broker-preimages.json` is the SHARED vector that BOTH this Rust suite and the
// Go broker/resourceshim tests load, so the LP4/BE8 domain-tagged preimages stay byte-identical:
// editing a preimage breaks BOTH languages against this ONE file (vs. independently-hardcoded copies
// that could silently diverge). Mirrors how `golden.rs` loads `canon.json`.
fn preimage_vectors() -> CanonValue {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec/golden-vectors/broker-preimages.json");
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    CanonValue::parse(&text).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

#[test]
fn ledger_commitment_golden_vector() {
    use feir_decision_core::verify::ledger_commitment;
    let v = preimage_vectors();
    let cases = v.get("ledger_commitment").unwrap().as_array().unwrap();
    assert!(!cases.is_empty(), "shared vector: ledger_commitment section is empty");
    for case in cases {
        let got = ledger_commitment(
            case.get("jti").unwrap().as_str().unwrap(),
            case.get("nonce").unwrap().as_str().unwrap(),
            case.get("used_at").unwrap().as_int().unwrap(),
        );
        assert_eq!(
            got,
            case.get("expect").unwrap().as_str().unwrap(),
            "ledger_commitment drifted from the shared vector"
        );
    }
}

#[test]
fn grant_head_root_golden_vector() {
    use feir_decision_core::verify::grant_head_root;
    let v = preimage_vectors();
    let parse_grants = |case: &CanonValue| -> Vec<(i64, String)> {
        case.get("grants")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                (
                    g.get("seq").unwrap().as_int().unwrap(),
                    g.get("content_hash").unwrap().as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let mut three: Vec<(i64, String)> = Vec::new();
    for case in v.get("grant_head_root").unwrap().as_array().unwrap() {
        let grants = parse_grants(case);
        assert_eq!(
            grant_head_root(&grants),
            case.get("expect").unwrap().as_str().unwrap(),
            "grant_head_root drifted from the shared vector (case {})",
            case.get("name").unwrap().as_str().unwrap()
        );
        if grants.len() == 3 {
            three = grants;
        }
    }
    // Folding is ORDER-SENSITIVE: a renumber/reorder yields a different root (suppression detection).
    assert!(three.len() == 3, "the shared vector must carry a 3-grant case");
    let reordered = vec![three[1].clone(), three[0].clone(), three[2].clone()];
    assert_ne!(grant_head_root(&reordered), grant_head_root(&three));
}

// ---- D2: offline PoP re-verification fixtures (ADR 0004) ----
use feir_decision_core::b64::encode as b64enc;
use feir_decision_core::hashx::hex_lower;
use feir_decision_core::verify::{cnf_kid as vk_cnf_kid, use_pop_challenge};

// the credential_binding the grant_evidence helper carries (so a D2 use's PoP challenge matches it)
fn test_credential_binding() -> String {
    sha256_prefixed(b"test-credential-binding")
}

// seal_d2_use builds a resource-role use receipt carrying cnf_pub + use_sig so the verifier RE-RUNS
// the Ed25519 PoP. Parameterized so negatives can desync one input: `bound_commitment` is what the PoP
// is signed over, `record_commitment` is the receipt's input_commit (== bound for a valid receipt),
// `cnf_pub_carried` is the carried key, `sign_with` actually signs.
#[allow(clippy::too_many_arguments)]
fn seal_d2_use(
    rec_sk: &SigningKey,
    res_sk: &SigningKey,
    record_id: &str,
    prev: &[String],
    used_at: i64,
    bound_commitment: &str,
    record_commitment: &str,
    cnf_kid_str: &str,
    cnf_pub_carried: &VerifyingKey,
    sign_with: &SigningKey,
) -> CanonValue {
    let nonce = format!("nonce-{used_at}");
    let cb = test_credential_binding();
    let challenge = use_pop_challenge(GID, RESOURCE, ACTION, bound_commitment, &cb, &nonce);
    let use_sig = b64enc(&sign_with.sign(&challenge).to_bytes());
    let pch = format!("sha256:{}", hex_lower(&challenge));
    let ue = CanonValue::object(vec![
        ("kind".into(), CanonValue::string("use")),
        ("grant_id".into(), CanonValue::string(GID)),
        ("action".into(), CanonValue::string(ACTION)),
        ("resource_id".into(), CanonValue::string(RESOURCE)),
        ("jti".into(), CanonValue::string(GID)),
        ("nonce".into(), CanonValue::string(&nonce)),
        ("pop_challenge_hash".into(), CanonValue::string(pch)),
        ("cnf_kid".into(), CanonValue::string(cnf_kid_str)),
        (
            "ledger_commitment".into(),
            CanonValue::string(feir_decision_core::verify::ledger_commitment(GID, &nonce, used_at)),
        ),
        ("used_at".into(), CanonValue::Int(used_at)),
        ("cnf_pub".into(), CanonValue::string(b64enc(cnf_pub_carried.as_bytes()))),
        ("use_sig".into(), CanonValue::string(use_sig)),
    ])
    .unwrap();
    let eh = sha256_prefixed(ue.serialize().as_bytes());
    let esig = sign_evidence("gateway_enforced", "proj-001", record_id, &eh, res_sk);
    let prev_json = CanonValue::Array(prev.iter().map(|p| CanonValue::string(p.clone())).collect()).serialize();
    let body = format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{record_id}","project_id":"proj-001","agent_id":"feir-resource","agent_version":"feir-resource",
        "session_id":"s","span_id":"sp-{record_id}","parent_span_id":null,"causal_prev_hashes":{prev_json},"display_seq":1,
        "agent_ts":"2026-06-15T10:00:05.000Z","received_ts":"2026-06-15T10:00:05.000Z",
        "event_type":"tool_call","action":"{ACTION}","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"tool_gateway","grant_id":"{GID}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "input_commit":{{"alg":"sha256","commitment":"{record_commitment}","low_entropy":true}},
        "extensions":{{"broker":{{"kind":"use","grant_id":"{GID}","resource_id":"{RESOURCE}","use_evidence":{ue}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#,
        ue = ue.serialize(),
    );
    seal(&CanonValue::parse(&body).unwrap(), rec_sk).unwrap()
}

// d2_grant builds a grant whose grant_evidence.cnf_kid matches the cnf key (so the predicate passes).
fn d2_grant(rec: &SigningKey, cnf_vk: &VerifyingKey) -> CanonValue {
    seal_grant(rec, rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", &vk_cnf_kid(cnf_vk), ISSUED, EXP))
}

#[test]
fn tier_b_pop_reverified_under_carried_cnf() {
    // D2: a use carrying the cnf pubkey + a valid use_sig has its Ed25519 PoP RE-RUN offline.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let cnf = signing_key_from_seed(&[5u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let pc = sha256_prefixed(b"params-commit");
    let grant = d2_grant(&rec, &cnf.verifying_key());
    let use_rec = seal_d2_use(&rec, &res, "use-1", &[content_hash_of(&grant)], USED, &pc, &pc, &vk_cnf_kid(&cnf.verifying_key()), &cnf.verifying_key(), &cnf);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 1);
    assert_eq!(r.uses_pop_reverified, 1, "the PoP should be independently re-run offline");
    assert!(feir_decision_core::verify::report_to_json(&r).contains(r#""uses_pop_reverified":1"#));
}

#[test]
fn tier_b_pop_reverify_forged_use_sig_is_a_violation() {
    // A receipt carrying the real cnf_pub but a use_sig signed by a DIFFERENT key fails the re-check.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let cnf = signing_key_from_seed(&[5u8; 32]);
    let imposter = signing_key_from_seed(&[9u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let pc = sha256_prefixed(b"params-commit");
    let grant = d2_grant(&rec, &cnf.verifying_key());
    // sign_with = imposter, but carry cnf's pubkey + cnf's kid
    let use_rec = seal_d2_use(&rec, &res, "use-1", &[content_hash_of(&grant)], USED, &pc, &pc, &vk_cnf_kid(&cnf.verifying_key()), &cnf.verifying_key(), &imposter);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert_eq!(r.uses_pop_reverified, 0);
    assert!(r.issues.iter().any(|i| i.contains("PoP re-verification")), "{:?}", r.issues);
}

#[test]
fn tier_b_pop_reverify_challenge_mismatch_is_a_violation() {
    // The receipt's input_commit differs from the params_commitment the PoP was signed over -> the
    // reconstructed challenge != pop_challenge_hash.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let cnf = signing_key_from_seed(&[5u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let bound = sha256_prefixed(b"params-A");
    let in_record = sha256_prefixed(b"params-B"); // != bound
    let grant = d2_grant(&rec, &cnf.verifying_key());
    let use_rec = seal_d2_use(&rec, &res, "use-1", &[content_hash_of(&grant)], USED, &bound, &in_record, &vk_cnf_kid(&cnf.verifying_key()), &cnf.verifying_key(), &cnf);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("reconstructed PoP challenge")), "{:?}", r.issues);
}

#[test]
fn tier_b_pop_reverify_wrong_cnf_pub_is_a_violation() {
    // The carried cnf_pub does not match the receipt's cnf_kid (which matches the grant) -> violation.
    let rec = signing_key_from_seed(&[0u8; 32]);
    let res = signing_key_from_seed(&[3u8; 32]);
    let cnf = signing_key_from_seed(&[5u8; 32]);
    let other = signing_key_from_seed(&[9u8; 32]);
    let tsa = test_tsa_key(&[200u8; 32]);
    let pc = sha256_prefixed(b"params-commit");
    let grant = d2_grant(&rec, &cnf.verifying_key());
    // cnf_kid = cnf's (matches grant), but carry OTHER's pubkey and sign with OTHER
    let use_rec = seal_d2_use(&rec, &res, "use-1", &[content_hash_of(&grant)], USED, &pc, &pc, &vk_cnf_kid(&cnf.verifying_key()), &other.verifying_key(), &other);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert_eq!(r.unmatched_violation, 1);
    assert!(r.issues.iter().any(|i| i.contains("cnf_pub does not match")), "{:?}", r.issues);
}

#[test]
fn use_pop_challenge_and_cnf_kid_golden_vectors() {
    // Cross-language pinned vectors from the SHARED file — MUST equal Go resourceshim.usePoPChallenge
    // + broker.KeyID. The multibyte case asserts byte-length prefixing is identical in both languages.
    let v = preimage_vectors();
    let pop_cases = v.get("use_pop_challenge").unwrap().as_array().unwrap();
    let cnf_cases = v.get("cnf_kid").unwrap().as_array().unwrap();
    assert!(!pop_cases.is_empty() && !cnf_cases.is_empty(), "shared vector: pop/cnf section is empty");
    for case in pop_cases {
        let ch = use_pop_challenge(
            case.get("grant_id").unwrap().as_str().unwrap(),
            case.get("resource_id").unwrap().as_str().unwrap(),
            case.get("action").unwrap().as_str().unwrap(),
            case.get("params_commitment").unwrap().as_str().unwrap(),
            case.get("credential_binding").unwrap().as_str().unwrap(),
            case.get("nonce").unwrap().as_str().unwrap(),
        );
        assert_eq!(
            hex_lower(&ch),
            case.get("expect_hex").unwrap().as_str().unwrap(),
            "use_pop_challenge drifted from the shared vector (case {})",
            case.get("name").unwrap().as_str().unwrap()
        );
    }
    for case in cnf_cases {
        let seed = feir_decision_core::hashx::hex32(case.get("seed_hex").unwrap().as_str().unwrap())
            .expect("seed_hex is 32 bytes");
        let cnf = signing_key_from_seed(&seed).verifying_key();
        assert_eq!(
            vk_cnf_kid(&cnf),
            case.get("expect").unwrap().as_str().unwrap(),
            "cnf_kid drifted from the shared vector"
        );
    }
}

// ---- D4: signed operation taxonomy fixtures (ADR 0004) ----

// a single resource-bound `{resource_id, action}` taxonomy entry.
fn tax_entry(resource: &str, action: &str) -> CanonValue {
    CanonValue::object(vec![
        ("resource_id".into(), CanonValue::string(resource)),
        ("action".into(), CanonValue::string(action)),
    ])
    .unwrap()
}

// convenience: build a taxonomy listing `actions` as single-operation ON `RESOURCE` (the common case).
fn taxonomy(tax_sk: &SigningKey, actions: &[&str], from: i64, until: i64) -> CanonValue {
    taxonomy_v(tax_sk, actions, from, until, 1)
}

// version-parameterized convenience builder (actions are bound to the `RESOURCE` const).
fn taxonomy_v(tax_sk: &SigningKey, actions: &[&str], from: i64, until: i64, version: i64) -> CanonValue {
    let single: Vec<(&str, &str)> = actions.iter().map(|a| (RESOURCE, *a)).collect();
    taxonomy_full(tax_sk, &single, &[], from, until, version)
}

// full builder: explicit resource-bound single_operation + escalating (resource, action) pairs.
fn taxonomy_full(tax_sk: &SigningKey, single: &[(&str, &str)], escalating: &[(&str, &str)], from: i64, until: i64, version: i64) -> CanonValue {
    let entries = |pairs: &[(&str, &str)]| CanonValue::Array(pairs.iter().map(|(r, a)| tax_entry(r, a)).collect());
    let mut fields = vec![
        ("kind".into(), CanonValue::string("operation_taxonomy")),
        ("version".into(), CanonValue::Int(version)),
        ("effective_from".into(), CanonValue::Int(from)),
        ("effective_until".into(), CanonValue::Int(until)),
        ("single_operation_actions".into(), entries(single)),
    ];
    if !escalating.is_empty() {
        fields.push(("escalating_actions".into(), entries(escalating)));
    }
    let body = CanonValue::object(fields).unwrap();
    let digest = sha256_prefixed(body.serialize().as_bytes());
    let sig = feir_decision_core::sign::sign("feir.taxonomy.v1", &digest, tax_sk);
    change_field(&body, "sig", CanonValue::string(sig))
}

// The pinned content digest of a taxonomy = sha256_prefixed(RCP-canonical taxonomy MINUS `sig`) —
// mirrors validate_taxonomy's preimage so a test pins exactly what the verifier recomputes.
fn tax_digest(tax: &CanonValue) -> String {
    let mut obj = tax.as_object().unwrap().clone();
    obj.retain(|(k, _)| k != "sig");
    sha256_prefixed(CanonValue::Object(obj).serialize().as_bytes())
}

fn pinned_roles_tax(broker_vk: VerifyingKey, resource_vk: VerifyingKey, tsa_vk: VerifyingKey, tax: CanonValue, tax_vk: VerifyingKey) -> VerifyOptions {
    // pin the honest digest + version so the taxonomy can reach `validated` (MF5); negative tests below
    // override `taxonomy_digest`/`taxonomy_version` to exercise the pin checks.
    let digest = tax_digest(&tax);
    let version = tax.get("version").and_then(|v| v.as_int());
    VerifyOptions {
        broker_authority_keys: vec![broker_vk],
        resource_authority_keys: vec![resource_vk],
        trusted_tsa_keys: vec![tsa_vk],
        taxonomy: Some(tax),
        taxonomy_keys: vec![tax_vk],
        taxonomy_digest: Some(digest),
        taxonomy_version: version,
        ..Default::default()
    }
}

// d4_bundle builds the standard happy-path grant+use+anchored-checkpoint bundle (single_operation).
fn d4_bundle(rec: &SigningKey, res: &SigningKey, tsa: &SigningKey) -> CanonValue {
    let grant = seal_grant(rec, rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED);
    let use_rec = seal_use(rec, res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(rec, &[content_hash_of(&use_rec)], 2, Some(tsa));
    tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp])
}

#[test]
fn tier_b_taxonomy_validated_use_is_action_verified() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100); // covers issued + used
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 1);
    assert_eq!(r.uses_action_unverified, 0, "a taxonomy-validated use is action-verified");
    assert_eq!(r.taxonomy_status, "validated");
    assert!(feir_decision_core::verify::report_to_json(&r).contains(r#""taxonomy_status":"validated""#));
}

#[test]
fn tier_b_taxonomy_unlisted_action_stays_unverified() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &["some.other:action"], ISSUED - 100, EXP + 100); // ACTION not listed
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(r.ok);
    assert_eq!(r.uses_action_unverified, 1, "an unlisted action stays unverified");
    assert_eq!(r.taxonomy_status, "validated");
}

// closure_manifest builds a coverage_manifest declaring side_effect_closure entries (resource_id, action,
// may_touch) for the T6 tests.
fn closure_manifest(entries: &[(&str, &str, &[&str])]) -> CanonValue {
    let arr: Vec<CanonValue> = entries
        .iter()
        .map(|(rid, act, touch)| {
            CanonValue::object(vec![
                ("resource_id".into(), CanonValue::string(*rid)),
                ("action".into(), CanonValue::string(*act)),
                ("may_touch".into(), CanonValue::Array(touch.iter().map(|t| CanonValue::string(*t)).collect())),
            ])
            .unwrap()
        })
        .collect();
    CanonValue::object(vec![("side_effect_closure".into(), CanonValue::Array(arr))]).unwrap()
}

// T6: a coverage_manifest whose side_effect_closure declares every touched resource -> closed + ok.
#[test]
fn tier_b_t6_closed_surface_is_ok() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa); // the only touched resource is RESOURCE
    let bundle = change_field(&bundle, "coverage_manifest", closure_manifest(&[(RESOURCE, ACTION, &[])]));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.unclosed_side_effects, 0);
    assert_eq!(r.side_effect_closure_status, "closed");
}

// T6: a resource the surface touches that is in NO declared closure -> unclosed violation (hard fail).
#[test]
fn tier_b_t6_undeclared_touched_resource_is_unclosed() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let bundle = change_field(&bundle, "coverage_manifest", closure_manifest(&[("unrelated-db", "x:y", &["audit-log"])]));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "an undeclared touched resource must fail the bundle");
    assert_eq!(r.unclosed_side_effects, 1);
    assert_eq!(r.side_effect_closure_status, "unclosed");
    assert!(r.issues.iter().any(|i| i.contains(RESOURCE) && i.contains("side_effect_closure")), "issues: {:?}", r.issues);
}

// T6 (action-bound, Codex): a resource declared via may_touch UNDER THE SAME action that touches it is closed.
// The surface touches (RESOURCE, ACTION); RESOURCE is declared as the may_touch of `other-primary` under the
// SAME ACTION, so (RESOURCE, ACTION) is in the declared closure -> closed.
#[test]
fn tier_b_t6_may_touch_under_same_action_is_closed() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let bundle = change_field(&bundle, "coverage_manifest", closure_manifest(&[("other-primary", ACTION, &[RESOURCE])]));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.side_effect_closure_status, "closed");
}

// T6 (action-bound, Codex regression): a resource declared ONLY under an UNRELATED action must NOT close it
// for the action actually acting on it. The surface touches (RESOURCE, ACTION); the manifest declares RESOURCE
// only under "billing:charge" (as primary AND as may_touch) — neither covers (RESOURCE, ACTION) -> unclosed.
#[test]
fn tier_b_t6_resource_under_unrelated_action_is_unclosed() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let bundle = change_field(&bundle, "coverage_manifest", closure_manifest(&[(RESOURCE, "billing:charge", &[]), ("billing-svc", "billing:charge", &[RESOURCE])]));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a resource declared only under an unrelated action must not close it for ACTION");
    assert_eq!(r.side_effect_closure_status, "unclosed");
    assert!(r.issues.iter().any(|i| i.contains(RESOURCE) && i.contains(ACTION) && i.contains("side_effect_closure")), "issues: {:?}", r.issues);
}

// T6: a present-but-malformed side_effect_closure fails closed (never silently treated as empty/closed).
#[test]
fn tier_b_t6_malformed_closure_fails_closed() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let bad_entry = CanonValue::object(vec![("resource_id".into(), CanonValue::string(RESOURCE))]).unwrap(); // missing action/may_touch
    let manifest = CanonValue::object(vec![("side_effect_closure".into(), CanonValue::Array(vec![bad_entry]))]).unwrap();
    let bundle = change_field(&bundle, "coverage_manifest", manifest);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a malformed side_effect_closure must fail closed");
    assert_eq!(r.side_effect_closure_status, "unclosed");
    assert!(r.issues.iter().any(|i| i.contains("malformed")), "issues: {:?}", r.issues);
}

// T6 (Codex hardening): an entry with an EMPTY action is malformed -> fail closed. An empty action must never
// enter the declared set, else an `action:""` entry could "close" a malformed action-less grant.
#[test]
fn tier_b_t6_empty_action_fails_closed() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let bundle = change_field(&bundle, "coverage_manifest", closure_manifest(&[(RESOURCE, "", &[])]));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "an empty-action closure entry must fail closed");
    assert_eq!(r.side_effect_closure_status, "unclosed");
    assert!(r.issues.iter().any(|i| i.contains("malformed")), "issues: {:?}", r.issues);
}

// T6: a coverage_manifest present but WITHOUT a side_effect_closure is `not_declared` (and still ok).
#[test]
fn tier_b_t6_no_closure_is_not_declared() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let manifest = CanonValue::object(vec![("conformance_level".into(), CanonValue::string("L2_use_receipts"))]).unwrap();
    let bundle = change_field(&bundle, "coverage_manifest", manifest);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.side_effect_closure_status, "not_declared");
    assert_eq!(r.unclosed_side_effects, 0);
}

#[test]
fn tier_b_taxonomy_stale_window_stays_unverified() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, USED - 1); // window ends BEFORE used_at
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(r.ok);
    assert_eq!(r.uses_action_unverified, 1, "a stale (out-of-window) taxonomy must not validate the use");
    // a listed action rejected by the effective window marks the taxonomy `stale` (MF5), not `validated`
    assert_eq!(r.taxonomy_status, "stale");
}

#[test]
fn tier_b_taxonomy_untrusted_signature() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let wrong = signing_key_from_seed(&[12u8; 32]);
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&wrong, &[ACTION], ISSUED - 100, EXP + 100); // signed by a NON-pinned key
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert_eq!(r.taxonomy_status, "untrusted");
    assert_eq!(r.uses_action_unverified, 1, "an untrusted taxonomy validates nothing");
}

#[test]
fn tier_b_taxonomy_via_json_opts() {
    // the Go/FFI auditor pins the taxonomy through the JSON options path (verify_bundle_with_json).
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100);
    let digest = tax_digest(&t);
    let key_arr = |vk| CanonValue::Array(vec![CanonValue::string(encode_pubkey(vk))]);
    let opts = CanonValue::object(vec![
        ("broker_authority_keys".into(), key_arr(&rec.verifying_key())),
        ("resource_authority_keys".into(), key_arr(&res.verifying_key())),
        ("tsa_keys".into(), key_arr(&tsa.verifying_key())),
        ("taxonomy".into(), t),
        ("taxonomy_keys".into(), key_arr(&tax.verifying_key())),
        ("taxonomy_digest".into(), CanonValue::string(digest)),
        ("taxonomy_version".into(), CanonValue::Int(1)),
    ])
    .unwrap();
    let report = feir_decision_core::verify::verify_bundle_with_json(&bundle.serialize(), &opts.serialize());
    assert!(report.contains(r#""taxonomy_status":"validated""#), "{report}");
    assert!(report.contains(r#""uses_action_unverified":0"#), "{report}");
}

// ---- D4 negative coverage: role separation (Codex AREA 1) + pinned digest/version (Codex AREA 3) ----

// A taxonomy_keys set that overlaps the broker authority keys is a FATAL config error: that broker key
// could self-validate a D4 taxonomy to fabricate `taxonomy_status:"validated"`.
#[test]
fn tier_b_taxonomy_keys_overlapping_broker_is_fatal() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100);
    let mut opts = pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key());
    opts.taxonomy_keys = vec![rec.verifying_key()]; // == broker key
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "a broker key reused as a taxonomy key must abort fatally");
    assert!(r.issues.iter().any(|i| i.contains("must be disjoint")), "issues: {:?}", r.issues);
}

// Same fatal abort when taxonomy_keys overlaps the RESOURCE authority keys (the pairwise check).
#[test]
fn tier_b_taxonomy_keys_overlapping_resource_is_fatal() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100);
    let mut opts = pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key());
    opts.taxonomy_keys = vec![res.verifying_key()]; // == resource key
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "a resource key reused as a taxonomy key must abort fatally");
    assert!(r.issues.iter().any(|i| i.contains("must be disjoint")), "issues: {:?}", r.issues);
}

// T7 (Codex convergence): an `authority_keys` set (the generic policy_engine_signed/human_signed elevation
// keys) that overlaps the RESOURCE authority keys is a FATAL config error — else a resource key could sign a
// generic record's evidence_sig and have it read as `verified` (forged generic authority).
#[test]
fn tier_b_authority_keys_overlapping_resource_is_fatal() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.trusted_authority_keys = vec![res.verifying_key()]; // == resource key
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "a resource key reused as a trusted authority key must abort fatally");
    assert!(r.issues.iter().any(|i| i.contains("must be disjoint")), "issues: {:?}", r.issues);
}

// MF5: a validly-signed taxonomy with NO pinned digest/version stays `untrusted` (fail-closed — the
// operator must vet a specific artifact; a signature alone does not make it `validated`).
#[test]
fn tier_b_taxonomy_unpinned_is_untrusted() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100);
    let mut opts = pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key());
    opts.taxonomy_digest = None;
    opts.taxonomy_version = None;
    let r = verify_bundle_with(&bundle, &opts);
    assert_eq!(r.taxonomy_status, "untrusted", "an unpinned taxonomy must not reach validated");
    assert_eq!(r.uses_action_unverified, 1);
}

// MF5: signature + version are fine, but the pinned digest does not match → `untrusted` (the bundle's
// taxonomy is not the artifact the operator pinned).
#[test]
fn tier_b_taxonomy_wrong_pinned_digest_is_untrusted() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100);
    let mut opts = pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key());
    opts.taxonomy_digest = Some(sha256_prefixed(b"not-the-real-taxonomy-digest"));
    let r = verify_bundle_with(&bundle, &opts);
    assert_eq!(r.taxonomy_status, "untrusted", "a pinned-digest mismatch must not reach validated");
    assert_eq!(r.uses_action_unverified, 1);
}

// MF5: signature + digest match, but the carried version != the pinned version → `untrusted` (rollback
// anchor: an operator pins version N and a re-signed-but-older taxonomy cannot pass).
#[test]
fn tier_b_taxonomy_wrong_pinned_version_is_untrusted() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy_v(&tax, &[ACTION], ISSUED - 100, EXP + 100, 2); // taxonomy is version 2
    let mut opts = pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key());
    opts.taxonomy_version = Some(1); // operator pins version 1
    let r = verify_bundle_with(&bundle, &opts);
    assert_eq!(r.taxonomy_status, "untrusted", "a pinned-version mismatch must not reach validated");
    assert_eq!(r.uses_action_unverified, 1);
}

// Tampering with the signed body (adding an action after signing) breaks both the content digest and
// the signature → `untrusted` (the signature binds the action list).
#[test]
fn tier_b_taxonomy_body_tampering_is_untrusted() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let honest = taxonomy(&tax, &["benign:read"], ISSUED - 100, EXP + 100);
    // attacker appends the grant's (RESOURCE, ACTION) to the action list after signing
    let tampered = change_field(
        &honest,
        "single_operation_actions",
        CanonValue::Array(vec![tax_entry(RESOURCE, "benign:read"), tax_entry(RESOURCE, ACTION)]),
    );
    let opts = pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), tampered, tax.verifying_key());
    let r = verify_bundle_with(&bundle, &opts);
    assert_eq!(r.taxonomy_status, "untrusted", "post-signature tampering must not reach validated");
    assert_eq!(r.uses_action_unverified, 1, "the smuggled action must NOT become action-verified");
}

// A NON-single_operation (session) grant stays `uses_action_unverified` even under a `validated`
// taxonomy that lists its action — the action-verified split is gated on `scope_class==single_operation`.
#[test]
fn tier_b_taxonomy_non_single_operation_stays_unverified() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "session", CNF, ISSUED, EXP));
    let ue = use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED);
    let use_rec = seal_use(&rec, &res, "use-1", &[content_hash_of(&grant)], ACTION, &ue);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100);
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 1);
    assert_eq!(r.taxonomy_status, "validated");
    assert_eq!(r.uses_action_unverified, 1, "a session-scope use is never action-verified, even under a validated taxonomy");
}

// Explicit baseline: no taxonomy pinned at all → `absent`, and every matched use stays unverified.
#[test]
fn tier_b_taxonomy_absent_baseline() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let opts = VerifyOptions {
        broker_authority_keys: vec![rec.verifying_key()],
        resource_authority_keys: vec![res.verifying_key()],
        trusted_tsa_keys: vec![tsa.verifying_key()],
        ..Default::default()
    };
    let r = verify_bundle_with(&bundle, &opts);
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.taxonomy_status, "absent");
    assert_eq!(r.uses_action_unverified, 1, "with no taxonomy every matched use stays unverified");
}

// ---- D4: resource-binding (Codex AREA 2) + mis-scope rejection + remaining coverage ----

// A taxonomy that lists the action FOR A DIFFERENT resource must NOT validate the use on RESOURCE — the
// listing is resource-bound, so a colliding action name on another resource stays unverified.
#[test]
fn tier_b_taxonomy_action_listed_for_other_resource_stays_unverified() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    // ACTION is single-operation only on "some-other-db", NOT on RESOURCE (orders-db)
    let t = taxonomy_full(&tax, &[("some-other-db", ACTION)], &[], ISSUED - 100, EXP + 100, 1);
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(r.ok);
    assert_eq!(r.taxonomy_status, "validated", "the artifact is still trusted");
    assert_eq!(r.uses_action_unverified, 1, "an action listed for another resource must not validate this use");
}

// A grant claiming single_operation for an action the taxonomy marks ESCALATING is mis-scoped: it is
// rejected AT ISSUANCE (a hard `issues` failure), and its use is skipped (never counted/verified).
#[test]
fn tier_b_taxonomy_escalating_single_op_grant_is_misscoped_violation() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa); // grant claims single_operation for (RESOURCE, ACTION), and is USED
    // taxonomy affirmatively marks (RESOURCE, ACTION) as escalating — so single_operation is mis-scoped
    let t = taxonomy_full(&tax, &[(RESOURCE, "benign:read")], &[(RESOURCE, ACTION)], ISSUED - 100, EXP + 100, 1);
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(!r.ok, "a mis-scoped grant must fail the bundle");
    assert!(r.issues.iter().any(|i| i.contains("mis-scoped")), "issues: {:?}", r.issues);
    // the violation is recorded once, at the grant — the use is skipped, not double-counted
    assert_eq!(r.uses_matched, 0, "a mis-scoped grant's use must not count as matched/verified");
    // a USED mis-scoped grant is rejected, NOT mis-reported as a clean unused grant
    assert_eq!(r.grants_unused, 0, "a mis-scoped grant must not be reported as unused");
    // exactly one mis-scope issue (no double-count)
    assert_eq!(r.issues.iter().filter(|i| i.contains("mis-scoped")).count(), 1);
}

// A D2 use (carrying a valid cnf_pub + use_sig — its PoP WOULD re-verify) against a mis-scoped grant is
// skipped BEFORE the PoP re-check: `uses_pop_reverified` stays 0 (no use-side counter leaks through a
// rejected grant), and the single mis-scope issue is recorded at the grant.
#[test]
fn tier_b_misscoped_grant_d2_use_does_not_leak_pop_reverified() {
    let (rec, res, cnf, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), signing_key_from_seed(&[5u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let pc = sha256_prefixed(b"params-commit");
    let grant = d2_grant(&rec, &cnf.verifying_key()); // single_operation (GID, ACTION, RESOURCE)
    let use_rec = seal_d2_use(&rec, &res, "use-1", &[content_hash_of(&grant)], USED, &pc, &pc, &vk_cnf_kid(&cnf.verifying_key()), &cnf.verifying_key(), &cnf);
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    // taxonomy marks (RESOURCE, ACTION) escalating → the grant is mis-scoped at issuance
    let t = taxonomy_full(&tax, &[], &[(RESOURCE, ACTION)], ISSUED - 100, EXP + 100, 1);
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(!r.ok);
    assert!(r.issues.iter().any(|i| i.contains("mis-scoped")), "issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 0);
    assert_eq!(r.uses_pop_reverified, 0, "a rejected grant's use must not increment uses_pop_reverified");
    assert_eq!(r.grants_unused, 0);
    assert_eq!(r.issues.iter().filter(|i| i.contains("mis-scoped")).count(), 1);
}

// The mis-scope rejection fires even when the grant is NEVER exercised — an issued-but-unused
// single_operation grant for an escalating pair is still a hard failure (no use receipt required).
#[test]
fn tier_b_taxonomy_unused_escalating_grant_is_misscoped() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    // grant only — NO use receipt
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let cp = checkpoint_over(&rec, &[content_hash_of(&grant)], 1, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let t = taxonomy_full(&tax, &[], &[(RESOURCE, ACTION)], ISSUED - 100, EXP + 100, 1);
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(!r.ok, "an unused mis-scoped grant must still fail the bundle");
    assert!(r.issues.iter().any(|i| i.contains("mis-scoped")), "issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 0);
}

// Precedence: a pair in BOTH single_operation_actions AND escalating_actions resolves to mis-scoped
// (escalating wins) — an adversarial taxonomy author cannot launder an escalating pair to action-verified
// by also listing it as single-operation.
#[test]
fn tier_b_taxonomy_escalating_beats_single_operation_listing() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    // (RESOURCE, ACTION) is in BOTH lists
    let t = taxonomy_full(&tax, &[(RESOURCE, ACTION)], &[(RESOURCE, ACTION)], ISSUED - 100, EXP + 100, 1);
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(!r.ok, "escalating must win over a single_operation listing of the same pair");
    assert!(r.issues.iter().any(|i| i.contains("mis-scoped")), "issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 0, "the pair must NOT be laundered to action-verified");
}

// tax_pairs fail-closed: a MALFORMED taxonomy entry (object missing `action`) sinks the WHOLE taxonomy to
// `untrusted` — it must NOT be silently dropped (which would weaken the listing) nor panic.
#[test]
fn tier_b_taxonomy_malformed_entry_is_untrusted() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    // an entry with resource_id but no `action`, then sign honestly so ONLY the malformed shape sinks it
    let bad_entry = CanonValue::object(vec![("resource_id".into(), CanonValue::string(RESOURCE))]).unwrap();
    let body = CanonValue::object(vec![
        ("kind".into(), CanonValue::string("operation_taxonomy")),
        ("version".into(), CanonValue::Int(1)),
        ("effective_from".into(), CanonValue::Int(ISSUED - 100)),
        ("effective_until".into(), CanonValue::Int(EXP + 100)),
        ("single_operation_actions".into(), CanonValue::Array(vec![bad_entry])),
    ])
    .unwrap();
    let digest = sha256_prefixed(body.serialize().as_bytes());
    let sig = feir_decision_core::sign::sign("feir.taxonomy.v1", &digest, &tax);
    let t = change_field(&body, "sig", CanonValue::string(sig));
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert_eq!(r.taxonomy_status, "untrusted", "a malformed entry must fail the whole taxonomy closed");
    assert_eq!(r.uses_action_unverified, 1);
}

// A taxonomy carrying NO `version` field cannot reach `validated` (the digest pin alone is not enough —
// MF5 forces the artifact to carry a version, per validate_taxonomy's `version?`).
#[test]
fn tier_b_taxonomy_missing_version_is_untrusted() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    // build an honest taxonomy then strip `version` and RE-SIGN so the signature itself is valid — only
    // the missing version field should sink it.
    let body = CanonValue::object(vec![
        ("kind".into(), CanonValue::string("operation_taxonomy")),
        ("effective_from".into(), CanonValue::Int(ISSUED - 100)),
        ("effective_until".into(), CanonValue::Int(EXP + 100)),
        ("single_operation_actions".into(), CanonValue::Array(vec![tax_entry(RESOURCE, ACTION)])),
    ])
    .unwrap();
    let digest = sha256_prefixed(body.serialize().as_bytes());
    let sig = feir_decision_core::sign::sign("feir.taxonomy.v1", &digest, &tax);
    let t = change_field(&body, "sig", CanonValue::string(sig));
    let mut opts = pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key());
    opts.taxonomy_version = Some(1); // operator pins a version, but the artifact carries none
    let r = verify_bundle_with(&bundle, &opts);
    assert_eq!(r.taxonomy_status, "untrusted", "a versionless taxonomy must not reach validated");
    assert_eq!(r.uses_action_unverified, 1);
}

// JSON-opts fail-closed: a non-string taxonomy_digest or non-integer taxonomy_version is an ERROR, not a
// silent degrade to "no pin" (which would leave a forever-`untrusted` taxonomy with no signal).
#[test]
fn tier_b_taxonomy_json_pins_are_fail_closed() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let bundle = d4_bundle(&rec, &res, &tsa);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100);
    let (bvk, rvk, tvk, xvk) = (rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), tax.verifying_key());
    let key_arr = |vk: &VerifyingKey| CanonValue::Array(vec![CanonValue::string(encode_pubkey(vk))]);
    let base = |digest: CanonValue, version: CanonValue| {
        CanonValue::object(vec![
            ("broker_authority_keys".into(), key_arr(&bvk)),
            ("resource_authority_keys".into(), key_arr(&rvk)),
            ("tsa_keys".into(), key_arr(&tvk)),
            ("taxonomy".into(), t.clone()),
            ("taxonomy_keys".into(), key_arr(&xvk)),
            ("taxonomy_digest".into(), digest),
            ("taxonomy_version".into(), version),
        ])
        .unwrap()
    };
    let good_digest = CanonValue::string(tax_digest(&t));
    // non-string digest → error
    let bad_digest = base(CanonValue::Int(7), CanonValue::Int(1));
    let r1 = feir_decision_core::verify::verify_bundle_with_json(&bundle.serialize(), &bad_digest.serialize());
    assert!(r1.contains(r#""error""#) && r1.contains("taxonomy_digest"), "{r1}");
    // non-integer version → error
    let bad_version = base(good_digest, CanonValue::string("1"));
    let r2 = feir_decision_core::verify::verify_bundle_with_json(&bundle.serialize(), &bad_version.serialize());
    assert!(r2.contains(r#""error""#) && r2.contains("taxonomy_version"), "{r2}");
}

// Mixed multi-use bundle: TWO single_operation grants — one for a taxonomy-listed action (its use is
// action-VERIFIED) and one for an unlisted action (its use stays unverified). `uses_action_unverified`
// must count exactly the unlisted one (1, not 0 and not 2) while `taxonomy_status` stays `validated`.
// This genuinely exercises the per-use split (a session-only bundle could not distinguish it).
#[test]
fn tier_b_taxonomy_mixed_uses_count_only_the_unverified() {
    let (rec, res, tsa, tax) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    const OTHER: &str = "db.query:invoices-ro"; // NOT listed in the taxonomy
    // both single_operation (so each is single-use, jti == grant_id), distinct grant_ids
    let g1 = seal_grant(&rec, &rec, "grant-a", &grant_evidence("grant-a", ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let g2 = seal_grant(&rec, &rec, "grant-b", &grant_evidence("grant-b", OTHER, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let u1 = seal_use(&rec, &res, "use-a", &[content_hash_of(&g1)], ACTION, &use_evidence("grant-a", ACTION, RESOURCE, "grant-a", CNF, USED));
    let u2 = seal_use(&rec, &res, "use-b", &[content_hash_of(&g2)], OTHER, &use_evidence("grant-b", OTHER, RESOURCE, "grant-b", CNF, USED + 1));
    let cp = checkpoint_over(&rec, &[content_hash_of(&u1), content_hash_of(&u2)], 4, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2, u1, u2], vec![cp]);
    let t = taxonomy(&tax, &[ACTION], ISSUED - 100, EXP + 100); // lists (RESOURCE, ACTION), not OTHER
    let r = verify_bundle_with(&bundle, &pinned_roles_tax(rec.verifying_key(), res.verifying_key(), tsa.verifying_key(), t, tax.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.uses_matched, 2);
    assert_eq!(r.taxonomy_status, "validated");
    assert_eq!(r.uses_action_unverified, 1, "exactly the unlisted-action use stays unverified; the listed one is action-verified");
}

// Cross-language golden vector: a FIXED taxonomy body (minus `sig`) → this exact `sha256:` digest. The
// digest preimage is RCP-canonical taxonomy-minus-`sig`; a Go/FFI auditor computing taxonomy_digest MUST
// reproduce this byte-for-byte. Hardcoding the expected value (not re-deriving it) is what catches drift
// in key ordering / NFC / sig-stripping that a self-mirroring helper cannot.
#[test]
fn taxonomy_digest_golden_vector() {
    let body = CanonValue::object(vec![
        ("kind".into(), CanonValue::string("operation_taxonomy")),
        ("version".into(), CanonValue::Int(1)),
        ("effective_from".into(), CanonValue::Int(1_718_445_600)),
        ("effective_until".into(), CanonValue::Int(1_718_449_200)),
        (
            "single_operation_actions".into(),
            CanonValue::Array(vec![tax_entry("orders-db", "db.query:orders-ro")]),
        ),
    ])
    .unwrap();
    let digest = sha256_prefixed(body.serialize().as_bytes());
    assert_eq!(digest, "sha256:eadbcd86089ce7b27a79fe516b42087bdc62c9215d7ba069295b4fbc04bc26b9");
}

// ---- D6: grant transparency / broker_trust (ADR 0004 / MF2) ----

fn ghr(grants: &[(i64, &str)]) -> String {
    let v: Vec<(i64, String)> = grants.iter().map(|(s, h)| (*s, h.to_string())).collect();
    feir_decision_core::verify::grant_head_root(&v)
}

fn grant_head_cv(max_seq: i64, prior: &str, root: &str) -> CanonValue {
    CanonValue::object(vec![
        ("max_seq".into(), CanonValue::Int(max_seq)),
        ("prior_head_hash".into(), CanonValue::string(prior)),
        ("cumulative_root".into(), CanonValue::string(root)),
    ])
    .unwrap()
}

fn grant_evidence_d6(gid: &str, broker_seq: i64) -> CanonValue {
    change_field(&grant_evidence(gid, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP), "broker_seq", CanonValue::Int(broker_seq))
}

// a checkpoint carrying a broker_grant_head (optionally anchored).
fn checkpoint_with_head(rec_sk: &SigningKey, frontier: &[String], record_count: i64, head: CanonValue, anchor_with: Option<&SigningKey>) -> CanonValue {
    let key_block = CanonValue::parse(r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active"}"#).unwrap();
    let body = checkpoint_body("cp0", "proj-001", 0, None, frontier, record_count, "2026-06-15T10:10:00.000Z", key_block).unwrap();
    let body = change_field(&body, "broker_grant_head", head);
    let cp = seal_checkpoint(&body, rec_sk).unwrap();
    match anchor_with {
        Some(tsa) => {
            let anchor = make_test_anchor(&checkpoint_hash(&cp), "2026-06-15T10:10:01.000Z", tsa, "tsa-1");
            attach_anchor(&cp, anchor)
        }
        None => cp,
    }
}

// a clean single-grant (broker_seq=1) bundle whose anchored checkpoint head correctly commits it.
fn d6_clean(rec: &SigningKey, tsa: &SigningKey) -> CanonValue {
    let grant = seal_grant(rec, rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    let head = grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &gh)]));
    let cp = checkpoint_with_head(rec, std::slice::from_ref(&gh), 1, head, Some(tsa));
    tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp])
}

#[test]
fn tier_b_broker_trust_sequence_verified() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = d6_clean(&rec, &tsa);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.broker_trust, "sequence_verified", "anchored gapless head must reach sequence_verified");
}

#[test]
fn tier_b_broker_trust_no_head_is_assumed() {
    // INHERENT RESIDUAL (ADR 0004 D6, total-suppression / pre-D6 equivalence): a grant with NO broker_seq +
    // a checkpoint with NO broker_grant_head field carries ZERO D6 signal, so the bundle is byte-identical
    // to a legitimate pre-D6 export and verifies clean as `assumed`. This is NOT a clean D6 guarantee — it
    // is the documented offline limit (an attacker who emits no D6 signal at all looks pre-D6). The moment
    // any seq'd grant or any head appears, strict D6 engages (see _total_suppression_*, _seqless_*, and
    // _d6_grant_without_head tests). Detection of this all-or-nothing case is pushed to the out-of-band
    // transparency monitor, which knows the project adopted D6.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let cp = checkpoint_over(&rec, &[content_hash_of(&grant)], 1, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "issues: {:?}", r.issues);
    assert_eq!(r.broker_trust, "assumed");
}

#[test]
fn tier_b_broker_trust_grant_id_equivocation_is_violation() {
    // D6 grant_id INJECTIVITY: one grant_id double-bound to TWO distinct credentials at broker_seq 1 and
    // 2, both co-committed in ONE anchored head with DISTINCT top-level record_ids. The head folds only
    // (broker_seq, content_hash), so it re-derives a gapless cumulative_root and — before the injectivity
    // guard — passed as `sequence_verified` with grant_verified=2 and zero issues, certifying a clean log
    // over an equivocated credential identity (a fail-OPEN). Must now fail closed. This is the
    // LOCALLY-decidable equivocation (both twins in one bundle), NOT the globally-consistent offline floor.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let g1 = seal_grant(&rec, &rec, "rec-A", &grant_evidence_d6(GID, 1));
    let g2 = seal_grant(&rec, &rec, "rec-B", &grant_evidence_d6(GID, 2));
    let (ha, hb) = (content_hash_of(&g1), content_hash_of(&g2));
    let head = grant_head_cv(2, &ghr(&[]), &ghr(&[(1, &ha), (2, &hb)]));
    let cp = checkpoint_with_head(&rec, &[ha.clone(), hb.clone()], 2, head, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "an equivocated grant_id must fail the bundle; broker_trust={}", r.broker_trust);
    assert_ne!(r.broker_trust, "sequence_verified", "equivocation must never reach sequence_verified");
    assert!(
        r.issues.iter().any(|i| i.contains("equivocated credential identity")),
        "issues: {:?}",
        r.issues
    );
}

#[test]
fn tier_b_broker_trust_d6_grant_without_head_is_violation() {
    // a D6 grant (carries broker_seq) but the checkpoint dropped its head -> suppression (the producer
    // always emits a head when D6 grants exist), so this must FAIL, not silently fall back to assumed.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 1));
    let cp = checkpoint_over(&rec, &[content_hash_of(&grant)], 1, Some(&tsa)); // NO broker_grant_head
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a D6 grant with no anchored head must fail");
    assert!(r.issues.iter().any(|i| i.contains("no broker_grant_head") || i.contains("dropped head")), "issues: {:?}", r.issues);
    assert_eq!(r.broker_trust, "assumed");
}

#[test]
fn tier_b_broker_trust_unanchored_head_is_consistent_export() {
    // head present + internally consistent, but the checkpoint is NOT anchored -> sequence_consistent_export.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    let head = grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &gh)]));
    let cp = checkpoint_with_head(&rec, std::slice::from_ref(&gh), 1, head, None); // NOT anchored
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert_eq!(r.broker_trust, "sequence_consistent_export", "an unanchored head is internal consistency only");
}

#[test]
fn tier_b_broker_trust_gap_is_violation() {
    // a grant with broker_seq=2 (no seq 1) -> the recorded log is not a gapless [1..N] prefix.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 2));
    let gh = content_hash_of(&grant);
    // head honestly folds the one recorded grant at seq 2, max_seq 2
    let head = grant_head_cv(2, &ghr(&[]), &ghr(&[(2, &gh)]));
    let cp = checkpoint_with_head(&rec, std::slice::from_ref(&gh), 1, head, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a gap in broker_seq must fail the bundle");
    assert!(r.issues.iter().any(|i| i.contains("gapless")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_broker_trust_root_mismatch_is_violation() {
    // anchored head with a WRONG cumulative_root -> re-derivation mismatch (suppression).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    let head = grant_head_cv(1, &ghr(&[]), "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let cp = checkpoint_with_head(&rec, std::slice::from_ref(&gh), 1, head, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert!(r.issues.iter().any(|i| i.contains("cumulative_root")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_broker_trust_tail_omission_is_violation() {
    // head claims max_seq=2 but only one grant (seq 1) is recorded -> tail omission.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    // cumulative_root honestly folds the one recorded grant, but max_seq claims 2
    let head = grant_head_cv(2, &ghr(&[]), &ghr(&[(1, &gh)]));
    let cp = checkpoint_with_head(&rec, std::slice::from_ref(&gh), 1, head, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert!(r.issues.iter().any(|i| i.contains("tail omission") || i.contains("max_seq")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_broker_trust_forked_prior_head_is_violation() {
    // the head's prior_head_hash does NOT chain to the empty-log root (a forked/restarted grant log).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    let head = grant_head_cv(1, "sha256:0000000000000000000000000000000000000000000000000000000000000000", &ghr(&[(1, &gh)]));
    let cp = checkpoint_with_head(&rec, std::slice::from_ref(&gh), 1, head, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok);
    assert!(r.issues.iter().any(|i| i.contains("prior_head_hash") && i.contains("fork/restart")), "issues: {:?}", r.issues);
}

// a checkpoint with explicit seq/id/prev (for multi-checkpoint chains), optional head, optional anchor.
#[allow(clippy::too_many_arguments)]
fn checkpoint_seqd(rec_sk: &SigningKey, cid: &str, seq: i64, prev: Option<&str>, frontier: &[String], count: i64, head: Option<CanonValue>, anchor_with: Option<&SigningKey>) -> CanonValue {
    let key_block = CanonValue::parse(r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active"}"#).unwrap();
    let mut body = checkpoint_body(cid, "proj-001", seq, prev, frontier, count, "2026-06-15T10:10:00.000Z", key_block).unwrap();
    if let Some(h) = head {
        body = change_field(&body, "broker_grant_head", h);
    }
    let cp = seal_checkpoint(&body, rec_sk).unwrap();
    match anchor_with {
        Some(tsa) => {
            let anchor = make_test_anchor(&checkpoint_hash(&cp), "2026-06-15T10:10:01.000Z", tsa, "tsa-1");
            attach_anchor(&cp, anchor)
        }
        None => cp,
    }
}

#[test]
fn tier_b_broker_trust_stale_subset_head_is_violation() {
    // CRITICAL false-clean (found by BOTH reviewers): an attacker keeps a head only on an EARLIER
    // checkpoint covering a SUBSET of grants, and DROPS the head from the genuinely-latest checkpoint that
    // commits a later grant. The verifier MUST bind D6 to the latest checkpoint and reject this — else
    // grant-2 is suppressed from every grant head while broker_trust reads sequence_verified.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let g1 = seal_grant(&rec, &rec, "grant-1", &grant_evidence_d6("grant-1", 1));
    let g2 = seal_grant(&rec, &rec, "grant-2", &grant_evidence_d6("grant-2", 2));
    let (h1, h2) = (content_hash_of(&g1), content_hash_of(&g2));
    let mut both = vec![h1.clone(), h2.clone()];
    both.sort();
    // cp0: anchored, head over ONLY grant-1 (a subset)
    let cp0 = checkpoint_seqd(&rec, "cp0", 0, None, std::slice::from_ref(&h1), 1, Some(grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &h1)]))), Some(&tsa));
    let cp0h = checkpoint_hash(&cp0);
    // cp1 (LATEST): commits BOTH grants, but its head was DROPPED
    let cp1 = checkpoint_seqd(&rec, "cp1", 1, Some(&cp0h), &both, 2, None, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2], vec![cp0, cp1]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a dropped head on the latest checkpoint must FAIL (grant-2 would be hidden)");
    assert!(r.issues.iter().any(|i| i.contains("no broker_grant_head") || i.contains("dropped head")), "issues: {:?}", r.issues);
    assert_eq!(r.broker_trust, "assumed");
}

#[test]
fn tier_b_broker_trust_fraudulent_historical_head_is_violation() {
    // CRITICAL (Codex round-2): cp0's FRONTIER commits grants 1 AND 2 but cp0's head covers only grant 1
    // (a historical suppression); a later cp1 carries a correct FULL head chaining to cp0's fraudulent
    // root. Validating EACH head against its OWN frontier (not only the latest) must catch cp0's fraud.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let g1 = seal_grant(&rec, &rec, "grant-1", &grant_evidence_d6("grant-1", 1));
    let g2 = seal_grant(&rec, &rec, "grant-2", &grant_evidence_d6("grant-2", 2));
    let g3 = seal_grant(&rec, &rec, "grant-3", &grant_evidence_d6("grant-3", 3));
    let (h1, h2, h3) = (content_hash_of(&g1), content_hash_of(&g2), content_hash_of(&g3));
    let mut f01 = vec![h1.clone(), h2.clone()];
    f01.sort();
    let mut fall = vec![h1.clone(), h2.clone(), h3.clone()];
    fall.sort();
    // cp0: commits g1+g2 but a FRAUDULENT head over only g1
    let cp0 = checkpoint_seqd(&rec, "cp0", 0, None, &f01, 2, Some(grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &h1)]))), Some(&tsa));
    let cp0h = checkpoint_hash(&cp0);
    let cp0_root = ghr(&[(1, &h1)]); // cp0's fraudulent cumulative_root (chains forward to cp1)
    // cp1: latest, commits all 3, a CORRECT head chaining to cp0's fraudulent root
    let cp1 = checkpoint_seqd(&rec, "cp1", 1, Some(&cp0h), &fall, 3, Some(grant_head_cv(3, &cp0_root, &ghr(&[(1, &h1), (2, &h2), (3, &h3)]))), Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2, g3], vec![cp0, cp1]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a fraudulent historical head (covering a subset of its OWN frontier) must fail");
    assert!(r.issues.iter().any(|i| i.contains("seq 0") && (i.contains("max_seq") || i.contains("cumulative_root"))), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_broker_trust_seqless_broker_grant_is_violation() {
    // a REAL broker grant signed WITHOUT broker_seq, committed by the latest checkpoint, would be silently
    // dropped from the head's log (excluded from max_seq + cumulative_root) — must be a suppression
    // violation, not a clean pass (the per-head checks over the seq'd grants alone would otherwise hold).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let g1 = seal_grant(&rec, &rec, "grant-1", &grant_evidence_d6("grant-1", 1));
    let smuggled = seal_grant(&rec, &rec, "grant-x", &grant_evidence("grant-x", ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP)); // NO broker_seq
    let (h1, hx) = (content_hash_of(&g1), content_hash_of(&smuggled));
    let mut both = vec![h1.clone(), hx.clone()];
    both.sort();
    let head = grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &h1)])); // covers ONLY grant-1
    let cp = checkpoint_with_head(&rec, &both, 2, head, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, smuggled], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a committed broker grant with no broker_seq must fail (smuggled out of the log)");
    assert!(r.issues.iter().any(|i| i.contains("no broker_seq") || i.contains("smuggled")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_broker_trust_historical_headless_checkpoint_is_violation() {
    // CRITICAL (Codex round-3): an EARLIER verified checkpoint commits a D6 grant but carries NO head,
    // while a later checkpoint has a correct full head. The earlier checkpoint binds a grant into the
    // anchored chain WITHOUT a transparency head — must be flagged, not skipped.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let g1 = seal_grant(&rec, &rec, "grant-1", &grant_evidence_d6("grant-1", 1));
    let g2 = seal_grant(&rec, &rec, "grant-2", &grant_evidence_d6("grant-2", 2));
    let (h1, h2) = (content_hash_of(&g1), content_hash_of(&g2));
    let mut both = vec![h1.clone(), h2.clone()];
    both.sort();
    // cp0: verified, anchored, commits grant-1 but carries NO broker_grant_head
    let cp0 = checkpoint_seqd(&rec, "cp0", 0, None, std::slice::from_ref(&h1), 1, None, Some(&tsa));
    let cp0h = checkpoint_hash(&cp0);
    // cp1: latest, a correct full head (treated as head[0] since cp0 has none → prior == empty root)
    let cp1 = checkpoint_seqd(&rec, "cp1", 1, Some(&cp0h), &both, 2, Some(grant_head_cv(2, &ghr(&[]), &ghr(&[(1, &h1), (2, &h2)]))), Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2], vec![cp0, cp1]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a verified checkpoint committing D6 grants with no head must fail");
    assert!(r.issues.iter().any(|i| i.contains("no (well-formed) broker_grant_head")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_broker_trust_malformed_head_is_violation() {
    // Codex round-5: a checkpoint whose broker_grant_head FIELD is present but UNPARSEABLE (max_seq is a
    // string, not an int) is a tampered D6 head — pre-D6 checkpoints never carry the field. It must ACTIVATE
    // strict D6 and FAIL, never silently demote to a benign headless checkpoint that would let the committed
    // seq-less grant slip through the no-D6 early return.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP)); // NO broker_seq
    let gh = content_hash_of(&grant);
    let garbled = change_field(&grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &gh)])), "max_seq", CanonValue::string("not-an-int"));
    let cp = checkpoint_with_head(&rec, std::slice::from_ref(&gh), 1, garbled, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a present-but-malformed broker_grant_head must fail, not pass as assumed");
    assert!(r.issues.iter().any(|i| i.contains("malformed broker_grant_head")), "issues: {:?}", r.issues);
    assert_eq!(r.broker_trust, "assumed");
}

#[test]
fn tier_b_broker_trust_duplicate_checkpoint_is_not_a_fork() {
    // Codex round-5: validate_chain tolerates a byte-identical DUPLICATE checkpoint (idempotent re-export);
    // D6 must too. Before the cp_heads dedup, chaining the same head twice made the 2nd copy's prior_head_hash
    // mismatch the 1st copy's cumulative_root and fabricated a fork/restart — falsely rejecting a valid bundle.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    let head = grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &gh)]));
    let cp = checkpoint_with_head(&rec, std::slice::from_ref(&gh), 1, head, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp.clone(), cp]); // SAME checkpoint twice
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "a byte-identical duplicate checkpoint must not fabricate a fork: {:?}", r.issues);
    assert_eq!(r.broker_trust, "sequence_verified");
}

#[test]
fn tier_b_broker_trust_total_suppression_is_inherent_residual() {
    // INHERENT RESIDUAL (ADR 0004 D6): when EVERY committed broker grant is seq-less AND no checkpoint carries
    // a broker_grant_head, the bundle has ZERO D6 signal and is byte-indistinguishable from a pre-D6 export —
    // it verifies clean as `assumed`. This pins the all-or-nothing boundary: total log suppression is NOT
    // decidable offline (closing it would false-positive genuine pre-D6 bundles), so it is pushed to the
    // out-of-band monitor. Partial suppression (any one seq'd grant or any head) IS caught — see _seqless_
    // and _malformed_head_ tests.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let g1 = seal_grant(&rec, &rec, "grant-1", &grant_evidence("grant-1", ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let g2 = seal_grant(&rec, &rec, "grant-2", &grant_evidence("grant-2", ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let mut both = vec![content_hash_of(&g1), content_hash_of(&g2)];
    both.sort();
    let cp = checkpoint_over(&rec, &both, 2, Some(&tsa)); // NO head anywhere
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g1, g2], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "no D6 signal -> indistinguishable from pre-D6: {:?}", r.issues);
    assert_eq!(r.broker_trust, "assumed");
}

// ---- D6.4: credential-descriptor cross-check ----

// a broker grant carrying a credential_commit over the descriptor (so a credential disclosure can open it).
fn seal_grant_cred(rec_sk: &SigningKey, broker_sk: &SigningKey, record_id: &str, ge: &CanonValue, commitment: &str) -> CanonValue {
    let eh = sha256_prefixed(ge.serialize().as_bytes());
    let esig = sign_evidence("gateway_enforced", "proj-001", record_id, &eh, broker_sk);
    let action = ge.get("action").unwrap().as_str().unwrap();
    let body = format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{record_id}","project_id":"proj-001","agent_id":"agent","agent_version":"feir-broker",
        "session_id":"s","span_id":"sp-{record_id}","parent_span_id":null,"causal_prev_hashes":[],"display_seq":0,
        "agent_ts":"2026-06-15T10:00:00.000Z","received_ts":"2026-06-15T10:00:00.000Z",
        "event_type":"credential_grant","action":"{action}","observed_via":"broker","status":"ok",
        "authority":{{"source":"gateway_enforced","enforcement_point":"credential_broker","grant_type":"id-jag","grant_id":"{record_id}","evidence_hash":"{eh}","evidence_sig":"{esig}"}},
        "credential_commit":{{"alg":"sha256","commitment":"{commitment}","low_entropy":true}},
        "extensions":{{"broker":{{"kind":"grant","grant_evidence":{ge}}}}},
        "key":{{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}}}"#,
        ge = ge.serialize(),
    );
    seal(&CanonValue::parse(&body).unwrap(), rec_sk).unwrap()
}

// a credential descriptor carrying the 6 cross-checked fields (act/aud/jti/cnf/exp/single_use), cnf = the
// canonical base64url of a real ed25519 key so its derived kid can be compared to grant_evidence.cnf_kid.
fn cred_descriptor(cnf_vk: &VerifyingKey, act: &str, aud: &str, jti: &str, exp: i64, single_use: bool) -> CanonValue {
    // mirrors the producer's capability descriptor: every field the verifier cross-checks against the signed
    // grant_evidence (act/aud/jti/cnf/exp/single_use + scope/sub/iat/nbf) is present and matches by default.
    CanonValue::object(vec![
        ("act".into(), CanonValue::string(act)),
        ("aud".into(), CanonValue::string(aud)),
        ("cnf".into(), CanonValue::string(feir_decision_core::b64::encode(cnf_vk.as_bytes()))),
        ("exp".into(), CanonValue::Int(exp)),
        ("iat".into(), CanonValue::Int(ISSUED)),
        ("jti".into(), CanonValue::string(jti)),
        ("nbf".into(), CanonValue::Int(ISSUED)),
        ("scope".into(), CanonValue::string("read:orders")),
        ("single_use".into(), CanonValue::Bool(single_use)),
        ("sub".into(), CanonValue::string("agent-1")),
        ("typ".into(), CanonValue::string("capability")),
    ])
    .unwrap()
}

// grant_evidence for a single_operation grant carrying a caller-chosen credential_binding + cnf_kid, plus the
// scope + agent_id the producer signs (so the D6.4 scope/subject cross-check has a real label to compare).
fn cred_ge(cnf_kid: &str, binding: &str) -> CanonValue {
    let ge = grant_evidence(GID, ACTION, RESOURCE, "single_operation", cnf_kid, ISSUED, EXP);
    let ge = change_field(&ge, "credential_binding", CanonValue::string(binding));
    let ge = change_field(&ge, "scope", CanonValue::string("read:orders"));
    change_field(&ge, "agent_id", CanonValue::string("agent-1"))
}

// assemble a verified+closed broker grant that carries a credential_commit over `descriptor` (with the given
// grant_evidence labels) + the opening disclosure, anchored so the grant is closed.
fn cred_bundle(rec: &SigningKey, tsa: &SigningKey, descriptor: &CanonValue, ge: &CanonValue) -> CanonValue {
    let dbytes = descriptor.serialize();
    let nonce = [0x11u8; 32];
    let commitment = feir_decision_core::commit(feir_decision_core::FieldDomain::parse("credential").unwrap(), dbytes.as_bytes(), &nonce).unwrap();
    let grant = seal_grant_cred(rec, rec, GID, ge, &commitment);
    let gh = content_hash_of(&grant);
    let cp = checkpoint_over(rec, std::slice::from_ref(&gh), 1, Some(tsa));
    let disclosure = CanonValue::object(vec![
        ("record_id".into(), CanonValue::string(GID)),
        ("field".into(), CanonValue::string("credential")),
        ("value_b64".into(), CanonValue::string(feir_decision_core::b64::encode(dbytes.as_bytes()))),
        ("nonce_hex".into(), CanonValue::string(feir_decision_core::hashx::hex_lower(&nonce))),
    ])
    .unwrap();
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    change_field(&bundle, "disclosures", CanonValue::Array(vec![disclosure]))
}

#[test]
fn tier_b_cred_descriptor_match() {
    // happy path: the disclosed descriptor's act/aud/jti/cnf/exp/single_use all agree with the signed grant
    // labels and sha256(descriptor) == credential_binding -> cross-check passes (checks==matched==1).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let cnf = signing_key_from_seed(&[9u8; 32]);
    let kid = feir_decision_core::verify::cnf_kid(&cnf.verifying_key());
    let descriptor = cred_descriptor(&cnf.verifying_key(), ACTION, RESOURCE, GID, EXP, true);
    let binding = sha256_prefixed(descriptor.serialize().as_bytes());
    let bundle = cred_bundle(&rec, &tsa, &descriptor, &cred_ge(&kid, &binding));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "matching descriptor must verify clean: {:?}", r.issues);
    assert_eq!((r.cred_label_checks, r.cred_label_matched), (1, 1));
    assert_eq!(r.disclosures_verified, 1);
}

#[test]
fn tier_b_cred_descriptor_action_mismatch_is_violation() {
    // the broker discloses a descriptor whose `act` is BROADER than the benign single-op the grant LABELS —
    // binding still matches (it is the real descriptor) but the label contradicts it: broker mislabel (D6.4).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let cnf = signing_key_from_seed(&[9u8; 32]);
    let kid = feir_decision_core::verify::cnf_kid(&cnf.verifying_key());
    let descriptor = cred_descriptor(&cnf.verifying_key(), "db.admin:orders-rw", RESOURCE, GID, EXP, true); // act != label
    let binding = sha256_prefixed(descriptor.serialize().as_bytes());
    let bundle = cred_bundle(&rec, &tsa, &descriptor, &cred_ge(&kid, &binding));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "descriptor act contradicting the grant label must fail");
    assert!(r.issues.iter().any(|i| i.contains("broker mislabel/equivocation")), "issues: {:?}", r.issues);
    assert_eq!((r.cred_label_checks, r.cred_label_matched), (1, 0));
}

#[test]
fn tier_b_cred_descriptor_scope_mismatch_is_violation() {
    // Codex: the broker mints a credential with a BROADER `scope` than the grant LABELS — the hash still
    // matches credential_binding (it IS the minted credential) but the labeled scope lies. Must be a violation.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let cnf = signing_key_from_seed(&[9u8; 32]);
    let kid = feir_decision_core::verify::cnf_kid(&cnf.verifying_key());
    let descriptor = change_field(&cred_descriptor(&cnf.verifying_key(), ACTION, RESOURCE, GID, EXP, true), "scope", CanonValue::string("admin:*"));
    let binding = sha256_prefixed(descriptor.serialize().as_bytes());
    let bundle = cred_bundle(&rec, &tsa, &descriptor, &cred_ge(&kid, &binding));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a broader descriptor scope than the grant label must fail");
    assert!(r.issues.iter().any(|i| i.contains("scope") && i.contains("broker mislabel")), "issues: {:?}", r.issues);
    assert_eq!((r.cred_label_checks, r.cred_label_matched), (1, 0));
}

#[test]
fn tier_b_cred_descriptor_subject_mismatch_is_violation() {
    // Codex: the credential's `sub` (the bound agent) differs from the grant's agent_id — a credential minted
    // for a DIFFERENT subject than labeled (subject confusion). Must be a violation.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let cnf = signing_key_from_seed(&[9u8; 32]);
    let kid = feir_decision_core::verify::cnf_kid(&cnf.verifying_key());
    let descriptor = change_field(&cred_descriptor(&cnf.verifying_key(), ACTION, RESOURCE, GID, EXP, true), "sub", CanonValue::string("agent-evil"));
    let binding = sha256_prefixed(descriptor.serialize().as_bytes());
    let bundle = cred_bundle(&rec, &tsa, &descriptor, &cred_ge(&kid, &binding));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "a descriptor sub != grant agent_id must fail");
    assert!(r.issues.iter().any(|i| i.contains("sub") && i.contains("agent_id")), "issues: {:?}", r.issues);
    assert_eq!((r.cred_label_checks, r.cred_label_matched), (1, 0));
}

#[test]
fn tier_b_cred_descriptor_single_use_mismatch_is_violation() {
    // the core attack: a session/batch credential (single_use=false) labeled single_operation. The descriptor
    // is honestly broad; the label lies. Must be a violation.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let cnf = signing_key_from_seed(&[9u8; 32]);
    let kid = feir_decision_core::verify::cnf_kid(&cnf.verifying_key());
    let descriptor = cred_descriptor(&cnf.verifying_key(), ACTION, RESOURCE, GID, EXP, false); // single_use=false vs label single_operation
    let binding = sha256_prefixed(descriptor.serialize().as_bytes());
    let bundle = cred_bundle(&rec, &tsa, &descriptor, &cred_ge(&kid, &binding));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "single_use=false under a single_operation label must fail");
    assert!(r.issues.iter().any(|i| i.contains("single_use")), "issues: {:?}", r.issues);
    assert_eq!((r.cred_label_checks, r.cred_label_matched), (1, 0));
}

#[test]
fn tier_b_cred_descriptor_binding_mismatch_is_violation() {
    // the signed credential_binding (used by the PoP path) disagrees with the disclosed credential_commit's
    // descriptor: sha256(descriptor) != credential_binding -> wrong/forged descriptor (D6.4).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let cnf = signing_key_from_seed(&[9u8; 32]);
    let kid = feir_decision_core::verify::cnf_kid(&cnf.verifying_key());
    let descriptor = cred_descriptor(&cnf.verifying_key(), ACTION, RESOURCE, GID, EXP, true);
    let wrong_binding = sha256_prefixed(b"a-different-descriptor"); // != sha256(descriptor)
    let bundle = cred_bundle(&rec, &tsa, &descriptor, &cred_ge(&kid, &wrong_binding));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "descriptor sha256 != credential_binding must fail");
    assert!(r.issues.iter().any(|i| i.contains("!= grant_evidence.credential_binding")), "issues: {:?}", r.issues);
    assert_eq!((r.cred_label_checks, r.cred_label_matched), (1, 0));
}

#[test]
fn tier_b_cred_descriptor_absent_is_residual() {
    // RESIDUAL: with NO credential disclosure, the verifier cannot cross-check labels vs the minted credential
    // (cred_label_checks==0). The bundle still verifies; label↔credential fidelity rests on broker_trust (D6).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let cnf = signing_key_from_seed(&[9u8; 32]);
    let kid = feir_decision_core::verify::cnf_kid(&cnf.verifying_key());
    let descriptor = cred_descriptor(&cnf.verifying_key(), ACTION, RESOURCE, GID, EXP, true);
    let binding = sha256_prefixed(descriptor.serialize().as_bytes());
    // build the grant + commit but DO NOT disclose (strip the disclosures the helper adds).
    let bundle = cred_bundle(&rec, &tsa, &descriptor, &cred_ge(&kid, &binding));
    let bundle = change_field(&bundle, "disclosures", CanonValue::Array(vec![]));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "absent disclosure must still verify: {:?}", r.issues);
    assert_eq!((r.cred_label_checks, r.cred_label_matched), (0, 0));
}

// ---- D7: deployment-attestation evaluation ----

// the attestation window must cover checkpoint_with_head's make_test_anchor timestamp (2026-06-15T10:10:01Z).
const ATT_ISSUED: &str = "2026-06-15T00:00:00.000Z";
const ATT_NOT_AFTER: &str = "2026-06-16T00:00:00.000Z";

// a D6 grant + anchored checkpoint(head); returns (bundle without attestation, checkpoint_hash, head_root).
fn d6_anchored(rec: &SigningKey, tsa: &SigningKey) -> (CanonValue, String, String) {
    let grant = seal_grant(rec, rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    let head = grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &gh)]));
    let cp = checkpoint_with_head(rec, std::slice::from_ref(&gh), 1, head, Some(tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp.clone()]);
    (bundle, checkpoint_hash(&cp), ghr(&[(1, &gh)]))
}

// the honest subject that binds the d6_anchored bundle (broker=rec, resource=res, no taxonomy, no manifest).
fn honest_subject(rec: &SigningKey, res: &SigningKey, cph: &str, head_root: &str) -> CanonValue {
    CanonValue::object(vec![
        ("project_id".into(), CanonValue::string("proj-001")),
        ("coverage_manifest_digest".into(), CanonValue::string("")),
        ("checkpoint_hash".into(), CanonValue::string(cph)),
        ("broker_grant_head_root".into(), CanonValue::string(head_root)),
        ("authority_kids".into(), CanonValue::Array(vec![
            CanonValue::string(feir_decision_core::verify::cnf_kid(&rec.verifying_key())),
            CanonValue::string(feir_decision_core::verify::cnf_kid(&res.verifying_key())),
        ])),
        ("resource_ids".into(), CanonValue::Array(vec![CanonValue::string(RESOURCE)])),
    ])
    .unwrap()
}

fn attestation(issuer_kid: &str, issued: &str, not_after: &str, subject: CanonValue, attest_sk: &SigningKey) -> CanonValue {
    let body = CanonValue::object(vec![
        ("kind".into(), CanonValue::string("deployment_attestation")),
        ("issuer_kid".into(), CanonValue::string(issuer_kid)),
        ("issued_at".into(), CanonValue::string(issued)),
        ("not_after".into(), CanonValue::string(not_after)),
        ("claim_types".into(), CanonValue::Array(vec![
            CanonValue::string("sandbox_isolation"),
            CanonValue::string("egress_policy"),
            CanonValue::string("key_non_transferability"),
        ])),
        ("subject".into(), subject),
    ])
    .unwrap();
    let digest = sha256_prefixed(body.serialize().as_bytes());
    let sig = feir_decision_core::sign::sign("feir.attestation.v1", &digest, attest_sk);
    change_field(&body, "sig", CanonValue::string(sig))
}

fn attest_opts(rec: &SigningKey, res: &SigningKey, tsa: &SigningKey, attest: &SigningKey) -> VerifyOptions {
    let mut o = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    o.attestation_keys = vec![attest.verifying_key()];
    o
}

#[test]
fn tier_b_attestation_unevaluated_when_absent() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let (bundle, _, _) = d6_anchored(&rec, &tsa);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "{:?}", r.issues);
    assert_eq!(r.attestation_status, "unevaluated");
}

#[test]
fn tier_b_attestation_unevaluated_without_pinned_issuer() {
    // attestation PRESENT but no attestation_keys pinned -> the verifier cannot evaluate -> unevaluated
    // (NOT failed: an unpinned issuer is "we don't assess", never a violation).
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, ATT_NOT_AFTER, honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key())); // no attestation_keys
    assert!(r.ok, "{:?}", r.issues);
    assert_eq!(r.attestation_status, "unevaluated");
}

#[test]
fn tier_b_attestation_ignores_non_proven_injected_resource() {
    // F10: a non-proven (e.g. relay-appended) record carrying a bogus resource_id must NOT enter the
    // attestation/closure surface — otherwise it would force the D7 attestation to bind a resource it
    // never covered (denial-of-attestation). The integrity gate on the harvest excludes it.
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    // Append a TAMPERED grant whose grant_evidence names a bogus resource (the edited top-level field
    // breaks its content_hash, so it verifies as non-proven).
    let evil = seal_grant(&rec, &rec, "r-evil", &grant_evidence("g-evil", ACTION, "evil-resource", "single_operation", CNF, ISSUED, EXP));
    let evil = change_field(&evil, "agent_id", CanonValue::string("tampered"));
    let mut recs = arr(&bundle, "records");
    recs.push(evil);
    let bundle = change_field(&bundle, "records", CanonValue::Array(recs));
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, ATT_NOT_AFTER, honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert_eq!(
        r.attestation_status, "attested_claims",
        "a non-proven injected resource must not pollute the attestation surface (F10); issues: {:?}",
        r.issues
    );
}

#[test]
fn tier_b_attestation_attested_claims() {
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, ATT_NOT_AFTER, honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(r.ok, "a matching fresh pinned-issuer attestation must verify: {:?}", r.issues);
    assert_eq!(r.attestation_status, "attested_claims");
    assert_eq!(r.attestation_issuer_kid.as_deref(), Some(feir_decision_core::verify::cnf_kid(&attest.verifying_key()).as_str()));
    assert!(r.attestation_claim_types.contains(&"sandbox_isolation".to_string()));
    assert!(r.attestation_subject_digest.is_some());
}

#[test]
fn tier_b_attestation_attested_claims_with_pinned_taxonomy() {
    // REGRESSION (D7.2): pinning a taxonomy issuer (the normal D4/D8 auditor posture) must NOT change the
    // attestation's authority_kids expectation. authority_kids binds the GRANT/USE authorities
    // (broker+resource) only; the taxonomy is a separate verifier-pinned artifact the producer never holds.
    // Folding taxonomy_keys into the compared kid set would force a spurious authority_kids mismatch -> failed.
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let tax = signing_key_from_seed(&[13u8; 32]); // disjoint from broker/resource/attest/tsa
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, ATT_NOT_AFTER, honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let mut opts = attest_opts(&rec, &res, &tsa, &attest);
    opts.taxonomy_keys = vec![tax.verifying_key()]; // auditor ALSO pins a taxonomy issuer
    let r = verify_bundle_with(&bundle, &opts);
    assert_eq!(r.attestation_status, "attested_claims", "pinning a taxonomy issuer must not break the attestation authority_kids match: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_bad_sig_is_failed() {
    // signed by a key that is NOT the pinned issuer -> sig does not verify -> failed (not unevaluated).
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let wrong = signing_key_from_seed(&[12u8; 32]);
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, ATT_NOT_AFTER, honest_subject(&rec, &res, &cph, &head_root), &wrong);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok, "a bad-signature attestation must fail the bundle");
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("sig does not verify")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_issuer_kid_mismatch_is_failed() {
    // sig verifies under the pinned issuer, but the CLAIMED issuer_kid names a different key.
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let att = attestation("ed25519-WrongKid0", ATT_ISSUED, ATT_NOT_AFTER, honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok);
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("issuer_kid does not match")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_stale_window_is_failed() {
    // the anchored checkpoint time falls OUTSIDE [issued_at, not_after] -> stale/not-covering.
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    // window ends BEFORE the anchored ts (ANCHOR_TS = 2026-06-15T10:10:01Z)
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), "2026-06-14T00:00:00.000Z", "2026-06-15T00:00:00.000Z", honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok);
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("outside the attestation window")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_subject_substitution_is_failed() {
    // CRITICAL (ADR 0004 D7 substitution test): a VALID, FRESH, PINNED-ISSUER attestation whose subject
    // names a DIFFERENT project must NOT pass — else an attestation for another deployment is replayable.
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let mut subject = honest_subject(&rec, &res, &cph, &head_root);
    subject = change_field(&subject, "project_id", CanonValue::string("proj-OTHER")); // signed, but wrong deployment
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, ATT_NOT_AFTER, subject, &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok, "a fresh valid attestation for a DIFFERENT subject must not pass");
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("substitution/replay") && i.contains("project_id")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_checkpoint_substitution_is_failed() {
    // subject names a different (wrong) checkpoint_hash -> substitution -> failed.
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, _cph, head_root) = d6_anchored(&rec, &tsa);
    let subject = honest_subject(&rec, &res, "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", &head_root);
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, ATT_NOT_AFTER, subject, &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok);
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("checkpoint_hash")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_keys_overlapping_broker_is_fatal() {
    // role separation: the attestation authority must be disjoint from broker/resource/taxonomy keys, else
    // a broker could self-attest. A shared key is a FATAL config error.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let (bundle, _, _) = d6_anchored(&rec, &tsa);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.attestation_keys = vec![rec.verifying_key()]; // == broker key
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok);
    assert!(r.issues.iter().any(|i| i.contains("attestation_keys") && i.contains("must be disjoint")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_keys_overlapping_tsa_is_fatal() {
    // the TSA mints the freshness timestamp the attestation window is anchored to; a key that is BOTH the
    // TSA and the attestation authority could self-mint a timestamp inside its own window -> fatal.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let (bundle, _, _) = d6_anchored(&rec, &tsa);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.attestation_keys = vec![tsa.verifying_key()]; // == TSA key
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok);
    assert!(r.issues.iter().any(|i| i.contains("trusted_tsa_keys") && i.contains("must be disjoint")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_empty_window_is_failed() {
    // a MISSING/empty issued_at would silently drop the LOWER freshness bound (open-ended backdating);
    // both bounds must be present, else the attestation is failed (not attested_claims).
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), "", ATT_NOT_AFTER, honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok, "an empty issued_at must fail (no bounded window)");
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("no bounded freshness window")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_malformed_window_is_failed() {
    // Codex: a non-empty but MALFORMED bound ("0".."z") sorts lexicographically around a real anchor
    // timestamp and would pass the window comparison — require canonical YYYY-MM-DDThh:mm:ss.mmmZ bounds.
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), "0", "z", honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok, "a malformed non-empty window must fail");
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("not canonical timestamps")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_shape_valid_but_impossible_window_is_failed() {
    // Codex round-2: a bound that PASSES the 24-char shape but names an impossible date/time
    // (2026-99-99T99:99:99.999Z) must be rejected — is_canonical_ts validates field RANGES, not just shape.
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let (bundle, cph, head_root) = d6_anchored(&rec, &tsa);
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, "2026-99-99T99:99:99.999Z", honest_subject(&rec, &res, &cph, &head_root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok, "a shape-valid but out-of-range window must fail");
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("not canonical timestamps")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_attestation_stale_anchored_replayed_on_later_bundle_is_failed() {
    // Codex: an attestation bound to the latest ANCHORED checkpoint (cp0) must NOT pass when a LATER verified
    // checkpoint (cp1, unanchored) has extended the bundle beyond it — the attestation does not cover the
    // bundle's true frontier (old anchored attestation replayed onto a later, unanchored-tail bundle).
    let (rec, res, tsa, attest) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[11u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    let root = ghr(&[(1, &gh)]);
    // cp0: seq 0, anchored, head over grant-1
    let cp0 = checkpoint_seqd(&rec, "cp0", 0, None, std::slice::from_ref(&gh), 1, Some(grant_head_cv(1, &ghr(&[]), &root)), Some(&tsa));
    let cp0h = checkpoint_hash(&cp0);
    // cp1: seq 1, UNANCHORED, head chains from cp0 over the same frontier
    let cp1 = checkpoint_seqd(&rec, "cp1", 1, Some(&cp0h), std::slice::from_ref(&gh), 1, Some(grant_head_cv(1, &root, &root)), None);
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp0, cp1]);
    // the attestation honestly binds cp0 (the latest ANCHORED) — but cp1 sits beyond it.
    let att = attestation(&feir_decision_core::verify::cnf_kid(&attest.verifying_key()), ATT_ISSUED, ATT_NOT_AFTER, honest_subject(&rec, &res, &cp0h, &root), &attest);
    let bundle = change_field(&bundle, "deployment_attestation", att);
    let r = verify_bundle_with(&bundle, &attest_opts(&rec, &res, &tsa, &attest));
    assert!(!r.ok, "an attestation that does not cover a later checkpoint must fail");
    assert_eq!(r.attestation_status, "failed");
    assert!(r.issues.iter().any(|i| i.contains("does not cover the bundle frontier")), "issues: {:?}", r.issues);
}

// ---- D5: two-phase intent/outcome gateway ----

// a grant + intent (record_id "intent-1") + (optional) outcome, DAG-linked and anchored. Returns the bundle.
fn two_phase_bundle(rec: &SigningKey, res: &SigningKey, tsa: &SigningKey, outcome: Option<CanonValue>) -> CanonValue {
    let grant = seal_grant(rec, rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let gh = content_hash_of(&grant);
    let intent = seal_intent(rec, res, "intent-1", std::slice::from_ref(&gh), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let ih = content_hash_of(&intent);
    match outcome {
        Some(o) => {
            let oh = content_hash_of(&o);
            let cp = checkpoint_over(rec, std::slice::from_ref(&oh), 3, Some(tsa));
            tier_b_bundle(&rec.verifying_key(), vec![grant, intent, o], vec![cp])
        }
        None => {
            let cp = checkpoint_over(rec, std::slice::from_ref(&ih), 2, Some(tsa));
            tier_b_bundle(&rec.verifying_key(), vec![grant, intent], vec![cp])
        }
    }
}

// the intent's content_hash, for an outcome's causal_prev_hashes (so the outcome is the DAG head).
fn intent_hash(rec: &SigningKey, res: &SigningKey) -> String {
    let grant = seal_grant(rec, rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let gh = content_hash_of(&grant);
    content_hash_of(&seal_intent(rec, res, "intent-1", std::slice::from_ref(&gh), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED)))
}

#[test]
fn tier_b_two_phase_complete_pair_matches() {
    // intent + matching outcome -> a complete two-phase use: counted, no anomaly.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let ih = intent_hash(&rec, &res);
    let outcome = seal_outcome(&rec, &res, "outcome-1", std::slice::from_ref(&ih), "intent-1", "intent-1", GID);
    let bundle = two_phase_bundle(&rec, &res, &tsa, Some(outcome));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "a complete two-phase pair must verify clean: {:?}", r.issues);
    assert_eq!((r.uses_matched, r.intent_without_outcome), (1, 0));
}

#[test]
fn tier_b_two_phase_intent_without_outcome_is_anomaly() {
    // a closed intent with NO outcome -> intent_without_outcome (the crash-after-act case): surfaced, NOT a
    // violation, NOT counted as matched, and does not consume the single-use grant.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let bundle = two_phase_bundle(&rec, &res, &tsa, None);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "a recorded intent without outcome is an anomaly, not a violation: {:?}", r.issues);
    assert_eq!((r.uses_matched, r.intent_without_outcome), (0, 1));
}

#[test]
fn tier_b_one_phase_use_still_matches() {
    // back-compat (ADR 0003): a one-phase `use` is still accepted + counted (it just cannot reach the D8
    // capstone). No intent_without_outcome anomaly.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let gh = content_hash_of(&grant);
    let use_rec = seal_use(&rec, &res, "use-1", std::slice::from_ref(&gh), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let uh = content_hash_of(&use_rec);
    let cp = checkpoint_over(&rec, std::slice::from_ref(&uh), 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "a one-phase use must still verify: {:?}", r.issues);
    assert_eq!((r.uses_matched, r.intent_without_outcome), (1, 0));
}

#[test]
fn tier_b_two_phase_mismatched_intent_ref_does_not_complete() {
    // a valid outcome that references a DIFFERENT (phantom) intent does not complete the real intent ->
    // intent_without_outcome (pairing is by the signed intent_ref == the intent's record_id).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let ih = intent_hash(&rec, &res);
    let outcome = seal_outcome(&rec, &res, "outcome-1", std::slice::from_ref(&ih), "intent-PHANTOM", "intent-PHANTOM", GID);
    let bundle = two_phase_bundle(&rec, &res, &tsa, Some(outcome));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert_eq!((r.uses_matched, r.intent_without_outcome), (0, 1), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_two_phase_unsigned_sibling_intent_ref_does_not_complete() {
    // Codex + finder: the verifier MUST join on the SIGNED use_outcome.intent_ref, not the unsigned sibling
    // extensions.broker.intent_ref. Here the resource signed a payload referencing a PHANTOM intent, but the
    // sibling points at the real intent-1 (as a relay holding the record key would forge). The intent must
    // NOT complete — proving the join key is bound to the resource authority signature.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let ih = intent_hash(&rec, &res);
    let outcome = seal_outcome(&rec, &res, "outcome-1", std::slice::from_ref(&ih), "intent-PHANTOM", "intent-1", GID); // signed!=sibling
    let bundle = two_phase_bundle(&rec, &res, &tsa, Some(outcome));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert_eq!((r.uses_matched, r.intent_without_outcome), (0, 1), "the unsigned sibling intent_ref must NOT complete the intent: {:?}", r.issues);
}

#[test]
fn tier_b_two_phase_outcome_for_other_grant_does_not_complete() {
    // finding #3: an outcome that attests a DIFFERENT grant_id than the intent's must not complete it
    // (the join binds intent_ref AND grant_id).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let ih = intent_hash(&rec, &res);
    let outcome = seal_outcome(&rec, &res, "outcome-1", std::slice::from_ref(&ih), "intent-1", "intent-1", "grant-OTHER"); // wrong grant
    let bundle = two_phase_bundle(&rec, &res, &tsa, Some(outcome));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert_eq!((r.uses_matched, r.intent_without_outcome), (0, 1), "an outcome for a different grant must not complete the intent: {:?}", r.issues);
}

#[test]
fn tier_b_two_phase_orphan_outcome_is_violation() {
    // Codex round-2: a valid resource-signed use_outcome with NO matching use_intent is a completion with NO
    // anchored pre-action intent (the resource skipped the before-act recording two-phase exists to require).
    // An outcome-only bundle must NOT read clean.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let gh = content_hash_of(&grant);
    let outcome = seal_outcome(&rec, &res, "outcome-1", std::slice::from_ref(&gh), "intent-1", "intent-1", GID);
    let oh = content_hash_of(&outcome);
    let cp = checkpoint_over(&rec, std::slice::from_ref(&oh), 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, outcome], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok, "an orphan outcome (no recorded intent) must be a violation");
    assert!(r.issues.iter().any(|i| i.contains("completion without a recorded intent")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_two_phase_outcome_signed_payload_wrong_kind_is_violation() {
    // Codex round-2: the SIGNED use_outcome payload must itself assert kind="use_outcome" — the role
    // discriminator that routed it here is the UNSIGNED sibling. A relabeled signed payload (kind="use")
    // must NOT complete the intent and must be flagged.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let ih = intent_hash(&rec, &res);
    let outcome = seal_outcome_k(&rec, &res, "outcome-1", std::slice::from_ref(&ih), "use", "intent-1", "intent-1", GID); // signed kind != use_outcome
    let bundle = two_phase_bundle(&rec, &res, &tsa, Some(outcome));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert_eq!((r.uses_matched, r.intent_without_outcome), (0, 1), "a wrong-kind signed payload must not complete: {:?}", r.issues);
    assert!(!r.ok && r.issues.iter().any(|i| i.contains("missing kind=use_outcome")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_two_phase_duplicate_outcomes_account_separately() {
    // Codex round-3: two closed validated outcomes for the SAME intent_ref — one attesting the right grant,
    // one a WRONG grant — must each account independently REGARDLESS of record order (no last-write-wins
    // collapse): the right-grant outcome completes the intent, the wrong-grant one is an orphan violation.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let gh = content_hash_of(&grant);
    let intent = seal_intent(&rec, &res, "intent-1", std::slice::from_ref(&gh), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let ih = content_hash_of(&intent);
    let ok_outcome = seal_outcome(&rec, &res, "outcome-ok", std::slice::from_ref(&ih), "intent-1", "intent-1", GID);
    let bad_outcome = seal_outcome(&rec, &res, "outcome-bad", std::slice::from_ref(&ih), "intent-1", "intent-1", "grant-OTHER");
    let mut frontier = vec![content_hash_of(&ok_outcome), content_hash_of(&bad_outcome)];
    frontier.sort();
    let orders = [
        vec![grant.clone(), intent.clone(), ok_outcome.clone(), bad_outcome.clone()],
        vec![grant.clone(), intent.clone(), bad_outcome.clone(), ok_outcome.clone()],
    ];
    for order in orders {
        let cp = checkpoint_over(&rec, &frontier, 4, Some(&tsa));
        let bundle = tier_b_bundle(&rec.verifying_key(), order, vec![cp]);
        let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
        assert_eq!((r.uses_matched, r.intent_without_outcome), (1, 0), "the right-grant outcome must complete regardless of order: {:?}", r.issues);
        assert!(!r.ok && r.issues.iter().any(|i| i.contains("outcome-bad") && i.contains("completion without a recorded intent")), "the wrong-grant outcome must be flagged orphan: {:?}", r.issues);
    }
}

#[test]
fn tier_b_two_phase_outcome_not_after_intent_does_not_complete() {
    // Codex round-4: the outcome must causally FOLLOW the intent (the before-act guarantee). Here the outcome
    // links to the GRANT, not the intent, so there is no causal edge intent->outcome (an unordered/backfilled
    // pair). It must NOT complete the intent; the outcome is an orphan.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let gh = content_hash_of(&grant);
    let intent = seal_intent(&rec, &res, "intent-1", std::slice::from_ref(&gh), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let ih = content_hash_of(&intent);
    let outcome = seal_outcome(&rec, &res, "outcome-1", std::slice::from_ref(&gh), "intent-1", "intent-1", GID); // prev = grant, NOT intent
    let oh = content_hash_of(&outcome);
    let mut frontier = vec![ih, oh]; // intent + outcome are separate DAG heads
    frontier.sort();
    let cp = checkpoint_over(&rec, &frontier, 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, intent, outcome], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert_eq!((r.uses_matched, r.intent_without_outcome), (0, 1), "an outcome not causally after the intent must not complete: {:?}", r.issues);
    assert!(!r.ok && r.issues.iter().any(|i| i.contains("completion without a recorded intent")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_two_phase_failed_pop_intent_does_not_consume_outcome() {
    // Codex round-4: an intent that PICKS its outcome but then FAILS pop_reverify must NOT consume the
    // outcome (consume only AFTER all acceptance checks) — else a failed-PoP intent would mask a validated
    // outcome from orphan accounting. The carried cnf_pub's kid != the use_evidence.cnf_kid -> PoP fails.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let cnf = signing_key_from_seed(&[9u8; 32]);
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let gh = content_hash_of(&grant);
    let ue = change_field(
        &change_field(&use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED), "cnf_pub", CanonValue::string(b64enc(cnf.verifying_key().as_bytes()))),
        "use_sig", CanonValue::string(b64enc(&[7u8; 64])),
    );
    let intent = seal_intent(&rec, &res, "intent-1", std::slice::from_ref(&gh), ACTION, &ue);
    let ih = content_hash_of(&intent);
    let outcome = seal_outcome(&rec, &res, "outcome-1", std::slice::from_ref(&ih), "intent-1", "intent-1", GID);
    let oh = content_hash_of(&outcome);
    let cp = checkpoint_over(&rec, std::slice::from_ref(&oh), 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, intent, outcome], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(!r.ok && r.uses_matched == 0, "a failed-PoP intent is a violation: {:?}", r.issues);
    assert!(r.issues.iter().any(|i| i.contains("PoP re-verification")) && r.issues.iter().any(|i| i.contains("completion without a recorded intent")), "the failed-PoP intent's outcome must be flagged orphan, not masked: {:?}", r.issues);
}

#[test]
fn tier_b_two_phase_backfilled_causal_edge_does_not_complete() {
    // Codex round-5: the before-act ordering must be bound to the RESOURCE signature, not the relay-controlled
    // top-level causal_prev_hashes. Here the resource-signed payload's intent_hash names a DIFFERENT intent,
    // but the record-signing key (a relay) BACKFILLED the top-level causal_prev to point at the real intent.
    // The SIGNED binding must govern -> the intent does NOT complete (the relay cannot forge the ordering).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP));
    let gh = content_hash_of(&grant);
    let intent = seal_intent(&rec, &res, "intent-1", std::slice::from_ref(&gh), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let ih = content_hash_of(&intent);
    let wrong_hash = sha256_prefixed(b"a-different-intent"); // the resource signed THIS, not the real intent
    // top-level prev is backfilled to the REAL intent hash, but the signed intent_hash is wrong.
    let outcome = seal_outcome_full(&rec, &res, "outcome-1", std::slice::from_ref(&ih), "use_outcome", "intent-1", "intent-1", GID, &wrong_hash);
    let oh = content_hash_of(&outcome);
    let cp = checkpoint_over(&rec, std::slice::from_ref(&oh), 3, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, intent, outcome], vec![cp]);
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert_eq!((r.uses_matched, r.intent_without_outcome), (0, 1), "a backfilled top-level edge must not complete when the SIGNED intent_hash differs: {:?}", r.issues);
    assert!(!r.ok && r.issues.iter().any(|i| i.contains("completion without a recorded intent")), "the backfilled outcome is an orphan: {:?}", r.issues);
}

#[test]
fn tier_b_two_phase_forged_outcome_does_not_complete() {
    // an outcome whose evidence is signed by a NON-resource key (forged) is not authority-verified, so it
    // cannot complete the intent -> intent_without_outcome (fail-closed). uses_matched stays 0.
    let (rec, res, tsa, forge) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]), signing_key_from_seed(&[88u8; 32]));
    let ih = intent_hash(&rec, &res);
    let outcome = seal_outcome(&rec, &forge, "outcome-1", std::slice::from_ref(&ih), "intent-1", "intent-1", GID); // forged auth
    let bundle = two_phase_bundle(&rec, &res, &tsa, Some(outcome));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert_eq!((r.uses_matched, r.intent_without_outcome), (0, 1), "a forged outcome must not complete an intent: {:?}", r.issues);
    // a closed-but-unauthorized use_outcome is itself a Tier-B violation (not a silently-ignored record).
    assert!(!r.ok && r.issues.iter().any(|i| i.contains("use_outcome") && i.contains("not validatable")), "issues: {:?}", r.issues);
}

// ---- M6 (ADR 0005): Cosig / M-of-N grant approval (dual control at issuance) ----

// a role-separated approver signing key (disjoint from rec/res/tsa seeds, which are 0/3/200).
fn approver(seed: u8) -> SigningKey {
    signing_key_from_seed(&[seed; 32])
}

// build a single_operation grant DECLARING cosig_threshold=M and carrying one cosignature per signer. Each
// signer signs the real feir.broker.cosig.approval.v1 challenge (grant_id/its-kid/credential_binding/M/exp),
// so the cosignatures are integrity-bound inside the signed grant_evidence (additive: an old verifier ignores
// them and the evidence_hash still re-derives).
fn cosigned_grant(rec: &SigningKey, threshold: i64, signers: &[&SigningKey]) -> CanonValue {
    cosigned_grant_rid(rec, GID, threshold, signers)
}

// as above but with an explicit record_id, so two records can share one grant_id with distinct content_hash
// (to exercise the F8 equivocation × cosig interaction). The cosig challenge always binds the grant_id (GID).
fn cosigned_grant_rid(rec: &SigningKey, record_id: &str, threshold: i64, signers: &[&SigningKey]) -> CanonValue {
    let cb = sha256_prefixed(b"test-credential-binding"); // the binding grant_evidence() embeds
    let cosigs: Vec<CanonValue> = signers
        .iter()
        .map(|sk| {
            let kid = cnf_kid(&sk.verifying_key());
            let challenge = cosig_approval_challenge(GID, &kid, &cb, threshold, EXP);
            let sig = feir_decision_core::b64::encode(&sk.sign(&challenge).to_bytes());
            CanonValue::object(vec![
                ("approver_kid".into(), CanonValue::string(kid)),
                ("sig".into(), CanonValue::string(sig)),
            ])
            .unwrap()
        })
        .collect();
    let ge = grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP);
    let ge = change_field(&ge, "cosig_threshold", CanonValue::Int(threshold));
    let ge = change_field(&ge, "cosignatures", CanonValue::Array(cosigs));
    seal_grant(rec, rec, record_id, &ge)
}

#[test]
fn tier_b_cosig_threshold_met_verifies() {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let (a1, a2) = (approver(40), approver(41));
    let grant = cosigned_grant(&rec, 2, &[&a1, &a2]);
    let gh = content_hash_of(&grant);
    let use_rec = seal_use(&rec, &res, "use-1", &[gh], ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.cosig_approver_keys = vec![a1.verifying_key(), a2.verifying_key()];
    let r = verify_bundle_with(&bundle, &opts);
    assert!(r.ok, "a 2-of-2 cosigned grant must verify; issues: {:?}", r.issues);
    assert_eq!(r.cosigned_grants_total, 1);
    assert_eq!(r.cosigned_grants_satisfied, 1);
    assert_eq!(r.cosig_threshold_failures, 0);
    assert_eq!(r.cosig_status, "satisfied");
    assert_eq!(r.uses_matched, 1, "the use joins the cosig-approved grant");
    let json = report_to_json(&r);
    for field in [
        r#""cosigned_grants_total":1"#,
        r#""cosigned_grants_satisfied":1"#,
        r#""cosig_threshold_failures":0"#,
        r#""cosig_status":"satisfied""#,
    ] {
        assert!(json.contains(field), "report JSON missing {field}: {json}");
    }
}

#[test]
fn tier_b_cosig_below_threshold_is_a_violation() {
    // a 2-of-N grant with only ONE valid approver is NOT Tier-B-eligible: the grant is not indexed, so its
    // use reads as an unmatched_violation (fail-closed).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let (a1, a2) = (approver(40), approver(41));
    let grant = cosigned_grant(&rec, 2, &[&a1]); // only one of two required approvers signed
    let gh = content_hash_of(&grant);
    let use_rec = seal_use(&rec, &res, "use-1", &[gh], ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.cosig_approver_keys = vec![a1.verifying_key(), a2.verifying_key()];
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "a grant short of its cosig threshold must not verify");
    assert_eq!(r.cosigned_grants_total, 1);
    assert_eq!(r.cosigned_grants_satisfied, 0);
    assert_eq!(r.cosig_threshold_failures, 1);
    assert_eq!(r.cosig_status, "unsatisfied");
    assert_eq!(r.uses_matched, 0, "the use cannot join an un-indexed grant");
    assert!(r.unmatched_violation >= 1, "the use is an unmatched violation: {:?}", r.issues);
    assert!(r.issues.iter().any(|i| i.contains("cosig threshold not met")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_cosig_duplicate_approver_counts_once() {
    // one approver signing twice must NOT inflate a 2-of-N threshold (distinct-key dedup).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let (a1, a2) = (approver(40), approver(41));
    let grant = cosigned_grant(&rec, 2, &[&a1, &a1]); // a1 twice -> one distinct approver
    let cp = checkpoint_over(&rec, &[content_hash_of(&grant)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.cosig_approver_keys = vec![a1.verifying_key(), a2.verifying_key()];
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "one approver signing twice must not satisfy a 2-of-N threshold");
    assert_eq!(r.cosig_threshold_failures, 1, "no threshold inflation");
    assert_eq!(r.cosigned_grants_satisfied, 0);
    assert_eq!(r.cosig_status, "unsatisfied");
}

#[test]
fn tier_b_cosig_forged_signature_does_not_count() {
    // an entry claiming approver a1's kid but signed by a DIFFERENT key must not count (the kid only selects
    // a candidate; acceptance still requires a real signature by that exact pinned key).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let (a1, imposter) = (approver(40), approver(99));
    let cb = sha256_prefixed(b"test-credential-binding");
    let a1_kid = cnf_kid(&a1.verifying_key());
    let challenge = cosig_approval_challenge(GID, &a1_kid, &cb, 1, EXP);
    let forged_sig = feir_decision_core::b64::encode(&imposter.sign(&challenge).to_bytes());
    let cosig = CanonValue::object(vec![
        ("approver_kid".into(), CanonValue::string(a1_kid)),
        ("sig".into(), CanonValue::string(forged_sig)),
    ])
    .unwrap();
    let ge = change_field(
        &change_field(&grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP), "cosig_threshold", CanonValue::Int(1)),
        "cosignatures",
        CanonValue::Array(vec![cosig]),
    );
    let grant = seal_grant(&rec, &rec, GID, &ge);
    let cp = checkpoint_over(&rec, &[content_hash_of(&grant)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.cosig_approver_keys = vec![a1.verifying_key()];
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "a forged cosignature must not satisfy the threshold");
    assert_eq!(r.cosig_threshold_failures, 1);
    assert_eq!(r.cosig_status, "unsatisfied");
}

#[test]
fn tier_b_cosig_approver_overlapping_a_role_is_fatal() {
    // an approver key that is ALSO the broker key collapses dual control to single control -> FATAL config
    // error (the R2 disjointness extension), aborting before any record is evaluated.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = cosigned_grant(&rec, 1, &[&approver(40)]);
    let cp = checkpoint_over(&rec, &[content_hash_of(&grant)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant], vec![cp]);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.cosig_approver_keys = vec![rec.verifying_key()]; // == broker_authority_keys -> overlap
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "an approver key overlapping the broker role is a fatal config error");
    assert!(
        r.issues.iter().any(|i| i.contains("cosig_approver_keys") && i.contains("disjoint")),
        "issues: {:?}",
        r.issues
    );
}

#[test]
fn tier_b_cosig_unpinned_approvers_fail_closed() {
    // a validly-cosigned grant whose approver keys the verifier did NOT pin counts zero approvals -> the grant
    // is not indexed (fail-closed: the governance keys must be pinned to trust the governance).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = cosigned_grant(&rec, 1, &[&approver(40)]);
    let gh = content_hash_of(&grant);
    let use_rec = seal_use(&rec, &res, "use-1", &[gh], ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()); // NO cosig_approver_keys
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "a cosigned grant with no pinned approvers must fail closed");
    assert_eq!(r.cosig_threshold_failures, 1);
    assert_eq!(r.cosigned_grants_satisfied, 0);
    assert_eq!(r.uses_matched, 0);
}

#[test]
fn tier_b_cosig_cosignatures_without_threshold_fails_closed() {
    // a grant carrying cosignatures but NO positive cosig_threshold is a malformed cosig declaration — it must
    // NOT be silently demoted to an ordinary grant (which would lose dual control). Fail-closed: not indexed.
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let a1 = approver(40);
    let cb = sha256_prefixed(b"test-credential-binding");
    let kid = cnf_kid(&a1.verifying_key());
    // threshold=1 used only to forge a well-formed-looking cosignature; the grant_evidence omits the threshold.
    let sig = feir_decision_core::b64::encode(&a1.sign(&cosig_approval_challenge(GID, &kid, &cb, 1, EXP)).to_bytes());
    let cosig = CanonValue::object(vec![
        ("approver_kid".into(), CanonValue::string(kid)),
        ("sig".into(), CanonValue::string(sig)),
    ])
    .unwrap();
    // grant_evidence with cosignatures but NO cosig_threshold field.
    let ge = change_field(
        &grant_evidence(GID, ACTION, RESOURCE, "single_operation", CNF, ISSUED, EXP),
        "cosignatures",
        CanonValue::Array(vec![cosig]),
    );
    let grant = seal_grant(&rec, &rec, GID, &ge);
    let gh = content_hash_of(&grant);
    let use_rec = seal_use(&rec, &res, "use-1", &[gh], ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.cosig_approver_keys = vec![a1.verifying_key()];
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "cosignatures without a positive threshold must fail closed");
    assert_eq!(r.uses_matched, 0, "the malformed grant must not be indexed");
    assert!(r.issues.iter().any(|i| i.contains("malformed cosig declaration")), "issues: {:?}", r.issues);
}

#[test]
fn tier_b_cosig_equivocating_sibling_is_still_rejected() {
    // F8 × cosig: a grant_id bound to two distinct records — one cosig-FAILED, one cosig-SATISFIED — is still
    // equivocation, so the bundle is rejected even though the satisfied sibling would otherwise index the grant.
    // (F8 injectivity now runs in the un-gated grant-counting pass, BEFORE any cosig/accounting logic, so the
    // cosig gate's `continue` can never skip the equivocation flag — this just confirms the two compose.)
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let (a1, a2) = (approver(40), approver(41));
    let g_fail = cosigned_grant_rid(&rec, "rec-A", 2, &[&a1]); // 1-of-2 -> fails the threshold
    let g_ok = cosigned_grant_rid(&rec, "rec-B", 2, &[&a1, &a2]); // 2-of-2 -> satisfied
    let mut frontier = vec![content_hash_of(&g_fail), content_hash_of(&g_ok)];
    frontier.sort();
    let cp = checkpoint_over(&rec, &frontier, 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![g_fail, g_ok], vec![cp]);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.cosig_approver_keys = vec![a1.verifying_key(), a2.verifying_key()];
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "an equivocated cosigned grant_id must reject the bundle regardless of the satisfied sibling");
    assert!(
        r.issues.iter().any(|i| i.contains("equivocated credential identity")),
        "issues: {:?}",
        r.issues
    );
}

#[test]
fn tier_b_cosig_threshold_above_u32_is_not_truncated() {
    // wasm32 fail-open guard (adversarial-review finding): the satisfaction test must compare in i64, not
    // `cosig_threshold as usize`. A broker-signed cosig_threshold of 2^32+1 truncates to 1 under a 32-bit
    // usize (the wasm/browser verifier), so the OLD code let a single approver satisfy it (1 >= 1) and index
    // a sub-threshold grant -> ok:true. With one approver and threshold 2^32+1 the grant MUST read as
    // unsatisfied. On 64-bit this passes with or without the fix (it documents the contract); on wasm32 it is
    // load-bearing (the truncated threshold is exactly 1).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let a1 = approver(40);
    let grant = cosigned_grant(&rec, 4_294_967_297, &[&a1]); // 2^32 + 1 -> truncates to 1 on a 32-bit usize
    let gh = content_hash_of(&grant);
    let use_rec = seal_use(&rec, &res, "use-1", &[gh], ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let cp = checkpoint_over(&rec, &[content_hash_of(&use_rec)], 2, Some(&tsa));
    let bundle = tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]);
    let mut opts = pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key());
    opts.cosig_approver_keys = vec![a1.verifying_key()];
    let r = verify_bundle_with(&bundle, &opts);
    assert!(!r.ok, "a cosig_threshold above u32 range with 1 approver must NOT be satisfied (no usize truncation)");
    assert_eq!(r.cosig_status, "unsatisfied");
    assert_eq!(r.cosig_threshold_failures, 1);
    assert_eq!(r.uses_matched, 0, "the sub-threshold grant must not index");
}

#[test]
fn cosig_approval_challenge_golden_vector() {
    // Cross-language pinned vectors from the SHARED file — MUST equal Go broker.CosigApprovalChallenge.
    // The multibyte case asserts byte-length LP4 prefixing is identical in both languages (ADR 0005 M6).
    let v = preimage_vectors();
    let cases = v.get("cosig_approval_challenge").unwrap().as_array().unwrap();
    assert!(!cases.is_empty(), "shared vector: cosig_approval_challenge section is empty");
    for case in cases {
        let ch = cosig_approval_challenge(
            case.get("grant_id").unwrap().as_str().unwrap(),
            case.get("approver_kid").unwrap().as_str().unwrap(),
            case.get("credential_binding").unwrap().as_str().unwrap(),
            case.get("threshold_m").unwrap().as_int().unwrap(),
            case.get("exp").unwrap().as_int().unwrap(),
        );
        assert_eq!(
            hex_lower(&ch),
            case.get("expect_hex").unwrap().as_str().unwrap(),
            "cosig_approval_challenge drifted from the shared vector (case {})",
            case.get("name").unwrap().as_str().unwrap()
        );
    }
}

// ---- D8: the attested_complete conjunctive capstone ----

// a VerifyReport with EVERY capstone condition satisfied — start from a real verify result (real wiring),
// then force the conjunction inputs. Tests then flip one input to prove each is load-bearing.
fn capstone_report() -> VerifyReport {
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    // a real, ok bundle (broker_trust=sequence_verified) carrying a REAL side_effect_closure manifest that
    // declares its only touched resource (RESOURCE, from the grant) — so the verifier COMPUTES coverage_manifest
    // and side_effect_closure_status=="closed" end-to-end rather than us asserting them (T6 e2e). The remaining
    // fields below are still synthesized because d6_clean carries no matched use / attestation of its own.
    let bundle = d6_clean(&rec, &tsa);
    let bundle = change_field(&bundle, "coverage_manifest", closure_manifest(&[(RESOURCE, ACTION, &[])]));
    let mut r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.ok, "baseline must verify: {:?}", r.issues);
    assert_eq!(r.side_effect_closure_status, "closed", "the real manifest must compute closed (T6 e2e): {:?}", r.issues);
    assert!(r.coverage_manifest.as_ref().is_some_and(|m| !m.is_null()), "the real manifest must be echoed: {:?}", r.coverage_manifest);
    r.uses_matched = 1;
    r.uses_pop_reverified = 1;
    r.uses_action_unverified = 0;
    r.one_phase_use_present = false;
    r.intent_without_outcome = 0;
    r.taxonomy_status = "validated".to_string();
    r.broker_trust = "sequence_verified".to_string();
    r.attestation_status = "attested_claims".to_string();
    r.unmatched_violation = 0;
    r.unmatched_pending = 0;
    r
}

#[test]
fn tier_b_d8_capstone_when_all_conditions_hold() {
    let out = report_to_json(&capstone_report());
    assert!(out.contains(r#""action_completeness":"attested_complete_over_brokered_surface""#), "the full conjunction must reach the capstone: {out}");
    // MF1: the resource-truthful conditional is ALWAYS surfaced alongside the capstone.
    assert!(out.contains(r#""resource_trust":"assumed_truthful""#), "resource_trust must always be present: {out}");
}

#[test]
#[allow(clippy::type_complexity)]
fn tier_b_d8_each_condition_is_load_bearing() {
    // removing ANY single conjunct must drop the capstone to claimed_over_manifest (a manifest is present).
    let mutators: Vec<(&str, fn(&mut VerifyReport))> = vec![
        ("not ok", |r| r.ok = false),
        // isolate the brokered-surface conjunct: zero uses_matched AND uses_pop_reverified together, so
        // PoP-equality (0==0) still holds and ONLY `uses_matched > 0` is violated (Codex).
        ("no brokered surface", |r| { r.uses_matched = 0; r.uses_pop_reverified = 0; }),
        ("one-phase use present (MF3)", |r| r.one_phase_use_present = true),
        ("intent without outcome (D5)", |r| r.intent_without_outcome = 1),
        ("taxonomy not validated (D4)", |r| r.taxonomy_status = "stale".to_string()),
        ("action unverified (D4)", |r| r.uses_action_unverified = 1),
        ("pop not reverified (D2)", |r| r.uses_pop_reverified = 0),
        ("broker_trust not sequence_verified (D6)", |r| r.broker_trust = "sequence_consistent_export".to_string()),
        ("attestation not attested_claims (D7)", |r| r.attestation_status = "unevaluated".to_string()),
        ("unmatched violation", |r| r.unmatched_violation = 1),
        ("unmatched pending", |r| r.unmatched_pending = 1),
        // M1 (ADR 0005): the two bounded_reuse conjuncts. Surfacing-redundant with unmatched_violation in a
        // live verify (each anomaly also bumps it), but this synthetic report keeps unmatched_violation=0
        // and flips ONLY the M1 counter, proving each is independently load-bearing in the capstone formula.
        ("bounded_reuse overspent (M1)", |r| r.bounded_reuse_overspent = 1),
        ("bounded_reuse seq replay (M1)", |r| r.bounded_reuse_seq_replays = 1),
        // M6 (ADR 0005): the two cosig conjuncts. Like the M1 pair these are surfacing-redundant with
        // unmatched_violation in a live verify (a short cosigned grant is un-indexed -> its use violates), but
        // this synthetic report flips ONLY the cosig counter (unmatched_violation left 0) to prove each is
        // independently load-bearing. The second mutator sets total=1/satisfied=0 with failures=0 to isolate
        // the `satisfied==total` conjunct from the `failures==0` one.
        ("cosig threshold failure (M6)", |r| r.cosig_threshold_failures = 1),
        ("cosig not all satisfied (M6)", |r| { r.cosigned_grants_total = 1; r.cosigned_grants_satisfied = 0; }),
        // string-isolation: `unclosed` in a live verify ALSO forces !ok (covered e2e by
        // tier_b_t6_undeclared_touched_resource_is_unclosed); here we mutate ONLY the status on a synthetic
        // report (ok left true) to prove the capstone gate keys on `=="closed"` independently of `ok`.
        ("side effect unclosed (T6)", |r| r.side_effect_closure_status = "unclosed".to_string()),
        // the KEY load-bearing case: `not_declared` does NOT force !ok, so this conjunct is the ONLY thing
        // blocking the capstone for a perfect bundle that asserts ZERO side-effect closure.
        ("side effect not declared (T6)", |r| r.side_effect_closure_status = "not_declared".to_string()),
    ];
    for (name, mutate) in mutators {
        let mut r = capstone_report();
        mutate(&mut r);
        let out = report_to_json(&r);
        assert!(out.contains(r#""action_completeness":"claimed_over_manifest""#), "removing condition '{name}' must block the capstone (-> claimed_over_manifest): {out}");
        assert!(!out.contains("attested_complete_over_brokered_surface"), "condition '{name}' removed but capstone still emitted: {out}");
    }
}

#[test]
fn tier_b_d8_no_manifest_is_not_claimed() {
    // the capstone is asserted OVER a coverage_manifest; with no manifest the label is `not_claimed` even if
    // every other condition holds (there is no scope claim to attest completeness over).
    let mut r = capstone_report();
    r.coverage_manifest = None;
    let out = report_to_json(&r);
    assert!(out.contains(r#""action_completeness":"not_claimed""#), "no manifest -> not_claimed: {out}");
    assert!(out.contains(r#""resource_trust":"assumed_truthful""#));
}

#[test]
fn tier_b_d8_null_manifest_is_not_a_capstone() {
    // Codex: a JSON `"coverage_manifest": null` deserializes to Some(Null) — NOT a real manifest. With every
    // OTHER conjunct passing it must NOT reach the capstone (and is not_claimed, not claimed_over_manifest).
    let mut r = capstone_report();
    r.coverage_manifest = Some(CanonValue::Null);
    let out = report_to_json(&r);
    assert!(!out.contains("attested_complete_over_brokered_surface"), "a null manifest must not reach the capstone: {out}");
    assert!(out.contains(r#""action_completeness":"not_claimed""#), "null manifest -> not_claimed: {out}");
}

#[test]
fn tier_b_d8_one_phase_use_blocks_capstone_end_to_end() {
    // MF3 end-to-end: a real bundle whose only matched use is ONE-PHASE sets one_phase_use_present, so even
    // with a manifest it can never reach the capstone (it carries the record-after-action gap).
    let (rec, res, tsa) = (signing_key_from_seed(&[0u8; 32]), signing_key_from_seed(&[3u8; 32]), test_tsa_key(&[200u8; 32]));
    let grant = seal_grant(&rec, &rec, GID, &grant_evidence_d6(GID, 1));
    let gh = content_hash_of(&grant);
    let use_rec = seal_use(&rec, &res, "use-1", std::slice::from_ref(&gh), ACTION, &use_evidence(GID, ACTION, RESOURCE, GID, CNF, USED));
    let uh = content_hash_of(&use_rec);
    let mut both = vec![gh.clone(), uh];
    both.sort();
    let head = grant_head_cv(1, &ghr(&[]), &ghr(&[(1, &gh)]));
    let cp = checkpoint_with_head(&rec, &both, 2, head, Some(&tsa));
    let bundle = change_field(&tier_b_bundle(&rec.verifying_key(), vec![grant, use_rec], vec![cp]), "coverage_manifest", CanonValue::string("m"));
    let r = verify_bundle_with(&bundle, &pinned_roles(rec.verifying_key(), res.verifying_key(), tsa.verifying_key()));
    assert!(r.one_phase_use_present, "a one-phase matched use must set the flag: {:?}", r.issues);
    assert!(!report_to_json(&r).contains("attested_complete_over_brokered_surface"), "a one-phase use must block the capstone");
}
