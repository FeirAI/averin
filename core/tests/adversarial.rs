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
    verify_bundle, verify_bundle_with, TrustLevel, TrustedKey, VerifyOptions,
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
    let esig_use = sign_evidence("gateway_enforced", record_id, &eh_use, &sk);
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
    let esig = sign_evidence("gateway_enforced", record_id, &eh, broker_sk);
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
    let esig = sign_evidence("gateway_enforced", record_id, eh, res_sk);
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

#[test]
fn ledger_commitment_golden_vector() {
    // Cross-language pinned vector — MUST equal Go resourceshim.ledgerCommitment (golden test there).
    assert_eq!(
        feir_decision_core::verify::ledger_commitment("jti-x", "nonce-y", 1_718_445_700),
        "sha256:b4566365dae04faf6e17e3ab8ab7183f7236b812fd1b957ef3fcd966ad6a163b"
    );
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
    let esig = sign_evidence("gateway_enforced", record_id, &eh, res_sk);
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
    // Cross-language pinned vectors — MUST equal Go resourceshim.usePoPChallenge + broker.KeyID.
    let ch = use_pop_challenge("g", "r", "a", "pc", "cb", "n");
    assert_eq!(hex_lower(&ch), "6e5f46c15724b1fa4af4c7e462d62a08fde27943e389171ff3e88993cdc1b4b5");
    // multibyte UTF-8 fields must length-prefix by BYTE count identically in both languages
    let mb = use_pop_challenge("café", "資源", "🔑", "pc", "cb", "n");
    assert_eq!(hex_lower(&mb), "a7dec20864a4b5b0c0bdcc79c9f8176100661498c763f04fa7106f88663073ce");
    let cnf = signing_key_from_seed(&[5u8; 32]).verifying_key();
    assert_eq!(vk_cnf_kid(&cnf), "ed25519-dZl3bDCF4_k");
}
