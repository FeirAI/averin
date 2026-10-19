//! feir-ops#1: gateway refusal records (`record_kind = gateway-refusal`).
//!
//! TEST-ONLY KEYS: every bundle here is signed by the seed sha256("averin-TEST-ONLY-record-v1"), a public
//! label (listed in spec/test-keys.json). It proves nothing about a deployment.

use averin_decision_core::canon::CanonValue;
use averin_decision_core::checkpoint::{checkpoint_body, seal_checkpoint};
use averin_decision_core::hashx::sha256_prefixed;
use averin_decision_core::record::seal;
use averin_decision_core::sign::{encode_pubkey, signing_key_from_seed};
use averin_decision_core::verify::{
    verify_bundle_with, verify_bundle_with_json, TrustedKey, VerifyOptions, VerifyReport,
};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

type Body = Vec<(String, CanonValue)>;
type Edit = Box<dyn Fn(&mut Body)>;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn label_seed(label: &str) -> [u8; 32] {
    let hex = sha256_prefixed(label.as_bytes());
    let hex = hex.strip_prefix("sha256:").unwrap();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn record_key() -> SigningKey {
    signing_key_from_seed(&label_seed("averin-TEST-ONLY-record-v1"))
}

fn other_key() -> SigningKey {
    signing_key_from_seed(&label_seed("averin-TEST-ONLY-resource-v1"))
}

fn j(text: &str) -> CanonValue {
    CanonValue::parse(text).unwrap()
}

fn set(b: &mut Body, k: &str, v: CanonValue) {
    if let Some(slot) = b.iter_mut().find(|(n, _)| n == k) {
        slot.1 = v;
    } else {
        b.push((k.to_string(), v));
    }
}

fn del(b: &mut Body, k: &str) {
    b.retain(|(n, _)| n != k);
}

const TS: &str = "2026-01-01T00:00:00.000Z";

fn key_block() -> CanonValue {
    j(
        r#"{"signing_key_id":"k0","key_epoch":0,"key_status":"active","key_valid_from":"2026-01-01T00:00:00.000Z"}"#,
    )
}

fn base(id: &str, event_type: &str, action: &str) -> Body {
    let v = j(&format!(
        r#"{{"schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
        "record_id":"{id}","project_id":"p1","agent_id":"agent-x","agent_version":"t","session_id":"s1",
        "span_id":"span-{id}","parent_span_id":null,"causal_prev_hashes":[],"display_seq":0,
        "agent_ts":"{TS}","received_ts":"{TS}","event_type":"{event_type}","action":"{action}",
        "observed_via":"sdk","status":"ok"}}"#
    ));
    let mut b = v.as_object().unwrap().clone();
    set(&mut b, "key", key_block());
    b
}

fn refusal_ext(class: &str, attempts: i64) -> CanonValue {
    j(&format!(
        r#"{{"gateway_refusal":{{"v":1,"reason_class":"{class}","entry_point":"mcp","attempts":{attempts},
        "first_at":"{TS}","last_at":"{TS}"}}}}"#
    ))
}

fn summary_ext() -> CanonValue {
    j(&format!(
        r#"{{"gateway_refusal":{{"v":1,"summary":true,"attempts":5,"by_class":{{"rate_limit":3,"spend_cap":2}},
        "first_at":"{TS}","last_at":"{TS}"}}}}"#
    ))
}

/// A well-formed refusal record body.
fn refusal(id: &str, class: &str, attempts: i64) -> Body {
    let mut b = base(id, "gateway_refusal", "change_payout_details");
    set(&mut b, "record_kind", CanonValue::string("gateway-refusal"));
    set(&mut b, "observed_via", CanonValue::string("gateway"));
    set(&mut b, "status", CanonValue::string("refused"));
    set(&mut b, "extensions", refusal_ext(class, attempts));
    b
}

fn ext_member(b: &mut Body, f: impl FnOnce(&mut Body)) {
    let mut ext = b
        .iter()
        .find(|(n, _)| n == "extensions")
        .unwrap()
        .1
        .as_object()
        .unwrap()
        .clone();
    let mut g = ext
        .iter()
        .find(|(n, _)| n == "gateway_refusal")
        .unwrap()
        .1
        .as_object()
        .unwrap()
        .clone();
    f(&mut g);
    set(&mut ext, "gateway_refusal", CanonValue::Object(g));
    set(b, "extensions", CanonValue::Object(ext));
}

/// Seal the bodies into one chained session, commit them with one checkpoint, return the bundle.
fn bundle(bodies: Vec<Body>) -> CanonValue {
    let sk = record_key();
    let mut sealed: Vec<CanonValue> = vec![];
    let mut prev: Option<String> = None;
    for (i, mut b) in bodies.into_iter().enumerate() {
        set(&mut b, "display_seq", CanonValue::Int(i as i64));
        let parents = prev.iter().map(CanonValue::string).collect();
        set(&mut b, "causal_prev_hashes", CanonValue::Array(parents));
        let rec = seal(&CanonValue::Object(b), &sk).expect("seal");
        prev = Some(
            rec.get("content_hash")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
        );
        sealed.push(rec);
    }
    let cp = checkpoint_body(
        "cp0",
        "p1",
        0,
        None,
        &[prev.unwrap()],
        sealed.len() as i64,
        TS,
        key_block(),
    )
    .unwrap();
    let cp = seal_checkpoint(&cp, &sk).unwrap();
    let keys = j(&format!(
        r#"[{{"signing_key_id":"k0","key_epoch":0,"key_status":"active","public_key":"{}"}}]"#,
        encode_pubkey(&sk.verifying_key())
    ));
    CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::Int(1)),
        ("project_id".into(), CanonValue::string("p1")),
        ("records".into(), CanonValue::Array(sealed)),
        ("checkpoints".into(), CanonValue::Array(vec![cp])),
        ("keys".into(), keys),
        ("disclosures".into(), CanonValue::Array(vec![])),
    ])
    .unwrap()
}

fn pinned(sk: &SigningKey) -> VerifyOptions {
    VerifyOptions {
        trusted_keys: Some(vec![TrustedKey {
            vk: sk.verifying_key(),
            status: None,
            status_changed_at: None,
        }]),
        ..Default::default()
    }
}

fn verify(b: &CanonValue) -> VerifyReport {
    verify_bundle_with(b, &pinned(&record_key()))
}

fn opts_json() -> String {
    format!(
        r#"{{"signing_keys":["{}"]}}"#,
        encode_pubkey(&record_key().verifying_key())
    )
}

fn tool_call(id: &str) -> Body {
    base(id, "tool_call", "db.query")
}

fn refusal_issues(r: &VerifyReport) -> Vec<&String> {
    r.issues
        .iter()
        .filter(|i| i.contains("gateway refusal"))
        .collect()
}

// gateway-refusal-counted-when-proven
#[test]
fn counts_integrity_proven_refusals_with_attempts_and_classes() {
    let b = bundle(vec![tool_call("r0"), refusal("r1", "not_granted", 3), {
        let mut s = refusal("r2", "not_granted", 1);
        set(&mut s, "action", CanonValue::string("*"));
        set(&mut s, "extensions", summary_ext());
        s
    }]);
    let r = verify(&b);
    assert!(r.ok, "{:?}", r.issues);
    assert_eq!(r.gateway_refusals, 2);
    assert_eq!(r.gateway_refusal_attempts, 8);
    let by: Vec<(&str, u64)> = r
        .gateway_refusals_by_class
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    assert_eq!(
        by,
        vec![("not_granted", 3), ("rate_limit", 3), ("spend_cap", 2)]
    );
    assert!(refusal_issues(&r).is_empty());
}

#[test]
fn unproven_refusals_are_not_counted() {
    // Pin a key that did not sign: every record is untrusted, so nothing may be counted as a blocked attempt.
    let b = bundle(vec![tool_call("r0"), refusal("r1", "not_granted", 3)]);
    let r = verify_bundle_with(&b, &pinned(&other_key()));
    assert!(!r.ok);
    assert_eq!(r.gateway_refusals, 0);
    assert_eq!(r.gateway_refusal_attempts, 0);
    assert!(r.gateway_refusals_by_class.is_empty());
}

#[test]
fn a_replayed_refusal_is_counted_once() {
    let b = bundle(vec![tool_call("r0"), refusal("r1", "not_granted", 3)]);
    let mut m = b.as_object().unwrap().clone();
    let mut recs = b.get("records").unwrap().as_array().unwrap().clone();
    recs.push(recs[1].clone()); // the same sealed record, verbatim
    set(&mut m, "records", CanonValue::Array(recs));
    let r = verify(&CanonValue::Object(m));
    assert_eq!(r.gateway_refusals, 1, "{:?}", r.issues);
    assert_eq!(r.gateway_refusal_attempts, 3);
}

// gateway-refusal-shape-fail-closed
#[test]
fn malformed_refusals_are_hard_issues_and_never_counted() {
    let cases: Vec<(&str, Edit)> = vec![
        (
            "unknown class",
            Box::new(|b| ext_member(b, |g| set(g, "reason_class", CanonValue::string("because")))),
        ),
        (
            "unknown entry point",
            Box::new(|b| ext_member(b, |g| set(g, "entry_point", CanonValue::string("ftp")))),
        ),
        (
            "zero attempts",
            Box::new(|b| ext_member(b, |g| set(g, "attempts", CanonValue::Int(0)))),
        ),
        (
            "unknown key (free text)",
            Box::new(|b| {
                ext_member(b, |g| {
                    set(g, "reason", CanonValue::string("credential x denied"))
                })
            }),
        ),
        (
            "params smuggled",
            Box::new(|b| ext_member(b, |g| set(g, "params", j(r#"{"k":"v"}"#)))),
        ),
        (
            "divergent event_type",
            Box::new(|b| set(b, "event_type", CanonValue::string("tool_call"))),
        ),
        (
            "carried authority",
            Box::new(|b| set(b, "authority", j(r#"{"source":"caller_declared"}"#))),
        ),
        (
            "carried use_evidence",
            Box::new(|b| {
                let mut ext = b
                    .iter()
                    .find(|(n, _)| n == "extensions")
                    .unwrap()
                    .1
                    .as_object()
                    .unwrap()
                    .clone();
                set(
                    &mut ext,
                    "broker",
                    j(
                        r#"{"kind":"use","use_evidence":{"resource_id":"orders-db","action":"db.query:orders-ro"}}"#,
                    ),
                );
                set(b, "extensions", CanonValue::Object(ext));
            }),
        ),
        (
            "summary sum mismatch",
            Box::new(|b| {
                set(
                    b,
                    "extensions",
                    j(&format!(
                        r#"{{"gateway_refusal":{{"v":1,"summary":true,"attempts":9,"by_class":{{"rate_limit":3,"spend_cap":2}},"first_at":"{TS}","last_at":"{TS}"}}}}"#
                    )),
                )
            }),
        ),
        (
            "summary unknown class",
            Box::new(|b| {
                set(
                    b,
                    "extensions",
                    j(&format!(
                        r#"{{"gateway_refusal":{{"v":1,"summary":true,"attempts":1,"by_class":{{"nope":1}},"first_at":"{TS}","last_at":"{TS}"}}}}"#
                    )),
                )
            }),
        ),
        ("missing extension", Box::new(|b| del(b, "extensions"))),
        (
            "credential is an object carrying a url",
            Box::new(|b| {
                ext_member(b, |g| {
                    set(
                        g,
                        "credential",
                        j(r#"{"url":"https://evil/?token=sk-live-123","params":{"a":"b"}}"#),
                    )
                })
            }),
        ),
        (
            "credential is a url string",
            Box::new(|b| {
                ext_member(b, |g| {
                    set(
                        g,
                        "credential",
                        CanonValue::string("https://evil/?token=sk-live-123"),
                    )
                })
            }),
        ),
        (
            "first_at is free text",
            Box::new(|b| {
                ext_member(b, |g| {
                    set(g, "first_at", CanonValue::string("see https://evil/x"))
                })
            }),
        ),
        (
            "last_at is not canonical",
            Box::new(|b| {
                ext_member(b, |g| {
                    set(g, "last_at", CanonValue::string("2026-01-01T00:00:00Z"))
                })
            }),
        ),
        (
            "status is not refused",
            Box::new(|b| set(b, "status", CanonValue::string("ok"))),
        ),
        (
            "observed_via is not gateway",
            Box::new(|b| set(b, "observed_via", CanonValue::string("proxy"))),
        ),
        (
            "action is free text",
            Box::new(|b| set(b, "action", CanonValue::string("delete https://evil/?k=v"))),
        ),
    ];
    for (name, f) in cases {
        let mut bad = refusal("r1", "not_granted", 3);
        f(&mut bad);
        let r = verify(&bundle(vec![tool_call("r0"), bad]));
        assert!(!r.ok, "{name}: must fail closed");
        assert_eq!(refusal_issues(&r).len(), 1, "{name}: {:?}", r.issues);
        assert_eq!(
            r.gateway_refusals, 0,
            "{name}: a malformed refusal is never counted"
        );
        assert_eq!(r.gateway_refusal_attempts, 0, "{name}");
    }
}

// A malformed refusal is a hard issue, but it carries no grant or use evidence: it must not turn the
// authorization claims into a contradiction (refuted). The verdict is the same as for the same history
// without the refusal being well formed: integrity stays satisfied, nothing is refuted.
#[test]
fn a_malformed_refusal_is_not_a_grant_contradiction() {
    use averin_decision_core::verify::ClaimDecision;
    let mut bad = refusal("r1", "not_granted", 3);
    ext_member(&mut bad, |g| {
        set(g, "reason_class", CanonValue::string("because"))
    });
    let r = verify(&bundle(vec![tool_call("r0"), bad]));
    assert!(!r.ok);
    assert_eq!(refusal_issues(&r).len(), 1, "{:?}", r.issues);
    let c = r.claims();
    for (name, d) in [
        ("authorized", c.authorized),
        ("complete_brokered", c.complete_brokered),
        ("complete_introspected", c.complete_introspected),
        ("temporal", c.temporal),
    ] {
        assert_ne!(
            d,
            ClaimDecision::Refuted,
            "{name}: a refusal shape failure refutes no authorization claim"
        );
    }
}

// legacy-history-unchanged
#[test]
fn legacy_event_type_only_record_keeps_its_verdict() {
    // An older averin could seal a GENERIC record with event_type gateway_refusal. It carries no record_kind,
    // so it is neither counted nor shape-checked: the verdict equals that of an ordinary record.
    let legacy = bundle(vec![tool_call("r0"), base("r1", "gateway_refusal", "x")]);
    let control = bundle(vec![tool_call("r0"), base("r1", "decision", "x")]);
    let (a, b) = (verify(&legacy), verify(&control));
    assert!(a.ok && b.ok, "{:?} {:?}", a.issues, b.issues);
    assert_eq!(a.issues, b.issues);
    assert_eq!(a.records_proven, b.records_proven);
    assert_eq!(a.gateway_refusals, 0);
    assert_eq!(a.gateway_refusal_attempts, 0);
}

// The report serializes the three new fields (CLI, WASM and FFI all use report_to_canon).
#[test]
fn report_serializes_the_refusal_fields() {
    let b = bundle(vec![tool_call("r0"), refusal("r1", "policy_deny", 4)]);
    let out = CanonValue::parse(&verify_bundle_with_json(&b.serialize(), &opts_json())).unwrap();
    assert_eq!(out.get("gateway_refusals"), Some(&CanonValue::Int(1)));
    assert_eq!(
        out.get("gateway_refusal_attempts"),
        Some(&CanonValue::Int(4))
    );
    assert_eq!(
        out.get("gateway_refusals_by_class")
            .unwrap()
            .get("policy_deny"),
        Some(&CanonValue::Int(4))
    );
    // a report with no refusals still carries zero counters, never an absent field
    let none = bundle(vec![tool_call("r0")]);
    let out = CanonValue::parse(&verify_bundle_with_json(&none.serialize(), &opts_json())).unwrap();
    assert_eq!(out.get("gateway_refusals"), Some(&CanonValue::Int(0)));
    assert_eq!(
        out.get("gateway_refusal_attempts"),
        Some(&CanonValue::Int(0))
    );
}

// The closed vocabularies in core equal vectors/refusal-classes.v1.json.
#[test]
fn vocabulary_matches_the_spec_file() {
    let spec = j(&std::fs::read_to_string(root().join("vectors/refusal-classes.v1.json")).unwrap());
    let strs = |k: &str| -> Vec<String> {
        spec.get(k)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    let core_classes: Vec<String> = averin_decision_core::refusal::REASON_CLASSES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let core_entries: Vec<String> = averin_decision_core::refusal::ENTRY_POINTS
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(strs("reason_classes"), core_classes);
    assert_eq!(strs("entry_points"), core_entries);
}

// ---- the cross-implementation vector (CLI/native, FFI and WASM replay the same rows) ----

fn capstone_row() -> (String, String) {
    let f = j(&std::fs::read_to_string(
        root().join("spec/fixtures/capstone-with-refusals-v3.json"),
    )
    .unwrap());
    (
        f.get("bundle").unwrap().serialize(),
        f.get("opts").unwrap().serialize(),
    )
}

fn vector_rows() -> Vec<(String, String, String)> {
    let shape_bad = {
        let mut bad = refusal("r1", "not_granted", 3);
        ext_member(&mut bad, |g| {
            set(g, "reason_class", CanonValue::string("because"))
        });
        bundle(vec![tool_call("r0"), bad])
    };
    let basic = bundle(vec![
        tool_call("r0"),
        refusal("r1", "not_granted", 3),
        refusal("r2", "policy_deny", 1),
    ]);
    let legacy = bundle(vec![tool_call("r0"), base("r1", "gateway_refusal", "x")]);
    let (cb, co) = capstone_row();
    vec![
        ("refusals_basic".into(), basic.serialize(), opts_json()),
        (
            "legacy_event_type_only".into(),
            legacy.serialize(),
            opts_json(),
        ),
        (
            "shape_unknown_class".into(),
            shape_bad.serialize(),
            opts_json(),
        ),
        ("capstone_with_refusals".into(), cb, co),
    ]
}

/// Writer (opt-in): AVERIN_WRITE_REFUSAL_VECTORS=<path>. The expectations are computed by the native verifier
/// and ALSO pinned to literals in `vector_expectations_are_the_intended_ones`, so the file is not circular.
#[test]
fn write_refusal_vectors() {
    let Ok(path) = std::env::var("AVERIN_WRITE_REFUSAL_VECTORS") else {
        return;
    };
    let rows: Vec<CanonValue> = vector_rows()
        .into_iter()
        .map(|(name, bundle_json, opts)| {
            let r = CanonValue::parse(&verify_bundle_with_json(&bundle_json, &opts)).unwrap();
            let g = |k: &str| r.get(k).cloned().unwrap();
            CanonValue::object(vec![
                ("name".into(), CanonValue::string(&name)),
                ("bundle_json".into(), CanonValue::string(&bundle_json)),
                ("opts_json".into(), CanonValue::string(&opts)),
                ("expected_ok".into(), g("ok")),
                ("expected_gateway_refusals".into(), g("gateway_refusals")),
                (
                    "expected_gateway_refusal_attempts".into(),
                    g("gateway_refusal_attempts"),
                ),
                (
                    "expected_gateway_refusals_by_class".into(),
                    g("gateway_refusals_by_class"),
                ),
                (
                    "expected_refusal_issue".into(),
                    CanonValue::Bool(
                        r.get("issues")
                            .unwrap()
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|i| i.as_str().unwrap().contains("gateway refusal")),
                    ),
                ),
            ])
            .unwrap()
        })
        .collect();
    std::fs::write(path, CanonValue::Array(rows).serialize() + "\n").unwrap();
}

#[test]
fn vector_expectations_are_the_intended_ones() {
    let rows = vector_rows();
    let rep = |name: &str| {
        let (_, b, o) = rows.iter().find(|(n, _, _)| n == name).unwrap();
        CanonValue::parse(&verify_bundle_with_json(b, o)).unwrap()
    };
    let int = |r: &CanonValue, k: &str| match r.get(k) {
        Some(CanonValue::Int(i)) => *i,
        _ => panic!("{k}"),
    };
    let basic = rep("refusals_basic");
    assert_eq!(basic.get("ok"), Some(&CanonValue::Bool(true)));
    assert_eq!(
        (
            int(&basic, "gateway_refusals"),
            int(&basic, "gateway_refusal_attempts")
        ),
        (2, 4)
    );
    let legacy = rep("legacy_event_type_only");
    assert_eq!(legacy.get("ok"), Some(&CanonValue::Bool(true)));
    assert_eq!(int(&legacy, "gateway_refusals"), 0);
    let bad = rep("shape_unknown_class");
    assert_eq!(bad.get("ok"), Some(&CanonValue::Bool(false)));
    assert_eq!(int(&bad, "gateway_refusals"), 0);
    // gateway-refusal-never-widens-surface: the real-producer capstone with refusals of UNGRANTED actions
    // (committed fixture, test-signed) stays attested complete with the side-effect closure closed.
    let cap = rep("capstone_with_refusals");
    assert_eq!(
        cap.get("ok"),
        Some(&CanonValue::Bool(true)),
        "{:?}",
        cap.get("issues")
    );
    assert_eq!(
        cap.get("side_effect_closure_status")
            .and_then(CanonValue::as_str),
        Some("closed")
    );
    assert_eq!(
        cap.get("action_completeness").and_then(CanonValue::as_str),
        Some("attested_complete_over_brokered_surface")
    );
    assert_eq!(
        (
            int(&cap, "gateway_refusals"),
            int(&cap, "gateway_refusal_attempts")
        ),
        (3, 58)
    );
}

/// Replays the committed vector file (the same file the Go FFI test and the WASM test replay).
#[test]
fn committed_vector_file_replays() {
    let path = root().join("spec/fixtures/gateway-refusal-vectors.json");
    let rows = j(&std::fs::read_to_string(path).unwrap());
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        let s = |k: &str| row.get(k).unwrap().as_str().unwrap().to_string();
        let r = CanonValue::parse(&verify_bundle_with_json(&s("bundle_json"), &s("opts_json")))
            .unwrap();
        let name = s("name");
        assert_eq!(r.get("ok"), row.get("expected_ok"), "{name}");
        assert_eq!(
            r.get("gateway_refusals"),
            row.get("expected_gateway_refusals"),
            "{name}"
        );
        assert_eq!(
            r.get("gateway_refusal_attempts"),
            row.get("expected_gateway_refusal_attempts"),
            "{name}"
        );
        assert_eq!(
            r.get("gateway_refusals_by_class"),
            row.get("expected_gateway_refusals_by_class"),
            "{name}"
        );
    }
}
