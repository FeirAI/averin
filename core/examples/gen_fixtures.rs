//! Regenerates `/spec/fixtures/bundle-valid.json` — a small, fully-sealed two-session run with a
//! checkpoint chain, used as the base for the adversarial acceptance tests (which derive tampered
//! / omitted / forked variants from it). Run with `cargo run --example gen_fixtures`.

use ed25519_dalek::SigningKey;
use feir_decision_core::canon::CanonValue;
use feir_decision_core::checkpoint::{checkpoint_body, seal_checkpoint};
use feir_decision_core::record::seal;
use feir_decision_core::sign::{encode_pubkey, signing_key_from_seed};
use std::path::PathBuf;

fn key_block() -> CanonValue {
    CanonValue::parse(
        r#"{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}"#,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn make_record(
    sk: &SigningKey,
    record_id: &str,
    session_id: &str,
    span_id: &str,
    parent_span: Option<&str>,
    prev: &[String],
    seq: i64,
    received_ts: &str,
) -> CanonValue {
    let parent = match parent_span {
        Some(p) => format!("\"{p}\""),
        None => "null".to_string(),
    };
    let prevs = prev
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{
          "schema_version": "2",
          "canon_version": "rcp-1",
          "domain": "flightrecorder.record.v2",
          "record_id": "{record_id}",
          "project_id": "proj-001",
          "agent_id": "billing-agent",
          "agent_version": "1.4.2",
          "session_id": "{session_id}",
          "span_id": "{span_id}",
          "parent_span_id": {parent},
          "causal_prev_hashes": [{prevs}],
          "display_seq": {seq},
          "agent_ts": "2026-06-15T10:00:0{seq}.000Z",
          "received_ts": "{received_ts}",
          "event_type": "tool_call",
          "action": "db.query",
          "observed_via": "sdk",
          "status": "ok",
          "cost_micros_usd": 18000,
          "key": {{"signing_key_id":"k0","key_epoch":0,"key_valid_from":"2026-06-01T00:00:00.000Z","key_status":"active"}}
        }}"#
    );
    seal(&CanonValue::parse(&body).unwrap(), sk).unwrap()
}

fn ch(rec: &CanonValue) -> String {
    rec.get("content_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec")
        .join("fixtures");
    std::fs::create_dir_all(&dir).unwrap();

    let sk = signing_key_from_seed(&[0u8; 32]);

    // session A: r0 -> r1 ; session B: r2 (independent root)
    let r0 = make_record(
        &sk,
        "r0",
        "sess-A",
        "spanA0",
        None,
        &[],
        0,
        "2026-06-15T10:00:00.100Z",
    );
    let r1 = make_record(
        &sk,
        "r1",
        "sess-A",
        "spanA1",
        Some("spanA0"),
        &[ch(&r0)],
        1,
        "2026-06-15T10:00:01.100Z",
    );
    let r2 = make_record(
        &sk,
        "r2",
        "sess-B",
        "spanB0",
        None,
        &[],
        2,
        "2026-06-15T10:00:02.100Z",
    );

    // heads after all three = {ch(r1), ch(r2)}; cp0 commits them, cp1 re-commits (no new work).
    let mut frontier = vec![ch(&r1), ch(&r2)];
    frontier.sort();

    let cb0 = checkpoint_body(
        "cp0",
        "proj-001",
        0,
        None,
        &frontier,
        3,
        "2026-06-15T10:01:00.000Z",
        key_block(),
    )
    .unwrap();
    let cp0 = seal_checkpoint(&cb0, &sk).unwrap();
    let cp0h = cp0
        .get("checkpoint_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let cb1 = checkpoint_body(
        "cp1",
        "proj-001",
        1,
        Some(&cp0h),
        &frontier,
        3,
        "2026-06-15T10:05:00.000Z",
        key_block(),
    )
    .unwrap();
    let cp1 = seal_checkpoint(&cb1, &sk).unwrap();

    let key_entry = CanonValue::object(vec![
        ("signing_key_id".into(), CanonValue::string("k0")),
        ("key_epoch".into(), CanonValue::Int(0)),
        (
            "public_key".into(),
            CanonValue::string(encode_pubkey(&sk.verifying_key())),
        ),
        ("key_status".into(), CanonValue::string("active")),
    ])
    .unwrap();

    let bundle = CanonValue::object(vec![
        ("bundle_version".into(), CanonValue::string("1")),
        ("project_id".into(), CanonValue::string("proj-001")),
        ("keys".into(), CanonValue::Array(vec![key_entry])),
        ("records".into(), CanonValue::Array(vec![r0, r1, r2])),
        ("checkpoints".into(), CanonValue::Array(vec![cp0, cp1])),
    ])
    .unwrap();

    let path = dir.join("bundle-valid.json");
    std::fs::write(&path, bundle.serialize()).unwrap();
    println!("wrote {}", path.display());
}
