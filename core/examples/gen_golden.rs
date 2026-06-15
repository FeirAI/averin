//! Regenerates `/spec/golden-vectors/*`. Run with `cargo run --example gen_golden`.
//! The committed vectors are the cross-implementation contract; `tests/golden.rs` asserts the
//! core reproduces them byte-for-byte. Regenerate only on an intentional RCP change.

use feir_decision_core::canon::CanonValue;
use feir_decision_core::commit::{commit, FieldDomain};
use feir_decision_core::hashx::hex_lower;
use feir_decision_core::record::{compute_content_hash, seal};
use feir_decision_core::sign::{encode_pubkey, signing_key_from_seed};
use std::path::PathBuf;

fn spec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec")
        .join("golden-vectors")
}

/// JSON-escape a string for an ASCII-safe manifest WITHOUT normalization (every non-ASCII code
/// point becomes a `\uXXXX` escape). Faithful to the exact bytes — critical so NFC/surrogate
/// test inputs are not silently pre-normalized. (`jstr` is NOT used for `input`/`canonical`.)
fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7E => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn canon_case(name: &str, note: &str, input: &str) -> String {
    // `input` is byte-preserved; the test uses `input_hex` as the authoritative source so the
    // manifest reader (which NFC-normalizes) can never alter the test input.
    let v = CanonValue::parse(input).expect("vector must parse");
    let canonical = v.serialize();
    format!(
        "    {{\n      \"name\": {},\n      \"note\": {},\n      \"input\": {},\n      \"input_hex\": {},\n      \"canonical\": {},\n      \"canonical_hex\": {}\n    }}",
        jstr(name),
        jstr(note),
        jstr(input),
        jstr(&hex_lower(input.as_bytes())),
        jstr(&canonical),
        jstr(&hex_lower(canonical.as_bytes())),
    )
}

fn main() {
    let dir = spec_dir();
    std::fs::create_dir_all(&dir).unwrap();

    // ---- canonicalization edge cases ----
    let cases = [
        canon_case(
            "key-sort-ascii",
            "object keys sort by UTF-16 code unit; ASCII is straightforward",
            r#"{"b":1,"a":2,"A":3,"0":4}"#,
        ),
        canon_case(
            "key-sort-supplementary-plane",
            "U+10000 (surrogate pair D800 DC00) sorts BEFORE U+FFFF in UTF-16 order, opposite of code-point order",
            "{\"\u{ffff}\":1,\"\u{10000}\":2}",
        ),
        canon_case(
            "integers-boundaries",
            "i64 min/max and zero; no leading zeros, no plus, no -0",
            r#"{"min":-9223372036854775808,"max":9223372036854775807,"zero":0,"neg":-5}"#,
        ),
        canon_case(
            "null-vs-present",
            "explicit null is retained and distinct from an omitted field",
            r#"{"a":null,"b":false}"#,
        ),
        canon_case(
            "string-escaping",
            "only \", \\, and C0 controls are escaped; non-ASCII emitted literally; no / escaping",
            "{\"q\":\"a\\\"b\\\\c/\\n\\t\u{00e9}\u{1f600}\"}",
        ),
        canon_case(
            "nfc-normalization",
            "decomposed e+combining-acute normalizes to precomposed U+00E9 (NFC)",
            "{\"k\":\"e\u{0301}\"}",
        ),
        canon_case(
            "nested-extensions",
            "extensions is the only place arbitrary keys live; still canonicalized",
            r#"{"extensions":{"z":1,"a":[3,2,1]},"a":true}"#,
        ),
    ];
    let canon_manifest = format!(
        "{{\n  \"profile\": \"rcp-1\",\n  \"description\": \"RCP v1 canonicalization golden vectors. Any implementation MUST reproduce `canonical` byte-for-byte from `input`.\",\n  \"cases\": [\n{}\n  ]\n}}\n",
        cases.join(",\n")
    );
    std::fs::write(dir.join("canon.json"), &canon_manifest).unwrap();
    println!("wrote {}", dir.join("canon.json").display());

    // ---- a full record content_hash vector (signing added in the sign module's vectors) ----
    let record_input = r#"{
  "schema_version": "2",
  "canon_version": "rcp-1",
  "domain": "flightrecorder.record.v2",
  "record_id": "11111111-1111-1111-1111-111111111111",
  "project_id": "22222222-2222-2222-2222-222222222222",
  "agent_id": "billing-agent",
  "agent_version": "1.4.2",
  "session_id": "33333333-3333-3333-3333-333333333333",
  "span_id": "span-0001",
  "parent_span_id": null,
  "causal_prev_hashes": [],
  "display_seq": 0,
  "agent_ts": "2026-06-15T10:00:00.000Z",
  "received_ts": "2026-06-15T10:00:00.123Z",
  "event_type": "llm_call",
  "action": "chat.completions",
  "observed_via": "proxy",
  "status": "ok",
  "tokens": { "in": 1200, "out": 300 },
  "cost_micros_usd": 18000,
  "key": {
    "signing_key_id": "key-2026-06",
    "key_epoch": 7,
    "key_valid_from": "2026-06-01T00:00:00.000Z",
    "key_status": "active"
  },
  "framework": "openai-agents"
}"#;
    let rec = CanonValue::parse(record_input).expect("record must parse");
    let canonical = rec.serialize();
    let content_hash = compute_content_hash(&rec).expect("content_hash");
    let manifest = format!(
        "{{\n  \"profile\": \"rcp-1\",\n  \"domain\": \"flightrecorder.record.v2\",\n  \"description\": \"Full Decision Record content_hash vector (RCP §9.1). Signing vector lives in sign-vectors.json.\",\n  \"input\": {},\n  \"input_hex\": {},\n  \"canonical\": {},\n  \"canonical_hex\": {},\n  \"content_hash\": {}\n}}\n",
        jstr(record_input),
        jstr(&hex_lower(record_input.as_bytes())),
        jstr(&canonical),
        jstr(&hex_lower(canonical.as_bytes())),
        jstr(&content_hash),
    );
    std::fs::write(dir.join("record-basic.json"), &manifest).unwrap();
    println!("wrote {}", dir.join("record-basic.json").display());
    println!("content_hash = {content_hash}");

    // ---- signing vector (Ed25519 is deterministic per RFC 8032, so this is reproducible) ----
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8; // seed = 00 01 02 ... 1f
    }
    let sk = signing_key_from_seed(&seed);
    let sealed = seal(&rec, &sk).expect("seal");
    let sealed_ch = sealed.get("content_hash").unwrap().as_str().unwrap();
    let sealed_sig = sealed.get("sig").unwrap().as_str().unwrap();
    let pubkey = encode_pubkey(&sk.verifying_key());

    // ---- commitment vector ----
    let mut nonce = [0u8; 32];
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = 0xA0 ^ (i as u8);
    }
    let commit_value = "transfer $900.00 to acct 0xDEADBEEF";
    let commitment = commit(FieldDomain::Input, commit_value.as_bytes(), &nonce).unwrap();

    let sign_manifest = format!(
        "{{\n  \"profile\": \"rcp-1\",\n  \"description\": \"Ed25519 signing + hiding-commitment vectors. Ed25519 is deterministic, so an implementation MUST reproduce `sig` exactly from `seed_hex` over the record body.\",\n  \"seed_hex\": {},\n  \"pubkey\": {},\n  \"record_body\": {},\n  \"content_hash\": {},\n  \"sig\": {},\n  \"commitment\": {{\n    \"field_domain\": \"input\",\n    \"value\": {},\n    \"value_hex\": {},\n    \"nonce_hex\": {},\n    \"commitment\": {}\n  }}\n}}\n",
        jstr(&hex_lower(&seed)),
        jstr(&pubkey),
        jstr(record_input),
        jstr(sealed_ch),
        jstr(sealed_sig),
        jstr(commit_value),
        jstr(&hex_lower(commit_value.as_bytes())),
        jstr(&hex_lower(&nonce)),
        jstr(&commitment),
    );
    std::fs::write(dir.join("sign-vectors.json"), &sign_manifest).unwrap();
    println!("wrote {}", dir.join("sign-vectors.json").display());
    println!("sig = {sealed_sig}");

    // A full sealed record (canonical bytes) usable as a CLI fixture.
    std::fs::write(dir.join("record-sealed.json"), sealed.serialize()).unwrap();
    println!("wrote {}", dir.join("record-sealed.json").display());
    println!("pubkey = {pubkey}");
}
