//! SB-27: over every case of the committed verdict oracle corpus (formal/oracle/verdict-expected.json),
//! the Rust `claim_verdict` and the JS `claimVerdict` (verifier/claim-verdict.js, run with node)
//! produce the same headline word. The CLI prints `claim_verdict(..).word()` (see cli_verdict.rs
//! for the end-to-end binary check). Each corpus row is crossed with every requested claim,
//! `ok` true/false and `keys_externally_pinned` true/false, plus malformed-contract cases and
//! non-boolean `ok` / `keys_externally_pinned` values.
//!
//! Needs `node` on PATH (CI ubuntu runners have it). Not a proof: a finite differential.

use averin_decision_core::verify::claim_verdict;
use averin_decision_core::CanonValue;
use std::io::Write;
use std::process::{Command, Stdio};

const CLAIMS: [&str; 6] = [
    "integrity",
    "authenticated",
    "authorized",
    "historical_authorized_as_of_snapshot",
    "complete_brokered",
    "complete_introspected",
];

fn report_json(
    ok: bool,
    pinned: bool,
    version: &str,
    row: &CanonValue,
    requested: &str,
    decision: Option<&str>,
) -> String {
    let field = |k: &str| row.get(k).and_then(CanonValue::as_str).unwrap().to_string();
    let decision = decision
        .map(str::to_string)
        .unwrap_or_else(|| field(requested));
    format!(
        r#"{{"ok":{ok},"keys_externally_pinned":{pinned},"claims_version":"{version}","claims":{{"integrity":"{}","authenticated":"{}","authorized":"{}","historical_authorized_as_of_snapshot":"{}","temporal":"{}","complete_brokered":"{}","complete_introspected":"{}","requested":"{requested}","requested_decision":"{decision}"}}}}"#,
        field("integrity"),
        field("authenticated"),
        field("authorized"),
        field("historical_authorized_as_of_snapshot"),
        field("temporal"),
        field("complete_brokered"),
        field("complete_introspected"),
    )
}

#[test]
fn rust_and_js_headline_words_agree_over_the_corpus() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let corpus = std::fs::read_to_string(root.join("formal/oracle/verdict-expected.json")).unwrap();
    let rows = CanonValue::parse(&corpus).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1324);

    let mut reports = Vec::new();
    for row in rows {
        for requested in CLAIMS {
            for ok in [true, false] {
                for pinned in [true, false] {
                    reports.push(report_json(ok, pinned, "2", row, requested, None));
                }
            }
        }
    }
    // Malformed or mismatched contracts must agree too (never accepted, never a crash).
    let first = &rows[rows.len() - 1];
    for pinned in [true, false] {
        reports.push(report_json(true, pinned, "3", first, "authorized", None));
        reports.push(report_json(
            true,
            pinned,
            "2",
            first,
            "authorized",
            Some("unknown"),
        ));
        reports.push(report_json(
            true,
            pinned,
            "2",
            first,
            "authorized",
            Some("refuted"),
        ));
        reports.push(report_json(
            true,
            pinned,
            "2",
            first,
            "bogus_claim",
            Some("satisfied"),
        ));
    }
    // Non-boolean flags: the Rust rule accepts only the JSON boolean true for `ok` and
    // `keys_externally_pinned`, so a truthy string or number must not read as ok or as pinned in JS.
    let base = report_json(true, true, "2", first, "authorized", Some("satisfied"));
    for v in [r#""false""#, r#""true""#, "1", "0", "null", "{}", "[]"] {
        reports.push(base.replace(
            r#""keys_externally_pinned":true"#,
            &format!(r#""keys_externally_pinned":{v}"#),
        ));
        reports.push(base.replace(r#""ok":true"#, &format!(r#""ok":{v}"#)));
    }
    reports.push(r#"{"ok":true,"keys_externally_pinned":true}"#.to_string());
    reports.push(r#"{"ok":true,"keys_externally_pinned":true,"claims_version":"2"}"#.to_string());
    reports.push("{}".to_string());

    let rust: Vec<&'static str> = reports
        .iter()
        .map(|r| claim_verdict(&CanonValue::parse(r).unwrap()).word())
        .collect();

    let js_path = root.join("verifier/claim-verdict.js");
    let script = format!(
        "import {{claimVerdict}} from {url:?};\n\
         const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));\n\
         process.stdout.write(JSON.stringify(input.map(r => claimVerdict(JSON.parse(r)).word)));",
        url = format!("file://{}", js_path.canonicalize().unwrap().display())
    );
    let mut child = Command::new("node")
        .args(["--input-type=module", "-e"])
        .arg(script.replace("require('node:fs')", "(await import('node:fs'))"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("node must be on PATH for the JS differential");
    let payload = serde_json_lite(&reports);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "node failed");
    let js = CanonValue::parse(&String::from_utf8(out.stdout).unwrap()).unwrap();
    let js: Vec<&str> = js
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(js.len(), rust.len());
    for (i, (a, b)) in rust.iter().zip(js.iter()).enumerate() {
        assert_eq!(a, b, "case {i}: {}", reports[i]);
    }
    // The corpus must exercise every word, or the differential proves little.
    for word in ["PASS", "CONSISTENT", "INSUFFICIENT", "FAIL"] {
        assert!(rust.contains(&word), "{word} never produced");
    }
}

/// A JSON array of strings (the reports contain no characters that need escaping beyond quotes).
fn serde_json_lite(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&s.replace('\\', "\\\\").replace('"', "\\\""));
        out.push('"');
    }
    out.push(']');
    out
}
