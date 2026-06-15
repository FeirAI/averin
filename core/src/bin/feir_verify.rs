//! `feir-verify` — offline verify CLI (wraps decision-core). Honest about what it proves.
//!
//!   feir-verify bundle <bundle.json>            full offline verification (records + checkpoint
//!                                                history + public keys); omission/fork/tamper.
//!   feir-verify record <record.json> [pubkey]   single record; without a key = integrity only.

use feir_decision_core::record::{validate_record_shape, verify_content_hash, verify_sealed};
use feir_decision_core::sign::decode_pubkey;
use feir_decision_core::verify::{verify_bundle_json, TrustLevel};
use feir_decision_core::CanonValue;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bundle") if args.len() >= 3 => verify_bundle_cmd(&args[2]),
        Some("record") if args.len() >= 3 => verify_record_cmd(&args[2], args.get(3)),
        _ => {
            eprintln!("usage:");
            eprintln!("  feir-verify bundle <bundle.json>");
            eprintln!("  feir-verify record <record.json> [ed25519pub:<key>]");
            ExitCode::from(2)
        }
    }
}

fn verify_bundle_cmd(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let report = match verify_bundle_json(&text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL: bundle is not valid JSON/RCP: {e}");
            return ExitCode::from(1);
        }
    };

    println!("feir offline verification");
    if let Some(p) = &report.project_id {
        println!("  project:      {p}");
    }
    println!(
        "  records:      {}/{} integrity-proven",
        report.records_proven, report.records_total
    );
    if !report.keys_externally_pinned {
        println!("  keys:         from the bundle (NOT externally pinned) — proves internal");
        println!("                consistency under the bundle's own key claims, not authenticity");
        println!("                against an out-of-band trust root.");
    }
    println!(
        "  DAG:          {} ({} heads, {} duplicates collapsed)",
        if report.dag_ok { "valid" } else { "INVALID" },
        report.dag_heads,
        report.collapsed_duplicates
    );
    println!(
        "  checkpoints:  {}/{} verified, {} anchored, chain {}",
        report.checkpoints_verified,
        report.checkpoints_total,
        report.checkpoints_anchored,
        if report.chain_ok { "ok" } else { "BROKEN" }
    );
    for t in &report.record_trust {
        let mark = match t.trust {
            TrustLevel::IntegrityProven => "✓",
            TrustLevel::Untrusted => "✗",
        };
        println!(
            "    {mark} {:<10} via {:<5} key={:<10} {}",
            t.record_id,
            t.observed_via,
            t.key_status,
            t.notes.first().cloned().unwrap_or_default()
        );
    }
    if let Some(b) = &report.first_broken_link {
        println!("  first broken link: {b}");
    }
    println!();
    if report.ok {
        println!(
            "RESULT: PASS — every record sealed, linked, and checkpoint-consistent (Level 1)."
        );
        println!("NOTE: this proves integrity/provenance, not that the records are a COMPLETE account (Level 3).");
        ExitCode::SUCCESS
    } else {
        println!("RESULT: FAIL — see issues above.");
        ExitCode::from(1)
    }
}

fn verify_record_cmd(path: &str, pubkey: Option<&String>) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let value = match CanonValue::parse(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(1);
        }
    };
    match pubkey {
        Some(pk) => {
            let vk = match decode_pubkey(pk) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: bad public key: {e}");
                    return ExitCode::from(2);
                }
            };
            match verify_sealed(&value, &vk) {
                Ok(()) => {
                    println!("PASS (authentic): shape + content_hash + signature verified");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("FAIL: {e}");
                    ExitCode::from(1)
                }
            }
        }
        None => match validate_record_shape(&value).and_then(|()| verify_content_hash(&value)) {
            Ok(()) => {
                println!(
                    "PASS (integrity only): content_hash recomputes and shape is valid.\n\
                     NOTE: not authenticated — pass the signer's ed25519pub: key to verify the signature."
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("FAIL: {e}");
                ExitCode::from(1)
            }
        },
    }
}
