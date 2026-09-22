//! `averin-verify` — offline verify CLI (wraps decision-core). Honest about what it proves.
//!
//!   averin-verify bundle <bundle.json> [opts.json]   full offline verification (records + checkpoint
//!                                                history + public keys); omission/fork/tamper.
//!                                                With opts.json the role-disjoint authority key sets are
//!                                                PINNED (authentic verification + the Tier-B/mode gates).
//!   averin-verify record <record.json> [pubkey]   single record; without a key = integrity only.

use averin_decision_core::record::{validate_record_shape, verify_content_hash, verify_sealed};
use averin_decision_core::sign::decode_pubkey;
use averin_decision_core::verify::{report_to_canon, verify_bundle_json, verify_bundle_with_json};
use averin_decision_core::CanonValue;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bundle") if args.len() >= 3 => verify_bundle_cmd(&args[2], args.get(3)),
        Some("record") if args.len() >= 3 => verify_record_cmd(&args[2], args.get(3)),
        _ => {
            eprintln!("usage:");
            eprintln!("  averin-verify bundle <bundle.json> [opts.json]   (opts.json pins role-disjoint keys)");
            eprintln!("  averin-verify record <record.json> [ed25519pub:<key>]");
            eprintln!();
            eprintln!("opts.json keys (each a role-disjoint set; omit a set to leave that mode unevaluated):");
            eprintln!("  signing_keys — the RECORD-SIGNING keys; pin them for AUTHENTIC verification (omitted =>");
            eprintln!("    internal consistency only; an empty [] is an error). Each is an ed25519pub: string or a");
            eprintln!("    {{key, status: active|retired|revoked|compromised, status_changed_at}} object (the");
            eprintln!("    authoritative RCP §10.2 compromise time). Disjoint from every role below but the broker.");
            eprintln!("  broker_authority_keys, resource_authority_keys, tsa_keys, taxonomy/taxonomy_keys/");
            eprintln!("  taxonomy_digest/taxonomy_version, attestation_keys, cosig_approver_keys, revocation_keys,");
            eprintln!("  federated_broker_keys (a {{broker_id: [keys]}} map), authority_keys — all base64url");
            eprintln!("  ed25519pub: strings (see docs/operator-verification.md).");
            ExitCode::from(2)
        }
    }
}

fn verify_bundle_cmd(path: &str, opts_path: Option<&String>) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    // With an opts.json, PIN the role-disjoint authority key sets (authentic verification + the Tier-B/mode
    // gates: cosig/revocation/federation/native/attestation/taxonomy). Without it, internal-consistency only
    // (keys from the bundle). The report comes back as canonical JSON either way, so one printer serves both.
    let report: CanonValue = match opts_path {
        Some(op) => {
            let opts_text = match std::fs::read_to_string(op) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: cannot read opts {op}: {e}");
                    return ExitCode::from(2);
                }
            };
            match CanonValue::parse(&verify_bundle_with_json(&text, &opts_text)) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("FAIL: verifier returned non-JSON: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        None => match verify_bundle_json(&text) {
            Ok(r) => report_to_canon(&r),
            Err(e) => {
                eprintln!("FAIL: bundle is not valid JSON/RCP: {e}");
                return ExitCode::from(1);
            }
        },
    };

    let gs = |k: &str| {
        report
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let gi = |k: &str| report.get(k).and_then(|v| v.as_int()).unwrap_or(0);
    let gb = |k: &str| matches!(report.get(k), Some(CanonValue::Bool(true)));

    println!("averin offline verification");
    let pid = gs("project_id");
    if !pid.is_empty() {
        println!("  project:      {pid}");
    }
    let bd = gs("bundle_digest"); // binds this verdict to the exact bytes verified (pair the report with the artifact)
    if !bd.is_empty() {
        println!("  bundle:       {bd}");
    }
    println!(
        "  records:      {}/{} integrity-proven",
        gi("records_proven"),
        gi("records_total")
    );
    if !gb("keys_externally_pinned") {
        println!(
            "  keys:         from the bundle (NOT externally pinned) — proves internal consistency"
        );
        println!("                under the bundle's own key claims, not authenticity. Pass an opts.json to PIN");
        println!(
            "                the role-disjoint authority keys (see docs/operator-verification.md)."
        );
    }
    println!(
        "  DAG:          {} ({} heads)",
        if gb("dag_ok") { "valid" } else { "INVALID" },
        gi("dag_heads")
    );
    // `checkpoints_anchored` counts anchors that VERIFIED under a pinned TSA; `checkpoints_anchors_attached` is
    // mere presence (an unverified token anyone can attach) — never print presence as "anchored".
    println!(
        "  checkpoints:  {}/{} verified, {} anchored (verified; {} attached), chain {}",
        gi("checkpoints_verified"),
        gi("checkpoints_total"),
        gi("checkpoints_anchored"),
        gi("checkpoints_anchors_attached"),
        if gb("chain_ok") { "ok" } else { "BROKEN" }
    );
    // Tier-B / ADR-0005 mode gates (only meaningful when the relevant key set was pinned via opts.json).
    println!(
        "  grant accountability: {} ({} grants, {} verified)",
        gs("grant_accountability"),
        gi("grant_total"),
        gi("grant_verified")
    );
    println!("  broker_trust:         {}", gs("broker_trust"));
    println!(
        "  uses:                 {} matched / {} pop-reverified ({} unmatched, {} pending)",
        gi("uses_matched"),
        gi("uses_pop_reverified"),
        gi("unmatched_violation"),
        gi("unmatched_pending")
    );
    for (label, key) in [
        ("taxonomy", "taxonomy_status"),
        ("attestation", "attestation_status"),
        ("cosig", "cosig_status"),
        ("delegation", "delegation_status"),
        ("revocation", "revocation_status"),
        ("revocation (merkle)", "revocation_merkle_status"),
        ("introspection", "introspection_status"),
        ("federation", "federation_status"),
    ] {
        let v = gs(key);
        if !v.is_empty() && v != "absent" && v != "unevaluated" {
            println!("  {label:<21} {v}");
        }
    }
    // Mode-specific counts (only printed when non-trivial — keeps the common single-broker output terse).
    let brokers_total = gi("brokers_total");
    if brokers_total > 0 {
        println!(
            "  federation brokers:   {}/{} seq-verified ({} suppressed, {} transitive via cross_broker_cert)",
            gi("brokers_seq_verified"), brokers_total, gi("cross_broker_suppression"), gi("transitive_grants")
        );
    } else if gi("transitive_grants") > 0 {
        println!(
            "  transitive_grants:    {} (elevated via cross_broker_cert)",
            gi("transitive_grants")
        );
    }
    if gi("revoked_uses_blocked") > 0 || gi("revoked_grants_matched") > 0 {
        println!(
            "  revocation blocks:    {} use(s) blocked, {} grant(s) matched on the list",
            gi("revoked_uses_blocked"),
            gi("revoked_grants_matched")
        );
    }
    if gi("revocation_nonmembership_verified") > 0 {
        println!(
            "  merkle non-revocation: {} grant(s) proven NOT revoked",
            gi("revocation_nonmembership_verified")
        );
    }
    println!(
        "  action_completeness:  {}  (resource_trust: {})",
        gs("action_completeness"),
        gs("resource_trust")
    );
    if let Some(issues) = report.get("issues").and_then(|v| v.as_array()) {
        for (i, iss) in issues.iter().enumerate() {
            if i >= 8 {
                println!("    … {} more issue(s)", issues.len() - 8);
                break;
            }
            if let Some(s) = iss.as_str() {
                println!("  ✗ {s}");
            }
        }
    }
    println!();
    if gb("ok") {
        // PASS is the INTEGRITY verdict (records sealed/linked, checkpoint chain consistent, no hard violation).
        // It is NOT the accountability capstone — echo that level on the same line so a reader never mistakes a
        // PASS for "fully accountable" when no role keys were pinned and the capstone is `not_claimed`.
        println!(
            "RESULT: PASS (integrity) — every record sealed, linked, and checkpoint-consistent."
        );
        println!(
            "        capstone: action_completeness={} · grant_accountability={} · broker_trust={}",
            gs("action_completeness"),
            gs("grant_accountability"),
            gs("broker_trust")
        );
        println!("NOTE: PASS is integrity-level; the capstone above is the higher claim. `not_claimed`/`incomplete`");
        println!("      are normal when role keys were not pinned (pass an opts.json to elevate). A `*_complete`");
        println!("      capstone is itself bounded by resource_trust:assumed_truthful (MF1).");
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
