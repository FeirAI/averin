//! `averin-verify` — offline verify CLI (wraps decision-core). Honest about what it proves.
//!
//!   averin-verify bundle <bundle.json> [opts.json]   full offline verification (records + checkpoint
//!                                                history + public keys); omission/fork/tamper.
//!                                                With opts.json the role-disjoint authority key sets are
//!                                                PINNED (authentic verification + the Tier-B/mode gates).
//!   averin-verify record <record.json> [pubkey]   single record; without a key = integrity only.
//!
//! `bundle` prints `RESULT: <word>` where the word is the same `claimVerdict` rule as the browser
//! verifier (`verifier/claim-verdict.js`) and exits:
//!   0  PASS          requested claim satisfied AND the signing keys were pinned externally
//!   2  CONSISTENT    requested claim satisfied only under the bundle's own keys (internal
//!                    consistency, not authenticity)
//!   1  FAIL          legacy `ok` false, or the requested claim is refuted
//!   1  INSUFFICIENT  requested claim not satisfied, or the claims contract missing or invalid
//! Usage errors and unreadable input files also exit 2 and print no `RESULT:` line (stderr only);
//! read the `RESULT:` line, not only the exit code, to tell CONSISTENT from a usage error.

use averin_decision_core::record::{validate_record_shape, verify_content_hash, verify_sealed};
use averin_decision_core::sign::decode_pubkey;
use averin_decision_core::verify::{
    claim_verdict, report_to_canon, verify_bundle_json, verify_bundle_with_json, ClaimVerdict,
};
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
            eprintln!("  claim_policy: {{requested: integrity|authenticated|authorized|");
            eprintln!(
                "    historical_authorized_as_of_snapshot|complete_brokered|complete_introspected,"
            );
            eprintln!("    revocation: pinned|disclosed|merkle|both, require_disclosure: bool,");
            eprintln!("    require_attestation: bool}}.");
            eprintln!("  revocation_temporal: {{policy: strict}} (default) or {{policy: db_serialized_v1,");
            eprintln!(
                "    evaluation_time: YYYY-MM-DDTHH:MM:SS.mmmZ, max_snapshot_age_seconds: N,"
            );
            eprintln!(
                "    min_authorization_watermark: N}}. Historical ordering against revocation is"
            );
            eprintln!("    database order under honest signers, never physical action time.");
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
    // Plan 009: current revocation above stays authoritative; historical ordering is separate.
    if let Some(t) = report.get("revocation_temporal") {
        let ts = |k: &str| t.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ti = |k: &str| t.get(k).and_then(|v| v.as_int()).unwrap_or(0);
        let snap = t.get("snapshot");
        let ss = |k: &str| {
            snap.and_then(|s| s.get(k))
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string()
        };
        if ts("policy") == "db_serialized_v1" || ss("status") != "absent" {
            println!(
                "  revocation temporal:  policy {} · snapshot {} (boundary {}, watermark {})",
                ts("policy"),
                ss("status"),
                ss("boundary_time"),
                snap.and_then(|s| s.get("authorization_high_watermark"))
                    .and_then(|v| v.as_int())
                    .map_or("-".to_string(), |w| w.to_string())
            );
            println!(
                "  historical ordering:  {} proven_before / {} at_or_after / {} indeterminate",
                ti("proven_before"),
                ti("at_or_after"),
                ti("indeterminate")
            );
            if ts("policy") == "db_serialized_v1" {
                println!("                        (database order only; not physical action time)");
            }
        }
    }
    println!(
        "  action_completeness:  {}  (resource_trust: {})",
        gs("action_completeness"),
        gs("resource_trust")
    );
    let claims = report.get("claims");
    let requested = claims
        .and_then(|c| c.get("requested"))
        .and_then(|v| v.as_str())
        .unwrap_or("integrity");
    let requested_decision = claims
        .and_then(|c| c.get("requested_decision"))
        .and_then(|v| v.as_str())
        .unwrap_or("insufficient");
    println!(
        "  requested claim: {requested} — {requested_decision} (claims v{})",
        gs("claims_version")
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
    // The headline word is `claimVerdict` (core/src/verify/headline.rs, verifier/claim-verdict.js):
    // PASS needs the requested claim satisfied AND externally pinned keys; the same satisfied claim
    // under the bundle's own keys is CONSISTENT (internal consistency, not authenticity).
    let verdict = claim_verdict(&report);
    match verdict {
        ClaimVerdict::Pass | ClaimVerdict::Consistent => {
            println!(
                "RESULT: {} ({requested}): requested claim satisfied; integrity diagnostics clean.",
                verdict.word()
            );
            if verdict == ClaimVerdict::Consistent {
                println!(
                    "        keys are the bundle's own, NOT externally pinned: this proves internal consistency only, not authenticity."
                );
            }
            if let Some(note) = historical_claim_note(&report) {
                println!("{note}");
            }
            println!(
                "        capstone: action_completeness={} · grant_accountability={} · broker_trust={}",
                gs("action_completeness"),
                gs("grant_accountability"),
                gs("broker_trust")
            );
            println!(
                "NOTE: The capstone remains bounded by resource_trust:assumed_truthful (MF1)."
            );
        }
        ClaimVerdict::Insufficient | ClaimVerdict::Fail => {
            println!(
                "RESULT: {}: integrity diagnostics or requested claim are not satisfied; see above.",
                verdict.word()
            );
            if let Some(note) = historical_claim_note(&report) {
                println!("{note}");
            }
        }
    }
    ExitCode::from(verdict.exit_code())
}

// V-L3: the legacy `ok` is a separate integrity result and can be false while the caller's
// requested historical_authorized_as_of_snapshot claim is satisfied. A consumer of that claim must
// read claims.* directly, never infer it from `ok`, so print the claim's own decision next to the
// legacy verdict whenever it was the requested claim (claims_version "2"). Same rule as the browser
// verifier and the web app: the requested decision under a valid claims contract (a known decision
// equal to the claim's own field), else "insufficient".
fn historical_claim_note(report: &CanonValue) -> Option<String> {
    if report.get("claims_version").and_then(CanonValue::as_str) != Some("2") {
        return None;
    }
    let claims = report.get("claims")?;
    if claims.get("requested").and_then(CanonValue::as_str)
        != Some("historical_authorized_as_of_snapshot")
    {
        return None;
    }
    let requested = claims
        .get("requested_decision")
        .and_then(CanonValue::as_str);
    let own = claims
        .get("historical_authorized_as_of_snapshot")
        .and_then(CanonValue::as_str);
    let decision = match requested {
        Some(d @ ("satisfied" | "insufficient" | "refuted")) if own == Some(d) => d,
        _ => "insufficient",
    };
    Some(format!(
        "        historical_authorized_as_of_snapshot: {decision} (read claims.*; the legacy ok is a separate integrity result and can differ)"
    ))
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

#[cfg(test)]
mod claim_contract_tests {
    use super::*;

    /// A report with a clean `ok` and pinned keys passes only under a valid satisfied contract.
    fn claim_contract_satisfied(report: &CanonValue) -> bool {
        let mut fields = match report {
            CanonValue::Object(f) => f.clone(),
            _ => vec![],
        };
        fields.push(("ok".into(), CanonValue::Bool(true)));
        fields.push(("keys_externally_pinned".into(), CanonValue::Bool(true)));
        claim_verdict(&CanonValue::object(fields).unwrap()) == ClaimVerdict::Pass
    }

    fn report(version: &str, decision: &str) -> CanonValue {
        CanonValue::object(vec![
            ("claims_version".into(), CanonValue::string(version)),
            (
                "claims".into(),
                CanonValue::object(vec![
                    ("requested".into(), CanonValue::string("authorized")),
                    ("authorized".into(), CanonValue::string(decision)),
                    ("requested_decision".into(), CanonValue::string(decision)),
                ])
                .unwrap(),
            ),
        ])
        .unwrap()
    }

    #[test]
    fn unsupported_or_malformed_claims_never_pass() {
        assert!(claim_contract_satisfied(&report("2", "satisfied")));
        assert!(!claim_contract_satisfied(&report("1", "satisfied")));
        assert!(!claim_contract_satisfied(&report("3", "satisfied")));
        assert!(!claim_contract_satisfied(&report("2", "insufficient")));
        assert!(!claim_contract_satisfied(&report("2", "refuted")));
        assert!(!claim_contract_satisfied(
            &CanonValue::object(vec![]).unwrap()
        ));
        let mut mismatched = report("2", "satisfied");
        if let CanonValue::Object(ref mut fields) = mismatched {
            if let Some((_, CanonValue::Object(claims))) =
                fields.iter_mut().find(|(k, _)| k == "claims")
            {
                if let Some((_, value)) = claims.iter_mut().find(|(k, _)| k == "authorized") {
                    *value = CanonValue::string("insufficient");
                }
            }
        }
        assert!(!claim_contract_satisfied(&mismatched));
    }

    fn historical_report(version: &str, decision: &str) -> CanonValue {
        CanonValue::object(vec![
            ("claims_version".into(), CanonValue::string(version)),
            ("ok".into(), CanonValue::Bool(false)),
            (
                "claims".into(),
                CanonValue::object(vec![
                    (
                        "requested".into(),
                        CanonValue::string("historical_authorized_as_of_snapshot"),
                    ),
                    (
                        "historical_authorized_as_of_snapshot".into(),
                        CanonValue::string(decision),
                    ),
                    ("requested_decision".into(), CanonValue::string(decision)),
                ])
                .unwrap(),
            ),
        ])
        .unwrap()
    }

    #[test]
    fn historical_claim_note_names_the_decision_even_while_ok_is_false() {
        let note = historical_claim_note(&historical_report("2", "satisfied"))
            .expect("requested historical claim under a valid v2 contract yields a note");
        assert!(note.contains("satisfied"));
        assert!(note.contains("historical_authorized_as_of_snapshot"));
    }

    #[test]
    fn historical_claim_note_falls_back_to_insufficient_under_an_invalid_contract() {
        let mismatched = CanonValue::object(vec![
            ("claims_version".into(), CanonValue::string("2")),
            (
                "claims".into(),
                CanonValue::object(vec![
                    (
                        "requested".into(),
                        CanonValue::string("historical_authorized_as_of_snapshot"),
                    ),
                    (
                        "historical_authorized_as_of_snapshot".into(),
                        CanonValue::string("satisfied"),
                    ),
                    ("requested_decision".into(), CanonValue::string("refuted")),
                ])
                .unwrap(),
            ),
        ])
        .unwrap();
        let note = historical_claim_note(&mismatched).expect("requested historical claim");
        assert!(note.contains(": insufficient"), "{note}");
        let unknown = historical_claim_note(&historical_report("2", "maybe")).unwrap();
        assert!(unknown.contains(": insufficient"), "{unknown}");
        let refuted = historical_claim_note(&historical_report("2", "refuted")).unwrap();
        assert!(refuted.contains(": refuted"), "{refuted}");
        assert!(!refuted.contains("revoked"), "neutral wording: {refuted}");
    }

    #[test]
    fn historical_claim_note_is_none_for_a_different_requested_claim() {
        assert!(historical_claim_note(&report("2", "satisfied")).is_none());
    }

    #[test]
    fn historical_claim_note_is_none_for_an_unsupported_claims_version() {
        assert!(historical_claim_note(&historical_report("1", "satisfied")).is_none());
        assert!(historical_claim_note(&CanonValue::object(vec![]).unwrap()).is_none());
    }
}
