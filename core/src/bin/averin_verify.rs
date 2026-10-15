//! `averin-verify` — offline verify CLI (wraps decision-core). Honest about what it proves.
//!
//!   averin-verify bundle <bundle.json> [opts.json]   full offline verification (records + checkpoint
//!                                                history + public keys); omission/fork/tamper.
//!                                                With opts.json the role-disjoint authority key sets are
//!                                                PINNED (authentic verification + the Tier-B/mode gates).
//!   averin-verify record <record.json> [pubkey]   single record; without a key = integrity only.
//!   averin-verify split <bundle.json> <outdir>    split a whole-history bundle into one month segment per
//!                                                month (`<project>-<YYYY-MM>.json`), AVE-01.
//!   averin-verify chain [--opts opts.json] <month1.json> <month2.json> ...
//!                                                verify month segments in order, each pinned to the
//!                                                previous month's head, and resolve the parents that
//!                                                point before a month's base.
//!
//! `bundle` prints `RESULT: <word>` where the word is the same `claimVerdict` rule as the browser
//! verifier (`verifier/claim-verdict.js`). `record` prints a `RESULT:` line with the same words and
//! exit codes: PASS (0) only with the signer's key passed on the command line, CONSISTENT (2) for
//! a keyless record whose shape and content hash check out, FAIL (1) when a check fails or the
//! file is not valid JSON. `bundle` exits:
//!   0  PASS          requested claim satisfied AND the signing keys were pinned externally
//!   2  CONSISTENT    requested claim satisfied only under the bundle's own keys (internal
//!                    consistency, not authenticity)
//!   1  FAIL          legacy `ok` false, or the requested claim is refuted
//!   1  INSUFFICIENT  requested claim not satisfied, or the claims contract missing or invalid
//! Usage errors and unreadable input files also exit 2 and print no `RESULT:` line (stderr only);
//! read the `RESULT:` line, not only the exit code, to tell CONSISTENT from a usage error.

use averin_decision_core::record::{validate_record_shape, verify_content_hash, verify_sealed};
use averin_decision_core::segment::{split_bundle, ChainState};
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
        Some("split") if args.len() == 4 => split_cmd(&args[2], &args[3]),
        Some("chain") if args.len() >= 3 => chain_cmd(&args[2..]),
        _ => {
            eprintln!("usage:");
            eprintln!("  averin-verify bundle <bundle.json> [opts.json]   (opts.json pins role-disjoint keys)");
            eprintln!("  averin-verify record <record.json> [ed25519pub:<key>]");
            eprintln!("  averin-verify split <bundle.json> <outdir>   (one month segment per month, AVE-01)");
            eprintln!("  averin-verify chain [--opts opts.json] <month1.json> <month2.json> ...");
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
    if let Some(sg) = report.get("segment") {
        let t = |k: &str| {
            sg.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string()
        };
        let n = |k: &str| sg.get(k).and_then(|v| v.as_int());
        println!(
            "  segment:      MONTH {} · base checkpoint {} · head checkpoint {} ({} records through the head) · link {}",
            t("month"),
            n("base_seq").map_or("none (first month)".to_string(), |v| v.to_string()),
            n("head_seq").map_or("-".to_string(), |v| v.to_string()),
            n("head_record_count").map_or("-".to_string(), |v| v.to_string()),
            t("link")
        );
        println!(
            "                this covers one month only. Earlier months are NOT checked here; run"
        );
        println!(
            "                `averin-verify chain` over every month to check the whole history."
        );
    }
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
    // The same words and exit codes as `bundle` (`ClaimVerdict`): PASS only under a key the
    // caller passed (externally pinned). A record whose shape and content hash check out without
    // a key is CONSISTENT (exit 2): nothing authenticated it.
    let (verdict, detail) = match CanonValue::parse(&text) {
        Err(e) => (ClaimVerdict::Fail, e.to_string()),
        Ok(value) => match pubkey {
            Some(pk) => {
                let vk = match decode_pubkey(pk) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("error: bad public key: {e}");
                        return ExitCode::from(2);
                    }
                };
                match verify_sealed(&value, &vk) {
                    Ok(()) => (
                        ClaimVerdict::Pass,
                        "(authentic): shape, content_hash and signature verified under the key you passed."
                            .to_string(),
                    ),
                    Err(e) => (ClaimVerdict::Fail, e.to_string()),
                }
            }
            None => match validate_record_shape(&value).and_then(|()| verify_content_hash(&value)) {
                Ok(()) => (
                    ClaimVerdict::Consistent,
                    "(integrity only): content_hash recomputes and shape is valid.\n        \
                     NOT authenticated: no key was given, so the signature was not checked. Pass the \
                     signer's ed25519pub: key to verify it."
                        .to_string(),
                ),
                Err(e) => (ClaimVerdict::Fail, e.to_string()),
            },
        },
    };
    if verdict == ClaimVerdict::Fail {
        println!("RESULT: {}: {detail}", verdict.word());
    } else {
        println!("RESULT: {} {detail}", verdict.word());
    }
    ExitCode::from(verdict.exit_code())
}

/// `averin-verify split <bundle.json> <outdir>`: write one `<project>-<YYYY-MM>.json` per month.
fn split_cmd(path: &str, outdir: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let bundle = match CanonValue::parse(&text) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FAIL: bundle is not valid JSON/RCP: {e}");
            return ExitCode::from(1);
        }
    };
    let segments = match split_bundle(&bundle) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FAIL: cannot split: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::create_dir_all(outdir) {
        eprintln!("error: cannot create {outdir}: {e}");
        return ExitCode::from(2);
    }
    let pid: String = bundle
        .get("project_id")
        .and_then(CanonValue::as_str)
        .unwrap_or("project")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    for (month, seg) in &segments {
        let file = std::path::Path::new(outdir).join(format!("{pid}-{month}.json"));
        if let Err(e) = std::fs::write(&file, seg.serialize()) {
            eprintln!("error: cannot write {}: {e}", file.display());
            return ExitCode::from(2);
        }
        println!("{}", file.display());
    }
    eprintln!(
        "split into {} month segment(s). Any revocation_list or deployment_attestation was not copied (it binds the whole bundle's latest checkpoint). Verify the result with `averin-verify chain`.",
        segments.len()
    );
    ExitCode::SUCCESS
}

/// `averin-verify chain [--opts opts.json] <month1.json> ...`: verify the months in the order given, each pinned to
/// the previous month's head (`genesis` for the first), then resolve cross-month parents. Reads one file at a time.
fn chain_cmd(args: &[String]) -> ExitCode {
    let (opts_text, files) = match args.first().map(String::as_str) {
        Some("--opts") if args.len() >= 3 => match std::fs::read_to_string(&args[1]) {
            Ok(t) => (Some(t), &args[2..]),
            Err(e) => {
                eprintln!("error: cannot read opts {}: {e}", args[1]);
                return ExitCode::from(2);
            }
        },
        _ => (None, args),
    };
    let base_opts = match &opts_text {
        Some(t) => match CanonValue::parse(t) {
            Ok(o) if o.as_object().is_some() => o,
            _ => {
                eprintln!("error: opts is not a JSON object");
                return ExitCode::from(2);
            }
        },
        None => CanonValue::Object(Vec::new()),
    };
    let mut chain = ChainState::new();
    let mut all_pinned = true;
    for file in files {
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: cannot read {file}: {e}");
                return ExitCode::from(2);
            }
        };
        let bundle = match CanonValue::parse(&text) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("FAIL: {file} is not valid JSON/RCP: {e}");
                return ExitCode::from(1);
            }
        };
        let mut members = base_opts.as_object().cloned().unwrap_or_default();
        members.retain(|(k, _)| k != "segment_base_checkpoint_hash");
        members.push((
            "segment_base_checkpoint_hash".into(),
            CanonValue::string(chain.next_pin()),
        ));
        let opts = match CanonValue::object(members) {
            Ok(o) => o.serialize(),
            Err(e) => {
                eprintln!("error: opts: {e}");
                return ExitCode::from(2);
            }
        };
        let report = match CanonValue::parse(&verify_bundle_with_json(&text, &opts)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("FAIL: verifier returned non-JSON: {e}");
                return ExitCode::from(1);
            }
        };
        let ok = matches!(report.get("ok"), Some(CanonValue::Bool(true)));
        all_pinned &= matches!(
            report.get("keys_externally_pinned"),
            Some(CanonValue::Bool(true))
        );
        let month = report
            .get("segment")
            .and_then(|s| s.get("month"))
            .and_then(CanonValue::as_str)
            .unwrap_or("?");
        println!(
            "  {file}: {} month {month}, {} records, link {}",
            if ok { "ok" } else { "FAIL" },
            report
                .get("records_total")
                .and_then(CanonValue::as_int)
                .unwrap_or(0),
            report
                .get("segment")
                .and_then(|s| s.get("link"))
                .and_then(CanonValue::as_str)
                .unwrap_or("-")
        );
        if !ok {
            if let Some(issues) = report.get("issues").and_then(CanonValue::as_array) {
                for i in issues.iter().take(5).filter_map(CanonValue::as_str) {
                    println!("    x {i}");
                }
            }
        }
        chain.absorb(&bundle, &report);
    }
    for i in &chain.issues {
        println!("  x {i}");
    }
    if chain.is_ok() {
        println!(
            "RESULT: {} (chain): {} month(s), {} records, head {} ({} records through it).",
            if all_pinned { "PASS" } else { "CONSISTENT" },
            chain.months,
            chain.records,
            chain.head_hash().unwrap_or("-"),
            chain.head_record_count()
        );
        println!(
            "        Each month verified and links to the previous head; the first month starts at genesis."
        );
        println!(
            "        Not checked across months: grant-log transparency and federation heads (verify a whole-history bundle for those)."
        );
        if all_pinned {
            ExitCode::SUCCESS
        } else {
            println!(
                "        keys are the bundles' own, NOT externally pinned: pass --opts with signing_keys to check authenticity."
            );
            ExitCode::from(2)
        }
    } else {
        println!("RESULT: FAIL (chain): see above.");
        ExitCode::from(1)
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
