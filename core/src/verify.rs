//! Offline bundle verification (RCP §10.1) — the capstone the CLI and WASM verifier call.
//!
//! Given an export bundle (records + full checkpoint history + public keys + anchors), produce a
//! [`VerifyReport`]: per-record trust annotations, DAG validity, and checkpoint-chain soundness
//! (omission #1 / fork #2 detection), plus external-anchor checks (backdating #3, key-compromise
//! #9). Never panics on attacker-controlled input.
//!
//! **Trust roots.** The bundle's `keys` list and `anchor` tokens are *attacker-supplied*. Pass
//! externally-pinned signing keys via [`VerifyOptions::trusted_keys`] and trusted TSA keys via
//! [`VerifyOptions::trusted_tsa_keys`] (both obtained out-of-band). Without signing-key pinning the
//! report sets `keys_externally_pinned = false` and proves only *internal consistency under the
//! bundle's own key claims*. A `revoked`/`compromised` status (worst of record-asserted and bundle-
//! asserted) downgrades a record to `Untrusted` **unless** an anchored checkpoint with anchor-time
//! `≤ status_changed_at` transitively commits it (RCP §10.2, threat #9).

use crate::anchor::verify_anchor;
use crate::authority::{verify_authority, AuthorityTrust};
use crate::canon::CanonValue;
use crate::checkpoint::{validate_chain, verify_checkpoint_sealed};
use crate::dag;
use crate::record::{validate_record_shape, verify_content_hash, verify_sealed};
use crate::sign::decode_pubkey;
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// L1: bytes sealed by a valid (and, if pinning is in effect, externally-trusted) key and
    /// unchanged since — or sealed by a later-compromised key but anchored before the compromise.
    IntegrityProven,
    /// Integrity/signature failed, key unavailable/unpinned, or key revoked/compromised without a
    /// qualifying anchor — provenance is not trustworthy.
    Untrusted,
}

#[derive(Debug, Clone)]
pub struct RecordTrust {
    pub index: usize,
    pub record_id: String,
    pub content_hash: String,
    pub integrity_ok: bool,
    pub signature_ok: bool,
    pub key_status: String,
    pub observed_via: String,
    pub trust: TrustLevel,
    /// Authority gradient (threat #4): none|declared|verified|failed. `verified` = an evidence_sig
    /// checked out under a pinned authority key, not just the agent's claim.
    pub authority: AuthorityTrust,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub ok: bool,
    pub project_id: Option<String>,
    pub keys_externally_pinned: bool,
    pub records_total: usize,
    pub records_proven: usize,
    pub record_trust: Vec<RecordTrust>,
    pub dag_ok: bool,
    pub dag_heads: usize,
    pub collapsed_duplicates: usize,
    pub checkpoints_total: usize,
    pub checkpoints_verified: usize,
    pub checkpoints_anchored: usize,
    pub chain_ok: bool,
    /// Selective-disclosure entries in the bundle, and how many matched their record's commitment.
    pub disclosures_total: usize,
    pub disclosures_verified: usize,
    /// Credential-broker grants (`event_type=credential_grant`) and how many verified to
    /// `gateway_enforced` under a pinned authority key (Level 3 Tier-A grant accountability).
    pub grant_total: usize,
    pub grant_verified: usize,
    /// The bundle's `coverage_manifest` echoed verbatim (the verifier does NOT trust it; it surfaces
    /// it so an auditor can evaluate the out-of-band attestations). `None` if absent.
    pub coverage_manifest: Option<CanonValue>,
    pub issues: Vec<String>,
    pub first_broken_link: Option<String>,
}

/// An out-of-band pinned key. Beyond the public-key bytes it may carry the *authoritative* key
/// status and compromise time (e.g. from a key-transparency record) — which the verifier trusts
/// over the bundle's self-asserted claims, closing the future-dated-compromise escalation.
pub struct TrustedKey {
    pub vk: VerifyingKey,
    pub status: Option<String>,
    pub status_changed_at: Option<String>,
}

impl From<VerifyingKey> for TrustedKey {
    fn from(vk: VerifyingKey) -> Self {
        TrustedKey {
            vk,
            status: None,
            status_changed_at: None,
        }
    }
}

#[derive(Default)]
pub struct VerifyOptions {
    /// If `Some`, a record is only `IntegrityProven` when its resolved key is in this set. When a
    /// pinned key carries `status`/`status_changed_at`, those authoritative values override the
    /// bundle's self-asserted claims (so an attacker cannot future-date a compromise to upgrade).
    pub trusted_keys: Option<Vec<TrustedKey>>,
    /// Trusted Ed25519 TSA keys for the hermetic `test-anchor` scheme (out-of-band).
    pub trusted_tsa_keys: Vec<VerifyingKey>,
    /// Trusted DER `SubjectPublicKeyInfo`s for real RFC 3161 TSAs (used with the `rfc3161` feature).
    pub trusted_tsa_spki: Vec<Vec<u8>>,
    /// Trusted authority-system public keys (policy engine / approval service). An `evidence_sig`
    /// that verifies under one of these elevates a record's authority to `verified` (threat #4).
    pub trusted_authority_keys: Vec<VerifyingKey>,
}

struct KeyEntry {
    vk: VerifyingKey,
    status: String,
    status_changed_at: Option<String>,
}

/// Provisional per-record state from pass 1, finalized in pass 2 after anchors are known.
struct Pending {
    index: usize,
    record_id: String,
    content_hash: String,
    observed_via: String,
    integrity_ok: bool,
    signature_ok: bool,
    pinned: bool,
    project_ok: bool,
    eff_status: String,
    status_changed_at: Option<String>,
    authority: AuthorityTrust,
    notes: Vec<String>,
}

fn s(v: &CanonValue, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string())
}

fn arr<'a>(
    bundle: &'a CanonValue,
    k: &str,
    empty: &'a [CanonValue],
    issues: &mut Vec<String>,
) -> &'a [CanonValue] {
    match bundle.get(k) {
        Some(v) => match v.as_array() {
            Some(a) => a.as_slice(),
            None => {
                issues.push(format!(
                    "bundle.{k} is present but not an array (malformed)"
                ));
                empty
            }
        },
        None => empty,
    }
}

fn status_rank(s: &str) -> u8 {
    match s {
        "active" => 0,
        "retired" => 1,
        "revoked" => 2,
        "compromised" => 3,
        _ => 4,
    }
}
fn worst_status(a: &str, b: &str) -> String {
    if status_rank(a) >= status_rank(b) {
        a
    } else {
        b
    }
    .to_string()
}

/// True iff `s` is exactly `YYYY-MM-DDThh:mm:ss.mmmZ` (fixed-ms UTC). Lexical `<=` on two such
/// strings equals chronological order; we only compare anchor vs status-change times that pass this.
fn is_canonical_ts(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 24 {
        return false;
    }
    let digit = |i: usize| b[i].is_ascii_digit();
    (0..4).all(digit)
        && b[4] == b'-'
        && digit(5)
        && digit(6)
        && b[7] == b'-'
        && digit(8)
        && digit(9)
        && b[10] == b'T'
        && digit(11)
        && digit(12)
        && b[13] == b':'
        && digit(14)
        && digit(15)
        && b[16] == b':'
        && digit(17)
        && digit(18)
        && b[19] == b'.'
        && digit(20)
        && digit(21)
        && digit(22)
        && b[23] == b'Z'
}

/// All content_hashes reachable as causal ancestors of `frontier` (inclusive) — the set a
/// checkpoint commits to (RCP §10.2 "transitively commits").
fn committed_set(
    records: &[CanonValue],
    by_hash: &BTreeMap<String, usize>,
    frontier: &[String],
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = frontier.to_vec();
    while let Some(h) = stack.pop() {
        if !seen.insert(h.clone()) {
            continue;
        }
        if let Some(&idx) = by_hash.get(&h) {
            if let Some(parents) = records[idx]
                .get("causal_prev_hashes")
                .and_then(|v| v.as_array())
            {
                for p in parents {
                    if let Some(ps) = p.as_str() {
                        stack.push(ps.to_string());
                    }
                }
            }
        }
    }
    seen
}

/// Verify selective-disclosure entries against the per-record hiding commitments embedded in the
/// (signed) record bodies. A bundle MAY carry a top-level `disclosures` array; each entry reveals
/// `(value, nonce)` for one `<field>_commit` so an auditor can confirm the disclosed value is the
/// one that was committed at seal time (RCP §9.3). A mismatch is tamper (threat #6) and an `issue`,
/// which fails the bundle. The commitment lives in the signed body, so a passing disclosure is only
/// meaningful for a record that itself verifies — the per-record trust pass enforces that
/// separately; here we only check value↔commitment binding.
fn verify_disclosures(
    bundle: &CanonValue,
    records: &[CanonValue],
    issues: &mut Vec<String>,
) -> (usize, usize) {
    let list = match bundle.get("disclosures") {
        // Absent, or an explicit JSON `null`, both mean "no disclosures" — an SDK that serializes an
        // empty Option as null must not brick an otherwise-valid bundle.
        None => return (0, 0),
        Some(v) if v.is_null() => return (0, 0),
        Some(v) => match v.as_array() {
            Some(a) => a,
            None => {
                issues.push("bundle.disclosures is present but not an array (malformed)".into());
                return (0, 0);
            }
        },
    };
    // record_id -> record body (first wins; duplicate ids are flagged separately in the trust pass).
    let mut by_id: BTreeMap<&str, &CanonValue> = BTreeMap::new();
    for rec in records {
        if let Some(id) = rec.get("record_id").and_then(|v| v.as_str()) {
            by_id.entry(id).or_insert(rec);
        }
    }
    let total = list.len();
    let mut verified = 0usize;
    // (record_id, field) must be disclosed at most once — a second disclosure for the same slot is
    // either redundant (inflating the count) or a contradiction (one commitment, two values).
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (i, d) in list.iter().enumerate() {
        let (rid, field, value_b64, nonce_hex) = match (
            d.get("record_id").and_then(|v| v.as_str()),
            d.get("field").and_then(|v| v.as_str()),
            d.get("value_b64").and_then(|v| v.as_str()),
            d.get("nonce_hex").and_then(|v| v.as_str()),
        ) {
            (Some(a), Some(b), Some(c), Some(e)) => (a, b, c, e),
            _ => {
                issues.push(format!(
                    "disclosure {i}: missing record_id/field/value_b64/nonce_hex"
                ));
                continue;
            }
        };
        if !seen.insert((rid, field)) {
            issues.push(format!(
                "disclosure {i}: duplicate disclosure for record '{rid}' field '{field}'"
            ));
            continue;
        }
        let domain = match crate::commit::FieldDomain::parse(field) {
            Some(dm) => dm,
            None => {
                issues.push(format!(
                    "disclosure {i}: field '{field}' not in input|output|rationale"
                ));
                continue;
            }
        };
        let rec = match by_id.get(rid) {
            Some(r) => *r,
            None => {
                issues.push(format!("disclosure {i}: no record '{rid}' in bundle"));
                continue;
            }
        };
        let commitment = rec
            .get(&format!("{field}_commit"))
            .and_then(|c| c.get("commitment"))
            .and_then(|v| v.as_str());
        let commitment = match commitment {
            Some(c) => c,
            None => {
                issues.push(format!(
                    "disclosure {i}: record '{rid}' has no {field}_commit.commitment to check"
                ));
                continue;
            }
        };
        let value = match crate::b64::decode(value_b64) {
            Ok(v) => v,
            Err(_) => {
                issues.push(format!("disclosure {i}: value_b64 is not valid base64url"));
                continue;
            }
        };
        let nonce = match crate::hashx::hex32(nonce_hex) {
            Some(n) => n,
            None => {
                issues.push(format!(
                    "disclosure {i}: nonce must be 64 lowercase hex chars (32 bytes)"
                ));
                continue;
            }
        };
        if crate::commit::verify_commitment(commitment, domain, &value, &nonce) {
            verified += 1;
        } else {
            issues.push(format!(
                "disclosure {i}: revealed {field} does not match record '{rid}' commitment (tamper, threat #6)"
            ));
        }
    }
    (total, verified)
}

pub fn verify_bundle_json(text: &str) -> Result<VerifyReport, crate::canon::CanonError> {
    Ok(verify_bundle(&CanonValue::parse(text)?))
}

fn opt_str(o: &Option<String>) -> CanonValue {
    match o {
        Some(s) => CanonValue::string(s.clone()),
        None => CanonValue::Null,
    }
}
fn str_array(v: &[String]) -> CanonValue {
    CanonValue::Array(v.iter().map(|s| CanonValue::string(s.clone())).collect())
}
fn count(n: usize) -> CanonValue {
    CanonValue::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// Serialize a [`VerifyReport`] to a canonical JSON object (reuses the RCP serializer). Used by the
/// WASM and FFI surfaces so all three targets emit identical report bytes.
pub fn report_to_canon(r: &VerifyReport) -> CanonValue {
    let records: Vec<CanonValue> = r
        .record_trust
        .iter()
        .map(|t| {
            CanonValue::object(vec![
                ("record_id".into(), CanonValue::string(t.record_id.clone())),
                (
                    "content_hash".into(),
                    CanonValue::string(t.content_hash.clone()),
                ),
                ("integrity_ok".into(), CanonValue::Bool(t.integrity_ok)),
                ("signature_ok".into(), CanonValue::Bool(t.signature_ok)),
                (
                    "key_status".into(),
                    CanonValue::string(t.key_status.clone()),
                ),
                (
                    "observed_via".into(),
                    CanonValue::string(t.observed_via.clone()),
                ),
                (
                    "trust".into(),
                    CanonValue::string(match t.trust {
                        TrustLevel::IntegrityProven => "integrity_proven",
                        TrustLevel::Untrusted => "untrusted",
                    }),
                ),
                ("authority".into(), CanonValue::string(t.authority.as_str())),
                ("notes".into(), str_array(&t.notes)),
            ])
            .unwrap()
        })
        .collect();
    CanonValue::object(vec![
        ("ok".into(), CanonValue::Bool(r.ok)),
        ("project_id".into(), opt_str(&r.project_id)),
        (
            "keys_externally_pinned".into(),
            CanonValue::Bool(r.keys_externally_pinned),
        ),
        ("records_total".into(), count(r.records_total)),
        ("records_proven".into(), count(r.records_proven)),
        ("dag_ok".into(), CanonValue::Bool(r.dag_ok)),
        ("dag_heads".into(), count(r.dag_heads)),
        ("collapsed_duplicates".into(), count(r.collapsed_duplicates)),
        ("checkpoints_total".into(), count(r.checkpoints_total)),
        ("checkpoints_verified".into(), count(r.checkpoints_verified)),
        ("checkpoints_anchored".into(), count(r.checkpoints_anchored)),
        ("chain_ok".into(), CanonValue::Bool(r.chain_ok)),
        ("disclosures_total".into(), count(r.disclosures_total)),
        ("disclosures_verified".into(), count(r.disclosures_verified)),
        ("grant_total".into(), count(r.grant_total)),
        ("grant_verified".into(), count(r.grant_verified)),
        // Tier-A grant accountability: every grant verified to gateway_enforced under a pinned key.
        (
            "grant_accountability".into(),
            CanonValue::string(if r.grant_total == 0 {
                "not_applicable"
            } else if r.grant_verified == r.grant_total {
                "complete"
            } else {
                "incomplete"
            }),
        ),
        // Tier-A is grant accountability only; action completeness (Tier B / Level 3) additionally
        // needs use receipts + attestations and is NOT claimed here (ADR 0002). broker_trust is
        // `assumed` (the bundle cannot prove the broker did not mint without recording);
        // attestation_status is `unevaluated` (this verifier does not evaluate the manifest).
        ("broker_trust".into(), CanonValue::string("assumed")),
        (
            "attestation_status".into(),
            CanonValue::string("unevaluated"),
        ),
        (
            "action_completeness".into(),
            CanonValue::string(if r.coverage_manifest.is_some() {
                "claimed_over_manifest"
            } else {
                "not_claimed"
            }),
        ),
        (
            "coverage_manifest".into(),
            r.coverage_manifest.clone().unwrap_or(CanonValue::Null),
        ),
        ("issues".into(), str_array(&r.issues)),
        ("first_broken_link".into(), opt_str(&r.first_broken_link)),
        ("record_trust".into(), CanonValue::Array(records)),
    ])
    .unwrap()
}

pub fn report_to_json(r: &VerifyReport) -> String {
    report_to_canon(r).serialize()
}

/// Verify a bundle JSON string and return the report as a JSON string (the shape WASM/FFI return).
pub fn verify_bundle_to_json(text: &str) -> String {
    match verify_bundle_json(text) {
        Ok(r) => report_to_json(&r),
        Err(e) => CanonValue::object(vec![
            ("ok".into(), CanonValue::Bool(false)),
            ("error".into(), CanonValue::string(e.to_string())),
        ])
        .unwrap()
        .serialize(),
    }
}

pub fn verify_bundle(bundle: &CanonValue) -> VerifyReport {
    verify_bundle_with(bundle, &VerifyOptions::default())
}

/// Verify a bundle (JSON) with out-of-band pinned trust roots supplied as a JSON options object, and
/// return the report JSON — the shape the FFI/CLI use to pass pinned keys for authority elevation
/// (the broker recording key for `gateway_enforced` grants) and key/TSA pinning. All option keys are
/// optional arrays: `authority_keys`/`signing_keys`/`tsa_keys` are `ed25519pub:` strings;
/// `tsa_spki_b64` are base64url-no-pad DER SubjectPublicKeyInfos.
pub fn verify_bundle_with_json(bundle_text: &str, opts_text: &str) -> String {
    let bundle = match CanonValue::parse(bundle_text) {
        Ok(b) => b,
        Err(e) => return error_report(&format!("bundle parse: {e}")),
    };
    let opts_val = match CanonValue::parse(opts_text) {
        Ok(o) => o,
        Err(e) => return error_report(&format!("options parse: {e}")),
    };
    // Parse pinned keys FAIL-CLOSED: any malformed entry is an error, never a silent drop — a caller
    // who supplied keys must not be downgraded to unpinned verification (signing keys) or get a
    // confusing grant_verified:0 (authority keys) because a key was pasted in the wrong encoding.
    let authority = match parse_pubkeys(&opts_val, "authority_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let tsa_keys = match parse_pubkeys(&opts_val, "tsa_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let tsa_spki = match parse_spki(&opts_val, "tsa_spki_b64") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let signing = match parse_pubkeys(&opts_val, "signing_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let mut opts = VerifyOptions {
        trusted_authority_keys: authority,
        trusted_tsa_keys: tsa_keys,
        trusted_tsa_spki: tsa_spki,
        ..Default::default()
    };
    if !signing.is_empty() {
        // No out-of-band status/compromise override here — that is the richer Rust API's job.
        opts.trusted_keys = Some(signing.into_iter().map(TrustedKey::from).collect());
    }
    report_to_json(&verify_bundle_with(&bundle, &opts))
}

/// Parse an optional array of `ed25519pub:` strings. Absent ⇒ empty; present-but-malformed ⇒ Err
/// (fail-closed, with the offending index + reason — never a silent drop).
fn parse_pubkeys(opts: &CanonValue, key: &str) -> Result<Vec<VerifyingKey>, String> {
    let arr = match opts.get(key) {
        None | Some(CanonValue::Null) => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| format!("{key} must be an array of ed25519pub: strings"))?,
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| format!("{key}[{i}] must be a string"))?;
        let vk = decode_pubkey(s)
            .map_err(|e| format!("{key}[{i}] is not a valid ed25519pub key: {e}"))?;
        out.push(vk);
    }
    Ok(out)
}

/// Parse an optional array of base64url DER SPKIs. Absent ⇒ empty; present-but-malformed ⇒ Err.
fn parse_spki(opts: &CanonValue, key: &str) -> Result<Vec<Vec<u8>>, String> {
    let arr = match opts.get(key) {
        None | Some(CanonValue::Null) => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| format!("{key} must be an array of base64url DER strings"))?,
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| format!("{key}[{i}] must be a string"))?;
        let der =
            crate::b64::decode(s).map_err(|e| format!("{key}[{i}] is not valid base64url: {e}"))?;
        out.push(der);
    }
    Ok(out)
}

fn error_report(msg: &str) -> String {
    CanonValue::object(vec![
        ("ok".into(), CanonValue::Bool(false)),
        ("error".into(), CanonValue::string(msg)),
    ])
    .unwrap()
    .serialize()
}

pub fn verify_bundle_with(bundle: &CanonValue, opts: &VerifyOptions) -> VerifyReport {
    let mut issues: Vec<String> = Vec::new();
    let project_id = s(bundle, "project_id");
    let keys_externally_pinned = opts.trusted_keys.is_some();

    let empty: Vec<CanonValue> = Vec::new();
    let key_entries = arr(bundle, "keys", &empty, &mut issues);
    let records = arr(bundle, "records", &empty, &mut issues);
    let checkpoints = arr(bundle, "checkpoints", &empty, &mut issues);
    if bundle.as_object().is_none() {
        issues.push("bundle is not a JSON object".into());
    }
    if bundle.get("records").is_none() {
        issues.push("bundle has no records".into());
    }

    // ---- 1. key store ----
    let mut keys: BTreeMap<(String, i64), KeyEntry> = BTreeMap::new();
    for e in key_entries {
        match (
            s(e, "signing_key_id"),
            e.get("key_epoch").and_then(|v| v.as_int()),
            s(e, "public_key"),
        ) {
            (Some(id), Some(epoch), Some(pk)) => match decode_pubkey(&pk) {
                Ok(vk) => {
                    keys.insert(
                        (id, epoch),
                        KeyEntry {
                            vk,
                            status: s(e, "key_status").unwrap_or_else(|| "active".into()),
                            status_changed_at: s(e, "status_changed_at"),
                        },
                    );
                }
                Err(err) => issues.push(format!("key {id}/{epoch} bad public_key: {err}")),
            },
            _ => issues.push("key entry missing signing_key_id/key_epoch/public_key".into()),
        }
    }
    let pinned_for = |vk: &VerifyingKey| -> Option<&TrustedKey> {
        opts.trusted_keys
            .as_ref()
            .and_then(|set| set.iter().find(|t| &t.vk == vk))
    };
    let is_trusted = |vk: &VerifyingKey| match &opts.trusted_keys {
        Some(_) => pinned_for(vk).is_some(),
        None => true,
    };

    // ---- 2. per-record pass 1 (provisional) ----
    let mut pending: Vec<Pending> = Vec::with_capacity(records.len());
    for (i, rec) in records.iter().enumerate() {
        let mut notes = Vec::new();
        let project_ok = match &project_id {
            Some(pid) => {
                let m = s(rec, "project_id").as_deref() == Some(pid.as_str());
                if !m {
                    notes.push("project_id does not match bundle".into());
                }
                m
            }
            None => true,
        };
        let rec_key_status = rec
            .get("key")
            .and_then(|k| s(k, "key_status"))
            .unwrap_or_else(|| "unknown".into());
        let key_id = rec.get("key").and_then(|k| s(k, "signing_key_id"));
        let key_epoch = rec
            .get("key")
            .and_then(|k| k.get("key_epoch"))
            .and_then(|v| v.as_int());
        let resolved = match (key_id, key_epoch) {
            (Some(id), Some(ep)) => keys.get(&(id, ep)),
            _ => {
                notes.push("record key block missing signing_key_id/key_epoch".into());
                None
            }
        };

        let integrity_ok = validate_record_shape(rec)
            .and_then(|()| verify_content_hash(rec))
            .is_ok();

        let (signature_ok, eff_status, pinned, status_changed_at) = match resolved {
            Some(entry) => {
                let sig_ok = integrity_ok && verify_sealed(rec, &entry.vk).is_ok();
                if !sig_ok {
                    if let Err(e) = verify_sealed(rec, &entry.vk) {
                        notes.push(format!("verify failed: {e}"));
                    }
                }
                let pin = pinned_for(&entry.vk);
                // worst of record-asserted, bundle-asserted, and (if pinned) the authoritative
                // pinned status — fail-safe in all directions.
                let mut eff = worst_status(&rec_key_status, &entry.status);
                if let Some(ps) = pin.and_then(|t| t.status.as_deref()) {
                    eff = worst_status(&eff, ps);
                }
                // Compromise time used for the anchored-before upgrade: under pinning ONLY the
                // auditor-supplied (authoritative) time is trusted; the bundle's self-asserted
                // time is ignored so an attacker cannot future-date a compromise to upgrade. Without
                // pinning (evidence-for-yourself), the bundle's self-asserted time is best-effort.
                let changed_at = if keys_externally_pinned {
                    pin.and_then(|t| t.status_changed_at.clone())
                } else {
                    entry.status_changed_at.clone()
                };
                (sig_ok, eff, is_trusted(&entry.vk), changed_at)
            }
            None => {
                notes.push("no public key available — signature unverifiable".into());
                (false, worst_status(&rec_key_status, "unknown"), false, None)
            }
        };
        if keys_externally_pinned && !pinned && signature_ok {
            notes.push("signed by a key that is NOT externally pinned".into());
        }

        let authority = verify_authority(rec, &opts.trusted_authority_keys);
        if authority == AuthorityTrust::Failed {
            notes.push("authority claims a verified source but its evidence_sig did not verify under a trusted authority key".into());
        }

        pending.push(Pending {
            index: i,
            record_id: s(rec, "record_id").unwrap_or_default(),
            content_hash: s(rec, "content_hash").unwrap_or_default(),
            observed_via: s(rec, "observed_via").unwrap_or_else(|| "unknown".into()),
            integrity_ok,
            signature_ok,
            pinned,
            project_ok,
            eff_status,
            status_changed_at,
            authority,
            notes,
        });
    }

    // record_ids must be unique (two distinct records may not share a record_id). This keeps
    // `record_id` a sound binding handle for authority evidence (a verified evidence triple bound to
    // a record_id cannot be copied onto a different record without colliding here).
    {
        let mut by_id: BTreeMap<String, String> = BTreeMap::new();
        for rec in records.iter() {
            if let (Some(id), Some(ch)) = (s(rec, "record_id"), s(rec, "content_hash")) {
                if let Some(prev) = by_id.insert(id.clone(), ch.clone()) {
                    if prev != ch {
                        issues.push(format!("duplicate record_id '{id}' on distinct records"));
                    }
                }
            }
        }
    }

    // selective-disclosure entries (optional): bind revealed (value, nonce) to record commitments.
    let (disclosures_total, disclosures_verified) =
        verify_disclosures(bundle, records, &mut issues);

    // ---- 3. DAG ----
    let (dag_ok, dag_heads, collapsed_duplicates, dag_opt) = match dag::build(records) {
        Ok(d) => (true, d.heads.len(), d.collapsed_duplicates, Some(d)),
        Err(e) => {
            issues.push(format!("DAG invalid: {e}"));
            (false, 0, 0, None)
        }
    };

    // ---- 4. checkpoints + anchors ----
    let mut checkpoints_verified = 0usize;
    let mut checkpoints_anchored = 0usize;
    // (seq, anchored_ts, frontier) for each checkpoint with a verified anchor
    let mut anchored: Vec<(i64, String, Vec<String>)> = Vec::new();
    for (i, cp) in checkpoints.iter().enumerate() {
        if let Some(pid) = &project_id {
            if s(cp, "project_id").as_deref() != Some(pid.as_str()) {
                issues.push(format!("checkpoint {i} project_id does not match bundle"));
            }
        }
        let vk = cp
            .get("key")
            .and_then(|k| s(k, "signing_key_id"))
            .zip(
                cp.get("key")
                    .and_then(|k| k.get("key_epoch"))
                    .and_then(|v| v.as_int()),
            )
            .and_then(|(id, ep)| keys.get(&(id, ep)))
            .filter(|e| !keys_externally_pinned || is_trusted(&e.vk))
            .map(|e| e.vk);
        let cp_verified = match vk {
            Some(vk) => match verify_checkpoint_sealed(cp, &vk) {
                Ok(()) => {
                    checkpoints_verified += 1;
                    true
                }
                Err(e) => {
                    issues.push(format!("checkpoint {i} invalid: {e}"));
                    false
                }
            },
            None => {
                issues.push(format!("checkpoint {i}: no trusted public key to verify"));
                false
            }
        };
        if let Some(anchor) = cp.get("anchor") {
            checkpoints_anchored += 1;
            let any_tsa_trust =
                !opts.trusted_tsa_keys.is_empty() || !opts.trusted_tsa_spki.is_empty();
            // Only an anchor on a *verified* checkpoint can contribute to trust — otherwise an
            // attacker pairs an unsigned checkpoint (arbitrary frontier) with a valid TSA token.
            if cp_verified && any_tsa_trust {
                let anchor_trust = crate::anchor::AnchorTrust {
                    test_anchor_keys: opts.trusted_tsa_keys.clone(),
                    rfc3161_tsa_spki: opts.trusted_tsa_spki.clone(),
                };
                let cph = s(cp, "checkpoint_hash").unwrap_or_default();
                match verify_anchor(&cph, anchor, &anchor_trust) {
                    Ok(ts) => {
                        let seq = cp
                            .get("checkpoint_seq")
                            .and_then(|v| v.as_int())
                            .unwrap_or(0);
                        let frontier: Vec<String> = cp
                            .get("frontier")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|h| h.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        anchored.push((seq, ts, frontier));
                    }
                    Err(e) => issues.push(format!("checkpoint {i} anchor invalid: {e}")),
                }
            }
        }
    }
    if !records.is_empty() && checkpoints.is_empty() {
        issues.push("no checkpoints: a non-empty run must be checkpoint-committed".into());
    }

    // anchored times must be non-decreasing with seq (RCP §10.1 step 5 — backdating #3).
    // NOTE: this compares only checkpoints that carry a *verified* anchor. Partial anchoring does
    // not enable a meaningful backdate: the latest anchored checkpoint cryptographically bounds the
    // existence time of all its causal ancestors, and `agent_ts` is untrusted regardless. Anchoring
    // every checkpoint is the exporter's responsibility, not a verifier PASS invariant.
    let mut sorted_anchored = anchored.clone();
    sorted_anchored.sort_by_key(|(seq, _, _)| *seq);
    for w in sorted_anchored.windows(2) {
        if w[1].1 < w[0].1 {
            issues.push(format!(
                "anchor time decreased across checkpoints {} -> {} (backdating, threat #3)",
                w[0].0, w[1].0
            ));
        }
    }

    let mut chain_ok = true;
    match &dag_opt {
        Some(d) if !checkpoints.is_empty() => {
            if let Err(e) = validate_chain(checkpoints, d) {
                chain_ok = false;
                issues.push(format!("checkpoint chain: {e}"));
            }
        }
        None if !checkpoints.is_empty() => chain_ok = false,
        _ => {}
    }

    // ---- 5. finalize per-record trust (pass 2) ----
    // Precompute the committed set ONCE per anchored checkpoint (not per record×checkpoint) to
    // avoid quadratic blowup on large bundles.
    let anchored_committed: Vec<(String, BTreeSet<String>)> = match dag_opt.as_ref() {
        Some(d) => anchored
            .iter()
            .map(|(_, ts, frontier)| (ts.clone(), committed_set(records, &d.by_hash, frontier)))
            .collect(),
        None => Vec::new(),
    };
    let anchored_before = |content_hash: &str, changed_at: &str| -> bool {
        // Lexical `<=` is only valid between two canonical fixed-precision UTC timestamps; a
        // malformed `changed_at` (or anchor time) must NOT silently skew the ordering — fail closed.
        if !is_canonical_ts(changed_at) {
            return false;
        }
        anchored_committed.iter().any(|(ts, committed)| {
            is_canonical_ts(ts) && ts.as_str() <= changed_at && committed.contains(content_hash)
        })
    };

    let mut record_trust = Vec::with_capacity(pending.len());
    let mut records_proven = 0usize;
    for mut p in pending {
        let base_ok = p.integrity_ok && p.signature_ok && p.project_ok && p.pinned;
        let trust = if !base_ok {
            TrustLevel::Untrusted
        } else if matches!(p.eff_status.as_str(), "active" | "retired") {
            TrustLevel::IntegrityProven
        } else if matches!(p.eff_status.as_str(), "revoked" | "compromised") {
            match &p.status_changed_at {
                Some(changed) if anchored_before(&p.content_hash, changed) => {
                    p.notes.push(format!(
                        "key {}: record anchored before status change — trustworthy",
                        p.eff_status
                    ));
                    TrustLevel::IntegrityProven
                }
                _ => {
                    p.notes.push(format!(
                        "key {}: NOT anchored before status change — untrusted (threat #9)",
                        p.eff_status
                    ));
                    TrustLevel::Untrusted
                }
            }
        } else {
            TrustLevel::Untrusted
        };

        if trust == TrustLevel::IntegrityProven {
            records_proven += 1;
        } else {
            issues.push(format!(
                "record {} ({}) untrusted: {}",
                p.index,
                p.record_id,
                p.notes.last().cloned().unwrap_or_default()
            ));
        }

        record_trust.push(RecordTrust {
            index: p.index,
            record_id: p.record_id,
            content_hash: p.content_hash,
            integrity_ok: p.integrity_ok,
            signature_ok: p.signature_ok,
            key_status: p.eff_status,
            observed_via: p.observed_via,
            trust,
            authority: p.authority,
            notes: p.notes,
        });
    }

    // Level 3 Tier-A: count credential-broker grants and how many are fully accountable. A grant only
    // counts as VERIFIED when the record is BOTH integrity-proven (its own seal is valid — event_type
    // and action are part of the signed body) AND its authority verified to gateway_enforced under a
    // pinned key. Gating on authority alone would count a body-tampered grant (a valid evidence triple
    // binds only source/record_id/evidence_hash, not the body) — so a forged action would read as
    // "complete". Grants are deduped by content_hash so a verbatim-replayed grant isn't double-counted.
    let mut grant_total = 0usize;
    let mut grant_verified = 0usize;
    let mut seen_grants: BTreeSet<&str> = BTreeSet::new();
    for rt in &record_trust {
        if s(&records[rt.index], "event_type").as_deref() == Some("credential_grant")
            && seen_grants.insert(rt.content_hash.as_str())
        {
            grant_total += 1;
            if rt.trust == TrustLevel::IntegrityProven && rt.authority == AuthorityTrust::Verified {
                grant_verified += 1;
            }
        }
    }
    let coverage_manifest = bundle.get("coverage_manifest").cloned();

    let first_broken_link = issues.first().cloned();
    let ok = issues.is_empty()
        && records_proven == records.len()
        && !records.is_empty()
        && dag_ok
        && checkpoints_verified == checkpoints.len()
        && !checkpoints.is_empty()
        && chain_ok;

    VerifyReport {
        ok,
        project_id,
        keys_externally_pinned,
        records_total: records.len(),
        records_proven,
        record_trust,
        dag_ok,
        dag_heads,
        collapsed_duplicates,
        checkpoints_total: checkpoints.len(),
        checkpoints_verified,
        checkpoints_anchored,
        chain_ok,
        disclosures_total,
        disclosures_verified,
        grant_total,
        grant_verified,
        coverage_manifest,
        issues,
        first_broken_link,
    }
}
