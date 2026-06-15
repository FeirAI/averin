//! Offline bundle verification (RCP §10.1) — the capstone the CLI and WASM verifier call.
//!
//! Given an export bundle (records + full checkpoint history + public keys [+ anchors, piece 6]),
//! produce a [`VerifyReport`]: per-record trust annotations, DAG validity, and checkpoint-chain
//! soundness (omission #1 / fork #2 detection). Never panics on attacker-controlled input.
//!
//! **Trust root.** The bundle's `keys` list is *attacker-supplied*. Pass externally-pinned keys via
//! [`VerifyOptions::trusted_keys`] (obtained out-of-band: the customer's published key, a key-
//! transparency record, etc.) to get authenticity. Without pinning, the report sets
//! `keys_externally_pinned = false` and proves only *internal consistency under the bundle's own
//! key claims* — the verifier never implies authenticity it cannot back. A `revoked`/`compromised`
//! status from EITHER the record's key block OR the bundle key entry (whichever is worse)
//! downgrades affected records to `Untrusted` (anchored-before rule: M1 piece 6).

use crate::canon::CanonValue;
use crate::checkpoint::{validate_chain, verify_checkpoint_sealed};
use crate::dag;
use crate::record::verify_sealed;
use crate::sign::decode_pubkey;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// L1: bytes sealed by a valid (and, if pinning is in effect, externally-trusted) key and
    /// unchanged since.
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
    pub issues: Vec<String>,
    pub first_broken_link: Option<String>,
}

#[derive(Default)]
pub struct VerifyOptions {
    /// If `Some`, a record is only `IntegrityProven` when its resolved key is in this set
    /// (out-of-band trust root). If `None`, trust rests on the bundle's self-asserted key list.
    pub trusted_keys: Option<Vec<VerifyingKey>>,
}

struct KeyEntry {
    vk: VerifyingKey,
    status: String,
    #[allow(dead_code)] // consumed by the anchored-before rule in piece 6
    status_changed_at: Option<String>,
}

fn s(v: &CanonValue, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string())
}

/// A present `keys`/`records`/`checkpoints` field MUST be an array — never silently coerce a
/// wrong-typed field to empty (#8); flag it and fall back to `empty`.
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

/// Severity rank of a key status (higher = less trustworthy). Unknown ranks worst.
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

pub fn verify_bundle_json(text: &str) -> Result<VerifyReport, crate::canon::CanonError> {
    Ok(verify_bundle(&CanonValue::parse(text)?))
}

pub fn verify_bundle(bundle: &CanonValue) -> VerifyReport {
    verify_bundle_with(bundle, &VerifyOptions::default())
}

pub fn verify_bundle_with(bundle: &CanonValue, opts: &VerifyOptions) -> VerifyReport {
    let mut issues: Vec<String> = Vec::new();

    let project_id = s(bundle, "project_id");
    let keys_externally_pinned = opts.trusted_keys.is_some();

    // ---- strict shape: a present keys/records/checkpoints field MUST be an array (#8) ----
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
        let (id, epoch, pk) = match (
            s(e, "signing_key_id"),
            e.get("key_epoch").and_then(|v| v.as_int()),
            s(e, "public_key"),
        ) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => {
                issues.push("key entry missing signing_key_id/key_epoch/public_key".into());
                continue;
            }
        };
        match decode_pubkey(&pk) {
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
            Err(err) => issues.push(format!("key {id}/{epoch} has bad public_key: {err}")),
        }
    }

    let is_trusted = |vk: &VerifyingKey| -> bool {
        match &opts.trusted_keys {
            Some(set) => set.contains(vk),
            None => true, // no pinning: bundle's key list is the (self-asserted) root
        }
    };

    // ---- 2. per-record verification + trust annotation ----
    let mut record_trust = Vec::with_capacity(records.len());
    let mut records_proven = 0usize;

    for (i, rec) in records.iter().enumerate() {
        let record_id = s(rec, "record_id").unwrap_or_default();
        let content_hash = s(rec, "content_hash").unwrap_or_default();
        let observed_via = s(rec, "observed_via").unwrap_or_else(|| "unknown".into());
        let mut notes = Vec::new();

        // project_id consistency (#6)
        if let Some(pid) = &project_id {
            if s(rec, "project_id").as_deref() != Some(pid.as_str()) {
                notes.push("project_id does not match bundle".into());
            }
        }

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

        let integ = crate::record::validate_record_shape(rec)
            .and_then(|()| crate::record::verify_content_hash(rec))
            .is_ok();

        let (integrity_ok, signature_ok, key_status, pinned) = match resolved {
            Some(entry) => {
                let sig_ok = verify_sealed(rec, &entry.vk).is_ok() && integ;
                if !sig_ok {
                    if let Err(e) = verify_sealed(rec, &entry.vk) {
                        notes.push(format!("verify failed: {e}"));
                    }
                }
                // effective status = worst of record-asserted and bundle-asserted (fail-safe, #4)
                let eff = worst_status(&rec_key_status, &entry.status);
                (integ, sig_ok, eff, is_trusted(&entry.vk))
            }
            None => {
                notes.push("no public key available — signature unverifiable".into());
                (
                    integ,
                    false,
                    worst_status(&rec_key_status, "unknown"),
                    false,
                )
            }
        };

        if keys_externally_pinned && !pinned && signature_ok {
            notes.push("signed by a key that is NOT externally pinned".into());
        }

        let pin_ok = if keys_externally_pinned { pinned } else { true };
        let project_ok = notes
            .iter()
            .all(|n| !n.contains("project_id does not match"));
        let trust = if integrity_ok
            && signature_ok
            && pin_ok
            && project_ok
            && matches!(key_status.as_str(), "active" | "retired")
        {
            records_proven += 1;
            TrustLevel::IntegrityProven
        } else {
            if matches!(key_status.as_str(), "revoked" | "compromised") {
                notes.push(format!(
                    "key status '{key_status}': trustworthy only if anchored before status change (anchor check: piece 6)"
                ));
            }
            TrustLevel::Untrusted
        };
        if trust == TrustLevel::Untrusted {
            issues.push(format!(
                "record {i} ({record_id}) untrusted: {}",
                notes.last().cloned().unwrap_or_default()
            ));
        }

        record_trust.push(RecordTrust {
            index: i,
            record_id,
            content_hash,
            integrity_ok,
            signature_ok,
            key_status,
            observed_via,
            trust,
            notes,
        });
    }

    // ---- 3. DAG ----
    let (dag_ok, dag_heads, collapsed_duplicates, dag_opt) = match dag::build(records) {
        Ok(d) => (true, d.heads.len(), d.collapsed_duplicates, Some(d)),
        Err(e) => {
            issues.push(format!("DAG invalid: {e}"));
            (false, 0, 0, None)
        }
    };

    // ---- 4. checkpoint chain ----
    let mut checkpoints_verified = 0usize;
    let mut checkpoints_anchored = 0usize;
    for (i, cp) in checkpoints.iter().enumerate() {
        if cp.get("anchor").is_some() {
            checkpoints_anchored += 1;
        }
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
        match vk {
            Some(vk) => match verify_checkpoint_sealed(cp, &vk) {
                Ok(()) => checkpoints_verified += 1,
                Err(e) => issues.push(format!("checkpoint {i} invalid: {e}")),
            },
            None => issues.push(format!("checkpoint {i}: no trusted public key to verify")),
        }
    }

    // require at least one checkpoint for any non-empty record set (#6)
    if !records.is_empty() && checkpoints.is_empty() {
        issues.push("no checkpoints: a non-empty run must be checkpoint-committed".into());
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

    // issues are pushed in verification order, so the first is the first broken link.
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
        issues,
        first_broken_link,
    }
}
