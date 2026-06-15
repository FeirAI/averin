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
    /// checked out under a pinned authority key (for a broker/resource record, the ROLE-specific key
    /// set — ADR 0003 R2), not just the agent's claim.
    pub authority: AuthorityTrust,
    /// Broker/resource role (ADR 0003 R2): broker|resource|none. Surfaces which role's key set the
    /// authority was checked under, so an auditor sees broker-signed vs resource-signed provenance.
    pub broker_role: String,
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
    /// Tier-B use↔grant join (ADR 0003 step 5), computed over the CLOSED set (records committed by a
    /// verified, anchored checkpoint, R3). `uses_total` = resource-role use receipts; `uses_matched` =
    /// closed uses bound to a closed grant under the full predicate; `uses_action_unverified` = matched
    /// uses against a taxonomy-unvalidated grant (R6, all of them in the demonstrator);
    /// `unmatched_violation` = a closed use with no/again a matching grant (hard fail); `unmatched_pending`
    /// = a use not yet closed (in-flight); `grants_unused` = closed grants with no matching use.
    pub uses_total: usize,
    pub uses_matched: usize,
    pub uses_action_unverified: usize,
    pub unmatched_violation: usize,
    pub unmatched_pending: usize,
    pub grants_unused: usize,
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
    /// Trusted authority-system public keys (policy engine / approval service) for NON-broker records.
    /// An `evidence_sig` that verifies under one of these elevates a record's authority to `verified`
    /// (threat #4). Broker/resource records are NOT elevated by this set — they use the role-specific
    /// sets below (ADR 0003 R2 role separation).
    pub trusted_authority_keys: Vec<VerifyingKey>,
    /// Trusted CREDENTIAL-BROKER recording keys. Only a `credential_broker`-role record (a grant)
    /// elevates under one of these (ADR 0003 R2). Must be disjoint from `resource_authority_keys`.
    pub broker_authority_keys: Vec<VerifyingKey>,
    /// Trusted RESOURCE recording keys. Only a `tool_gateway`-role record (a use receipt) elevates
    /// under one of these (ADR 0003 R2). Must be disjoint from `broker_authority_keys`.
    pub resource_authority_keys: Vec<VerifyingKey>,
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
    broker_role: BrokerRole,
    notes: Vec<String>,
}

/// A record's broker/resource role (ADR 0003 R2), classified fail-closed from the
/// `(extensions.broker.kind, authority.enforcement_point)` discriminator. `None` means the record
/// does not claim a recognized Tier-B role (a plain record, or a fail-closed misclassification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerRole {
    Broker,
    Resource,
    None,
}

impl BrokerRole {
    fn as_str(self) -> &'static str {
        match self {
            BrokerRole::Broker => "broker",
            BrokerRole::Resource => "resource",
            BrokerRole::None => "none",
        }
    }
}

/// Classify a record's role from `(extensions.broker.kind, authority.enforcement_point)` — fail-closed:
/// EXACTLY one recognized tuple maps to each role, and a `kind`/`enforcement_point` that point at
/// different roles (ambiguous), an unrecognized value, or an absent component all map to `None`
/// (ADR 0003 R2). `claims_role` is true iff the record carries a broker `kind` at all (so an
/// unclassifiable record that nonetheless *claims* a Tier-B role can be surfaced, not silently
/// dropped).
fn classify_role(rec: &CanonValue) -> (BrokerRole, bool) {
    let kind = rec
        .get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get("kind"))
        .and_then(|v| v.as_str());
    let ep = rec
        .get("authority")
        .and_then(|a| a.get("enforcement_point"))
        .and_then(|v| v.as_str());
    let role = match (kind, ep) {
        (Some("grant"), Some("credential_broker")) => BrokerRole::Broker,
        (Some("use"), Some("tool_gateway")) => BrokerRole::Resource,
        _ => BrokerRole::None,
    };
    (role, kind.is_some())
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
                (
                    "broker_role".into(),
                    CanonValue::string(t.broker_role.clone()),
                ),
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
        ("uses_total".into(), count(r.uses_total)),
        ("uses_matched".into(), count(r.uses_matched)),
        (
            "uses_action_unverified".into(),
            count(r.uses_action_unverified),
        ),
        (
            "unmatched_violation".into(),
            count(r.unmatched_violation),
        ),
        ("unmatched_pending".into(), count(r.unmatched_pending)),
        ("grants_unused".into(), count(r.grants_unused)),
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
    let broker_authority = match parse_pubkeys(&opts_val, "broker_authority_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let resource_authority = match parse_pubkeys(&opts_val, "resource_authority_keys") {
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
        broker_authority_keys: broker_authority,
        resource_authority_keys: resource_authority,
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

/// A fatal-configuration `VerifyReport` (ok=false) returned BEFORE any record is evaluated — used for
/// the R2 disjoint-key-set check, so an ambiguous key universe never proceeds to a "clean" verdict.
fn fatal_config_report(project_id: Option<String>, msg: &str) -> VerifyReport {
    VerifyReport {
        ok: false,
        project_id,
        keys_externally_pinned: false,
        records_total: 0,
        records_proven: 0,
        record_trust: Vec::new(),
        dag_ok: false,
        dag_heads: 0,
        collapsed_duplicates: 0,
        checkpoints_total: 0,
        checkpoints_verified: 0,
        checkpoints_anchored: 0,
        chain_ok: false,
        disclosures_total: 0,
        disclosures_verified: 0,
        grant_total: 0,
        grant_verified: 0,
        uses_total: 0,
        uses_matched: 0,
        uses_action_unverified: 0,
        unmatched_violation: 0,
        unmatched_pending: 0,
        grants_unused: 0,
        coverage_manifest: None,
        issues: vec![msg.to_string()],
        first_broken_link: Some(msg.to_string()),
    }
}

/// Re-derive a broker record's `evidence_hash` from the canonical evidence payload it embeds at
/// `extensions.broker.<payload_key>` and confirm it equals the signed `authority.evidence_hash`
/// (ADR 0003 R1). `verify_authority` only proves a signature over the opaque `evidence_hash`, so a
/// `Verified` authority alone does NOT prove the signer committed to the semantic match fields. Unless
/// the verifier reads those fields from a payload whose RCP hash equals the signed hash, the match
/// would fire on unverified values. Returns false if the payload or the signed hash is absent, or the
/// two differ. The embedded payload is part of the signed body, so this binds it to the seal.
fn evidence_rederivable(rec: &CanonValue, payload_key: &str) -> bool {
    let signed = match rec
        .get("authority")
        .and_then(|a| a.get("evidence_hash"))
        .and_then(|v| v.as_str())
    {
        Some(h) => h,
        None => return false,
    };
    let payload = match rec
        .get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get(payload_key))
    {
        Some(p) => p,
        None => return false,
    };
    crate::hashx::sha256_prefixed(payload.serialize().as_bytes()) == signed
}

/// Read a string field from a record's canonical evidence payload at `extensions.broker.<payload_key>`
/// (ADR 0003 — the verifier reads match inputs ONLY from the proven payload).
fn ev_str(rec: &CanonValue, payload_key: &str, field: &str) -> Option<String> {
    rec.get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get(payload_key))
        .and_then(|p| p.get(field))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Read an integer field from a record's canonical evidence payload (used for issued_at/exp/used_at).
fn ev_int(rec: &CanonValue, payload_key: &str, field: &str) -> Option<i64> {
    rec.get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get(payload_key))
        .and_then(|p| p.get(field))
        .and_then(|v| v.as_int())
}

pub fn verify_bundle_with(bundle: &CanonValue, opts: &VerifyOptions) -> VerifyReport {
    let mut issues: Vec<String> = Vec::new();
    let project_id = s(bundle, "project_id");

    // R2 (ADR 0003): broker and resource authority key sets MUST be disjoint. A key present in both
    // could sign either a grant or a use and pass role separation, so this is a FATAL configuration
    // error — abort before evaluating any record (VerifyingKey equality is raw-bytes, which also
    // settles the derived key id). Never proceed on an ambiguous key universe.
    if opts
        .broker_authority_keys
        .iter()
        .any(|bk| opts.resource_authority_keys.contains(bk))
    {
        return fatal_config_report(
            project_id,
            "broker_authority_keys and resource_authority_keys must be disjoint (a key in both breaks R2 role separation) — fatal configuration error",
        );
    }

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

        // R2 (ADR 0003): verify the authority evidence under the record's ROLE-specific key set — a
        // broker-role record (grant) only elevates under broker keys, a resource-role record (use)
        // only under resource keys, and any other record under the generic authority keys. This makes
        // role confusion (a resource key signing a grant, or vice versa) fail to elevate.
        let (broker_role, claims_role) = classify_role(rec);
        let auth_keys: &[VerifyingKey] = match broker_role {
            BrokerRole::Broker => &opts.broker_authority_keys,
            BrokerRole::Resource => &opts.resource_authority_keys,
            BrokerRole::None => &opts.trusted_authority_keys,
        };
        let authority = verify_authority(rec, auth_keys);
        if authority == AuthorityTrust::Failed {
            notes.push(format!(
                "authority claims a verified source but its evidence_sig did not verify under a trusted {} authority key",
                broker_role.as_str()
            ));
        }
        // R2 rule 4: a record that CLAIMS a Tier-B role (carries extensions.broker.kind) but does not
        // classify to a recognized (kind, enforcement_point) role is a fail-closed verification
        // failure — surfaced as an issue, never a silent drop that could let a mislabeled use escape.
        if claims_role && broker_role == BrokerRole::None {
            let msg = format!(
                "record {i}: extensions.broker.kind set but (kind, enforcement_point) is not a recognized broker/resource role (R2 fail-closed)"
            );
            notes.push(msg.clone());
            issues.push(msg);
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
            broker_role,
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
            broker_role: p.broker_role.as_str().to_string(),
            notes: p.notes,
        });
    }

    // Level 3 Tier-A: count credential-broker grants and how many are fully accountable. A grant only
    // counts as VERIFIED when ALL of: the record is integrity-proven (its own seal is valid —
    // event_type and action are part of the signed body); it classifies to the BROKER role and its
    // authority verified under a pinned BROKER key (ADR 0003 R2 — a resource key, or the generic
    // authority set, can NOT elevate a grant); AND its signed authority.evidence_hash re-derives from
    // the embedded extensions.broker.grant_evidence (R1) — so the hash actually commits to the
    // canonical match fields, not an opaque value. A credential_grant that does NOT classify as broker
    // is a fail-closed verification failure (surfaced, never silently uncounted). Grants are deduped by
    // content_hash so a verbatim-replayed grant isn't double-counted.
    let mut grant_total = 0usize;
    let mut grant_verified = 0usize;
    let mut seen_grants: BTreeSet<&str> = BTreeSet::new();
    for rt in &record_trust {
        let rec = &records[rt.index];
        if s(rec, "event_type").as_deref() == Some("credential_grant")
            && seen_grants.insert(rt.content_hash.as_str())
        {
            grant_total += 1;
            // R2: a credential_grant MUST carry the broker role discriminator (kind=grant +
            // enforcement_point=credential_broker). A grant that doesn't is mislabeled/misrouted — its
            // authority was checked under the wrong (or no) role key set; fail closed.
            if rt.broker_role != BrokerRole::Broker.as_str() {
                issues.push(format!(
                    "grant {} ({}): credential_grant does not classify to the broker role (kind/enforcement_point) — R2 fail-closed",
                    rt.index, rt.record_id
                ));
                continue;
            }
            // MUST-FIX 1 divergence guard: `kind` is duplicated at extensions.broker.kind (the role
            // discriminator that made this a broker record) and inside the canonical grant_evidence. If
            // the embedded payload's kind disagrees, fail closed — the signed evidence and the role
            // label disagree on what this record is. (An absent grant_evidence is caught by the
            // re-derivation check below; this only fires on a present-but-divergent kind.)
            let ge_kind = rec
                .get("extensions")
                .and_then(|e| e.get("broker"))
                .and_then(|b| b.get("grant_evidence"))
                .and_then(|g| g.get("kind"))
                .and_then(|v| v.as_str());
            if matches!(ge_kind, Some(k) if k != "grant") {
                issues.push(format!(
                    "grant {} ({}): grant_evidence.kind diverges from the extensions.broker.kind role discriminator (MUST-FIX 1 fail-closed)",
                    rt.index, rt.record_id
                ));
                continue;
            }
            if rt.trust == TrustLevel::IntegrityProven && rt.authority == AuthorityTrust::Verified {
                if evidence_rederivable(rec, "grant_evidence") {
                    grant_verified += 1;
                } else {
                    issues.push(format!(
                        "grant {} ({}): authority.evidence_hash is not re-derivable from extensions.broker.grant_evidence (payload absent or divergent — R1, threat #4)",
                        rt.index, rt.record_id
                    ));
                }
            }
        }
    }

    // ---- Tier-B (ADR 0003 step 5): use↔grant join over the CLOSED set (R3) ----
    // CLOSED = a record's content_hash is transitively committed by a verified, ANCHORED checkpoint
    // (the union of the anchored committed sets). Tier-B outcomes are computed over closed records
    // only; a use not yet closed is `unmatched_pending` (in-flight), never a violation. Replacing an
    // exporter watermark with this cryptographic boundary closes the watermark-specific suppression
    // path (MUST-FIX 2); never-anchored use suppression remains an accepted residual.
    let closed: BTreeSet<&str> = anchored_committed
        .iter()
        .flat_map(|(_, set)| set.iter().map(String::as_str))
        .collect();

    // Index closed, fully-verified grants by grant_id, reading match fields ONLY from the proven
    // grant_evidence (R1). `used` tracks matched uses (single-use ≤1 per grant_id, and grants_unused).
    struct GrantInfo {
        action: String,
        resource_id: String,
        scope_class: String,
        cnf_kid: String,
        issued_at: i64,
        exp: i64,
        used: usize,
    }
    let mut grants_by_id: BTreeMap<String, GrantInfo> = BTreeMap::new();
    for rt in &record_trust {
        let rec = &records[rt.index];
        let qualifies = rt.broker_role == BrokerRole::Broker.as_str()
            && rt.trust == TrustLevel::IntegrityProven
            && rt.authority == AuthorityTrust::Verified
            && evidence_rederivable(rec, "grant_evidence")
            && closed.contains(rt.content_hash.as_str());
        if !qualifies {
            continue;
        }
        match (
            ev_str(rec, "grant_evidence", "grant_id"),
            ev_str(rec, "grant_evidence", "action"),
            ev_str(rec, "grant_evidence", "resource_id"),
            ev_str(rec, "grant_evidence", "scope_class"),
            ev_str(rec, "grant_evidence", "cnf_kid"),
            ev_int(rec, "grant_evidence", "issued_at"),
            ev_int(rec, "grant_evidence", "exp"),
        ) {
            (Some(gid), Some(action), Some(resource_id), Some(scope_class), Some(cnf_kid), Some(issued_at), Some(exp)) => {
                grants_by_id.entry(gid).or_insert(GrantInfo {
                    action,
                    resource_id,
                    scope_class,
                    cnf_kid,
                    issued_at,
                    exp,
                    used: 0,
                });
            }
            // A verified, closed broker grant whose grant_evidence is missing a required match field is
            // a fail-closed failure surfaced as an issue — NOT a silent skip (which would let a use
            // against it read as "action without a credential" and mask the real cause).
            _ => issues.push(format!(
                "grant {} ({}): closed broker grant has incomplete grant_evidence (missing a required match field) — fail-closed",
                rt.index, rt.record_id
            )),
        }
    }

    let mut uses_total = 0usize;
    let mut uses_matched = 0usize;
    let mut uses_action_unverified = 0usize;
    let mut unmatched_violation = 0usize;
    let mut unmatched_pending = 0usize;
    let mut seen_uses: BTreeSet<&str> = BTreeSet::new();
    for rt in &record_trust {
        let rec = &records[rt.index];
        if rt.broker_role != BrokerRole::Resource.as_str() {
            continue;
        }
        if !seen_uses.insert(rt.content_hash.as_str()) {
            continue; // verbatim-duplicate use deduped (not double-counted)
        }
        uses_total += 1;
        if !closed.contains(rt.content_hash.as_str()) {
            unmatched_pending += 1; // in-flight: not yet committed by a verified anchored checkpoint
            continue;
        }
        // A CLOSED use must be cryptographically validatable (integrity + resource-role authority +
        // re-derivable use_evidence) before its match fields can be trusted — otherwise fail closed.
        let violation = |issues: &mut Vec<String>, msg: String| {
            issues.push(format!("use {} ({}): {msg}", rt.index, rt.record_id));
        };
        if rt.trust != TrustLevel::IntegrityProven
            || rt.authority != AuthorityTrust::Verified
            || !evidence_rederivable(rec, "use_evidence")
        {
            unmatched_violation += 1;
            violation(&mut issues, "closed but not validatable (integrity / resource authority / re-derivable evidence) — Tier-B violation".into());
            continue;
        }
        // MUST-FIX 1: read match inputs ONLY from use_evidence; a divergent top-level `action` echo is a
        // hard failure, not a silent non-match.
        let u_action = ev_str(rec, "use_evidence", "action");
        if let (Some(top), Some(ua)) = (s(rec, "action"), &u_action) {
            if &top != ua {
                unmatched_violation += 1;
                violation(&mut issues, "top-level action diverges from use_evidence.action (MUST-FIX 1)".into());
                continue;
            }
        }
        // MUST-FIX 1 (mirror of the grant-side kind guard): `kind` is duplicated at extensions.broker.kind
        // (the role discriminator that made this a resource record) and inside use_evidence. The payload
        // MUST say kind="use"; absence or divergence is a hard failure.
        if ev_str(rec, "use_evidence", "kind").as_deref() != Some("use") {
            unmatched_violation += 1;
            violation(&mut issues, "use_evidence.kind is absent or diverges from the extensions.broker.kind discriminator (MUST-FIX 1)".into());
            continue;
        }
        // MUST-FIX 4: the receipt must CARRY well-formed audit fields the verifier surfaces for offline
        // inspection — pop_challenge_hash + ledger_commitment as sha256:<hex>, and a non-empty nonce.
        // (The verifier does NOT re-run PoP or prove ledger ordering — that is the resource-shim TCB —
        // but a use that simply omits or mangles these fields must not read as a clean match.)
        let well_formed_sha = |key: &str| {
            ev_str(rec, "use_evidence", key)
                .as_deref()
                .and_then(crate::hashx::parse_sha256)
                .is_some()
        };
        if !well_formed_sha("pop_challenge_hash") || !well_formed_sha("ledger_commitment") {
            unmatched_violation += 1;
            violation(&mut issues, "use_evidence is missing or malformed pop_challenge_hash / ledger_commitment (must be sha256:<hex>) — MUST-FIX 4".into());
            continue;
        }
        if ev_str(rec, "use_evidence", "nonce").is_none_or(|n| n.is_empty()) {
            unmatched_violation += 1;
            violation(&mut issues, "use_evidence is missing the PoP nonce (R4) — violation".into());
            continue;
        }
        let (gid, action, resource_id, jti, cnf_kid, used_at) = match (
            ev_str(rec, "use_evidence", "grant_id"),
            u_action,
            ev_str(rec, "use_evidence", "resource_id"),
            ev_str(rec, "use_evidence", "jti"),
            ev_str(rec, "use_evidence", "cnf_kid"),
            ev_int(rec, "use_evidence", "used_at"),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => (a, b, c, d, e, f),
            _ => {
                unmatched_violation += 1;
                violation(&mut issues, "use_evidence is missing a required match field — violation".into());
                continue;
            }
        };
        let g = match grants_by_id.get_mut(&gid) {
            Some(g) => g,
            None => {
                unmatched_violation += 1;
                violation(&mut issues, format!("no matching closed grant '{gid}' — action without a credential (Tier-B violation)"));
                continue;
            }
        };
        // Full predicate: action / resource / temporal-window / cnf_kid equality, read from the proven
        // payloads on both sides.
        // The temporal window is [issued_at, exp) — used_at >= exp is expired, matching the resource
        // shim's `now >= exp` rejection (so the verifier is not more lenient than the gateway).
        if action != g.action
            || resource_id != g.resource_id
            || cnf_kid != g.cnf_kid
            || used_at < g.issued_at
            || used_at >= g.exp
        {
            unmatched_violation += 1;
            violation(&mut issues, format!("action/resource/cnf/window does not match grant '{gid}' — violation"));
            continue;
        }
        // Single-use (R5 rev 4): per-grant_id at most once, regardless of jti; jti must equal grant_id.
        let single = g.scope_class == "single_operation";
        if single && jti != gid {
            unmatched_violation += 1;
            violation(&mut issues, format!("single_operation grant '{gid}' requires use_evidence.jti == grant_id (R5) — violation"));
            continue;
        }
        if single && g.used >= 1 {
            unmatched_violation += 1;
            violation(&mut issues, format!("single-use grant '{gid}' exercised more than once — double-spend (R5)"));
            continue;
        }
        g.used += 1;
        uses_matched += 1;
        // R6: no signed operation taxonomy validates scope_class==single_operation, so a matched use is
        // a demonstrator artifact (action_unverified) and never contributes to an attested_complete
        // upgrade.
        uses_action_unverified += 1;
    }
    let grants_unused = grants_by_id.values().filter(|g| g.used == 0).count();

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
        uses_total,
        uses_matched,
        uses_action_unverified,
        unmatched_violation,
        unmatched_pending,
        grants_unused,
        coverage_manifest,
        issues,
        first_broken_link,
    }
}
