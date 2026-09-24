//! Plan 009: historical ordering of an authorization against a revocation, kept separate from
//! current revocation. See `docs/decisions/0007-temporal-revocation.md`.
//!
//! The only positive historical basis implemented is `db_serialized_v1`: Averin allocates a
//! per-project authorization ordinal inside the project transaction that stores a resource-signed
//! receipt, and a prospective revocation allocates its cutoff from the same counter. A receipt is
//! `proven_before` a revocation iff its authenticated ordinal is strictly below the authenticated
//! cutoff, and the snapshot that disclosed the revocation state covers the ordinal. This proves an
//! order inside Averin's database under honest resource signer, revocation signer and database
//! serialization. It does not prove physical action time or independent database membership.
//!
//! The caller selects the policy out of band. Nothing in a bundle can select or weaken it.

use crate::canon::CanonValue;
use std::collections::{BTreeMap, BTreeSet};

/// Receipt ordering sub-object inside `use_evidence`, `use_outcome` or `introspection_evidence`.
pub const AUTHORIZATION_ORDER_FORMAT: &str = "averin.authorization_order.v1";
/// Versioned disclosed revocation list. It is carried under the legacy `revocation_list` key but
/// signed in a different domain, so a legacy verifier rejects it instead of misreading it.
pub const REVOCATION_LIST_V2_FORMAT: &str = "averin.revocation.list.v2";
pub const REVOCATION_LIST_V2_DOMAIN: &str = "averin.revocation.v2";
/// Versioned Merkle revocation root whose leaves commit each grant's mode and cutoff.
pub const MERKLE_ROOT_V2_FORMAT: &str = "averin.revocation.merkleroot.v2";
pub const MERKLE_ROOT_V2_DOMAIN: &str = "averin.broker.revocation.merkleroot.v2";
/// The named trust basis every positive historical judgment carries in the report.
pub const DB_SERIALIZED_V1_TRUST_BASIS: &str = "db_serialized_v1: order of authorization receipts and revocation cutoffs within Averin's project database, assuming an honest resource signer, an honest revocation signer and correct database serialization; it does not prove physical action time or independent database membership";

/// Caller-selected temporal revocation policy (plan 009). `Strict` is today's behavior: no
/// historical positive is ever produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TemporalPolicy {
    #[default]
    Strict,
    DbSerializedV1(DbSerializedPolicy),
}

/// The caller's clock and freshness requirements. Construct with [`DbSerializedPolicy::new`], which
/// rejects a malformed evaluation time, a non-positive maximum age and a negative watermark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbSerializedPolicy {
    evaluation_time: String,
    evaluation_ms: i64,
    max_snapshot_age_seconds: i64,
    min_authorization_watermark: i64,
}

impl DbSerializedPolicy {
    pub fn new(
        evaluation_time: &str,
        max_snapshot_age_seconds: i64,
        min_authorization_watermark: i64,
    ) -> Result<Self, String> {
        let evaluation_ms = canonical_ts_millis(evaluation_time).ok_or(
            "revocation_temporal.evaluation_time must be a canonical YYYY-MM-DDTHH:MM:SS.mmmZ time",
        )?;
        // One year is far above any operational freshness bound and keeps the millisecond
        // arithmetic well inside i64.
        if !(1..=366 * 24 * 3600).contains(&max_snapshot_age_seconds) {
            return Err(
                "revocation_temporal.max_snapshot_age_seconds must be between 1 and 31622400"
                    .into(),
            );
        }
        if min_authorization_watermark < 0 {
            return Err("revocation_temporal.min_authorization_watermark must be >= 0".into());
        }
        Ok(Self {
            evaluation_time: evaluation_time.to_string(),
            evaluation_ms,
            max_snapshot_age_seconds,
            min_authorization_watermark,
        })
    }
    pub fn evaluation_time(&self) -> &str {
        &self.evaluation_time
    }
    pub fn max_snapshot_age_seconds(&self) -> i64 {
        self.max_snapshot_age_seconds
    }
    pub fn min_authorization_watermark(&self) -> i64 {
        self.min_authorization_watermark
    }
    pub(super) fn evaluation_ms(&self) -> i64 {
        self.evaluation_ms
    }
}

impl TemporalPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::DbSerializedV1(_) => "db_serialized_v1",
        }
    }

    /// Parse `revocation_temporal` from the caller's verify options. Absence is `strict`. Every
    /// other malformed, unknown or partial value is a configuration error, never a fallback.
    pub(super) fn parse(opts: &CanonValue) -> Result<Self, String> {
        let raw = match opts.get("revocation_temporal") {
            None => return Ok(Self::Strict),
            Some(v) => v,
        };
        let fields = raw
            .as_object()
            .ok_or("revocation_temporal must be an object")?;
        for (key, _) in fields {
            if !matches!(
                key.as_str(),
                "policy"
                    | "evaluation_time"
                    | "max_snapshot_age_seconds"
                    | "min_authorization_watermark"
            ) {
                return Err(format!("revocation_temporal has unknown field {key:?}"));
            }
        }
        match raw.get("policy") {
            Some(CanonValue::Str(s)) if s == "strict" => {
                if fields.len() != 1 {
                    return Err("revocation_temporal policy strict takes no other fields".into());
                }
                Ok(Self::Strict)
            }
            Some(CanonValue::Str(s)) if s == "db_serialized_v1" => {
                let eval = raw.get("evaluation_time").and_then(|v| v.as_str()).ok_or(
                    "revocation_temporal.evaluation_time is required for db_serialized_v1",
                )?;
                let age = match raw.get("max_snapshot_age_seconds") {
                    Some(CanonValue::Int(n)) => *n,
                    _ => {
                        return Err("revocation_temporal.max_snapshot_age_seconds (integer) is required for db_serialized_v1".into())
                    }
                };
                let min =
                    match raw.get("min_authorization_watermark") {
                        None => 0,
                        Some(CanonValue::Int(n)) => *n,
                        Some(_) => return Err(
                            "revocation_temporal.min_authorization_watermark must be an integer"
                                .into(),
                        ),
                    };
                Ok(Self::DbSerializedV1(DbSerializedPolicy::new(
                    eval, age, min,
                )?))
            }
            Some(_) => Err("revocation_temporal.policy is unsupported".into()),
            None => Err("revocation_temporal.policy is required".into()),
        }
    }
}

/// Milliseconds since the Unix epoch for a canonical `YYYY-MM-DDTHH:MM:SS.mmmZ` time with a real
/// calendar date. `None` for every other spelling, including 2026-02-30.
pub fn canonical_ts_millis(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 24
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let mut n = 0i64;
        for &c in &b[from..to] {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + i64::from(c - b'0');
        }
        Some(n)
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, min, sec, ms) = (num(11, 13)?, num(14, 16)?, num(17, 19)?, num(20, 23)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > days_in_month || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((((days * 24 + hour) * 60 + min) * 60 + sec) * 1000 + ms)
}

/// One grant's revocation mode as committed by a v2 artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevState {
    /// Compromise or legacy revocation: every use is invalid.
    Total,
    /// Cancellation effective at this authorization ordinal: uses with a smaller ordinal predate it.
    Prospective(i64),
}

impl RevState {
    /// Conservative combination: any total revocation wins; otherwise the earliest cutoff.
    pub fn combine(self, other: RevState) -> RevState {
        match (self, other) {
            (RevState::Prospective(a), RevState::Prospective(b)) => RevState::Prospective(a.min(b)),
            _ => RevState::Total,
        }
    }
    fn mode(self) -> &'static str {
        match self {
            RevState::Total => "total",
            RevState::Prospective(_) => "prospective",
        }
    }
    fn cutoff(self) -> i64 {
        match self {
            RevState::Total => 0,
            RevState::Prospective(c) => c,
        }
    }
}

/// The authenticated snapshot identity signed into a v2 revocation artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub project_id: String,
    pub boundary_time: String,
    pub boundary_ms: i64,
    pub watermark: i64,
}

/// Parse the signed `project_id` and `snapshot` of a v2 artifact. Exact fields only.
pub(super) fn parse_snapshot(artifact: &CanonValue) -> Result<Snapshot, String> {
    let project_id = artifact
        .get("project_id")
        .and_then(|v| v.as_str())
        .filter(|p| !p.is_empty())
        .ok_or("missing project_id")?
        .to_string();
    let snap = artifact.get("snapshot").ok_or("missing snapshot")?;
    let fields = snap.as_object().ok_or("snapshot is not an object")?;
    if fields.len() != 2 {
        return Err(
            "snapshot must carry exactly boundary_time and authorization_high_watermark".into(),
        );
    }
    let boundary_time = snap
        .get("boundary_time")
        .and_then(|v| v.as_str())
        .ok_or("snapshot.boundary_time missing")?
        .to_string();
    let boundary_ms =
        canonical_ts_millis(&boundary_time).ok_or("snapshot.boundary_time is not canonical")?;
    let watermark = match snap.get("authorization_high_watermark") {
        Some(CanonValue::Int(n)) if *n >= 0 => *n,
        _ => return Err("snapshot.authorization_high_watermark must be an integer >= 0".into()),
    };
    Ok(Snapshot {
        project_id,
        boundary_time,
        boundary_ms,
        watermark,
    })
}

/// The committed revocations of a v2 disclosed list. `ids` is every grant id named anywhere in the
/// list, including a malformed entry, because a signed revocation must still block current use.
pub(super) struct V2Entries {
    pub states: BTreeMap<String, RevState>,
    pub ids: BTreeSet<String>,
    pub well_formed: bool,
}

pub(super) fn parse_v2_entries(list: &CanonValue, watermark: Option<i64>) -> V2Entries {
    let mut out = V2Entries {
        states: BTreeMap::new(),
        ids: BTreeSet::new(),
        well_formed: true,
    };
    let Some(arr) = list.get("revocations").and_then(|v| v.as_array()) else {
        out.well_formed = false;
        return out;
    };
    let mut previous: Option<String> = None;
    for e in arr {
        let gid = e.get("grant_id").and_then(|v| v.as_str()).map(String::from);
        if let Some(g) = &gid {
            out.ids.insert(g.clone());
        }
        let state = parse_state(e, watermark);
        match (gid, state) {
            (Some(g), Some(st)) if !g.is_empty() => {
                // Strictly sorted and unique: the producer's canonical order. A duplicate is still
                // combined conservatively for current revocation but marks the list malformed.
                if previous.as_deref().is_some_and(|p| p >= g.as_str()) {
                    out.well_formed = false;
                }
                previous = Some(g.clone());
                let merged = match out.states.get(&g) {
                    Some(prior) => prior.combine(st),
                    None => st,
                };
                out.states.insert(g, merged);
            }
            (Some(g), None) => {
                // A malformed mode/cutoff can never support a positive; treat the named grant as
                // totally revoked for historical purposes.
                out.well_formed = false;
                out.states.insert(g, RevState::Total);
            }
            _ => out.well_formed = false,
        }
    }
    out
}

fn parse_state(e: &CanonValue, watermark: Option<i64>) -> Option<RevState> {
    let fields = e.as_object()?;
    match e.get("mode").and_then(|v| v.as_str())? {
        "total" if fields.len() == 2 => Some(RevState::Total),
        "prospective" if fields.len() == 3 => match e.get("cutoff_order") {
            Some(CanonValue::Int(c)) if *c >= 1 && watermark.is_none_or(|w| *c <= w) => {
                Some(RevState::Prospective(*c))
            }
            _ => None,
        },
        _ => None,
    }
}

fn lp4(pre: &mut Vec<u8>, b: &[u8]) {
    pre.extend_from_slice(&(b.len() as u32).to_be_bytes());
    pre.extend_from_slice(b);
}

/// The v2 Merkle sort key for a grant: `sha256(LP4("averin.broker.revocation.key.v2") ‖ LP4(grant_id))`.
pub fn revocation_key_v2(grant_id: &str) -> [u8; 32] {
    crate::hashx::sha256(&revocation_key_v2_preimage(grant_id))
}

/// Exact bytes hashed by [`revocation_key_v2`].
#[doc(hidden)]
pub fn revocation_key_v2_preimage(grant_id: &str) -> Vec<u8> {
    let mut pre = Vec::new();
    lp4(&mut pre, b"averin.broker.revocation.key.v2");
    lp4(&mut pre, grant_id.as_bytes());
    pre
}

/// The committed state digest: `sha256(LP4("averin.broker.revocation.state.v2") ‖ LP4(mode) ‖ BE8(cutoff))`,
/// with mode `total` (cutoff 0), `prospective` (cutoff >= 1) or `sentinel` (cutoff 0).
pub fn revocation_state_digest_v2(mode: &str, cutoff: i64) -> [u8; 32] {
    crate::hashx::sha256(&revocation_state_v2_preimage(mode, cutoff))
}

/// Exact bytes hashed by [`revocation_state_digest_v2`].
#[doc(hidden)]
pub fn revocation_state_v2_preimage(mode: &str, cutoff: i64) -> Vec<u8> {
    let mut pre = Vec::new();
    lp4(&mut pre, b"averin.broker.revocation.state.v2");
    lp4(&mut pre, mode.as_bytes());
    pre.extend_from_slice(&(cutoff as u64).to_be_bytes());
    pre
}

/// The 32-byte leaf value folded by the RFC6962 tree:
/// `sha256(LP4("averin.broker.revocation.entry.v2") ‖ key ‖ state_digest)`.
pub fn revocation_entry_v2(key: &[u8; 32], state_digest: &[u8; 32]) -> [u8; 32] {
    crate::hashx::sha256(&revocation_entry_v2_preimage(key, state_digest))
}

/// Exact bytes hashed by [`revocation_entry_v2`].
#[doc(hidden)]
pub fn revocation_entry_v2_preimage(key: &[u8; 32], state_digest: &[u8; 32]) -> Vec<u8> {
    let mut pre = Vec::new();
    lp4(&mut pre, b"averin.broker.revocation.entry.v2");
    pre.extend_from_slice(key);
    pre.extend_from_slice(state_digest);
    pre
}

/// Producer reference for the v2 Merkle root over `(grant_id, state)` entries: leaves sorted by key
/// and bracketed by sentinel keys `0x00*32` and `0xff*32`. Kept in sync with Go by a golden vector.
pub fn revocation_merkle_root_v2(entries: &[(&str, RevState)]) -> String {
    let leaves = revocation_leaves_v2(entries);
    let mut level: Vec<[u8; 32]> = leaves.iter().map(super::merkle_leaf_hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(super::merkle_node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    format!("sha256:{}", crate::hashx::hex_lower(&level[0]))
}

/// The sorted, sentinel-bracketed `(key, state_digest)` pairs and their leaf values.
pub fn revocation_leaves_v2(entries: &[(&str, RevState)]) -> Vec<[u8; 32]> {
    let mut pairs: Vec<([u8; 32], [u8; 32])> = entries
        .iter()
        .map(|(g, st)| {
            (
                revocation_key_v2(g),
                revocation_state_digest_v2(st.mode(), st.cutoff()),
            )
        })
        .collect();
    pairs.sort();
    let sentinel = revocation_state_digest_v2("sentinel", 0);
    let mut out = Vec::with_capacity(pairs.len() + 2);
    out.push(revocation_entry_v2(&[0u8; 32], &sentinel));
    out.extend(pairs.iter().map(|(k, s)| revocation_entry_v2(k, s)));
    out.push(revocation_entry_v2(&[0xffu8; 32], &sentinel));
    out
}

/// Per-grant verdict of a v2 Merkle proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProofV2 {
    NotRevoked,
    Revoked(RevState),
    Unproven,
}

/// Verify a v2 proof. A membership proof must carry the grant's mode and cutoff in clear; the
/// verifier re-derives the committed state digest, so a stripped or altered cutoff cannot
/// authenticate. A non-membership proof reveals the neighbours' keys and opaque state digests only.
pub(super) fn check_revocation_proof_v2(
    proof: &CanonValue,
    grant_id: &str,
    root: &[u8; 32],
    leaf_count: usize,
    watermark: i64,
) -> ProofV2 {
    let q = revocation_key_v2(grant_id);
    let int = |k: &str| proof.get(k).and_then(|v| v.as_int()).filter(|i| *i >= 0);
    let path = |k: &str| super::parse_hex32_path(proof.get(k));
    let hex = |v: Option<&CanonValue>| v.and_then(|x| x.as_str()).and_then(super::parse_hex32);
    match proof.get("type").and_then(|v| v.as_str()).unwrap_or("") {
        "membership" => {
            let Some(state) = parse_state_fields(proof, watermark) else {
                return ProofV2::Unproven;
            };
            let (Some(i), Some(p)) = (int("index"), path("path")) else {
                return ProofV2::Unproven;
            };
            let leaf = revocation_entry_v2(
                &q,
                &revocation_state_digest_v2(state.mode(), state.cutoff()),
            );
            if super::merkle_root_from_proof(&leaf, i as usize, leaf_count, &p) == Some(*root) {
                ProofV2::Revoked(state)
            } else {
                ProofV2::Unproven
            }
        }
        "nonmembership" => {
            let side = |k: &str| {
                let o = proof.get(k)?;
                if o.as_object()?.len() != 2 {
                    return None;
                }
                Some((hex(o.get("key"))?, hex(o.get("state_digest"))?))
            };
            let (Some((lo_key, lo_state)), Some((hi_key, hi_state))) = (side("lo"), side("hi"))
            else {
                return ProofV2::Unproven;
            };
            let (Some(li), Some(hi_i), Some(lp), Some(hp)) = (
                int("lo_index"),
                int("hi_index"),
                path("lo_path"),
                path("hi_path"),
            ) else {
                return ProofV2::Unproven;
            };
            if li.checked_add(1) != Some(hi_i) || !(lo_key < q && q < hi_key) {
                return ProofV2::Unproven;
            }
            let lo = revocation_entry_v2(&lo_key, &lo_state);
            let hi = revocation_entry_v2(&hi_key, &hi_state);
            if super::merkle_root_from_proof(&lo, li as usize, leaf_count, &lp) != Some(*root)
                || super::merkle_root_from_proof(&hi, hi_i as usize, leaf_count, &hp) != Some(*root)
            {
                return ProofV2::Unproven;
            }
            ProofV2::NotRevoked
        }
        _ => ProofV2::Unproven,
    }
}

// A membership proof's clear state: `mode` plus `cutoff_order` for a prospective revocation.
fn parse_state_fields(proof: &CanonValue, watermark: i64) -> Option<RevState> {
    match proof.get("mode").and_then(|v| v.as_str())? {
        "total" if proof.get("cutoff_order").is_none() => Some(RevState::Total),
        "prospective" => match proof.get("cutoff_order") {
            Some(CanonValue::Int(c)) if *c >= 1 && *c <= watermark => {
                Some(RevState::Prospective(*c))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The authenticated ordinal inside a receipt's signed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum OrderEv {
    Absent,
    Malformed,
    Present { project_id: String, ordinal: i64 },
}

impl OrderEv {
    pub(super) fn ordinal(&self) -> Option<i64> {
        match self {
            OrderEv::Present { ordinal, .. } => Some(*ordinal),
            _ => None,
        }
    }
}

/// Read `extensions.broker.<payload_key>.authorization_order`. The caller has already proved that the
/// payload re-derives the resource-signed evidence hash.
pub(super) fn authorization_order(rec: &CanonValue, payload_key: &str) -> OrderEv {
    let Some(o) = rec
        .get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get(payload_key))
        .and_then(|p| p.get("authorization_order"))
    else {
        return OrderEv::Absent;
    };
    let well = o.as_object().is_some_and(|f| f.len() == 3)
        && o.get("format").and_then(|v| v.as_str()) == Some(AUTHORIZATION_ORDER_FORMAT);
    match (well, o.get("project_id"), o.get("ordinal")) {
        (true, Some(CanonValue::Str(p)), Some(CanonValue::Int(n))) if !p.is_empty() && *n >= 1 => {
            OrderEv::Present {
                project_id: p.clone(),
                ordinal: *n,
            }
        }
        _ => OrderEv::Malformed,
    }
}

/// One grant's revocation as evaluated from every present, validly signed artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRevocation {
    /// No pinned revocation issuer, or no signed artifact.
    NotEvaluated,
    /// Not revoked according to a legacy (v1) artifact only: not bound to a snapshot.
    NotRevokedUnbound,
    /// Not revoked in the complete v2 snapshot state.
    NotRevokedAsOfSnapshot,
    Prospective(i64),
    Total,
    /// A Merkle root is present but this grant has no valid proof.
    Unproven,
}

impl GrantRevocation {
    pub fn current_str(self) -> &'static str {
        match self {
            GrantRevocation::NotEvaluated => "not_evaluated",
            GrantRevocation::NotRevokedUnbound | GrantRevocation::NotRevokedAsOfSnapshot => {
                "not_revoked"
            }
            GrantRevocation::Prospective(_) => "revoked_prospective",
            GrantRevocation::Total => "revoked_total",
            GrantRevocation::Unproven => "unproven",
        }
    }
}

/// Accumulates one grant's revocation over the present artifacts. v1 artifacts can only add a
/// total revocation or an unproven path; only v2 artifacts can support "not revoked as of snapshot".
#[derive(Default)]
pub(super) struct GrantRevocationAcc {
    total: bool,
    unproven: bool,
    cutoff: Option<i64>,
    v2_sources: usize,
    v2_nonmember: usize,
    any_source: bool,
}

impl GrantRevocationAcc {
    pub(super) fn legacy_member(&mut self) {
        self.any_source = true;
        self.total = true;
    }
    pub(super) fn legacy_nonmember(&mut self) {
        self.any_source = true;
    }
    pub(super) fn unproven(&mut self) {
        self.any_source = true;
        self.unproven = true;
    }
    pub(super) fn v2(&mut self, state: Option<RevState>) {
        self.any_source = true;
        self.v2_sources += 1;
        match state {
            None => self.v2_nonmember += 1,
            Some(RevState::Total) => self.total = true,
            Some(RevState::Prospective(c)) => {
                self.cutoff = Some(self.cutoff.map_or(c, |p| p.min(c)));
            }
        }
    }
    pub(super) fn finish(&self) -> GrantRevocation {
        if self.total {
            GrantRevocation::Total
        } else if self.unproven {
            GrantRevocation::Unproven
        } else if let Some(c) = self.cutoff {
            GrantRevocation::Prospective(c)
        } else if self.v2_sources > 0 && self.v2_nonmember == self.v2_sources {
            GrantRevocation::NotRevokedAsOfSnapshot
        } else if self.any_source {
            GrantRevocation::NotRevokedUnbound
        } else {
            GrantRevocation::NotEvaluated
        }
    }
}

/// The per-receipt historical judgment reported separately from current revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalOrdering {
    ProvenBefore,
    AtOrAfter,
    Indeterminate,
}

impl HistoricalOrdering {
    pub fn as_str(self) -> &'static str {
        match self {
            HistoricalOrdering::ProvenBefore => "proven_before",
            HistoricalOrdering::AtOrAfter => "at_or_after",
            HistoricalOrdering::Indeterminate => "indeterminate",
        }
    }
}

/// `snapshot` is `Some` only when the caller selected `db_serialized_v1` and the snapshot
/// authenticated and met the caller's freshness and watermark requirements. `validated` means the
/// receipt passed every legacy validation (or the identical shadow validation for a revoked grant).
///
/// `at_or_after` needs only an authenticated ordinal and an authenticated cutoff: cutoffs never
/// move later, so it is adverse whatever snapshot carried it. `proven_before` additionally needs
/// the verified snapshot, the same project and an ordinal at or below the snapshot watermark: any
/// revocation missing from the snapshot was allocated a cutoff above that watermark.
pub(super) fn classify(
    snapshot: Option<&Snapshot>,
    validated: bool,
    order: &OrderEv,
    grant: GrantRevocation,
) -> HistoricalOrdering {
    let OrderEv::Present {
        project_id,
        ordinal,
    } = order
    else {
        return HistoricalOrdering::Indeterminate;
    };
    if !validated {
        return HistoricalOrdering::Indeterminate;
    }
    if let GrantRevocation::Prospective(c) = grant {
        if *ordinal >= c {
            return HistoricalOrdering::AtOrAfter;
        }
    }
    let Some(snap) = snapshot else {
        return HistoricalOrdering::Indeterminate;
    };
    if *project_id != snap.project_id || *ordinal > snap.watermark {
        return HistoricalOrdering::Indeterminate;
    }
    match grant {
        GrantRevocation::NotRevokedAsOfSnapshot | GrantRevocation::Prospective(_) => {
            HistoricalOrdering::ProvenBefore
        }
        _ => HistoricalOrdering::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_time_rejects_impossible_dates() {
        assert_eq!(canonical_ts_millis("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            canonical_ts_millis("2026-06-15T10:10:01.250Z"),
            Some(1_781_518_201_250)
        );
        assert_eq!(
            canonical_ts_millis("2024-02-29T00:00:00.000Z"),
            Some(1_709_164_800_000)
        );
        for bad in [
            "2026-02-29T00:00:00.000Z",
            "2026-04-31T00:00:00.000Z",
            "2026-13-01T00:00:00.000Z",
            "2026-06-15T24:00:00.000Z",
            "2026-06-15T10:10:01Z",
            "2026-06-15 10:10:01.000Z",
            "２026-06-15T10:10:01.000Z",
        ] {
            assert_eq!(canonical_ts_millis(bad), None, "{bad}");
        }
    }

    #[test]
    fn combine_is_conservative() {
        use RevState::*;
        assert_eq!(Prospective(9).combine(Prospective(4)), Prospective(4));
        assert_eq!(Prospective(4).combine(Total), Total);
        assert_eq!(Total.combine(Prospective(4)), Total);
    }

    #[test]
    fn classification_requires_every_input() {
        let snap = Snapshot {
            project_id: "p".into(),
            boundary_time: "1970-01-01T00:00:00.000Z".into(),
            boundary_ms: 0,
            watermark: 10,
        };
        let at = |n| OrderEv::Present {
            project_id: "p".into(),
            ordinal: n,
        };
        let pb = HistoricalOrdering::ProvenBefore;
        let aa = HistoricalOrdering::AtOrAfter;
        let ind = HistoricalOrdering::Indeterminate;
        let p5 = GrantRevocation::Prospective(5);
        assert_eq!(classify(Some(&snap), true, &at(4), p5), pb);
        assert_eq!(
            classify(Some(&snap), true, &at(5), p5),
            aa,
            "equality is after"
        );
        assert_eq!(classify(Some(&snap), true, &at(6), p5), aa);
        assert_eq!(classify(None, true, &at(4), p5), ind);
        assert_eq!(
            classify(None, true, &at(5), p5),
            aa,
            "a cutoff needs no snapshot"
        );
        assert_eq!(classify(Some(&snap), false, &at(5), p5), ind, "unvalidated");
        assert_eq!(classify(Some(&snap), false, &at(4), p5), ind);
        assert_eq!(classify(Some(&snap), true, &OrderEv::Absent, p5), ind);
        assert_eq!(classify(Some(&snap), true, &OrderEv::Malformed, p5), ind);
        let clean = GrantRevocation::NotRevokedAsOfSnapshot;
        assert_eq!(
            classify(Some(&snap), true, &at(11), clean),
            ind,
            "beyond watermark"
        );
        assert_eq!(classify(Some(&snap), true, &at(11), p5), aa);
        assert_eq!(
            classify(Some(&snap), true, &at(4), GrantRevocation::Total),
            ind
        );
        assert_eq!(
            classify(Some(&snap), true, &at(4), GrantRevocation::Unproven),
            ind
        );
        assert_eq!(
            classify(
                Some(&snap),
                true,
                &at(4),
                GrantRevocation::NotRevokedUnbound
            ),
            ind
        );
        assert_eq!(
            classify(
                Some(&snap),
                true,
                &at(4),
                GrantRevocation::NotRevokedAsOfSnapshot
            ),
            pb
        );
        let other = OrderEv::Present {
            project_id: "q".into(),
            ordinal: 1,
        };
        assert_eq!(classify(Some(&snap), true, &other, p5), ind);
    }
}
