//! AVE-01: month segments. A project's history is split into separately checkable bundles, one per month, each
//! chained to the previous month's last checkpoint, so no single export has to hold all history.
//!
//! A segment is an ordinary bundle plus a `segment` block (`averin.segment.v1`):
//!
//! ```text
//! "segment": { "format": "averin.segment.v1", "month": "2026-09",
//!              "base_seq": 12, "base_checkpoint_hash": "sha256:...", "base_record_count": 480 }
//! ```
//!
//! `checkpoints` carries the base checkpoint first (a real, signed, possibly anchored checkpoint) and then
//! the checkpoints created in `month`. `records` carries only the records those checkpoints commit beyond the
//! base. The first month has no base (`null`, `null`, `0`) and verifies exactly like a whole-history bundle.
//! The verifier checks one segment and its link ([`crate::verify`]); [`ChainState`] chains the months and resolves
//! the parents that point before a base.

use crate::canon::CanonValue;
use crate::checkpoint::{validate_chain, CheckpointError};
use crate::dag::Dag;
use crate::hashx::parse_sha256;
use crate::verify::SEGMENT_FORMAT;
use std::collections::{BTreeMap, BTreeSet};

fn str_of<'a>(v: &'a CanonValue, k: &str) -> Option<&'a str> {
    v.get(k).and_then(CanonValue::as_str)
}

fn array_of<'a>(v: &'a CanonValue, k: &str) -> &'a [CanonValue] {
    v.get(k)
        .and_then(CanonValue::as_array)
        .map_or(&[][..], |a| a.as_slice())
}

fn seq_of(cp: &CanonValue) -> Option<i64> {
    cp.get("checkpoint_seq").and_then(CanonValue::as_int)
}

fn parents_of(rec: &CanonValue) -> impl Iterator<Item = &str> {
    array_of(rec, "causal_prev_hashes")
        .iter()
        .filter_map(CanonValue::as_str)
}

/// Content hashes of `frontier` and every ancestor present in `by_hash` (what a checkpoint commits).
fn closure(
    records: &[CanonValue],
    by_hash: &BTreeMap<&str, usize>,
    frontier: &[CanonValue],
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = frontier
        .iter()
        .filter_map(|h| h.as_str().map(String::from))
        .collect();
    while let Some(h) = stack.pop() {
        if !seen.insert(h.clone()) {
            continue;
        }
        if let Some(&i) = by_hash.get(h.as_str()) {
            stack.extend(parents_of(&records[i]).map(String::from));
        }
    }
    seen
}

/// Split a whole-history bundle into one segment per month, oldest first: `(month, segment bundle)`.
///
/// Month membership is the checkpoint's `created_ts`; a record belongs to the first checkpoint whose frontier
/// commits it (the set difference of two closures, so record order in the input does not matter). Refuses
/// anything it cannot split faithfully: months that go backwards with the checkpoint seq, a checkpoint whose
/// `record_count` is not the size of its committed history, or records no checkpoint commits. It does not verify
/// signatures; run the verifier on every output (`averin-verify chain`).
///
/// `revocation_list` and `deployment_attestation` bind the whole bundle's latest checkpoint and cannot be
/// re-issued offline, so they are not copied into a split segment.
pub fn split_bundle(bundle: &CanonValue) -> Result<Vec<(String, CanonValue)>, String> {
    let records = array_of(bundle, "records");
    let mut cps: Vec<&CanonValue> = array_of(bundle, "checkpoints").iter().collect();
    if cps.is_empty() {
        return Err("bundle has no checkpoints".into());
    }
    cps.sort_by_key(|c| seq_of(c));
    let mut by_hash: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, r) in records.iter().enumerate() {
        by_hash
            .entry(str_of(r, "content_hash").ok_or("record without content_hash")?)
            .or_insert(i);
    }

    // group the checkpoints by month in seq order; months may not go backwards
    let mut groups: Vec<(String, Vec<&CanonValue>)> = Vec::new();
    for cp in &cps {
        let ts = str_of(cp, "created_ts").ok_or("checkpoint without created_ts")?;
        let m = ts
            .get(..7)
            .ok_or("checkpoint created_ts is too short")?
            .to_string();
        match groups.last_mut() {
            Some((gm, g)) if *gm == m => g.push(cp),
            Some((gm, _)) if *gm > m => {
                return Err(format!(
                    "checkpoint dated {m} follows one dated {gm}: months go backwards"
                ))
            }
            _ => groups.push((m, vec![cp])),
        }
    }

    let mut out = Vec::new();
    let mut prev_closure: BTreeSet<String> = BTreeSet::new();
    let mut base: Option<&CanonValue> = None;
    let mut total_assigned = 0usize;
    for (month, group) in &groups {
        let last = group.last().ok_or("empty month group")?;
        let frontier = array_of(last, "frontier");
        let committed = closure(records, &by_hash, frontier);
        let mine: Vec<CanonValue> = records
            .iter()
            .filter(|r| {
                str_of(r, "content_hash")
                    .is_some_and(|h| committed.contains(h) && !prev_closure.contains(h))
            })
            .cloned()
            .collect();
        let expect = last
            .get("record_count")
            .and_then(CanonValue::as_int)
            .ok_or("checkpoint without record_count")?;
        if i64::try_from(committed.len()).ok() != Some(expect) {
            return Err(format!(
                "checkpoint {} record_count {expect} is not the size of its committed history ({})",
                seq_of(last).unwrap_or(-1),
                committed.len()
            ));
        }
        total_assigned = committed.len();
        let (base_seq, base_hash, base_count) = match base {
            None => (CanonValue::Null, CanonValue::Null, 0),
            Some(b) => (
                CanonValue::Int(seq_of(b).ok_or("base without seq")?),
                CanonValue::string(str_of(b, "checkpoint_hash").ok_or("base without hash")?),
                b.get("record_count")
                    .and_then(CanonValue::as_int)
                    .ok_or("base without record_count")?,
            ),
        };
        let mut members: Vec<(String, CanonValue)> = bundle
            .as_object()
            .ok_or("bundle is not an object")?
            .iter()
            .filter(|(k, _)| {
                !matches!(
                    k.as_str(),
                    "records"
                        | "checkpoints"
                        | "segment"
                        | "revocation_list"
                        | "deployment_attestation"
                        | "filtered_records"
                        | "disclosures"
                )
            })
            .cloned()
            .collect();
        let mut cps_out: Vec<CanonValue> = base.into_iter().cloned().collect();
        cps_out.extend(group.iter().map(|c| (*c).clone()));
        members.push(("records".into(), CanonValue::Array(mine.clone())));
        members.push(("checkpoints".into(), CanonValue::Array(cps_out)));
        let mine_hashes: BTreeSet<&str> = mine
            .iter()
            .filter_map(|r| str_of(r, "content_hash"))
            .collect();
        let disclosures: Vec<CanonValue> = array_of(bundle, "disclosures")
            .iter()
            .filter(|d| {
                str_of(d, "record_id").is_some_and(|id| {
                    mine.iter().any(|r| {
                        str_of(r, "record_id") == Some(id)
                            && str_of(r, "content_hash").is_some_and(|h| mine_hashes.contains(h))
                    })
                })
            })
            .cloned()
            .collect();
        if bundle.get("disclosures").is_some() {
            members.push(("disclosures".into(), CanonValue::Array(disclosures)));
        }
        members.push((
            "segment".into(),
            CanonValue::object(vec![
                ("format".into(), CanonValue::string(SEGMENT_FORMAT)),
                ("month".into(), CanonValue::string(month.clone())),
                ("base_seq".into(), base_seq),
                ("base_checkpoint_hash".into(), base_hash),
                ("base_record_count".into(), CanonValue::Int(base_count)),
            ])
            .map_err(|e| e.to_string())?,
        ));
        out.push((
            month.clone(),
            CanonValue::object(members).map_err(|e| e.to_string())?,
        ));
        prev_closure = committed;
        base = Some(last);
    }
    if total_assigned != records.len() {
        return Err(format!(
            "{} record(s) are committed by no checkpoint",
            records.len() - total_assigned
        ));
    }
    Ok(out)
}

/// The month-by-month walk behind `averin-verify chain`: feed it each segment's bundle and report, oldest first.
/// It checks what no single month can: that each segment starts from the previous one's head, that months and
/// projects agree, that every parent a month points before its base exists in an earlier month, and that every
/// grant or intent a use or outcome names across a month boundary is held by an earlier month (existence only: the
/// use-to-grant predicate is evaluated in the month that holds both, never across months).
#[derive(Default)]
pub struct ChainState {
    project_id: Option<String>,
    head_hash: Option<String>,
    head_record_count: i64,
    last_month: Option<String>,
    seen: BTreeSet<String>,
    seen_ids: BTreeSet<String>,
    pub months: usize,
    pub records: usize,
    pub issues: Vec<String>,
}

impl ChainState {
    pub fn new() -> Self {
        Self::default()
    }

    /// The base pin to verify the next segment with: the previous head, or `genesis` for the first month.
    pub fn next_pin(&self) -> String {
        self.head_hash.clone().unwrap_or_else(|| "genesis".into())
    }

    pub fn head_hash(&self) -> Option<&str> {
        self.head_hash.as_deref()
    }

    pub fn head_record_count(&self) -> i64 {
        self.head_record_count
    }

    /// Absorb one segment after it was verified with [`ChainState::next_pin`]. `report` is its verification report.
    pub fn absorb(&mut self, bundle: &CanonValue, report: &CanonValue) {
        let label = bundle
            .get("segment")
            .and_then(|s| str_of(s, "month"))
            .unwrap_or("?")
            .to_string();
        let mut issue = |m: String| self.issues.push(format!("{label}: {m}"));
        if report.get("ok") != Some(&CanonValue::Bool(true)) {
            issue("segment does not verify".into());
        }
        let Some(seg) = report.get("segment") else {
            issue("not a month segment".into());
            return;
        };
        if seg
            .get("link")
            .and_then(CanonValue::as_str)
            .is_some_and(|l| l == "base_unpinned")
        {
            issue("base is not the previous month's head".into());
        }
        let month = str_of(seg, "month").unwrap_or("").to_string();
        if let Some(prev) = &self.last_month {
            if month.as_str() <= prev.as_str() {
                issue(format!("month does not follow {prev}"));
            }
        }
        let pid = str_of(bundle, "project_id").map(String::from);
        match (&self.project_id, &pid) {
            (Some(a), Some(b)) if a != b => issue(format!("project {b} differs from {a}")),
            (None, _) => self.project_id.clone_from(&pid),
            _ => {}
        }
        let base_count = bundle
            .get("segment")
            .and_then(|s| s.get("base_record_count"))
            .and_then(CanonValue::as_int)
            .unwrap_or(-1);
        if self.head_hash.is_some() && base_count != self.head_record_count {
            issue(format!(
                "base record count {base_count} != previous head's {}",
                self.head_record_count
            ));
        }
        // parents that point before the base must exist in an earlier month
        let records = array_of(bundle, "records");
        let mine: BTreeSet<&str> = records
            .iter()
            .filter_map(|r| str_of(r, "content_hash"))
            .collect();
        let base_frontier: BTreeSet<&str> = bundle
            .get("segment")
            .and_then(|s| str_of(s, "base_checkpoint_hash"))
            .and_then(|bh| {
                array_of(bundle, "checkpoints")
                    .iter()
                    .find(|c| str_of(c, "checkpoint_hash") == Some(bh))
            })
            .map(|c| {
                array_of(c, "frontier")
                    .iter()
                    .filter_map(CanonValue::as_str)
                    .collect()
            })
            .unwrap_or_default();
        let mut dangling = BTreeSet::new();
        for r in records {
            for p in parents_of(r) {
                if !mine.contains(p) && !base_frontier.contains(p) && !self.seen.contains(p) {
                    dangling.insert(p.to_string());
                }
            }
        }
        if !dangling.is_empty() {
            issue(format!(
                "{} parent(s) name no record in this or any earlier month, e.g. {}",
                dangling.len(),
                dangling.iter().next().map_or("", String::as_str)
            ));
        }
        // a use or outcome that names a grant or intent sealed before this month must find it in an earlier month
        for u in array_of(seg, "unresolved_cross_month") {
            let (Some(kind), Some(rid), Some(reference)) =
                (str_of(u, "kind"), str_of(u, "record_id"), str_of(u, "ref"))
            else {
                issue("malformed unresolved_cross_month entry".into());
                continue;
            };
            if !self.seen_ids.contains(reference) {
                issue(format!(
                    "{kind} {rid} names {reference}, which no earlier month holds"
                ));
            }
        }
        self.seen.extend(mine.iter().map(|h| h.to_string()));
        self.seen_ids.extend(
            records
                .iter()
                .filter_map(|r| str_of(r, "record_id").map(String::from)),
        );
        self.records += records.len();
        self.months += 1;
        self.last_month = Some(month);
        self.head_hash = str_of(seg, "head_checkpoint_hash").map(String::from);
        self.head_record_count = seg
            .get("head_record_count")
            .and_then(CanonValue::as_int)
            .unwrap_or(0);
    }

    /// True when every absorbed segment verified, linked and resolved, and at least one was absorbed.
    pub fn is_ok(&self) -> bool {
        self.months > 0 && self.issues.is_empty()
    }
}

/// The base checkpoint of a month segment: the last checkpoint of the previous segment, carried in the segment
/// as its first checkpoint. Its own signature, key and anchor are checked with every other checkpoint; this
/// is what the chain rules need from it.
pub struct SegmentBase<'a> {
    pub seq: i64,
    pub hash: &'a str,
    /// The base checkpoint's `record_count`: the records of all earlier segments.
    pub record_count: i64,
}

#[derive(Debug, PartialEq)]
pub enum SegmentChainError {
    /// A rule the whole-history chain check also has (fork, gap, count, frontier ...).
    Chain(CheckpointError),
    /// The base checkpoint the segment states is not the first checkpoint of the chain it carries.
    BaseMismatch { stated_seq: i64, found_seq: i64 },
    /// No checkpoint follows the base, so the segment commits nothing.
    SegmentEmpty { base_seq: i64 },
}

impl std::fmt::Display for SegmentChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chain(e) => write!(f, "{e}"),
            Self::BaseMismatch { stated_seq, found_seq } => write!(
                f,
                "segment base checkpoint seq {stated_seq} is not the first checkpoint carried (found {found_seq})"
            ),
            Self::SegmentEmpty { base_seq } => {
                write!(f, "segment has no checkpoint after its base checkpoint {base_seq}")
            }
        }
    }
}

fn cp_str<'a>(o: &'a CanonValue, k: &'static str) -> Result<&'a str, CheckpointError> {
    o.get(k)
        .ok_or(CheckpointError::MissingField(k))?
        .as_str()
        .ok_or(CheckpointError::FieldType(k))
}

fn cp_int(o: &CanonValue, k: &'static str) -> Result<i64, CheckpointError> {
    o.get(k)
        .ok_or(CheckpointError::MissingField(k))?
        .as_int()
        .ok_or(CheckpointError::FieldType(k))
}

/// [`validate_chain`] for a month segment. `None` is exactly [`validate_chain`]. With a base the chain starts at
/// the base checkpoint instead of seq 0 (its `prev_checkpoint_hash` is not required to be null and its frontier,
/// whose members are earlier records, is not required to be present); a later checkpoint's frontier may name
/// base frontier members the DAG carries as `external_frontier`; at least one checkpoint follows the base; and the
/// latest checkpoint's frontier equals the DAG heads and its `record_count` equals the base's count plus the
/// records carried. Everything else (seq gaps, forks, previous-hash links, non-decreasing counts) is the
/// whole-history rule applied from the base.
pub fn validate_segment_chain(
    checkpoints: &[CanonValue],
    dag: &Dag,
    base: Option<&SegmentBase<'_>>,
) -> Result<(), SegmentChainError> {
    let Some(base) = base else {
        return validate_chain(checkpoints, dag)
            .map(|_| ())
            .map_err(SegmentChainError::Chain);
    };
    let c = SegmentChainError::Chain;
    let mut ordered: Vec<&CanonValue> = checkpoints.iter().collect();
    ordered.sort_by_key(|cp| seq_of(cp).unwrap_or(i64::MIN));

    let first = ordered
        .first()
        .ok_or(c(CheckpointError::MissingField("checkpoint_seq")))?;
    let first_seq = cp_int(first, "checkpoint_seq").map_err(c)?;
    if first_seq != base.seq || cp_str(first, "checkpoint_hash").map_err(c)? != base.hash {
        return Err(SegmentChainError::BaseMismatch {
            stated_seq: base.seq,
            found_seq: first_seq,
        });
    }

    for w in ordered.windows(2) {
        let (a, b) = (w[0], w[1]);
        let (sa, sb) = (
            cp_int(a, "checkpoint_seq").map_err(c)?,
            cp_int(b, "checkpoint_seq").map_err(c)?,
        );
        if sa == sb {
            if cp_str(a, "checkpoint_hash").map_err(c)?
                != cp_str(b, "checkpoint_hash").map_err(c)?
            {
                return Err(c(CheckpointError::ForkDetected { seq: sa }));
            }
            continue;
        }
        if sb != sa + 1 {
            return Err(c(CheckpointError::SeqGap { prev: sa, next: sb }));
        }
        let prev_ref = b
            .get("prev_checkpoint_hash")
            .and_then(CanonValue::as_str)
            .ok_or(c(CheckpointError::MissingField("prev_checkpoint_hash")))?;
        let prev_hash = cp_str(a, "checkpoint_hash").map_err(c)?;
        if prev_ref != prev_hash {
            return Err(c(CheckpointError::PrevHashMismatch {
                seq: sb,
                expected: prev_hash.to_string(),
                found: prev_ref.to_string(),
            }));
        }
        let (ca, cb) = (
            cp_int(a, "record_count").map_err(c)?,
            cp_int(b, "record_count").map_err(c)?,
        );
        if cb < ca {
            return Err(c(CheckpointError::RecordCountDecreased {
                seq: sb,
                from: ca,
                to: cb,
            }));
        }
    }

    for cp in &ordered {
        let seq = cp_int(cp, "checkpoint_seq").map_err(c)?;
        let frontier = cp
            .get("frontier")
            .ok_or(c(CheckpointError::MissingField("frontier")))?
            .as_array()
            .ok_or(c(CheckpointError::FieldType("frontier")))?;
        for fh in frontier {
            let h = fh
                .as_str()
                .ok_or(c(CheckpointError::FieldType("frontier")))?;
            if parse_sha256(h).is_none() {
                return Err(c(CheckpointError::BadFrontierHash(h.to_string())));
            }
            // The base checkpoint's own frontier names records of earlier segments, which this one does not carry.
            if seq == base.seq {
                continue;
            }
            if !dag.by_hash.contains_key(h) && !dag.external_frontier.contains(h) {
                return Err(c(CheckpointError::FrontierMemberMissing {
                    seq,
                    hash: h.to_string(),
                }));
            }
        }
    }

    let mut by_prev: BTreeMap<&str, &str> = BTreeMap::new();
    for cp in &ordered {
        if let Some(prev) = cp.get("prev_checkpoint_hash").and_then(CanonValue::as_str) {
            let this = cp_str(cp, "checkpoint_hash").map_err(c)?;
            if by_prev
                .insert(prev, this)
                .is_some_and(|other| other != this)
            {
                return Err(c(CheckpointError::ForkSharedPrev {
                    prev: prev.to_string(),
                }));
            }
        }
    }

    let latest = ordered
        .last()
        .ok_or(c(CheckpointError::MissingField("checkpoint_seq")))?;
    let seq = cp_int(latest, "checkpoint_seq").map_err(c)?;
    if seq == base.seq {
        return Err(SegmentChainError::SegmentEmpty { base_seq: base.seq });
    }
    let frontier: BTreeSet<&str> = latest
        .get("frontier")
        .and_then(CanonValue::as_array)
        .ok_or(c(CheckpointError::FieldType("frontier")))?
        .iter()
        .filter_map(CanonValue::as_str)
        .collect();
    let heads: BTreeSet<&str> = dag.heads.iter().map(String::as_str).collect();
    if frontier != heads {
        return Err(c(CheckpointError::LatestFrontierMismatch {
            seq,
            stated: frontier.len(),
            actual_heads: heads.len(),
        }));
    }
    let stated = cp_int(latest, "record_count").map_err(c)?;
    // Checked arithmetic and conversion, NOT `as`: on the wasm32 verifier `usize == u32`, so a signed count of
    // 2^32 + n would truncate to n and match an n-record DAG (a platform-dependent verdict).
    let expected = i64::try_from(dag.by_hash.len())
        .ok()
        .and_then(|n| n.checked_add(base.record_count));
    if expected != Some(stated) {
        return Err(c(CheckpointError::RecordCountMismatch {
            seq,
            stated,
            actual: dag.by_hash.len(),
        }));
    }
    Ok(())
}
