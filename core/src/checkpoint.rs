//! Frontier checkpoints (RCP §9.4 / §10). A checkpoint commits the set of head `content_hash`es
//! for a project, hash-chained via `prev_checkpoint_hash` and (in M1 piece 6) externally
//! anchored. Offline verification detects omitted sessions (#1) and forked history (#2).

use crate::canon::CanonValue;
use crate::dag::Dag;
use crate::hashx::parse_sha256;
use crate::record::{hash_body, RecordError};
use crate::sign::{self, CHECKPOINT_SIG_TAG};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub const CHECKPOINT_DOMAIN: &str = "flightrecorder.checkpoint.v2";
pub const CHECKPOINT_CANON_VERSION: &str = "rcp-1";

/// Keys excluded from the checkpoint hash preimage: `anchor` is added AFTER signing; the hash and
/// sig obviously cannot cover themselves.
const STRIP: &[&str] = &["anchor", "checkpoint_hash", "sig"];

#[derive(Debug, PartialEq)]
pub enum CheckpointError {
    Hash(RecordError),
    DomainMismatch(String),
    MissingField(&'static str),
    FieldType(&'static str),
    BadFrontierHash(String),
    SignatureInvalid(String),
    // chain-level
    FirstSeqNotZero(i64),
    FirstPrevNotNull,
    SeqGap {
        prev: i64,
        next: i64,
    },
    ForkDetected {
        seq: i64,
    },
    PrevHashMismatch {
        seq: i64,
        expected: String,
        found: String,
    },
    RecordCountDecreased {
        seq: i64,
        from: i64,
        to: i64,
    },
    FrontierMemberMissing {
        seq: i64,
        hash: String,
    },
    ForkSharedPrev {
        prev: String,
    },
    LatestFrontierMismatch {
        seq: i64,
        stated: usize,
        actual_heads: usize,
    },
    RecordCountMismatch {
        seq: i64,
        stated: i64,
        actual: usize,
    },
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CheckpointError::*;
        match self {
            Hash(e) => write!(f, "checkpoint hash: {e}"),
            DomainMismatch(d) => write!(f, "checkpoint domain mismatch: {d}"),
            MissingField(k) => write!(f, "checkpoint missing field '{k}'"),
            FieldType(k) => write!(f, "checkpoint field '{k}' has wrong type"),
            BadFrontierHash(h) => write!(f, "malformed frontier hash {h}"),
            SignatureInvalid(e) => write!(f, "checkpoint signature invalid: {e}"),
            FirstSeqNotZero(s) => write!(f, "first checkpoint seq is {s}, expected 0"),
            FirstPrevNotNull => write!(f, "first checkpoint prev_checkpoint_hash must be null"),
            SeqGap { prev, next } => write!(f, "checkpoint seq gap: {prev} -> {next}"),
            ForkDetected { seq } => {
                write!(f, "FORK: two distinct checkpoints share seq {seq} (threat #2)")
            }
            PrevHashMismatch { seq, expected, found } => {
                write!(f, "checkpoint {seq} prev_checkpoint_hash {found} != prior {expected}")
            }
            RecordCountDecreased { seq, from, to } => {
                write!(f, "checkpoint {seq} record_count decreased {from} -> {to}")
            }
            FrontierMemberMissing { seq, hash } => write!(
                f,
                "OMISSION: checkpoint {seq} frontier head {hash} is absent from the bundle (threat #1)"
            ),
            ForkSharedPrev { prev } => write!(
                f,
                "FORK: two distinct checkpoints share prev_checkpoint_hash {prev} (threat #2)"
            ),
            LatestFrontierMismatch { seq, stated, actual_heads } => write!(
                f,
                "latest checkpoint {seq} frontier ({stated} heads) != actual DAG heads ({actual_heads}) — uncommitted or omitted session (threat #1)"
            ),
            RecordCountMismatch { seq, stated, actual } => write!(
                f,
                "latest checkpoint {seq} record_count {stated} != actual record count {actual}"
            ),
        }
    }
}
impl std::error::Error for CheckpointError {}

fn str_field<'a>(o: &'a CanonValue, k: &'static str) -> Result<&'a str, CheckpointError> {
    o.get(k)
        .ok_or(CheckpointError::MissingField(k))?
        .as_str()
        .ok_or(CheckpointError::FieldType(k))
}
fn int_field(o: &CanonValue, k: &'static str) -> Result<i64, CheckpointError> {
    o.get(k)
        .ok_or(CheckpointError::MissingField(k))?
        .as_int()
        .ok_or(CheckpointError::FieldType(k))
}

pub fn compute_checkpoint_hash(cp: &CanonValue) -> Result<String, RecordError> {
    hash_body(cp, STRIP)
}

/// Build a frontier-checkpoint body from heads + chain metadata (helper for producers/tests).
#[allow(clippy::too_many_arguments)] // a checkpoint body genuinely has this many committed fields
pub fn checkpoint_body(
    checkpoint_id: &str,
    project_id: &str,
    seq: i64,
    prev_checkpoint_hash: Option<&str>,
    frontier: &[String],
    record_count: i64,
    created_ts: &str,
    key: CanonValue,
) -> Result<CanonValue, CheckpointError> {
    // frontier must be de-duplicated + byte-sorted (RCP §10).
    let mut fr = frontier.to_vec();
    fr.sort();
    fr.dedup();
    let frontier_val = CanonValue::Array(fr.into_iter().map(CanonValue::Str).collect());
    let prev = match prev_checkpoint_hash {
        Some(h) => CanonValue::Str(h.to_string()),
        None => CanonValue::Null,
    };
    CanonValue::object(vec![
        ("schema_version".into(), CanonValue::string("2")),
        (
            "canon_version".into(),
            CanonValue::string(CHECKPOINT_CANON_VERSION),
        ),
        ("domain".into(), CanonValue::string(CHECKPOINT_DOMAIN)),
        ("checkpoint_id".into(), CanonValue::string(checkpoint_id)),
        ("project_id".into(), CanonValue::string(project_id)),
        ("checkpoint_seq".into(), CanonValue::Int(seq)),
        ("prev_checkpoint_hash".into(), prev),
        ("frontier".into(), frontier_val),
        ("record_count".into(), CanonValue::Int(record_count)),
        ("created_ts".into(), CanonValue::string(created_ts)),
        ("key".into(), key),
    ])
    .map_err(|e| CheckpointError::Hash(RecordError::SignatureInvalid(e.to_string())))
}

/// Seal a checkpoint body: compute `checkpoint_hash` and sign it (RCP §9.4). `anchor` is added
/// later by the anchoring job and is excluded from the preimage.
pub fn seal_checkpoint(cp_body: &CanonValue, sk: &SigningKey) -> Result<CanonValue, RecordError> {
    let ch = compute_checkpoint_hash(cp_body)?;
    let sig = sign::sign(CHECKPOINT_SIG_TAG, &ch, sk);
    let stripped = cp_body.without_keys(&["checkpoint_hash", "sig"]);
    let with_hash = set_field(&stripped, "checkpoint_hash", CanonValue::Str(ch));
    Ok(set_field(&with_hash, "sig", CanonValue::Str(sig)))
}

fn set_field(obj: &CanonValue, key: &str, value: CanonValue) -> CanonValue {
    let mut members = obj.as_object().expect("set_field on non-object").clone();
    if let Some(slot) = members.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value;
    } else {
        members.push((key.to_string(), value));
    }
    CanonValue::Object(members)
}

/// Verify a single sealed checkpoint: domain, recomputed `checkpoint_hash`, and `sig`.
pub fn verify_checkpoint_sealed(cp: &CanonValue, vk: &VerifyingKey) -> Result<(), CheckpointError> {
    let domain = str_field(cp, "domain")?;
    if domain != CHECKPOINT_DOMAIN {
        return Err(CheckpointError::DomainMismatch(domain.to_string()));
    }
    let stored = str_field(cp, "checkpoint_hash")?.to_string();
    let computed = compute_checkpoint_hash(cp).map_err(CheckpointError::Hash)?;
    if stored != computed {
        return Err(CheckpointError::Hash(RecordError::ContentHashMismatch {
            expected: stored,
            computed,
        }));
    }
    let sig = str_field(cp, "sig")?;
    sign::verify(CHECKPOINT_SIG_TAG, &computed, sig, vk)
        .map_err(|e| CheckpointError::SignatureInvalid(e.to_string()))
}

/// Validate the checkpoint chain structure (RCP §10.1 steps 3-4-6) over checkpoints whose own
/// hash/sig have already been verified. Detects seq gaps, **forks** (#2), prev-hash breaks,
/// record_count regressions, and frontier **omissions** (#1) against the present record DAG.
///
/// `checkpoints` need not be pre-sorted. Returns the checkpoints in seq order on success.
pub fn validate_chain<'a>(
    checkpoints: &'a [CanonValue],
    dag: &Dag,
) -> Result<Vec<&'a CanonValue>, CheckpointError> {
    let mut ordered: Vec<&CanonValue> = checkpoints.iter().collect();
    // sort by seq; equal seq with distinct checkpoint_hash is a fork.
    ordered.sort_by_key(|c| {
        c.get("checkpoint_seq")
            .and_then(|v| v.as_int())
            .unwrap_or(i64::MIN)
    });

    if let Some(first) = ordered.first() {
        if int_field(first, "checkpoint_seq")? != 0 {
            return Err(CheckpointError::FirstSeqNotZero(int_field(
                first,
                "checkpoint_seq",
            )?));
        }
        if !first
            .get("prev_checkpoint_hash")
            .map(|v| v.is_null())
            .unwrap_or(false)
        {
            return Err(CheckpointError::FirstPrevNotNull);
        }
    }

    for w in ordered.windows(2) {
        let (a, b) = (w[0], w[1]);
        let (sa, sb) = (
            int_field(a, "checkpoint_seq")?,
            int_field(b, "checkpoint_seq")?,
        );
        if sa == sb {
            // same seq: fork if the checkpoint_hash differs (identical is a duplicate, still a fork
            // signal in a single chain — but treat byte-identical as benign dedupe).
            let ha = str_field(a, "checkpoint_hash")?;
            let hb = str_field(b, "checkpoint_hash")?;
            if ha != hb {
                return Err(CheckpointError::ForkDetected { seq: sa });
            }
            continue;
        }
        if sb != sa + 1 {
            return Err(CheckpointError::SeqGap { prev: sa, next: sb });
        }
        let prev_ref = b
            .get("prev_checkpoint_hash")
            .and_then(|v| v.as_str())
            .ok_or(CheckpointError::MissingField("prev_checkpoint_hash"))?;
        let prev_hash = str_field(a, "checkpoint_hash")?;
        if prev_ref != prev_hash {
            return Err(CheckpointError::PrevHashMismatch {
                seq: sb,
                expected: prev_hash.to_string(),
                found: prev_ref.to_string(),
            });
        }
        let (ca, cb) = (int_field(a, "record_count")?, int_field(b, "record_count")?);
        if cb < ca {
            return Err(CheckpointError::RecordCountDecreased {
                seq: sb,
                from: ca,
                to: cb,
            });
        }
    }

    // frontier omission check: every committed head must still be present (RCP §10.1 step 4).
    for cp in &ordered {
        let seq = int_field(cp, "checkpoint_seq")?;
        let frontier = cp
            .get("frontier")
            .ok_or(CheckpointError::MissingField("frontier"))?
            .as_array()
            .ok_or(CheckpointError::FieldType("frontier"))?;
        for fh in frontier {
            let h = fh.as_str().ok_or(CheckpointError::FieldType("frontier"))?;
            if parse_sha256(h).is_none() {
                return Err(CheckpointError::BadFrontierHash(h.to_string()));
            }
            if !dag.by_hash.contains_key(h) {
                return Err(CheckpointError::FrontierMemberMissing {
                    seq,
                    hash: h.to_string(),
                });
            }
        }
    }

    // fork by shared prev_checkpoint_hash (a branch point) — all-pairs over non-null prevs.
    let mut by_prev: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for cp in &ordered {
        if let Some(prev) = cp.get("prev_checkpoint_hash").and_then(|v| v.as_str()) {
            let this = str_field(cp, "checkpoint_hash")?;
            if let Some(other) = by_prev.insert(prev, this) {
                if other != this {
                    return Err(CheckpointError::ForkSharedPrev {
                        prev: prev.to_string(),
                    });
                }
            }
        }
    }

    // RCP §10.1 step 4: the LATEST checkpoint must summarize the full present DAG — its frontier
    // must equal the actual heads and its record_count the actual record count. Without this, a
    // subset frontier could leave a real head (and its session) uncovered (threat #1/#7).
    if let Some(latest) = ordered.last() {
        let seq = int_field(latest, "checkpoint_seq")?;
        let frontier: std::collections::BTreeSet<&str> = latest
            .get("frontier")
            .and_then(|v| v.as_array())
            .ok_or(CheckpointError::FieldType("frontier"))?
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        let heads: std::collections::BTreeSet<&str> =
            dag.heads.iter().map(|s| s.as_str()).collect();
        if frontier != heads {
            return Err(CheckpointError::LatestFrontierMismatch {
                seq,
                stated: frontier.len(),
                actual_heads: heads.len(),
            });
        }
        let stated = int_field(latest, "record_count")?;
        if stated < 0 || stated as usize != dag.by_hash.len() {
            return Err(CheckpointError::RecordCountMismatch {
                seq,
                stated,
                actual: dag.by_hash.len(),
            });
        }
    }

    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag;
    use crate::sign::signing_key_from_seed;

    fn h(n: u8) -> String {
        format!("sha256:{}", crate::hashx::hex_lower(&[n; 32]))
    }
    fn key_block() -> CanonValue {
        CanonValue::parse(r#"{"signing_key_id":"k","key_epoch":0,"key_status":"active"}"#).unwrap()
    }
    fn rec(ch: &str, parents: &[&str]) -> CanonValue {
        let plist = parents
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(",");
        CanonValue::parse(&format!(
            r#"{{"content_hash":"{ch}","causal_prev_hashes":[{plist}]}}"#
        ))
        .unwrap()
    }

    #[test]
    fn seal_and_verify_checkpoint() {
        let sk = signing_key_from_seed(&[8u8; 32]);
        let body = checkpoint_body(
            "cp0",
            "proj",
            0,
            None,
            &[h(1)],
            1,
            "2026-06-15T10:00:00.000Z",
            key_block(),
        )
        .unwrap();
        let sealed = seal_checkpoint(&body, &sk).unwrap();
        assert!(verify_checkpoint_sealed(&sealed, &sk.verifying_key()).is_ok());
        // wrong key fails
        let other = signing_key_from_seed(&[9u8; 32]).verifying_key();
        assert!(verify_checkpoint_sealed(&sealed, &other).is_err());
    }

    #[test]
    fn chain_ok_and_omission_detected() {
        let sk = signing_key_from_seed(&[8u8; 32]);
        let records = vec![rec(&h(1), &[]), rec(&h(2), &[&h(1)])];
        let dag = dag::build(&records).unwrap();
        // cp0 commits head h2
        let b0 = checkpoint_body(
            "cp0",
            "p",
            0,
            None,
            &[h(2)],
            2,
            "2026-06-15T10:00:00.000Z",
            key_block(),
        )
        .unwrap();
        let c0 = seal_checkpoint(&b0, &sk).unwrap();
        let c0h = c0
            .get("checkpoint_hash")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let b1 = checkpoint_body(
            "cp1",
            "p",
            1,
            Some(&c0h),
            &[h(2)],
            2,
            "2026-06-15T10:05:00.000Z",
            key_block(),
        )
        .unwrap();
        let c1 = seal_checkpoint(&b1, &sk).unwrap();
        assert!(validate_chain(&[c0.clone(), c1.clone()], &dag).is_ok());

        // now omit the session whose head is h2: dag without h2
        let dag_omitted = dag::build(&[rec(&h(1), &[])]).unwrap();
        let err = validate_chain(&[c0, c1], &dag_omitted).unwrap_err();
        assert!(
            matches!(err, CheckpointError::FrontierMemberMissing { .. }),
            "{err}"
        );
    }

    #[test]
    fn fork_detected() {
        let sk = signing_key_from_seed(&[8u8; 32]);
        let dag = dag::build(&[rec(&h(1), &[])]).unwrap();
        let b0 = checkpoint_body(
            "cp0",
            "p",
            0,
            None,
            &[h(1)],
            1,
            "2026-06-15T10:00:00.000Z",
            key_block(),
        )
        .unwrap();
        let c0 = seal_checkpoint(&b0, &sk).unwrap();
        // a second, distinct checkpoint also at seq 0 (e.g. different created_ts) -> fork
        let b0b = checkpoint_body(
            "cp0b",
            "p",
            0,
            None,
            &[h(1)],
            1,
            "2026-06-15T11:00:00.000Z",
            key_block(),
        )
        .unwrap();
        let c0b = seal_checkpoint(&b0b, &sk).unwrap();
        let err = validate_chain(&[c0, c0b], &dag).unwrap_err();
        assert!(
            matches!(err, CheckpointError::ForkDetected { seq: 0 }),
            "{err}"
        );
    }

    #[test]
    fn prev_hash_break_detected() {
        let sk = signing_key_from_seed(&[8u8; 32]);
        let dag = dag::build(&[rec(&h(1), &[])]).unwrap();
        let b0 = checkpoint_body(
            "cp0",
            "p",
            0,
            None,
            &[h(1)],
            1,
            "2026-06-15T10:00:00.000Z",
            key_block(),
        )
        .unwrap();
        let c0 = seal_checkpoint(&b0, &sk).unwrap();
        // cp1 points prev at the wrong hash
        let b1 = checkpoint_body(
            "cp1",
            "p",
            1,
            Some(&h(7)),
            &[h(1)],
            1,
            "2026-06-15T10:05:00.000Z",
            key_block(),
        )
        .unwrap();
        let c1 = seal_checkpoint(&b1, &sk).unwrap();
        let err = validate_chain(&[c0, c1], &dag).unwrap_err();
        assert!(
            matches!(err, CheckpointError::PrevHashMismatch { .. }),
            "{err}"
        );
    }
}
