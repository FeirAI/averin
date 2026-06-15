//! Causal DAG construction & validation (RCP §10.1 step 2). Records hash-link to their
//! `causal_prev_hashes`; the graph must be acyclic and every parent must resolve. Duplicate
//! `content_hash`es collapse to one node (threat #8). Heads (records referenced by no other
//! record) are the frontier inputs for checkpoints.

use crate::canon::CanonValue;
use crate::hashx::parse_sha256;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq)]
pub enum DagError {
    RecordNotObject(usize),
    MissingContentHash(usize),
    BadContentHash(usize),
    CausalNotArray(usize),
    BadParentHash { record: String, parent: String },
    MissingParent { record: String, parent: String },
    Cycle { remaining: usize },
}

impl std::fmt::Display for DagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DagError::RecordNotObject(i) => write!(f, "record {i} is not an object"),
            DagError::MissingContentHash(i) => write!(f, "record {i} missing content_hash"),
            DagError::BadContentHash(i) => write!(f, "record {i} has malformed content_hash"),
            DagError::CausalNotArray(i) => {
                write!(f, "record {i} causal_prev_hashes is not an array")
            }
            DagError::BadParentHash { record, parent } => {
                write!(f, "record {record} has malformed parent hash {parent}")
            }
            DagError::MissingParent { record, parent } => {
                write!(
                    f,
                    "record {record} references missing parent {parent} (omission/broken link)"
                )
            }
            DagError::Cycle { remaining } => {
                write!(f, "causal DAG has a cycle ({remaining} records unresolved)")
            }
        }
    }
}
impl std::error::Error for DagError {}

pub struct Dag {
    /// content_hash → index of its first occurrence in the input slice.
    pub by_hash: BTreeMap<String, usize>,
    /// Head content_hashes (no record lists them as a parent), de-duplicated, byte-sorted.
    pub heads: Vec<String>,
    /// Topological order (every parent precedes its children).
    pub topo_order: Vec<String>,
    /// Count of collapsed duplicate `content_hash`es (threat #8).
    pub collapsed_duplicates: usize,
}

fn content_hash_of(rec: &CanonValue, i: usize) -> Result<String, DagError> {
    let ch = rec
        .get("content_hash")
        .ok_or(DagError::MissingContentHash(i))?
        .as_str()
        .ok_or(DagError::MissingContentHash(i))?;
    if parse_sha256(ch).is_none() {
        return Err(DagError::BadContentHash(i));
    }
    Ok(ch.to_string())
}

fn parents_of(rec: &CanonValue, i: usize) -> Result<Vec<&str>, DagError> {
    let arr = match rec.get("causal_prev_hashes") {
        Some(v) => v.as_array().ok_or(DagError::CausalNotArray(i))?,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::with_capacity(arr.len());
    for p in arr {
        let s = p.as_str().ok_or(DagError::CausalNotArray(i))?;
        out.push(s);
    }
    Ok(out)
}

/// Build and validate the causal DAG over a set of (already content-hash-verified) records.
pub fn build(records: &[CanonValue]) -> Result<Dag, DagError> {
    // 1. index by content_hash; collapse exact duplicates (same content_hash == same bytes).
    let mut by_hash: BTreeMap<String, usize> = BTreeMap::new();
    let mut collapsed_duplicates = 0usize;
    for (i, rec) in records.iter().enumerate() {
        if rec.as_object().is_none() {
            return Err(DagError::RecordNotObject(i));
        }
        let ch = content_hash_of(rec, i)?;
        if by_hash.insert(ch, i).is_some() {
            collapsed_duplicates += 1;
        }
    }

    // 2. validate parents resolve + build child adjacency and in-degrees.
    let mut in_degree: BTreeMap<&str, usize> = by_hash.keys().map(|k| (k.as_str(), 0)).collect();
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut referenced: BTreeMap<&str, bool> =
        by_hash.keys().map(|k| (k.as_str(), false)).collect();

    for (ch, &i) in &by_hash {
        let parents = parents_of(&records[i], i)?;
        // de-dup within a record's parent list so a repeated parent doesn't inflate in-degree.
        let mut seen = std::collections::BTreeSet::new();
        for p in parents {
            if parse_sha256(p).is_none() {
                return Err(DagError::BadParentHash {
                    record: ch.clone(),
                    parent: p.to_string(),
                });
            }
            if !by_hash.contains_key(p) {
                return Err(DagError::MissingParent {
                    record: ch.clone(),
                    parent: p.to_string(),
                });
            }
            if !seen.insert(p) {
                continue;
            }
            *in_degree.get_mut(ch.as_str()).unwrap() += 1;
            children.entry(p).or_default().push(ch.as_str());
            *referenced.get_mut(p).unwrap() = true;
        }
    }

    // 3. Kahn topological sort (roots = in_degree 0). Deterministic order via BTreeMap iteration.
    let mut queue: Vec<&str> = in_degree
        .iter()
        .filter(|(_, &d)| d == 0)
        .map(|(&k, _)| k)
        .collect();
    queue.sort_unstable();
    let mut indeg = in_degree.clone();
    let mut topo: Vec<String> = Vec::with_capacity(by_hash.len());
    let mut qi = 0;
    while qi < queue.len() {
        let n = queue[qi];
        qi += 1;
        topo.push(n.to_string());
        if let Some(cs) = children.get(n) {
            let mut newly: Vec<&str> = Vec::new();
            for &c in cs {
                let d = indeg.get_mut(c).unwrap();
                *d -= 1;
                if *d == 0 {
                    newly.push(c);
                }
            }
            newly.sort_unstable();
            queue.extend(newly);
        }
    }
    if topo.len() != by_hash.len() {
        return Err(DagError::Cycle {
            remaining: by_hash.len() - topo.len(),
        });
    }

    // 4. heads = nodes referenced by nobody, byte-sorted (= RCP §10 frontier of this record set).
    let mut heads: Vec<String> = referenced
        .iter()
        .filter(|(_, &r)| !r)
        .map(|(&k, _)| k.to_string())
        .collect();
    heads.sort();

    Ok(Dag {
        by_hash,
        heads,
        topo_order: topo,
        collapsed_duplicates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn h(n: u8) -> String {
        format!("sha256:{}", crate::hashx::hex_lower(&[n; 32]))
    }

    #[test]
    fn linear_and_diamond() {
        let (a, b, c, d) = (h(1), h(2), h(3), h(4));
        // a -> b,c -> d   (diamond)
        let recs = vec![
            rec(&a, &[]),
            rec(&b, &[&a]),
            rec(&c, &[&a]),
            rec(&d, &[&b, &c]),
        ];
        let dag = build(&recs).unwrap();
        assert_eq!(dag.heads, vec![d.clone()]);
        // parents precede children
        let pos = |x: &str| dag.topo_order.iter().position(|y| y == x).unwrap();
        assert!(pos(&a) < pos(&b) && pos(&b) < pos(&d) && pos(&c) < pos(&d));
    }

    #[test]
    fn detects_missing_parent() {
        let (a, b) = (h(1), h(2));
        let recs = vec![rec(&b, &[&a])]; // a not present
        assert!(matches!(build(&recs), Err(DagError::MissingParent { .. })));
    }

    #[test]
    fn detects_cycle() {
        let (a, b) = (h(1), h(2));
        let recs = vec![rec(&a, &[&b]), rec(&b, &[&a])];
        assert!(matches!(build(&recs), Err(DagError::Cycle { .. })));
    }

    #[test]
    fn collapses_duplicate_content_hash() {
        let a = h(1);
        let recs = vec![rec(&a, &[]), rec(&a, &[])];
        let dag = build(&recs).unwrap();
        assert_eq!(dag.collapsed_duplicates, 1);
        assert_eq!(dag.heads, vec![a]);
    }

    #[test]
    fn multiple_heads() {
        let (a, b) = (h(1), h(2));
        let dag = build(&[rec(&a, &[]), rec(&b, &[])]).unwrap();
        assert_eq!(dag.heads.len(), 2);
    }
}
