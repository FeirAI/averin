//! Incremental committed-grant-log machinery for the D6 transparency check (wave1 export perf).
//!
//! `committed_broker_log` + `grant_head_root` recompute a checkpoint's whole grant log from scratch: one DAG walk,
//! one scan of every record, one sort and one hash fold per checkpoint, so a history with C checkpoints and N
//! records costs O(C x N). [`LogCursor`] returns exactly the same `(count, gapless, root)` for a sequence of
//! frontiers while doing work proportional to what is NEW in each frontier.
//!
//! Exactness rules (see the proofs in the module tests and docs/dev/TESTING.md):
//! - State from the previous frontier is reused only after the walk from the new frontier has REACHED every known
//!   member of the previous frontier. The committed set is closed under parents, so the previous closure is then a
//!   subset of the new one, and every node of the new closure is either found by the walk or is an ancestor of
//!   such a reached member. Otherwise the cursor resets and recomputes in full, as the old code did.
//! - The log is the sorted sequence of `(broker_seq, record_trust position)` entries, which is exactly the old
//!   "filter `record_trust` in index order, then stable-sort by seq". New entries are merged in at their sorted
//!   position; the hash fold resumes from the stored accumulator at that position, never from a bundle value.
//! - No hash-ordered iteration; indices are bounds-checked slices, no `unwrap` on bundle data.
//!
//! The old per-frontier functions stay in `verify.rs` as the single-checkpoint fallback and as the test oracle.

use super::{
    ev_int, ev_str, grant_head_seed_preimage, grant_head_step_preimage, log_payload_key,
    RecordTrust,
};
use crate::canon::CanonValue;
use std::collections::BTreeMap;

/// The causal DAG, indexed once and shared by every partition. Node ids are positions in the DAG's topological
/// order, so every parent id is smaller than its child id.
pub(super) struct DagIndex {
    node_of: BTreeMap<String, usize>,
    /// Known parents of each node (the edges `committed_set` follows; unknown hashes are not expanded).
    parents: Vec<Vec<usize>>,
}

// `FORCE_SLOW` (test builds only) makes every index unbuildable so the old per-frontier code runs. The counters
// are per thread and always compiled: they let a test prove that an honest history never takes a slow path and
// that the fast path really ran (a refactor that silently stops using the index leaves every verdict unchanged,
// so only these counters can catch it). They are read through `verify::slow_path_probe`.
#[cfg(test)]
thread_local! {
    pub(super) static FORCE_SLOW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
thread_local! {
    pub(super) static INDEX_FALLBACKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static CURSOR_RESETS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Checkpoint frontiers (or headless / reach questions) answered by the old per-frontier code.
    pub(super) static FRONTIER_FALLBACKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Frontiers answered by `LogCursor::advance`.
    pub(super) static CURSOR_ADVANCES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// `anchored_before` lookups answered by the per-checkpoint walk instead of the anchor index.
    pub(super) static ANCHOR_FALLBACKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn bump(c: &'static std::thread::LocalKey<std::cell::Cell<usize>>) {
    c.with(|x| x.set(x.get().saturating_add(1)));
}

impl DagIndex {
    /// `None` when `topo_order` is not a bijection onto `by_hash`. The caller then uses the old code.
    pub(super) fn build(
        records: &[CanonValue],
        by_hash: &BTreeMap<String, usize>,
        topo_order: &[String],
    ) -> Option<DagIndex> {
        #[cfg(test)]
        if FORCE_SLOW.with(|f| f.get()) {
            bump(&INDEX_FALLBACKS);
            return None;
        }
        let built = Self::build_inner(records, by_hash, topo_order);
        if built.is_none() {
            bump(&INDEX_FALLBACKS);
        }
        built
    }

    fn build_inner(
        records: &[CanonValue],
        by_hash: &BTreeMap<String, usize>,
        topo_order: &[String],
    ) -> Option<DagIndex> {
        let mut node_of: BTreeMap<String, usize> = BTreeMap::new();
        for (i, h) in topo_order.iter().enumerate() {
            if !by_hash.contains_key(h) || node_of.insert(h.clone(), i).is_some() {
                return None;
            }
        }
        if node_of.len() != by_hash.len() {
            return None;
        }
        let mut parents: Vec<Vec<usize>> = Vec::with_capacity(topo_order.len());
        for (i, h) in topo_order.iter().enumerate() {
            let mut list = Vec::new();
            let rec = records.get(*by_hash.get(h)?)?;
            if let Some(arr) = rec.get("causal_prev_hashes").and_then(|v| v.as_array()) {
                for p in arr {
                    if let Some(&pn) = p.as_str().and_then(|name| node_of.get(name)) {
                        // `topo_order` must list parents first; the reach and anchor DPs rely on it. A
                        // violation (not produced by `dag::build`) refuses the index so the per-frontier
                        // code runs instead.
                        if pn >= i {
                            return None;
                        }
                        list.push(pn);
                    }
                }
            }
            parents.push(list);
        }
        Some(DagIndex { node_of, parents })
    }
}

/// The brokers whose log (partition `Some(id)`) is committed by `frontier` at least once: the single-walk form
/// of "`committed_broker_log(frontier, Some(id))` is non-empty" for every broker at once. `None` when a log
/// entry's hash is not a DAG node (the caller then uses the per-broker old code).
pub(super) fn brokers_committed_by(
    dag: &DagIndex,
    record_trust: &[RecordTrust],
    records: &[CanonValue],
    frontier: &[String],
) -> Option<std::collections::BTreeSet<String>> {
    let mut seen = vec![false; dag.parents.len()];
    let mut stack: Vec<usize> = frontier
        .iter()
        .filter_map(|f| dag.node_of.get(f).copied())
        .collect();
    while let Some(x) = stack.pop() {
        if !seen[x] {
            seen[x] = true;
            stack.extend(dag.parents[x].iter().copied());
        }
    }
    let mut out = std::collections::BTreeSet::new();
    for rt in record_trust {
        let Some(key) = log_payload_key(&rt.broker_role) else {
            continue;
        };
        let rec = records.get(rt.index)?;
        let node = *dag.node_of.get(&rt.content_hash)?;
        if !seen[node] || ev_int(rec, key, "broker_seq").filter(|s| *s >= 1).is_none() {
            continue;
        }
        if let Some(b) = ev_str(rec, key, "broker_id").filter(|b| !b.is_empty()) {
            out.insert(b);
        }
    }
    Some(out)
}

/// The log entries of one partition (`None` = all brokers, `Some(id)` = one federation partition).
pub(super) struct LogIndex<'d> {
    dag: &'d DagIndex,
    /// Log entries `(broker_seq, record_trust position)` of each node, in `record_trust` order.
    entries: Vec<Vec<(i64, usize)>>,
}

impl<'d> LogIndex<'d> {
    /// `None` when a log-role record's content hash is not a DAG node (cannot happen for a DAG built over these
    /// records); the caller then uses the old code.
    pub(super) fn build(
        dag: &'d DagIndex,
        record_trust: &[RecordTrust],
        records: &[CanonValue],
        broker_id: Option<&str>,
    ) -> Option<LogIndex<'d>> {
        let mut entries: Vec<Vec<(i64, usize)>> = vec![Vec::new(); dag.parents.len()];
        for (pos, rt) in record_trust.iter().enumerate() {
            let Some(key) = log_payload_key(&rt.broker_role) else {
                continue;
            };
            let rec = records.get(rt.index)?;
            let in_partition = match broker_id {
                None => true,
                Some(bid) => {
                    ev_str(rec, key, "broker_id")
                        .filter(|b| !b.is_empty())
                        .as_deref()
                        == Some(bid)
                }
            };
            if !in_partition {
                continue;
            }
            let Some(seq) = ev_int(rec, key, "broker_seq").filter(|s| *s >= 1) else {
                continue;
            };
            // a log entry whose hash is no DAG node could still be "committed" by being named in a frontier;
            // that cannot happen for a DAG built over these records, so refuse the index rather than guess.
            let node = *dag.node_of.get(&rt.content_hash)?;
            entries[node].push((seq, pos));
        }
        Some(LogIndex { dag, entries })
    }

    /// For each partition entry node: does `frontier` commit at least one log entry? (`!log_for(F).is_empty()`.)
    /// `reach[x]` = x has an entry, or any parent of x reaches one; computed once, parents first.
    pub(super) fn reach(&self) -> Vec<bool> {
        let mut reach = vec![false; self.dag.parents.len()];
        for x in 0..self.dag.parents.len() {
            reach[x] = !self.entries[x].is_empty() || self.dag.parents[x].iter().any(|&p| reach[p]);
        }
        reach
    }

    /// Whether a frontier commits at least one log entry, given [`LogIndex::reach`].
    pub(super) fn commits_any(&self, reach: &[bool], frontier: &[String]) -> bool {
        frontier
            .iter()
            .any(|f| self.dag.node_of.get(f).is_some_and(|&n| reach[n]))
    }
}

/// What a frontier's committed log looks like: the three values the D6 checks compare.
pub(super) struct LogState {
    pub n: i64,
    pub gapless: bool,
    pub root: String,
}

pub(super) struct LogCursor<'a, 'd> {
    idx: &'a LogIndex<'d>,
    /// Membership of the previous frontier's committed closure (known nodes only).
    in_prev: Vec<bool>,
    /// Known members of the previous frontier.
    prev_front: Vec<usize>,
    /// The previous log, sorted by `(seq, record_trust position)`.
    log: Vec<(i64, usize)>,
    /// `accs[i]` is the fold accumulator after the first `i` log entries (`accs[0]` is the seed).
    accs: Vec<[u8; 32]>,
    /// Smallest index `i` with `log[i].0 != i + 1`, `usize::MAX` when the log is a gapless prefix `[1..n]`.
    gap_at: usize,
    visit: Vec<u64>,
    hit: Vec<u64>,
    gen: u64,
}

impl<'a, 'd> LogCursor<'a, 'd> {
    pub(super) fn new(idx: &'a LogIndex<'d>) -> Self {
        let n = idx.dag.parents.len();
        LogCursor {
            idx,
            in_prev: vec![false; n],
            prev_front: Vec::new(),
            log: Vec::new(),
            accs: vec![crate::hashx::sha256(&grant_head_seed_preimage())],
            gap_at: usize::MAX,
            visit: vec![0; n],
            hit: vec![0; n],
            gen: 0,
        }
    }

    /// Walk from `frontier` without expanding nodes already in the previous closure. Returns the newly found
    /// nodes. Nodes of the previous closure that the walk met are stamped in `hit`.
    fn walk(&mut self, frontier: &[usize]) -> Vec<usize> {
        self.gen += 1;
        let g = self.gen;
        let mut stack: Vec<usize> = frontier.to_vec();
        let mut fresh = Vec::new();
        while let Some(x) = stack.pop() {
            if self.in_prev[x] {
                self.hit[x] = g;
                continue;
            }
            if self.visit[x] == g {
                continue;
            }
            self.visit[x] = g;
            fresh.push(x);
            stack.extend(self.idx.dag.parents[x].iter().copied());
        }
        fresh
    }

    fn reset(&mut self) {
        bump(&CURSOR_RESETS);
        self.in_prev.iter_mut().for_each(|b| *b = false);
        self.prev_front.clear();
        self.log.clear();
        self.accs.truncate(1);
        self.gap_at = usize::MAX;
    }

    /// The `(count, gapless, root)` of `committed_broker_log(frontier)` for this partition.
    pub(super) fn advance(&mut self, frontier: &[String], rts: &[RecordTrust]) -> LogState {
        bump(&CURSOR_ADVANCES);
        let front: Vec<usize> = frontier
            .iter()
            .filter_map(|f| self.idx.dag.node_of.get(f).copied())
            .collect();
        let mut fresh = self.walk(&front);
        let g = self.gen;
        // containment: every known member of the previous frontier was reached, so C_prev is a subset of
        // closure(F) and the fresh nodes are exactly closure(F) minus C_prev.
        if !self.prev_front.iter().all(|&m| self.hit[m] == g) {
            self.reset();
            fresh = self.walk(&front);
        }
        for &x in &fresh {
            self.in_prev[x] = true;
        }
        self.prev_front = front;

        let mut add: Vec<(i64, usize)> = fresh
            .iter()
            .flat_map(|&x| self.idx.entries[x].iter().copied())
            .collect();
        if !add.is_empty() {
            add.sort_unstable();
            // everything before `p` stays in place, so its accumulators and gap status stay valid.
            let p = self.log.partition_point(|e| *e < add[0]);
            let mut tail = self.log.split_off(p);
            tail.extend(add);
            tail.sort_unstable();
            self.accs.truncate(p + 1);
            if self.gap_at >= p {
                self.gap_at = usize::MAX;
            }
            for (j, &(seq, pos)) in tail.iter().enumerate() {
                let i = p + j;
                if self.gap_at == usize::MAX && seq != i as i64 + 1 {
                    self.gap_at = i;
                }
                let prev = self.accs[i];
                let content_hash = rts.get(pos).map(|r| r.content_hash.as_str()).unwrap_or("");
                self.accs
                    .push(crate::hashx::sha256(&grant_head_step_preimage(
                        &prev,
                        seq,
                        content_hash,
                    )));
            }
            self.log.extend(tail);
        }
        let acc = self.accs[self.log.len()];
        LogState {
            n: self.log.len() as i64,
            gapless: self.gap_at == usize::MAX,
            root: format!("sha256:{}", crate::hashx::hex_lower(&acc)),
        }
    }
}

impl DagIndex {
    /// For each node, the smallest canonical anchor time among the anchored checkpoints whose frontier commits
    /// it (`None` when no such checkpoint). `anchors` yields `(anchor time, frontier)` for every anchored
    /// checkpoint; a time that is not canonical is skipped (it can never satisfy `anchored_before`).
    /// Equivalent to "min over anchors whose `committed_set(frontier)` contains the node": the seed puts each
    /// frontier member's time on it and the propagation pushes the minimum to every ancestor, children first.
    pub(super) fn min_anchor_times<'a>(
        &self,
        anchors: impl Iterator<Item = (&'a str, &'a [String])>,
        is_canonical: impl Fn(&str) -> bool,
    ) -> Vec<Option<&'a str>> {
        let mut min_ts: Vec<Option<&'a str>> = vec![None; self.parents.len()];
        for (ts, frontier) in anchors {
            if !is_canonical(ts) {
                continue;
            }
            for f in frontier {
                if let Some(&n) = self.node_of.get(f) {
                    if min_ts[n].is_none_or(|cur| ts < cur) {
                        min_ts[n] = Some(ts);
                    }
                }
            }
        }
        for x in (0..self.parents.len()).rev() {
            if let Some(t) = min_ts[x] {
                for &p in &self.parents[x] {
                    if min_ts[p].is_none_or(|cur| t < cur) {
                        min_ts[p] = Some(t);
                    }
                }
            }
        }
        min_ts
    }

    pub(super) fn node(&self, hash: &str) -> Option<usize> {
        self.node_of.get(hash).copied()
    }
}

#[cfg(test)]
mod tests {
    //! Differential tests: every answer of the incremental code is compared with the old per-frontier code
    //! (`committed_set`, `committed_broker_log`, `grant_head_root`) on seeded random histories that include
    //! multi-parent merges, duplicate content hashes, unknown frontier hashes, non-head frontier members, seq
    //! gaps, duplicate seqs, seq 0 and negative seqs, voids and several brokers.
    use super::super::{
        committed_broker_log, committed_set, grant_head_root, is_canonical_ts, BrokerRole,
        RecordTrust, TrustLevel,
    };
    use super::*;
    use crate::authority::AuthorityTrust;
    use crate::dag;
    use std::collections::BTreeSet;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn hash_of(i: usize) -> String {
        format!("sha256:{:064x}", i + 1)
    }

    struct Case {
        records: Vec<CanonValue>,
        rts: Vec<RecordTrust>,
        dag: dag::Dag,
    }

    fn make_case(rng: &mut Rng) -> Case {
        let n = 1 + rng.below(40);
        let mut json: Vec<String> = Vec::new();
        let mut roles: Vec<&'static str> = Vec::new();
        let mut counter = 0i64;
        for i in 0..n {
            let mut parents = BTreeSet::new();
            if i > 0 {
                for _ in 0..rng.below(4) {
                    // mostly recent nodes, so there are several long chains with occasional merges
                    let span = if rng.below(4) == 0 { i } else { i.min(4) };
                    let back = 1 + rng.below(span);
                    parents.insert(i - back);
                }
            }
            let plist: Vec<String> = parents
                .iter()
                .map(|p| format!("\"{}\"", hash_of(*p)))
                .collect();
            let role = match rng.below(8) {
                0 => BrokerRole::Void,
                1 => BrokerRole::None,
                2 => BrokerRole::Resource,
                _ => BrokerRole::Broker,
            };
            let seq: i64 = match rng.below(12) {
                0 => 0,
                1 => -1 - rng.below(3) as i64,
                2 => 1 + rng.below(8) as i64, // duplicate / out of order
                3 => 100 + rng.below(3) as i64,
                _ => {
                    counter += 1;
                    counter
                }
            };
            let bid = match rng.below(4) {
                0 => "\"a\"".to_string(),
                1 => "\"b\"".to_string(),
                2 => "\"\"".to_string(),
                _ => "null".to_string(),
            };
            let key = if role == BrokerRole::Void {
                "void_evidence"
            } else {
                "grant_evidence"
            };
            let body = if rng.below(10) == 0 {
                String::new()
            } else {
                format!("\"extensions\":{{\"broker\":{{\"{key}\":{{\"broker_seq\":{seq},\"broker_id\":{bid}}}}}}},")
            };
            json.push(format!(
                "{{\"content_hash\":\"{}\",{body}\"causal_prev_hashes\":[{}]}}",
                hash_of(i),
                plist.join(",")
            ));
            roles.push(role.as_str());
        }
        // a duplicate record under an existing content hash (a different body), and a shuffled record order
        if rng.below(3) == 0 {
            let d = rng.below(n);
            json.push(json[d].replace("\"broker_seq\":", "\"broker_seq\":1,\"zzz\":"));
            roles.push(roles[d]);
        }
        let mut order: Vec<usize> = (0..json.len()).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i + 1));
        }
        let records: Vec<CanonValue> = order
            .iter()
            .map(|&i| CanonValue::parse(&json[i]).unwrap())
            .collect();
        let rts: Vec<RecordTrust> = order
            .iter()
            .enumerate()
            .map(|(idx, &i)| RecordTrust {
                index: idx,
                record_id: format!("r{idx}"),
                content_hash: records[idx]
                    .get("content_hash")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
                integrity_ok: true,
                signature_ok: true,
                key_status: "active".into(),
                observed_via: "broker".into(),
                trust: TrustLevel::IntegrityProven,
                authority: AuthorityTrust::None,
                broker_role: roles[i].to_string(),
                notes: Vec::new(),
            })
            .collect();
        let dag = dag::build(&records).expect("generated history is a DAG");
        Case { records, rts, dag }
    }

    fn make_frontier(rng: &mut Rng, case: &Case, prev: &[String]) -> Vec<String> {
        let all: Vec<&String> = case.dag.topo_order.iter().collect();
        let mut f: Vec<String> = match rng.below(6) {
            0 => Vec::new(),
            1 => prev.to_vec(),
            2 => {
                let mut p = prev.to_vec();
                p.push(all[rng.below(all.len())].clone());
                p
            }
            3 => prev.iter().filter(|_| rng.below(2) == 0).cloned().collect(),
            4 => case.dag.heads.clone(),
            _ => (0..1 + rng.below(4))
                .map(|_| all[rng.below(all.len())].clone())
                .collect(),
        };
        if rng.below(6) == 0 {
            f.push(format!("sha256:{:064x}", 0xdead_0000 + rng.below(3)));
        }
        f
    }

    #[test]
    fn cursor_matches_the_per_frontier_code() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut resets_or_merges = 0usize;
        for case_no in 0..1500 {
            let case = make_case(&mut rng);
            let dix = DagIndex::build(&case.records, &case.dag.by_hash, &case.dag.topo_order)
                .expect("index builds");
            for bid in [None, Some("a"), Some("b")] {
                let ix = LogIndex::build(&dix, &case.rts, &case.records, bid).expect("log index");
                let reach = ix.reach();
                let mut cur = LogCursor::new(&ix);
                let mut prev: Vec<String> = Vec::new();
                for step in 0..14 {
                    let f = make_frontier(&mut rng, &case, &prev);
                    let log =
                        committed_broker_log(&case.rts, &case.records, &case.dag.by_hash, &f, bid);
                    let st = cur.advance(&f, &case.rts);
                    let ctx =
                        format!("case {case_no} step {step} partition {bid:?} frontier {f:?}");
                    assert_eq!(st.n, log.len() as i64, "{ctx}");
                    assert_eq!(
                        st.gapless,
                        log.iter().enumerate().all(|(i, (s, _))| *s == i as i64 + 1),
                        "{ctx}"
                    );
                    assert_eq!(st.root, grant_head_root(&log), "{ctx}");
                    assert_eq!(ix.commits_any(&reach, &f), !log.is_empty(), "{ctx}");
                    if log.len() > 1 && log.windows(2).any(|w| w[0].0 >= w[1].0) {
                        resets_or_merges += 1;
                    }
                    prev = f;
                }
            }
        }
        assert!(
            resets_or_merges > 100,
            "the generator must exercise unordered logs"
        );
    }

    #[test]
    fn anchor_times_match_the_per_checkpoint_sets() {
        let stamps = [
            "2026-06-15T10:00:00.000Z",
            "2026-06-15T10:00:01.000Z",
            "2026-06-15T10:00:02.000Z",
            "not-a-timestamp",
            // non-canonical stamps that sort BEFORE every canonical one: without the canonical guard one of
            // these would become the minimum and make an anchor look earlier than it provably is.
            "2026-06-15T09:00:00Z",
            "2025-06-15T10:00:00.000",
        ];
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for case_no in 0..800 {
            let case = make_case(&mut rng);
            let dix =
                DagIndex::build(&case.records, &case.dag.by_hash, &case.dag.topo_order).unwrap();
            let anchors: Vec<(String, Vec<String>)> = (0..rng.below(5))
                .map(|_| {
                    let f = make_frontier(&mut rng, &case, &[]);
                    (stamps[rng.below(stamps.len())].to_string(), f)
                })
                .collect();
            let min_ts = dix.min_anchor_times(
                anchors.iter().map(|(t, f)| (t.as_str(), f.as_slice())),
                is_canonical_ts,
            );
            let sets: Vec<(String, BTreeSet<String>)> = anchors
                .iter()
                .map(|(t, f)| {
                    (
                        t.clone(),
                        committed_set(&case.records, &case.dag.by_hash, f),
                    )
                })
                .collect();
            for h in &case.dag.topo_order {
                for c in stamps.iter().filter(|c| is_canonical_ts(c)) {
                    let old = sets.iter().any(|(ts, set)| {
                        is_canonical_ts(ts) && ts.as_str() <= *c && set.contains(h)
                    });
                    let new = dix
                        .node(h)
                        .and_then(|n| min_ts[n])
                        .is_some_and(|ts| ts <= *c);
                    assert_eq!(old, new, "case {case_no} hash {h} changed_at {c}");
                }
            }
        }
    }

    // ---- compute_*-level differentials and slow-path guards ----

    use super::super::{compute_broker_trust, compute_federation_trust, FedHeadCp, GrantHead};

    fn case_from(parts: &[(&str, &str, i64, &[usize])]) -> Case {
        // (role, broker_id, broker_seq, parent indexes), in topological order
        let mut json = Vec::new();
        let mut roles = Vec::new();
        for (i, (role, bid, seq, ps)) in parts.iter().enumerate() {
            let plist: Vec<String> = ps.iter().map(|p| format!("\"{}\"", hash_of(*p))).collect();
            json.push(format!(
                "{{\"content_hash\":\"{}\",\"extensions\":{{\"broker\":{{\"grant_evidence\":{{\"broker_seq\":{seq},\"broker_id\":\"{bid}\",\"grant_id\":\"g{i}\"}}}}}},\"causal_prev_hashes\":[{}]}}",
                hash_of(i),
                plist.join(",")
            ));
            roles.push(*role);
        }
        let records: Vec<CanonValue> = json.iter().map(|j| CanonValue::parse(j).unwrap()).collect();
        let rts: Vec<RecordTrust> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| RecordTrust {
                index: idx,
                record_id: format!("r{idx}"),
                content_hash: r.get("content_hash").unwrap().as_str().unwrap().to_string(),
                integrity_ok: true,
                signature_ok: true,
                key_status: "active".into(),
                observed_via: "broker".into(),
                trust: TrustLevel::IntegrityProven,
                authority: AuthorityTrust::None,
                broker_role: roles[idx].to_string(),
                notes: Vec::new(),
            })
            .collect();
        let dag = dag::build(&records).expect("DAG");
        Case { records, rts, dag }
    }

    type FedOut = (
        String,
        String,
        usize,
        usize,
        usize,
        Vec<(String, String)>,
        Vec<String>,
    );

    fn run_fed(case: &Case, cps: &[FedHeadCp], headless: &[Vec<String>]) -> FedOut {
        let mut issues = Vec::new();
        let ev = compute_federation_trust(
            cps,
            headless,
            false,
            &case.rts,
            &case.records,
            &case.dag.by_hash,
            &case.dag.topo_order,
            &case.dag.heads,
            cps.iter().map(|c| c.0).max().unwrap_or(0),
            &mut issues,
        );
        (
            ev.broker_trust,
            ev.status,
            ev.brokers_total,
            ev.brokers_seq_verified,
            ev.cross_broker_suppression,
            ev.per_broker,
            issues,
        )
    }

    fn run_both_fed(case: &Case, cps: &[FedHeadCp], headless: &[Vec<String>]) -> FedOut {
        FORCE_SLOW.with(|f| f.set(true));
        let slow = run_fed(case, cps, headless);
        FORCE_SLOW.with(|f| f.set(false));
        let fast = run_fed(case, cps, headless);
        assert_eq!(
            fast, slow,
            "indexed and per-frontier federation results differ"
        );
        fast
    }

    #[test]
    fn federation_headless_checkpoint_that_commits_a_grant_is_suppression() {
        // a verified headless checkpoint commits broker a's grant: M4 suppression, indexed branch must see it.
        let case = case_from(&[("broker", "a", 1, &[]), ("broker", "b", 1, &[0])]);
        let heads: BTreeMap<String, GrantHead> = BTreeMap::new();
        let front = vec![hash_of(0)];
        let latest = (1, false, heads, case.dag.heads.clone());
        let out = run_both_fed(&case, &[latest], &[front]);
        assert!(
            out.6.iter().any(|i| i.contains("broker 'a': a verified checkpoint commits its grants but carries no broker_grant_heads map")),
            "{:?}",
            out.6
        );
        assert_eq!(out.1, "suppression");
    }

    #[test]
    fn federation_map_missing_a_broker_the_frontier_commits_is_suppression() {
        let case = case_from(&[("broker", "a", 1, &[]), ("broker", "b", 1, &[0])]);
        let full = case.dag.heads.clone();
        let log_a = committed_broker_log(
            &case.rts,
            &case.records,
            &case.dag.by_hash,
            &full,
            Some("a"),
        );
        let mut m = BTreeMap::new();
        m.insert(
            "a".to_string(),
            GrantHead {
                max_seq: log_a.len() as i64,
                prior_head_hash: grant_head_root(&[]),
                cumulative_root: grant_head_root(&log_a),
            },
        );
        // an earlier checkpoint (seq 1) commits b's grant but its map has no head for b; the latest carries both
        let early = (1, false, m.clone(), full.clone());
        let out = run_both_fed(&case, &[early], &[]);
        assert!(
            out.6.iter().any(|i| i.contains("broker 'b' checkpoint seq 1: commits its grants but its broker_grant_heads has no head for it")),
            "{:?}",
            out.6
        );
    }

    #[test]
    fn compute_trust_matches_the_per_frontier_code_on_random_histories() {
        let mut rng = Rng(0x0bad_5eed_1234_5678);
        let mut suppressed_seen = 0usize;
        let mut clean_seen = 0usize;
        for case_no in 0..600 {
            let case = make_case(&mut rng);
            let mut prev: Vec<String> = Vec::new();
            let mut cps = Vec::new();
            let mut headless = Vec::new();
            let mut chain: BTreeMap<String, String> = BTreeMap::new();
            for seq in 1..=(1 + rng.below(5)) as i64 {
                let f = make_frontier(&mut rng, &case, &prev);
                let mut m = BTreeMap::new();
                for b in ["a", "b", "c"] {
                    if rng.below(5) == 0 {
                        continue; // dropped head
                    }
                    let log = committed_broker_log(
                        &case.rts,
                        &case.records,
                        &case.dag.by_hash,
                        &f,
                        Some(b),
                    );
                    let honest = rng.below(3) != 0;
                    let prior = chain
                        .get(b)
                        .cloned()
                        .unwrap_or_else(|| grant_head_root(&[]));
                    let root = grant_head_root(&log);
                    chain.insert(b.to_string(), root.clone());
                    m.insert(
                        b.to_string(),
                        GrantHead {
                            max_seq: log.len() as i64 + if honest { 0 } else { 1 },
                            prior_head_hash: prior,
                            cumulative_root: root,
                        },
                    );
                }
                if rng.below(4) == 0 {
                    headless.push(f.clone());
                } else {
                    cps.push((seq, rng.below(2) == 0, m, f.clone()));
                }
                prev = f;
            }
            let out = run_both_fed(&case, &cps, &headless);
            if out.1 == "suppression" {
                suppressed_seen += 1;
            } else {
                clean_seen += 1;
            }
            // broker-trust (D6), same comparison
            let cp_heads: Vec<(i64, bool, GrantHead, Vec<String>)> = cps
                .iter()
                .filter_map(|(s, a, m, f)| m.get("a").map(|h| (*s, *a, h.clone(), f.clone())))
                .collect();
            let run_broker = || {
                let mut issues = Vec::new();
                let t = compute_broker_trust(
                    &cp_heads,
                    &headless,
                    false,
                    &case.rts,
                    &case.records,
                    &case.dag.by_hash,
                    &case.dag.topo_order,
                    &case.dag.heads,
                    cps.iter().map(|c| c.0).max().unwrap_or(0),
                    &mut issues,
                );
                (t, issues)
            };
            FORCE_SLOW.with(|f| f.set(true));
            let slow = run_broker();
            FORCE_SLOW.with(|f| f.set(false));
            assert_eq!(run_broker(), slow, "case {case_no}: broker trust differs");
        }
        assert!(
            suppressed_seen > 50 && clean_seen > 0,
            "{suppressed_seen} {clean_seen}"
        );
    }

    #[test]
    fn honest_growing_history_never_takes_a_slow_path() {
        // a long linear history, one grant per record, a checkpoint every 10 records, each frontier extending
        // the previous one: the index must build and the cursor must never reset.
        let n = 3000;
        let parts: Vec<(&str, &str, i64, Vec<usize>)> = (0..n)
            .map(|i| {
                (
                    "broker",
                    "a",
                    i as i64 + 1,
                    if i == 0 { vec![] } else { vec![i - 1] },
                )
            })
            .collect();
        let refs: Vec<(&str, &str, i64, &[usize])> = parts
            .iter()
            .map(|(r, b, s, p)| (*r, *b, *s, p.as_slice()))
            .collect();
        let case = case_from(&refs);
        let mut cps = Vec::new();
        let mut prior = grant_head_root(&[]);
        for k in 1..=(n / 10) {
            let f = vec![hash_of(k * 10 - 1)];
            let log =
                committed_broker_log(&case.rts, &case.records, &case.dag.by_hash, &f, Some("a"));
            let root = grant_head_root(&log);
            let mut m = BTreeMap::new();
            m.insert(
                "a".to_string(),
                GrantHead {
                    max_seq: log.len() as i64,
                    prior_head_hash: prior.clone(),
                    cumulative_root: root.clone(),
                },
            );
            prior = root;
            cps.push((k as i64, k == n / 10, m, f));
        }
        for c in [
            &INDEX_FALLBACKS,
            &CURSOR_RESETS,
            &FRONTIER_FALLBACKS,
            &CURSOR_ADVANCES,
        ] {
            c.with(|x| x.set(0));
        }
        let out = run_fed(&case, &cps, &[]);
        assert_eq!(out.1, "sequence_verified", "{:?}", out.6);
        // the single-broker D6 path on the same history
        let d6: Vec<(i64, bool, GrantHead, Vec<String>)> = cps
            .iter()
            .map(|(s, a, m, f)| (*s, *a, m["a"].clone(), f.clone()))
            .collect();
        let mut issues = Vec::new();
        let t = compute_broker_trust(
            &d6,
            &[],
            false,
            &case.rts,
            &case.records,
            &case.dag.by_hash,
            &case.dag.topo_order,
            &case.dag.heads,
            (n / 10) as i64,
            &mut issues,
        );
        assert_eq!(t, "sequence_verified", "{issues:?}");
        assert_eq!(
            INDEX_FALLBACKS.with(|c| c.get()),
            0,
            "index fell back to the per-frontier code"
        );
        assert_eq!(
            CURSOR_RESETS.with(|c| c.get()),
            0,
            "cursor reset on an honest growing history"
        );
        // the fast path really ran: one cursor advance per head, in the federation run and in the D6 run, and
        // no frontier was answered by the old per-frontier code (guards against a silent revert of the speed-up).
        assert_eq!(
            CURSOR_ADVANCES.with(|c| c.get()),
            2 * (n / 10),
            "cursor not used for every head"
        );
        assert_eq!(
            FRONTIER_FALLBACKS.with(|c| c.get()),
            0,
            "a frontier took the per-frontier code on an honest history"
        );
    }

    #[test]
    fn headless_checks_use_the_index_not_the_per_frontier_walk() {
        // a headless frontier that commits grants, in D6 and in federation: the issue is raised through the
        // reach DP / single-walk broker set, never through the per-frontier code.
        let case = case_from(&[("broker", "a", 1, &[]), ("broker", "b", 1, &[0])]);
        let headless = vec![vec![hash_of(1)]];
        for c in [&FRONTIER_FALLBACKS, &CURSOR_ADVANCES] {
            c.with(|x| x.set(0));
        }
        let out = run_fed(&case, &[], &headless);
        assert!(
            out.6
                .iter()
                .any(|i| i.contains("broker 'a': a verified checkpoint commits")),
            "{:?}",
            out.6
        );
        assert!(
            out.6
                .iter()
                .any(|i| i.contains("broker 'b': a verified checkpoint commits")),
            "{:?}",
            out.6
        );
        let mut issues = Vec::new();
        let d6: Vec<(i64, bool, GrantHead, Vec<String>)> = Vec::new();
        let _ = compute_broker_trust(
            &d6,
            &headless,
            false,
            &case.rts,
            &case.records,
            &case.dag.by_hash,
            &case.dag.topo_order,
            &case.dag.heads,
            0,
            &mut issues,
        );
        assert!(
            issues
                .iter()
                .any(|i| i.contains("carries no (well-formed)")),
            "{issues:?}"
        );
        assert_eq!(
            FRONTIER_FALLBACKS.with(|c| c.get()),
            0,
            "headless check took the per-frontier code"
        );
    }

    #[test]
    fn many_brokers_do_not_hold_per_broker_indexes() {
        // 300 brokers, one grant each, one checkpoint: the verdict is unchanged by the lazy per-broker build.
        let n = 300;
        let parts: Vec<(&str, String, i64, Vec<usize>)> = (0..n)
            .map(|i| {
                (
                    "broker",
                    format!("b{i}"),
                    1,
                    if i == 0 { vec![] } else { vec![i - 1] },
                )
            })
            .collect();
        let refs: Vec<(&str, &str, i64, &[usize])> = parts
            .iter()
            .map(|(r, b, s, p)| (*r, b.as_str(), *s, p.as_slice()))
            .collect();
        let case = case_from(&refs);
        let fast = run_fed(&case, &[], &[vec![hash_of(n - 1)]]);
        FORCE_SLOW.with(|f| f.set(true));
        let slow = run_fed(&case, &[], &[vec![hash_of(n - 1)]]);
        FORCE_SLOW.with(|f| f.set(false));
        assert_eq!(fast, slow);
    }

    #[test]
    fn a_child_listed_before_its_parent_refuses_the_index() {
        // topo_order that lists a child before its parent must not build the index (the reach and anchor DPs
        // read parents first), so the per-frontier code runs instead.
        let case = case_from(&[("broker", "a", 1, &[]), ("broker", "a", 2, &[0])]);
        let mut topo = case.dag.topo_order.clone();
        topo.reverse();
        assert!(DagIndex::build(&case.records, &case.dag.by_hash, &case.dag.topo_order).is_some());
        assert!(DagIndex::build(&case.records, &case.dag.by_hash, &topo).is_none());
    }
}
