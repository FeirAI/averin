package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync/atomic"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/store"
)

// DefaultCheckpointShadowEvery is how often (1 in N incremental cuts) the full computation is also run and
// compared. A mismatch refuses to sign.
const DefaultCheckpointShadowEvery = 100

// checkpointCutState is the per-server bookkeeping of the shadow check.
type checkpointCutState struct {
	cuts        atomic.Int64 // incremental cuts so far; the shadow check runs when cuts % every == 0
	every       int64        // 0 means DefaultCheckpointShadowEvery
	latched     atomic.Bool  // set by a mismatch: every later cut is shadow-checked until restart
	incremental atomic.Int64 // cuts taken incrementally (observable in tests)
	full        atomic.Int64 // cuts taken by the full computation (no usable base, or a guard disagreed)
}

// WithCheckpointShadowEvery sets the shadow-check period (every n-th incremental cut also runs the full
// computation). n < 1 is treated as 1 (check every cut): the knob can only make the check stricter, never turn
// it off.
func (s *Server) WithCheckpointShadowEvery(n int) *Server {
	if n < 1 {
		n = 1
	}
	s.cut.every = int64(n)
	return s
}

// cutBase is what the incremental cut reads from the latest checkpoint L.
type cutBase struct {
	seq       int64    // L.Seq
	hash      string   // L.CheckpointHash
	count     int64    // L.record_count
	frontier  []string // L.frontier
	maxSeq    int64    // L.broker_grant_head.max_seq
	root      string   // L.broker_grant_head.cumulative_root
	fedMax    int64    // L.broker_grant_heads[brokerID].max_seq (federated only)
	fedRoot   string   // L.broker_grant_heads[brokerID].cumulative_root (federated only)
	federated bool
}

// parseCutBase extracts the base from L. ok=false means "no usable base, use the full computation": an
// unparseable body, a pre-D6 checkpoint (no broker_grant_head), or (when this server has a broker id) no entry
// for that broker yet (a pre-federation checkpoint or the first federated cut).
func parseCutBase(l store.Checkpoint, brokerID string) (cutBase, bool) {
	var p struct {
		RecordCount     *int64   `json:"record_count"`
		Frontier        []string `json:"frontier"`
		BrokerGrantHead struct {
			MaxSeq         int64  `json:"max_seq"`
			CumulativeRoot string `json:"cumulative_root"`
		} `json:"broker_grant_head"`
		BrokerGrantHeads map[string]struct {
			MaxSeq         int64  `json:"max_seq"`
			CumulativeRoot string `json:"cumulative_root"`
		} `json:"broker_grant_heads"`
	}
	if err := json.Unmarshal([]byte(l.JSON), &p); err != nil || p.RecordCount == nil || p.Frontier == nil || *p.RecordCount < 0 {
		return cutBase{}, false
	}
	if p.BrokerGrantHead.CumulativeRoot == "" {
		return cutBase{}, false
	}
	b := cutBase{seq: l.Seq, hash: l.CheckpointHash, count: *p.RecordCount, frontier: p.Frontier,
		maxSeq: p.BrokerGrantHead.MaxSeq, root: p.BrokerGrantHead.CumulativeRoot}
	if brokerID != "" {
		e, has := p.BrokerGrantHeads[brokerID]
		if !has || e.CumulativeRoot == "" || e.MaxSeq != b.maxSeq {
			return cutBase{}, false
		}
		b.federated, b.fedMax, b.fedRoot = true, e.MaxSeq, e.CumulativeRoot
	}
	return b, true
}

// checkGaplessGrantLogAfter is checkGaplessGrantLog for the grants after a prior head that covered exactly
// 1..priorMax: the new members must be exactly priorMax+1..priorMax+len(gl) (so a grant with seq <= priorMax,
// a duplicate and a gap are all refused) and the store's allocated max must equal the end of that range.
func checkGaplessGrantLogAfter(gl []broker.GrantSeqHash, priorMax, maxAllocated int64) error {
	for i := 1; i < len(gl); i++ {
		if gl[i].Seq == gl[i-1].Seq {
			return fmt.Errorf("broker_seq %d is held by two recorded entries (%s, %s) — duplicate seq", gl[i].Seq, gl[i-1].ContentHash, gl[i].ContentHash)
		}
	}
	for i, g := range gl {
		if want := priorMax + int64(i) + 1; g.Seq != want {
			return fmt.Errorf("recorded grant broker_seq set is not a gapless [1..N] prefix (position %d holds seq %d)", priorMax+int64(i)+1, g.Seq)
		}
	}
	if n := priorMax + int64(len(gl)); maxAllocated != n {
		return fmt.Errorf("allocated broker_seq max %d != %d recorded grants (a reserved or orphaned seq has no recorded grant; retry that grant or inspect and recover it with GET/POST /v2/broker-seq/void)", maxAllocated, n)
	}
	return nil
}

// cutBodyIncremental builds the checkpoint body from the latest checkpoint L plus the records after it
// (history-scaling PR2). inc=false (with a nil error) means there is no usable base and the caller must use
// cutBodyFull. It reads O(|D|) rows, D being the records after L, plus a handful of one-row reads, whatever the
// history.
//
// WHY IT EQUALS THE FULL COMPUTATION (cutBodyFull), field by field. Everything is read in one project write
// transaction (the project guard is held), and L is the checkpoint the previous such transaction signed.
//
//  1. seq and prev. Seqs are assigned from NextCheckpointSeq (the checkpoint count) under the guard into an
//     insert-only table keyed (project, seq), so they are 0..n-1 and the next seq is L.seq+1; the previous hash
//     is L's hash (LatestCheckpointHash is L). The cut reads NextCheckpointSeq as well and falls back to the
//     full computation if it is not L.seq+1.
//  2. count. Records are insert-only and ordinals are assigned under the guard, so the records are exactly
//     ordinals 1..c_L (L's record_count, read in L's own transaction) plus D, the records with ordinal > c_L:
//     count = c_L + |D|. The cut also reads RecordCount (an index read) and REFUSES when it differs.
//  3. frontier. Parents are server-derived (the session's current heads, or a forced intent hash of an
//     existing record), so no record ever names a later one. Hence an old record is a head of (S union D) iff it
//     is a head of S and no record in D names it, and a record of D is a head iff no record of D names it. With
//     F_L = heads(S) (L's signed frontier): frontier = (F_L minus parents(D)) union (hashes(D) minus parents(D)).
//  4. grant root. GrantHeadRoot is a left fold from a fixed seed, so root(g1..gN) = fold(root(g1..gM),
//     g(M+1)..gN). R_L is the root over exactly 1..M_L (L was signed only after the gapless check). No grant
//     with seq <= M_L can be recorded after L (allocation is MAX+1, idempotent per grant id, and a void fills
//     only an unrecorded seq), so the grants after L are exactly G, those in D. The cut REFUSES unless their
//     seqs are exactly M_L+1..N and MaxBrokerSeq = N (the checkGaplessGrantLog refusal, shifted). max_seq is N
//     (M_L when G is empty), prior_head_hash is R_L.
//  5. federation. One broker id owns the whole log, so 4 applies to its entry in broker_grant_heads, chained
//     from L's entry for that broker.
//
// Beyond this argument there are a differential property test (incremental equals full on random histories)
// and the shadow check in checkpointBodyChecked.
func (s *Server) cutBodyIncremental(st store.Store, projectID, created string) (body map[string]any, inc bool, err error) {
	l, hasL, err := st.LatestCheckpoint(projectID)
	if err != nil {
		return nil, false, fmt.Errorf("checkpoint: read project snapshot: %w", err)
	}
	if !hasL {
		return nil, false, nil
	}
	base, ok := parseCutBase(l, s.brokerID)
	if !ok {
		return nil, false, nil
	}
	nextSeq, err := st.NextCheckpointSeq(projectID)
	if err != nil {
		return nil, false, fmt.Errorf("checkpoint: read project snapshot: %w", err)
	}
	if nextSeq != base.seq+1 {
		return nil, false, nil // seqs are not 0..n-1 under L: let the full computation define the cut
	}

	// D: the records after L, paged. Only the frontier fold and the grant members are kept.
	var fold store.FrontierFold
	var gl []broker.GrantSeqHash
	after := base.count
	for {
		page, perr := st.RecordsAfter(projectID, after, store.HeadsPageSize)
		if perr != nil {
			return nil, false, fmt.Errorf("checkpoint: read project snapshot: %w", perr)
		}
		for _, r := range page {
			fold.Add(r)
		}
		g, gerr := grantLog(page)
		if gerr != nil {
			return nil, false, gerr
		}
		gl = append(gl, g...)
		after += int64(len(page))
		if len(page) < store.HeadsPageSize {
			break
		}
	}
	count := after
	total, err := st.RecordCount(projectID)
	if err != nil {
		return nil, false, fmt.Errorf("checkpoint: read project snapshot: %w", err)
	}
	if int64(total) != count {
		return nil, false, fmt.Errorf("checkpoint refused: latest checkpoint counted %d records and %d follow it, but the project holds %d", base.count, count-base.count, total)
	}
	maxAlloc, err := st.MaxBrokerSeq(projectID)
	if err != nil {
		return nil, false, fmt.Errorf("checkpoint: read project snapshot: %w", err)
	}
	sort.Slice(gl, func(i, j int) bool { return gl[i].Seq < gl[j].Seq })
	if err := checkGaplessGrantLogAfter(gl, base.maxSeq, maxAlloc); err != nil {
		return nil, false, fmt.Errorf("checkpoint refused: %w", err)
	}
	grantHead, err := broker.BrokerGrantHeadFrom(base.root, base.maxSeq, gl)
	if err != nil {
		return nil, false, fmt.Errorf("checkpoint: %w", err)
	}
	body = s.checkpointBody(projectID, base.seq+1, base.hash, true, fold.Heads(base.frontier), int(count), grantHead, created)
	if base.federated {
		entry, ferr := broker.BrokerGrantHeadFrom(base.fedRoot, base.fedMax, gl)
		if ferr != nil {
			return nil, false, fmt.Errorf("checkpoint: %w", ferr)
		}
		body["broker_grant_heads"] = map[string]any{s.brokerID: entry}
	}
	return body, true, nil
}

// checkpointBody assembles the fields common to both cuts, so they can only differ in the values computed.
func (s *Server) checkpointBody(projectID string, seq int64, prev string, hasPrev bool, heads []string, count int, grantHead map[string]any, created string) map[string]any {
	if heads == nil {
		heads = []string{}
	}
	var prevVal any
	if hasPrev {
		prevVal = prev
	}
	return map[string]any{
		"schema_version":       "2",
		"canon_version":        "rcp-1",
		"domain":               "flightrecorder.checkpoint.v2",
		"checkpoint_id":        fmt.Sprintf("cp-%s-%d", projectID, seq), // deterministic per seq
		"project_id":           projectID,
		"checkpoint_seq":       seq,
		"prev_checkpoint_hash": prevVal,
		"frontier":             heads,
		"record_count":         count,
		"broker_grant_head":    grantHead,
		"created_ts":           created,
		"key":                  s.keyBlock(),
	}
}

// checkpointBodyChecked returns the body to sign: the incremental cut when it applies, else the full
// computation. Every n-th incremental cut (and every one after a mismatch has latched) also computes the full
// body with the same created_ts and REFUSES to sign unless the two are byte-identical: an incremental cut that
// disagrees with the definition must never reach a signature, because checkpoints are append-only.
func (s *Server) checkpointBodyChecked(st store.Store, projectID string) (map[string]any, error) {
	created := ts(s.now())
	body, inc, err := s.cutBodyIncremental(st, projectID, created)
	if err != nil {
		return nil, err
	}
	if !inc {
		s.cut.full.Add(1)
		return s.cutBodyFull(st, projectID, created)
	}
	s.cut.incremental.Add(1)
	every := s.cut.every
	if every < 1 {
		every = DefaultCheckpointShadowEvery
	}
	if n := s.cut.cuts.Add(1); !s.cut.latched.Load() && n%every != 0 {
		return body, nil
	}
	s.mCutShadowChecks.Inc()
	full, ferr := s.cutBodyFull(st, projectID, created)
	if ferr != nil {
		return nil, fmt.Errorf("checkpoint refused: shadow full computation failed: %w", ferr)
	}
	a, _ := json.Marshal(body)
	b, _ := json.Marshal(full)
	if !bytes.Equal(a, b) {
		s.cut.latched.Store(true) // every later cut is shadow-checked until restart
		s.mCutShadowMismatch.Inc()
		log.Printf("ALERT: checkpoint cut for project %s REFUSED: the incremental cut differs from the full computation in %s; every later cut is now shadow-checked", projectID, differingFields(body, full))
		return nil, fmt.Errorf("checkpoint refused: the incremental cut disagrees with the full computation")
	}
	return full, nil
}

// differingFields names the top-level body fields whose values differ (never the values: a frontier can be long).
func differingFields(a, b map[string]any) string {
	var out []string
	for k, av := range a {
		x, _ := json.Marshal(av)
		y, _ := json.Marshal(b[k])
		if !bytes.Equal(x, y) {
			out = append(out, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return fmt.Sprint(out)
}
