package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/store"
)

// DefaultCheckpointShadowEvery is how often (1 in N incremental cuts) the full computation is scheduled to also
// run and be compared. A mismatch refuses to sign. A scheduled shadow only runs when the project's last shadow
// attempt is at least DefaultCheckpointShadowMinInterval old, so the effective cadence of the scheduled check is
// max(every 100th cut, once per hour per project). The first incremental cut after a start and every cut after
// a mismatch are not rate-limited.
const DefaultCheckpointShadowEvery = 100

// DefaultCheckpointShadowMinInterval is the least time between two shadow attempts of one project on the
// scheduled path (a verified project, nothing latched). The shadow is O(history). It runs on a read snapshot
// outside the project write lock (it no longer holds the project write lock), but it still costs database CPU, a pool connection
// and memory for up to the shadow budget, so at a high cut rate "every 100th cut" would come due every few minutes
// and each run would load the database. This WEAKENS what the scheduled shadow covers: between two attempts an
// incorrect incremental cut is caught only by the per-cut count and contiguity guards, not by the full comparison.
const DefaultCheckpointShadowMinInterval = time.Hour

// The shadow's own time budget and the backoff after a shadow that could not run (lead decision, history
// scaling PR2): the full computation is O(history) and stops completing as history grows, so it must neither
// hold the project write guard for the whole statement timeout nor be retried on every cut.
//
// The default budget is 20 s (it was 1 s, and 5 s before that). While the shadow ran under the project write
// lock the budget was the write stall, so it was cut to 1 s. The shadow now runs on a read snapshot outside that
// lock, so the budget bounds only the delay of one cut response, one pool connection, one snapshot and database CPU,
// and a larger budget keeps the comparison running on longer histories. Release-1 soak evidence (about 0.5
// calls/s): the full computation stopped fitting 5 s reliably from about 5 h of history, a slope of about 1 s per
// hour of history, so 20 s is an estimate of about 20 h before it stops fitting (not measured); a cheaper full
// computation is a separate follow-up. The differential tests stay the primary assurance.
const (
	DefaultCheckpointShadowBudget  = 20 * time.Second
	MaxCheckpointShadowBudget      = 20 * time.Second // below the 30 s statement timeout, which it must never reach
	DefaultCheckpointShadowBackoff = 10 * time.Minute
	maxShadowBackoffDoublings      = 6 // the wait doubles per consecutive failure up to 64 times the base
)

// checkpointSignTimeout bounds phase 3 of a shadowed cut (base check, then seal and store), which runs detached from
// the caller's cancellation. It is O(1) work, so it is normally milliseconds; its legitimate waits are the in-process
// write slot, a pool connection and the guard row, whose own wait is bounded by a 10 s lock_timeout. 15 s lets that
// lock wait fail with its own clear error first. The commit keeps its own 10 s bound on top.
const checkpointSignTimeout = 15 * time.Second

// checkpointCutState is the per-server bookkeeping of the shadow check.
type checkpointCutState struct {
	every       int64        // 0 means DefaultCheckpointShadowEvery
	latched     atomic.Bool  // set by a mismatch: every later cut is shadow-checked until restart
	verified    sync.Map     // project -> struct{}: its first incremental cut since process start passed a shadow check
	incremental atomic.Int64 // cuts taken incrementally (observable in tests)
	full        atomic.Int64 // cuts taken by the full computation (no usable base, or a guard disagreed)

	budget      time.Duration // 0 means DefaultCheckpointShadowBudget
	signTimeout time.Duration // 0 means checkpointSignTimeout; tests only shorten it
	backoff     time.Duration // 0 means DefaultCheckpointShadowBackoff
	minIval     time.Duration // minimum time between scheduled shadow attempts; only tightened below the default via the builder
	minSet      bool          // minIval was set explicitly (0 then means no rate limit)
	mu          sync.Mutex
	retry       map[string]shadowRetry // project -> when its next shadow attempt may run
	lastTry     map[string]time.Time   // project -> start of its last shadow attempt, whatever the outcome
	gates       map[string]*cutGate    // project -> its cut gate while a cut holds or awaits it (guarded by mu)

	lastShadowNanos atomic.Int64 // duration of the most recent shadow computation of any project
}

// shadowRetry is the backoff state of one project after a shadow that could not run.
type shadowRetry struct {
	notBefore time.Time
	fails     int
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

// WithCheckpointShadowBudget sets the time budget of one shadow computation (default 20 s, at most 20 s, at
// least 1 ms): a shadow that cannot finish inside it stops holding its snapshot and pool connection and counts
// as "could not run", not as a mismatch.
func (s *Server) WithCheckpointShadowBudget(d time.Duration) *Server {
	if d < time.Millisecond {
		d = time.Millisecond
	}
	if d > MaxCheckpointShadowBudget {
		d = MaxCheckpointShadowBudget
	}
	s.cut.budget = d
	return s
}

// WithCheckpointShadowBackoff sets the base wait before a project's next shadow attempt after one that could
// not run (default 10 min; it doubles per consecutive failure up to 64 times, and resets when a shadow runs).
// d < 1 ms is treated as 1 ms.
func (s *Server) WithCheckpointShadowBackoff(d time.Duration) *Server {
	if d < time.Millisecond {
		d = time.Millisecond
	}
	s.cut.backoff = d
	return s
}

// WithCheckpointShadowMinInterval sets the least time between two scheduled shadow attempts of one project
// (default DefaultCheckpointShadowMinInterval, 1 h). d < 0 is treated as 0, which disables the rate limit (the
// strictest setting); d above the default is clamped to it, so the knob can only tighten the check.
func (s *Server) WithCheckpointShadowMinInterval(d time.Duration) *Server {
	if d < 0 {
		d = 0
	}
	if d > DefaultCheckpointShadowMinInterval {
		d = DefaultCheckpointShadowMinInterval
	}
	s.cut.minIval = d
	s.cut.minSet = true
	return s
}

func (s *Server) shadowMinInterval() time.Duration {
	if !s.cut.minSet {
		return DefaultCheckpointShadowMinInterval
	}
	return s.cut.minIval
}

// shadowTooSoon reports whether the project's last shadow attempt is younger than the minimum interval.
func (s *Server) shadowTooSoon(projectID string) bool {
	ival := s.shadowMinInterval()
	if ival <= 0 {
		return false
	}
	s.cut.mu.Lock()
	defer s.cut.mu.Unlock()
	t, ok := s.cut.lastTry[projectID]
	return ok && s.now().Sub(t) < ival
}

// shadowAttempted records the start of a shadow attempt (any outcome).
func (s *Server) shadowAttempted(projectID string) {
	s.cut.mu.Lock()
	defer s.cut.mu.Unlock()
	if s.cut.lastTry == nil {
		s.cut.lastTry = map[string]time.Time{}
	}
	s.cut.lastTry[projectID] = s.now()
}

// shadowWaiting reports whether the project's next shadow attempt is still inside its backoff.
func (s *Server) shadowWaiting(projectID string) bool {
	s.cut.mu.Lock()
	defer s.cut.mu.Unlock()
	r, ok := s.cut.retry[projectID]
	return ok && s.now().Before(r.notBefore)
}

// shadowFailed records a shadow that could not run and schedules the next attempt after a backoff.
func (s *Server) shadowFailed(projectID string) time.Duration {
	base := s.cut.backoff
	if base <= 0 {
		base = DefaultCheckpointShadowBackoff
	}
	s.cut.mu.Lock()
	defer s.cut.mu.Unlock()
	if s.cut.retry == nil {
		s.cut.retry = map[string]shadowRetry{}
	}
	r := s.cut.retry[projectID]
	wait := base << min(r.fails, maxShadowBackoffDoublings)
	s.cut.retry[projectID] = shadowRetry{notBefore: s.now().Add(wait), fails: r.fails + 1}
	return wait
}

func (s *Server) shadowRan(projectID string) {
	s.cut.mu.Lock()
	delete(s.cut.retry, projectID)
	s.cut.mu.Unlock()
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
		if g.Seq >= 1 && g.Seq <= priorMax { // that seq is already folded into the latest checkpoint's head
			return fmt.Errorf("broker_seq %d is held by two recorded entries (one already folded into the latest checkpoint, and %s) — duplicate seq", g.Seq, g.ContentHash)
		}
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
// WHY IT EQUALS THE FULL COMPUTATION (cutBodyFull), field by field. Everything is read in ONE consistent state: a
// project write transaction (the project guard is held), or the repeatable-read snapshot of a shadowed cut, which
// is a prefix of the guard-serialized write sequence (every write commits under the guard). L is the latest
// checkpoint of that state.
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
		if oerr := store.CheckPageOrdinals(page, after); oerr != nil {
			return nil, false, fmt.Errorf("checkpoint refused: %w", oerr)
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

// checkpointBodyChecked is phase 1 of a cut, run inside the project write transaction. It returns the body to
// sign: the incremental cut when it applies and no shadow is due, else the full computation. When a shadow is due
// it returns *errShadowDue instead and the caller rolls back and runs the comparison off the lock (shadowOffLock),
// then signs the compared bytes under the lock after a base check. In a shadowed cut the full body is also computed with the same created_ts, and signing is REFUSED unless the two are
// byte-identical, when (a) the checkpoint being cut has seq % every == 0 (chosen per project from the checkpoint
// itself, so no project can be skipped by a rotation of cuts, and a refused seq is retried as the same seq and
// shadowed again, also after a restart, so a refusal needs no stored state to stay a refusal; this scheduled
// shadow is additionally rate-limited to one attempt per project per DefaultCheckpointShadowMinInterval, so its
// cadence is max(every 100th cut, once per hour per project) and a due cut inside that hour is signed
// incrementally without a shadow), (b) it is the
// first incremental cut of the project since this process started and has not yet passed a shadow check (a base
// altered while the process was down, and a first cut after migration), or (c) a mismatch has latched. An
// incremental cut that disagrees with the definition must never reach a signature, because checkpoints are
// append-only. A shadow that CANNOT RUN (a read error, a statement timeout, its own time budget) is not a
// disagreement: the incremental body is signed, averin_checkpoint_shadow_failed_total is counted, an ALERT is
// logged and the project's next shadow waits for a backoff. A full body that was computed but came back over
// budget is still compared: a mismatch refuses, a match is signed and counted as late. A shadowed checkpoint
// covers the records committed when its snapshot was taken (records committed during the shadow go into the next
// checkpoint). The shadow therefore
// stops being effective once the full computation no longer fits its budget; the counter shows it, and the differential tests plus the per-cut
// count and contiguity guards are what still hold the equality.
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
	seq, _ := body["checkpoint_seq"].(int64)
	_, verified := s.cut.verified.Load(projectID)
	if verified && !s.cut.latched.Load() && seq%every != 0 {
		return body, nil
	}
	if verified && !s.cut.latched.Load() && s.shadowTooSoon(projectID) {
		return body, nil // scheduled shadow, but the project's last attempt is inside the minimum interval
	}
	if s.shadowWaiting(projectID) {
		return body, nil // the last shadow of this project could not run: wait out its backoff, then try again
	}
	// A shadow is due. It does NOT run here: this is the project write transaction. The caller rolls it back and
	// runs the comparison on a read snapshot outside the write lock (shadowOffLock), then signs under the lock
	// again (createCheckpointTx with the precomputed result). The base L this decision was made against is carried
	// along so phase 3 can refuse if it moved.
	prev, _ := body["prev_checkpoint_hash"].(string)
	return nil, &errShadowDue{seq: seq - 1, hash: prev}
}

// errShadowDue is returned by checkpointBodyChecked (phase 1, inside the write transaction) when the incremental
// cut applies and a shadow is due: the transaction rolls back having written nothing, and the shadow runs off the
// lock. seq and hash identify the latest checkpoint L the decision was made against.
type errShadowDue struct {
	seq  int64
	hash string
}

func (e *errShadowDue) Error() string {
	return "checkpoint cut: shadow check due (it runs outside the project write transaction)"
}

// errShadowRaced means the latest checkpoint of the project moved while the shadow ran (another writer process
// cut in between). Nothing was signed.
var errShadowRaced = errors.New("checkpoint cut abandoned: the project's latest checkpoint changed while its shadow check ran (another writer cut a checkpoint); nothing was signed, retry the cut")

// shadowResult is the outcome of a completed phase 2: the exact bytes to sign (the compared body) and what the
// snapshot covered, for the phase 3 checks.
type shadowResult struct {
	bodyJSON []byte
	baseSeq  int64
	baseHash string
	count    int64 // RecordCount at the snapshot
	maxSeq   int64 // MaxBrokerSeq at the snapshot
	// unchecked is true when the full computation could not run and the incremental body is to be signed without its
	// check (the "signed WITHOUT its shadow check" ALERT has been logged). On an error return it is true only when
	// that happened before the failure, so a later failure can say its earlier ALERT claimed a signature that did
	// not follow.
	unchecked bool
}

// shadowOffLock is phase 2 of a shadowed cut. It computes the incremental and the full body on ONE
// repeatable-read snapshot S of the project, with the same created_ts, without the project write lock, and
// compares them byte for byte. It returns the bytes to sign: the compared body (or, when the full computation
// could not run, the incremental body, as before). A mismatch returns the refusal here, so no lock is taken and
// nothing is sealed. It runs detached from the caller's cancellation (bounded by budget + 5 s) so a client that
// hangs up is not counted as a failed shadow. On an error, shadowResult.unchecked is true only if the full
// computation could not run (its ALERT was logged) and the snapshot's commit then failed.
//
// Both bodies are deterministic functions of S: records and checkpoints are append-only and every write commits
// under the project guard, so S is a prefix of the guard-serialized write sequence, a state a locked cut could
// have seen. The checkpoint signed from this result covers exactly S (records committed after S go into the next
// checkpoint).
func (s *Server) shadowOffLock(ctx context.Context, projectID string, due *errShadowDue) (shadowResult, error) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.shadowBudget()+5*time.Second)
	defer cancel()
	var res shadowResult
	err := s.st.WithProjectRead(sctx, projectID, func(snap store.Store) error {
		// The first statement of the snapshot: on PostgreSQL it fixes the snapshot. If the latest checkpoint is not
		// the base phase 1 decided on, another writer cut in between: abandon, counters untouched.
		l, has, e := snap.LatestCheckpoint(projectID)
		if e != nil {
			return fmt.Errorf("checkpoint: read project snapshot: %w", e)
		}
		if !has || l.Seq != due.seq || l.CheckpointHash != due.hash {
			s.mCutShadowRaced.Inc()
			return errShadowRaced
		}
		// created_ts is taken AFTER the snapshot's first read, so it is not earlier than any commit in S.
		created := ts(s.now())
		body, ok, e := s.cutBodyIncremental(snap, projectID, created)
		if e != nil {
			return e // the incremental cut's own refusal at S: no shadow is counted, as before
		}
		if !ok {
			return errors.New("checkpoint refused: the incremental cut no longer applies on the shadow snapshot")
		}
		cnt, e := snap.RecordCount(projectID)
		if e != nil {
			return fmt.Errorf("checkpoint: read project snapshot: %w", e)
		}
		maxSeq, e := snap.MaxBrokerSeq(projectID)
		if e != nil {
			return fmt.Errorf("checkpoint: read project snapshot: %w", e)
		}
		signed, unchecked, e := s.compareShadow(snap, projectID, created, body)
		if e != nil {
			return e
		}
		res = shadowResult{bodyJSON: signed, baseSeq: due.seq, baseHash: due.hash, count: int64(cnt), maxSeq: maxSeq, unchecked: unchecked}
		return nil
	})
	if err != nil {
		return shadowResult{unchecked: res.unchecked}, err
	}
	return res, nil
}

// compareShadow runs the full computation for the snapshot store st under the shadow budget and compares it with
// the incremental body. It returns the JSON to sign, or a refusal on a mismatch. unchecked is true only on the
// could-not-run path (the incremental body is returned without its check). The classification, counters, latch and
// ALERT texts are unchanged from the in-lock shadow.
func (s *Server) compareShadow(st store.Store, projectID, created string, body map[string]any) (signed []byte, unchecked bool, err error) {
	s.shadowAttempted(projectID)
	s.mCutShadowChecks.Inc()
	began := time.Now()
	var full map[string]any
	ferr := st.WithBudget(s.shadowBudget(), func(b store.Store) error {
		var e error
		full, e = s.cutBodyFull(b, projectID, created)
		return e
	})
	s.cut.lastShadowNanos.Store(int64(time.Since(began)))
	var refusal *cutRefusedError
	if errors.As(ferr, &refusal) { // the definition itself refuses where the incremental cut would sign: a disagreement
		s.cut.latched.Store(true)
		s.mCutShadowMismatch.Inc()
		log.Printf("ALERT: checkpoint cut for project %s REFUSED: the full computation refuses (%v) where the incremental cut would sign; every later cut is now shadow-checked", projectID, ferr)
		return nil, false, fmt.Errorf("checkpoint refused: the incremental cut disagrees with the full computation: %w", ferr)
	}
	// A full body that WAS computed is always compared, even when it came back late (ErrBudgetExceeded with a
	// body): a late answer is still an answer, and the incremental body is never signed unseen when one exists.
	late := ferr != nil && full != nil && errors.Is(ferr, store.ErrBudgetExceeded)
	if ferr != nil && !late {
		// The shadow produced no body (a read error, a statement timeout, its own budget). It is a check, not part
		// of the definition: sign the incremental body, which passed its own count and contiguity guards, and make
		// the failure loud. Refusing on "could not check" would stop checkpoints for good once history outgrows the
		// full computation.
		s.mCutShadowFailed.Inc()
		wait := s.shadowFailed(projectID)
		log.Printf("ALERT: checkpoint cut for project %s signed WITHOUT its shadow check: the full computation could not run (%v); next shadow attempt in %s", projectID, ferr, wait)
		out, _ := json.Marshal(body)
		return out, true, nil
	}
	a, _ := json.Marshal(body)
	b, _ := json.Marshal(full)
	if !bytes.Equal(a, b) {
		s.cut.latched.Store(true) // every later cut is shadow-checked until restart
		s.mCutShadowMismatch.Inc()
		log.Printf("ALERT: checkpoint cut for project %s REFUSED: the incremental cut differs from the full computation in %s; every later cut is now shadow-checked", projectID, differingFields(body, full))
		return nil, false, fmt.Errorf("checkpoint refused: the incremental cut disagrees with the full computation")
	}
	if late {
		// The bodies agree, but the full computation no longer fits its budget: count it and back off.
		s.mCutShadowFailed.Inc()
		wait := s.shadowFailed(projectID)
		log.Printf("ALERT: checkpoint cut for project %s shadow ran LATE (%v) and matched; next shadow attempt in %s", projectID, ferr, wait)
	} else {
		s.shadowRan(projectID)
	}
	s.cut.verified.Store(projectID, struct{}{})
	return b, false, nil
}

// cutGate is the per-project cut gate: a one-slot, context-cancellable, reference-counted semaphore. It is held
// across all phases of every cut of the project in this process (liveness, not safety): two cuts of one project
// never run two O(history) shadows at once and a same-process cut cannot move the base during a shadow. Writers
// never take it, and the lock order is always gate, then project write guard.
type cutGate struct {
	slot chan struct{}
	refs int
}

// acquireCutGate waits for the project's cut gate (or ctx) and returns its release.
func (s *Server) acquireCutGate(ctx context.Context, projectID string) (func(), error) {
	s.cut.mu.Lock()
	if s.cut.gates == nil {
		s.cut.gates = map[string]*cutGate{}
	}
	g := s.cut.gates[projectID]
	if g == nil {
		g = &cutGate{slot: make(chan struct{}, 1)}
		s.cut.gates[projectID] = g
	}
	g.refs++
	s.cut.mu.Unlock()
	drop := func() {
		s.cut.mu.Lock()
		g.refs--
		if g.refs == 0 {
			delete(s.cut.gates, projectID)
		}
		s.cut.mu.Unlock()
	}
	select {
	case g.slot <- struct{}{}:
		return func() { <-g.slot; drop() }, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}

func (s *Server) cutGateCount() int {
	s.cut.mu.Lock()
	defer s.cut.mu.Unlock()
	return len(s.cut.gates)
}

// cutSignTimeout is the bound of phase 3 of a shadowed cut.
func (s *Server) cutSignTimeout() time.Duration {
	if s.cut.signTimeout <= 0 {
		return checkpointSignTimeout
	}
	return s.cut.signTimeout
}

// logCutNotSigned logs that a cut failed after its shadow check and before it was signed (at the read snapshot's
// commit in phase 2, or at the signing step in phase 3). Phase 3 runs detached from the
// caller, so the HTTP error often reaches nobody. The line starts with WARNING, not ALERT: an ALERT line counts a
// shadow attempt and this is not one. unchecked says the earlier "signed WITHOUT its shadow check" ALERT was for
// this cut; its counter and backoff are recorded before signing and are not undone.
func (s *Server) logCutNotSigned(projectID string, unchecked bool, err error) {
	note := ""
	if unchecked {
		note = " (the earlier ALERT said this cut was signed WITHOUT its shadow check)"
	}
	log.Printf("WARNING: checkpoint cut for project %s failed after its shadow check, before it was signed%s; nothing was signed unless the error reports an unknown commit outcome: %v", projectID, note, err)
}

func (s *Server) shadowBudget() time.Duration {
	if s.cut.budget <= 0 {
		return DefaultCheckpointShadowBudget
	}
	return s.cut.budget
}

// cutRefusedError marks a refusal by the full computation itself (a broker_seq gap), as opposed to a read that
// failed: the first is a verdict, the second means the check could not run.
type cutRefusedError struct{ err error }

func (e *cutRefusedError) Error() string { return "checkpoint refused: " + e.err.Error() }
func (e *cutRefusedError) Unwrap() error { return e.err }

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
