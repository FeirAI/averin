// Package store is the append-only metadata store for sealed records and checkpoints. The Postgres
// implementation revokes UPDATE/DELETE (integrity comes from the DAG+anchor, this is defense in
// depth); the in-memory implementation is for tests. Frontier/heads are derived, never trusted from
// the client.
package store

import (
	"errors"
	"sort"
	"sync"
)

// Record is a sealed Decision Record plus the few fields the store indexes on.
type Record struct {
	JSON        string // full sealed record JSON (canonical bytes from the Rust core)
	ContentHash string // sha256:...
	SessionID   string
	Parents     []string // causal_prev_hashes
	// Disclosures are the secrets that open this record's committed low-entropy fields. They are
	// persisted ATOMICALLY with the record (and only when the record is freshly created), so a
	// committed field can never end up in a sealed record with no way to disclose it. Empty for
	// records without committed fields. Ignored on an idempotent/collapsed PutRecord.
	Disclosures []DisclosureSecret
}

// Checkpoint is a sealed (and possibly anchored) checkpoint.
type Checkpoint struct {
	JSON           string
	CheckpointHash string
	Seq            int64
}

// DisclosureSecret is what a `selective_disclosure` export needs to reveal one committed low-entropy
// field: the content-store digest of the raw value plus the nonce that opens its hiding commitment.
// It is bound to (record_id, field); the record body carries only the commitment.
type DisclosureSecret struct {
	RecordID    string
	Field       string // input | output | rationale
	ValueDigest string // content-store digest (sha256:...) of the raw value bytes
	NonceHex    string // 64 lowercase hex chars
}

var ErrNotFound = errors.New("not found")

// Store is append-only: records and checkpoints are never mutated or removed.
type Store interface {
	// PutRecord stores a record under an idempotency key. If the key was already used, it returns
	// the previously stored record and created=false (threat #8: retry duplication collapses).
	PutRecord(projectID, idemKey string, rec Record) (stored Record, created bool, err error)
	// RecordByIdem returns the record previously stored under an idempotency key, if any. The broker
	// uses it to detect an idempotent (or pre-D6 legacy) grant retry BEFORE allocating a broker_seq, so
	// a replay can never burn a seq it then fails to record and manufacture a false transparency gap (D6).
	RecordByIdem(projectID, idemKey string) (rec Record, found bool, err error)
	// Heads returns the current head content_hashes for a session (records not referenced as a
	// causal parent within that session), byte-sorted.
	Heads(projectID, sessionID string) ([]string, error)
	// ProjectHeads returns the heads across all sessions (the checkpoint frontier).
	ProjectHeads(projectID string) ([]string, error)
	NextDisplaySeq(projectID, sessionID string) (int64, error)
	Sessions(projectID string) ([]string, error)
	SessionRecords(projectID, sessionID string) ([]Record, error)
	AllRecords(projectID string) ([]Record, error)
	RecordCount(projectID string) (int, error)

	PutCheckpoint(projectID string, cp Checkpoint) error
	Checkpoints(projectID string) ([]Checkpoint, error)
	NextCheckpointSeq(projectID string) (int64, error)
	LatestCheckpointHash(projectID string) (string, bool, error)

	// AllocateBrokerSeq returns the grant-transparency sequence number for a grant (ADR 0004 D6 / MF2):
	// strictly increasing and gapless per project [1..N], IDEMPOTENT on grantID (a retry of the same
	// deterministic grant_id returns the same seq, so an idempotent re-issue does not create a gap). The
	// seq is bound into the SIGNED grant_evidence, so it is allocated just before the grant is sealed —
	// and ONLY after the request has fully validated (the broker calls it from inside Prepare, post-
	// validation), so a rejected grant never burns a seq. The only way to leave a gap is for a VALID
	// grant to be allocated a seq and then never persisted (a crash between mint and PutRecord); a retry
	// of the same deterministic grant_id reclaims that exact seq, so a permanent gap requires a fully
	// abandoned valid grant — which the verifier surfaces as a transparency anomaly (fail-toward-detection).
	//
	// DEPLOYMENT CONSTRAINT: the gapless RECORDED ORDER (a higher seq never anchored before a lower one)
	// holds because the api serializes allocate→seal→insert under its single-process ingest mutex — the
	// same single-instance assumption the DAG-frontier read already relies on. A multi-instance deployment
	// sharing one store must additionally hold a DISTRIBUTED per-project lock across allocate→seal→insert
	// (extend the Postgres advisory lock here to span the record insert), or two instances could record
	// seq N+1 before seq N and a checkpoint could anchor a transient false gap.
	AllocateBrokerSeq(projectID, grantID string) (int64, error)
	// ReleaseBrokerSeq rolls back an allocation whose grant was NOT recorded (a failure after allocation
	// but before the record committed), so the durable max sequence only advances for grants that exist —
	// keeping the recorded log gapless. Safe to call when no allocation was made (no-op). MUST be called
	// under the same per-project serialization as the allocation (the api's ingest lock), so the released
	// seq is the current max and is cleanly reusable by the next allocation.
	//
	// ROLLBACK is BEST-EFFORT, not atomic with the allocation: the Mem store never errors here (so the Mem
	// path is fully gapless), but a Postgres DELETE can fail. The api SURFACES that failure (it does not
	// swallow it). A surfaced orphan SELF-HEALS — the deterministic grant_id makes AllocateBrokerSeq
	// idempotent, so a retry of the same grant reuses the orphaned seq and records it. A PERMANENT gap
	// therefore needs the narrow triple of {failure after allocation, failed rollback, client never
	// retries}, which surfaces as a transparency anomaly the operator investigates. The full production
	// hardening is to make allocation and record insertion ONE transaction (held across the cgo signing),
	// which also subsumes the multi-instance ordering lock — out of scope for the single-instance demo.
	ReleaseBrokerSeq(projectID, grantID string) error

	// Disclosures returns every disclosure secret for the project (for selective_disclosure export),
	// in canonical (record_id, field) order. Disclosure secrets are written atomically with their
	// record via PutRecord (Record.Disclosures); there is no separate write path.
	Disclosures(projectID string) ([]DisclosureSecret, error)

	// PutAnchor records the RFC 3161 timestamp token (base64url) for a checkpoint seq, decoupled from
	// the checkpoint row so the TSA call happens out of the checkpoint critical section and a failed
	// anchor can be backfilled. Insert-only/idempotent per (project, seq).
	PutAnchor(projectID string, seq int64, tokenB64 string) error
	// Anchors returns seq -> token_b64 for the project, so the export can join each checkpoint with
	// its anchor. Never nil.
	Anchors(projectID string) (map[int64]string, error)
}

// Mem is an in-memory Store for tests and single-node dev.
type Mem struct {
	mu       sync.Mutex
	projects map[string]*project
}

type project struct {
	records      []Record
	idem         map[string]int // idempotency key -> record index
	byHash       map[string]struct{}
	checks       []Checkpoint
	seqBySess    map[string]int64
	disclosure   []DisclosureSecret
	discSeen     map[string]struct{} // record_id\x00field -> present (dedupe)
	anchors    map[int64]string // checkpoint seq -> token_b64
	brokerSeq  map[string]int64 // grant_id -> broker_seq (idempotent allocation, D6); next = max(values)+1
}

func NewMem() *Mem { return &Mem{projects: map[string]*project{}} }

func (m *Mem) proj(id string) *project {
	p := m.projects[id]
	if p == nil {
		p = &project{
			idem:      map[string]int{},
			byHash:    map[string]struct{}{},
			seqBySess: map[string]int64{},
			discSeen:  map[string]struct{}{},
			anchors:   map[int64]string{},
			brokerSeq: map[string]int64{},
		}
		m.projects[id] = p
	}
	return p
}

func (m *Mem) PutRecord(projectID, idemKey string, rec Record) (Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if idemKey != "" {
		if i, ok := p.idem[idemKey]; ok {
			return p.records[i], false, nil
		}
	}
	// collapse exact duplicate content (same bytes == same content_hash) — threat #8. Match Postgres
	// (append-only): do NOT bind idemKey onto the collapsed row. content-dedup and idem-retry are distinct
	// concerns — a later retry of the SAME key collapses on content_hash again to the same row, so the
	// binding buys nothing, and Postgres physically cannot do it (records REVOKEs UPDATE and a content_hash
	// unique index forbids a second row). A NEW key under identical content therefore stays unbound on BOTH
	// stores — RecordByIdem(newKey) is found=false — so the broker's idempotent-grant probe and the use/
	// use-outcome retry guards see one consistent answer regardless of backend.
	if _, dup := p.byHash[rec.ContentHash]; dup {
		for _, r := range p.records {
			if r.ContentHash == rec.ContentHash {
				return r, false, nil
			}
		}
	}
	p.records = append(p.records, rec)
	idx := len(p.records) - 1
	p.byHash[rec.ContentHash] = struct{}{}
	if idemKey != "" {
		p.idem[idemKey] = idx
	}
	// Persist this record's disclosure secrets atomically with it (same lock). Dedup on
	// (record_id, field) so a malformed slice can't double-record.
	for _, d := range rec.Disclosures {
		key := d.RecordID + "\x00" + d.Field
		if _, ok := p.discSeen[key]; ok {
			continue
		}
		p.discSeen[key] = struct{}{}
		p.disclosure = append(p.disclosure, d)
	}
	return rec, true, nil
}

func (m *Mem) RecordByIdem(projectID, idemKey string) (Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if i, ok := p.idem[idemKey]; ok {
		return p.records[i], true, nil
	}
	return Record{}, false, nil
}

func headsOf(recs []Record) []string {
	referenced := map[string]struct{}{}
	for _, r := range recs {
		for _, p := range r.Parents {
			referenced[p] = struct{}{}
		}
	}
	var heads []string
	for _, r := range recs {
		if _, ref := referenced[r.ContentHash]; !ref {
			heads = append(heads, r.ContentHash)
		}
	}
	return sortedUnique(heads)
}

func (m *Mem) Heads(projectID, sessionID string) ([]string, error) {
	recs, _ := m.SessionRecords(projectID, sessionID)
	return headsOf(recs), nil
}

func (m *Mem) ProjectHeads(projectID string) ([]string, error) {
	recs, _ := m.AllRecords(projectID)
	return headsOf(recs), nil
}

func (m *Mem) NextDisplaySeq(projectID, sessionID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	n := p.seqBySess[sessionID]
	p.seqBySess[sessionID] = n + 1
	return n, nil
}

func (m *Mem) Sessions(projectID string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]struct{}{}
	var out []string
	for _, r := range m.proj(projectID).records {
		if _, ok := seen[r.SessionID]; !ok {
			seen[r.SessionID] = struct{}{}
			out = append(out, r.SessionID)
		}
	}
	return out, nil
}

func (m *Mem) SessionRecords(projectID, sessionID string) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Record
	for _, r := range m.proj(projectID).records {
		if r.SessionID == sessionID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *Mem) AllRecords(projectID string) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Record(nil), m.proj(projectID).records...), nil
}

func (m *Mem) RecordCount(projectID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.proj(projectID).byHash), nil
}

func (m *Mem) PutCheckpoint(projectID string, cp Checkpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	p.checks = append(p.checks, cp)
	return nil
}

func (m *Mem) Checkpoints(projectID string) ([]Checkpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Checkpoint(nil), m.proj(projectID).checks...), nil
}

func (m *Mem) NextCheckpointSeq(projectID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.proj(projectID).checks)), nil
}

func (m *Mem) AllocateBrokerSeq(projectID, grantID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if seq, ok := p.brokerSeq[grantID]; ok {
		return seq, nil // idempotent: a retry of the same grant_id gets its original seq (no gap)
	}
	// Derive next from the CURRENT max in the map (not a monotonic counter) so a ReleaseBrokerSeq of the
	// highest seq is reusable — keeping the recorded sequence gapless even when a grant fails after
	// allocation. Mirrors Postgres `MAX(seq)+1`.
	var max int64
	for _, s := range p.brokerSeq {
		if s > max {
			max = s
		}
	}
	p.brokerSeq[grantID] = max + 1
	return max + 1, nil
}

func (m *Mem) ReleaseBrokerSeq(projectID, grantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.proj(projectID).brokerSeq, grantID)
	return nil
}

func (m *Mem) LatestCheckpointHash(projectID string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if len(p.checks) == 0 {
		return "", false, nil
	}
	return p.checks[len(p.checks)-1].CheckpointHash, true, nil
}

func (m *Mem) PutAnchor(projectID string, seq int64, tokenB64 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.proj(projectID).anchors
	if _, ok := a[seq]; ok {
		return nil // idempotent: the anchor for a seq is immutable once set
	}
	a[seq] = tokenB64
	return nil
}

func (m *Mem) Anchors(projectID string) (map[int64]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.proj(projectID).anchors
	out := make(map[int64]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out, nil
}

func (m *Mem) Disclosures(projectID string) ([]DisclosureSecret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Non-nil empty (not nil) to match Postgres and so the export layer marshals [] not null.
	out := append([]DisclosureSecret{}, m.proj(projectID).disclosure...)
	// Canonical (record_id, field) order — identical to the Postgres query, so a Mem-backed and a
	// Postgres-backed export of the same data serialize to the same bytes.
	sort.Slice(out, func(i, j int) bool {
		if out[i].RecordID != out[j].RecordID {
			return out[i].RecordID < out[j].RecordID
		}
		return out[i].Field < out[j].Field
	})
	return out, nil
}

func sortedUnique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	// insertion sort (small frontiers); byte order == default string order
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
