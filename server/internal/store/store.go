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

	// PutDisclosure records the secret that opens one committed field, keyed by (record_id, field).
	// Idempotent: re-recording the same (record_id, field) is a no-op (the commitment is immutable).
	PutDisclosure(projectID string, d DisclosureSecret) error
	// Disclosures returns every disclosure secret for the project (for selective_disclosure export).
	Disclosures(projectID string) ([]DisclosureSecret, error)
}

// Mem is an in-memory Store for tests and single-node dev.
type Mem struct {
	mu       sync.Mutex
	projects map[string]*project
}

type project struct {
	records    []Record
	idem       map[string]int // idempotency key -> record index
	byHash     map[string]struct{}
	checks     []Checkpoint
	seqBySess  map[string]int64
	disclosure []DisclosureSecret
	discSeen   map[string]struct{} // record_id\x00field -> present (dedupe)
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
	// collapse exact duplicate content (same bytes == same content_hash) — threat #8
	if _, dup := p.byHash[rec.ContentHash]; dup {
		for _, r := range p.records {
			if r.ContentHash == rec.ContentHash {
				if idemKey != "" {
					p.idem[idemKey] = indexOf(p.records, rec.ContentHash)
				}
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
	return rec, true, nil
}

func indexOf(recs []Record, hash string) int {
	for i, r := range recs {
		if r.ContentHash == hash {
			return i
		}
	}
	return -1
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

func (m *Mem) LatestCheckpointHash(projectID string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if len(p.checks) == 0 {
		return "", false, nil
	}
	return p.checks[len(p.checks)-1].CheckpointHash, true, nil
}

func (m *Mem) PutDisclosure(projectID string, d DisclosureSecret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	key := d.RecordID + "\x00" + d.Field
	if _, ok := p.discSeen[key]; ok {
		return nil // idempotent: the commitment for (record_id, field) is immutable
	}
	p.discSeen[key] = struct{}{}
	p.disclosure = append(p.disclosure, d)
	return nil
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
