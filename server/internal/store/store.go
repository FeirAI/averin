// Package store is the append-only metadata store for sealed records and checkpoints. The Postgres
// implementation revokes UPDATE/DELETE (integrity comes from the DAG+anchor, this is defense in
// depth); the in-memory implementation is for tests. Frontier/heads are derived, never trusted from
// the client.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
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

// ErrCommitAmbiguous wraps the ONE PutRecord error whose outcome is genuinely unknown — a tx.Commit() that
// failed AFTER a fresh record insert, so the record may or may not have become durable. Every other store
// failure (begin, select, insert, disclosure-insert, a read-only/collapse commit) persists NO new record, so
// a caller that consumed an irreversible resource (a use credential) may safely roll back on those but MUST
// NOT roll back on this one (releasing a durable-but-invisible receipt's credential would allow a double-spend).
var ErrCommitAmbiguous = errors.New("store: commit outcome unknown (a record insert may or may not have persisted)")

// ErrRecordIDConflict is returned by PutRecord when a DIFFERENT record (different content_hash, different or no
// idempotency key) already holds the new record's record_id in the project. record_id is unique per project: the
// offline verifier rejects a bundle carrying a duplicate record_id, and disclosure secrets are keyed
// (record_id, field), so a second record under an existing id would poison verification forever and lose its
// opening secret. Nothing is persisted on this error (it is NOT commit-ambiguous). An exact idempotent replay
// (same idempotency key, or byte-identical content) still collapses onto the stored row as before.
var ErrRecordIDConflict = errors.New("store: record_id already used by a different record in this project")

// ErrBrokerSeqVoided is returned by AllocateBrokerSeq for a grant_id whose reserved broker_seq an operator VOIDED
// (VoidBrokerSeq). The voided seq is filled by a signed grant_void tombstone, so that grant_id can never be issued
// again — neither at its old seq (a duplicate) nor at a new one (the tombstone binds the grant_id). A retry must use
// a new idempotency key (a new grant_id).
var ErrBrokerSeqVoided = errors.New("store: this grant's broker_seq was voided by the operator (grant_void tombstone); re-issue under a new idempotency key")

// BrokerSeqReservation is one row of the broker_seq allocation ledger: the grant_id holding seq, when it was
// allocated (the store's clock), and whether an operator has voided it.
type BrokerSeqReservation struct {
	GrantID     string
	Seq         int64
	AllocatedAt time.Time
	Voided      bool
}

// recordIDOf extracts the record_id carried in a sealed record's JSON ("" if absent/unparseable — such a record
// does not participate in the uniqueness check, matching the Postgres expression index, where NULL never conflicts).
func recordIDOf(recordJSON string) string {
	var p struct {
		RecordID string `json:"record_id"`
	}
	_ = json.Unmarshal([]byte(recordJSON), &p)
	return p.RecordID
}

// Store is append-only: records and checkpoints are never mutated or removed.
type Store interface {
	// PutRecord stores a record under an idempotency key. If the key was already used, it returns
	// the previously stored record and created=false (threat #8: retry duplication collapses). A NEW record
	// whose record_id is already held by a different record in the project fails with ErrRecordIDConflict.
	PutRecord(projectID, idemKey string, rec Record) (stored Record, created bool, err error)
	// RecordByIdem returns the record previously stored under an idempotency key, if any. The broker
	// uses it to detect an idempotent (or pre-D6 legacy) grant retry BEFORE allocating a broker_seq, so
	// a replay can never burn a seq it then fails to record and manufacture a false transparency gap (D6).
	RecordByIdem(projectID, idemKey string) (rec Record, found bool, err error)
	// HasRecordID reports whether a record carrying recordID is already stored in the project. The api's batch
	// pre-pass uses it to reject a record_id collision BEFORE any batch item is sealed (all-or-nothing); the
	// authoritative check is PutRecord's ErrRecordIDConflict.
	HasRecordID(projectID, recordID string) (bool, error)
	// Heads returns the current head content_hashes for a session (records not referenced as a
	// causal parent within that session), byte-sorted.
	Heads(projectID, sessionID string) ([]string, error)
	// ProjectHeads returns the heads across all sessions (the checkpoint frontier).
	ProjectHeads(projectID string) ([]string, error)
	NextDisplaySeq(projectID, sessionID string) (int64, error)
	Sessions(projectID string) ([]string, error)
	SessionRecords(projectID, sessionID string) ([]Record, error)
	AllRecords(projectID string) ([]Record, error)
	// RecordsPage returns up to `limit` records NEWEST-FIRST, skipping the newest `offset`, WITHOUT loading
	// the whole project history into memory (Postgres pages in SQL). It backs the paged app list endpoint so
	// a large tenant is not fully materialized per list call. limit<=0 returns an empty page; offset<0 == 0.
	RecordsPage(projectID string, limit, offset int) ([]Record, error)
	// GrantRecords returns the project's credential-broker GRANT and grant_void tombstone records (a superset of the
	// transparency-log membership set — it filters on the necessary marker extensions.broker.kind in {"grant",
	// "grant_void"}; api.grantLog
	// re-applies the exact D6 rule). It exists so checkpoint creation folds the grant head from the grant
	// records alone instead of a full-history scan; it MUST never omit a real grant (that would be
	// suppression), so implementations filter LOOSELY (superset) and let grantLog tighten. Never nil.
	GrantRecords(projectID string) ([]Record, error)
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
	//
	// fresh reports whether THIS call created the allocation (true) or returned an existing reservation for the
	// grant_id (false). Only a fresh allocation may be released by the caller that made it: an existing one may
	// belong to a prior attempt whose commit was ambiguous and may still land (see api.settleFailedGrantSeq).
	AllocateBrokerSeq(projectID, grantID string) (seq int64, fresh bool, err error)
	// ReleaseBrokerSeq rolls back an allocation whose grant was NOT recorded (a failure after allocation
	// but before the record committed), so the durable max sequence only advances for grants that exist —
	// keeping the recorded log gapless. Safe to call when no allocation was made (no-op). MUST be called
	// under the same per-project serialization as the allocation (the api's ingest lock).
	//
	// ONLY THE CURRENT MAX IS RELEASED. If the grant's seq is no longer the project's max (an earlier release of
	// it was lost — e.g. a failed Postgres DELETE — and higher seqs have since been allocated), deleting it would
	// punch a hole in the MIDDLE of [1..N] that no allocation can ever refill (the next allocation for this
	// grant_id would get MAX+1), so no gapless checkpoint could be signed again. Such a non-max allocation is
	// instead KEPT (a no-op, nil error): the grant's idempotent retry reclaims that exact seq and fills the hole.
	// (Found by TLA+ model checking, formal/tla/GrantLog.tla.)
	//
	// ROLLBACK is BEST-EFFORT, not atomic with the allocation: the Mem store never errors here (so the Mem
	// path is fully gapless), but a Postgres DELETE can fail. The api SURFACES that failure (it does not
	// swallow it). A surfaced orphan SELF-HEALS — the deterministic grant_id makes AllocateBrokerSeq
	// idempotent, so a retry of the same grant reuses the orphaned seq and records it. A PERMANENT gap
	// therefore needs the narrow triple of {failure after allocation, failed rollback, client never
	// retries}, which surfaces as a transparency anomaly the operator investigates — and the api's checkpoint
	// creation refuses to sign while any allocated seq (MaxBrokerSeq) lacks a recorded grant, so such a gap is
	// never ANCHORED (checkpoints are append-only; an anchored gap would fail verification forever). The full production
	// hardening is to make allocation and record insertion ONE transaction (held across the cgo signing),
	// which also subsumes the multi-instance ordering lock — out of scope for the single-instance demo.
	ReleaseBrokerSeq(projectID, grantID string) error
	// MaxBrokerSeq returns the highest broker_seq currently ALLOCATED for the project (0 if none). Checkpoint
	// creation compares it against the recorded grant set under the ingest lock and refuses to sign when an
	// allocated seq has no recorded grant (a reserved/orphaned seq), so a gap can never be anchored.
	MaxBrokerSeq(projectID string) (int64, error)
	// BrokerSeqAt returns the allocation-ledger row holding seq in the project (found=false if none). The operator
	// void endpoint uses it to name the reserved grant_id and check the reservation's age.
	BrokerSeqAt(projectID string, seq int64) (res BrokerSeqReservation, found bool, err error)
	// VoidBrokerSeq marks the reservation (grantID, seq) VOIDED. The allocation row is KEPT, so MaxBrokerSeq still
	// counts it and MAX+1 never re-issues the voided number; ReleaseBrokerSeq never deletes it; and
	// AllocateBrokerSeq(grantID) fails with ErrBrokerSeqVoided from now on (the grant_id is retired, never handed
	// the voided seq back). Idempotent for the same (grantID, seq); an error if seq is not reserved by grantID. The
	// caller (the api, under ingestMu) seals the grant_void tombstone that fills the seq in the recorded log.
	VoidBrokerSeq(projectID, grantID string, seq int64) error

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
	records    []Record
	idem       map[string]int // idempotency key -> record index
	byHash     map[string]struct{}
	byRecordID map[string]struct{} // record_id -> present (per-project uniqueness)
	checks     []Checkpoint
	seqBySess  map[string]int64
	disclosure []DisclosureSecret
	discSeen   map[string]struct{}  // record_id\x00field -> present (dedupe)
	anchors    map[int64]string     // checkpoint seq -> token_b64
	brokerSeq  map[string]int64     // grant_id -> broker_seq (idempotent allocation, D6); next = max(values)+1
	brokerAt   map[string]time.Time // grant_id -> allocation time (the operator void's safety age)
	voided     map[string]struct{}  // grant_id -> voided (row kept in brokerSeq; never released or re-allocated)
}

func NewMem() *Mem { return &Mem{projects: map[string]*project{}} }

func (m *Mem) proj(id string) *project {
	p := m.projects[id]
	if p == nil {
		p = &project{
			idem:       map[string]int{},
			byHash:     map[string]struct{}{},
			byRecordID: map[string]struct{}{},
			seqBySess:  map[string]int64{},
			discSeen:   map[string]struct{}{},
			anchors:    map[int64]string{},
			brokerSeq:  map[string]int64{},
			brokerAt:   map[string]time.Time{},
			voided:     map[string]struct{}{},
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
	// record_id is unique per project (checked AFTER the idem/content collapses above, so an exact replay still
	// returns the stored row). A different record under an already-held record_id persists nothing.
	rid := recordIDOf(rec.JSON)
	if rid != "" {
		if _, taken := p.byRecordID[rid]; taken {
			return Record{}, false, fmt.Errorf("%w: %q", ErrRecordIDConflict, rid)
		}
	}
	p.records = append(p.records, rec)
	idx := len(p.records) - 1
	p.byHash[rec.ContentHash] = struct{}{}
	if rid != "" {
		p.byRecordID[rid] = struct{}{}
	}
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

func (m *Mem) HasRecordID(projectID, recordID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.proj(projectID).byRecordID[recordID]
	return ok, nil
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

// RecordsPage returns up to `limit` records newest-first, skipping the newest `offset`. The Mem store holds
// records oldest-first in insertion order, so we walk from the end. (Postgres does the same via SQL
// ORDER BY ... DESC LIMIT/OFFSET — this is the dev/test parity path, not the memory-bounded one.)
func (m *Mem) RecordsPage(projectID string, limit, offset int) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 {
		return []Record{}, nil
	}
	if offset < 0 {
		offset = 0
	}
	recs := m.proj(projectID).records
	total := len(recs)
	// newest-first index i (0 = newest) maps to recs[total-1-i].
	start := offset
	if start > total {
		start = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	out := make([]Record, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, recs[total-1-i])
	}
	return out, nil
}

// GrantRecords returns the project's grant-tuple and grant_void records (a superset for api.grantLog). Mem filters on
// the necessary marker extensions.broker.kind in {"grant", "grant_void"} so it matches the Postgres implementation's superset; a
// non-grant is dropped and grantLog re-verifies enforcement_point+broker_seq. Parse failures are conservatively
// INCLUDED (never silently dropped) so a malformed grant can never be suppressed from the transparency log.
func (m *Mem) GrantRecords(projectID string) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Record{}
	for _, r := range m.proj(projectID).records {
		var parsed struct {
			Extensions struct {
				Broker struct {
					Kind string `json:"kind"`
				} `json:"broker"`
			} `json:"extensions"`
		}
		if err := json.Unmarshal([]byte(r.JSON), &parsed); err != nil || parsed.Extensions.Broker.Kind == "grant" || parsed.Extensions.Broker.Kind == "grant_void" {
			out = append(out, r)
		}
	}
	return out, nil
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

func (m *Mem) AllocateBrokerSeq(projectID, grantID string) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if _, v := p.voided[grantID]; v {
		return 0, false, ErrBrokerSeqVoided // never hand a voided seq back (it is filled by a tombstone)
	}
	if seq, ok := p.brokerSeq[grantID]; ok {
		return seq, false, nil // idempotent: a retry of the same grant_id gets its original seq (no gap)
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
	p.brokerAt[grantID] = time.Now()
	return max + 1, true, nil
}

func (m *Mem) ReleaseBrokerSeq(projectID, grantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	bs := p.brokerSeq
	seq, ok := bs[grantID]
	if !ok {
		return nil
	}
	if _, v := p.voided[grantID]; v {
		return nil // a voided seq is filled by its tombstone: never released (MAX+1 would re-issue it)
	}
	for _, s := range bs {
		if s > seq {
			return nil // not the current max: keep the reservation (see ReleaseBrokerSeq) so a retry refills it
		}
	}
	delete(bs, grantID)
	delete(p.brokerAt, grantID)
	return nil
}

func (m *Mem) BrokerSeqAt(projectID string, seq int64) (BrokerSeqReservation, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	for gid, s := range p.brokerSeq {
		if s == seq {
			_, v := p.voided[gid]
			return BrokerSeqReservation{GrantID: gid, Seq: s, AllocatedAt: p.brokerAt[gid], Voided: v}, true, nil
		}
	}
	return BrokerSeqReservation{}, false, nil
}

func (m *Mem) VoidBrokerSeq(projectID, grantID string, seq int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(projectID)
	if s, ok := p.brokerSeq[grantID]; !ok || s != seq {
		return fmt.Errorf("store: broker_seq %d is not reserved by grant %s", seq, grantID)
	}
	p.voided[grantID] = struct{}{}
	return nil
}

func (m *Mem) MaxBrokerSeq(projectID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var max int64
	for _, s := range m.proj(projectID).brokerSeq {
		if s > max {
			max = s
		}
	}
	return max, nil
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
