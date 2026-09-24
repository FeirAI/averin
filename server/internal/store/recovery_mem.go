package store

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrRecoveryConflict = errors.New("store: recovery operation conflicts with an immutable fence or result")
var ErrRecoveryFenced = errors.New("store: grant reservation is permanently fenced for recovery")

func recoveryTombstoneInsert(raw, idem string, seq int64) bool {
	if idem != fmt.Sprintf("grant-void:%d", seq) {
		return false
	}
	var shape struct {
		Extensions struct {
			Broker struct {
				Kind string `json:"kind"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	return json.Unmarshal([]byte(raw), &shape) == nil && shape.Extensions.Broker.Kind == "grant_void"
}

func (m *Mem) PendingGrantByGrant(projectID, grantID string) (PendingGrant, bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return PendingGrant{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.proj(projectID).pending {
		if row.GrantID == grantID {
			row.Payload = append([]byte(nil), row.Payload...)
			return row, true, nil
		}
	}
	return PendingGrant{}, false, nil
}

func (m *Mem) RecoveryFenceAt(projectID string, seq int64) (RecoveryFence, bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return RecoveryFence{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.proj(projectID).fences[seq]
	return f, ok, nil
}

func (m *Mem) RecoveryFenceByGrant(projectID, grantID string) (RecoveryFence, bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return RecoveryFence{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.proj(projectID).fences {
		if f.GrantID == grantID {
			return f, true, nil
		}
	}
	return RecoveryFence{}, false, nil
}

func sameFence(a, b RecoveryFence) bool {
	return a.ProjectID == b.ProjectID && a.Seq == b.Seq && a.GrantID == b.GrantID &&
		a.Generation == b.Generation && a.OperationID == b.OperationID &&
		a.ActorID == b.ActorID && a.SessionID == b.SessionID && a.Reason == b.Reason &&
		a.RequestDigest == b.RequestDigest
}

func (m *Mem) PutRecoveryFence(f RecoveryFence) (RecoveryFence, bool, error) {
	if !m.inTx {
		return RecoveryFence{}, false, errors.New("store: recovery fence requires project transaction")
	}
	unlock, err := m.mutation(f.ProjectID)
	if err != nil {
		return RecoveryFence{}, false, err
	}
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(f.ProjectID)
	if old, ok := p.fences[f.Seq]; ok {
		if !sameFence(old, f) {
			return old, false, ErrRecoveryConflict
		}
		return old, false, nil
	}
	for _, old := range p.fences {
		if old.GrantID == f.GrantID || old.OperationID == f.OperationID {
			return old, false, ErrRecoveryConflict
		}
	}
	if p.brokerSeq[f.GrantID] != f.Seq || f.Generation != 1 {
		return RecoveryFence{}, false, ErrRecoveryConflict
	}
	f.FencedAt = m.now()
	p.fences[f.Seq] = f
	return f, true, nil
}

func (m *Mem) RecoveryResultAt(projectID string, seq int64) (RecoveryResult, bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return RecoveryResult{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.proj(projectID).results[seq]
	return r, ok, nil
}

func (m *Mem) PutRecoveryResult(r RecoveryResult) (RecoveryResult, bool, error) {
	if !m.inTx {
		return RecoveryResult{}, false, errors.New("store: recovery result requires project transaction")
	}
	unlock, err := m.mutation(r.ProjectID)
	if err != nil {
		return RecoveryResult{}, false, err
	}
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.proj(r.ProjectID)
	f, ok := p.fences[r.Seq]
	if !ok || f.Generation != r.Generation || (r.Outcome != "recorded" && r.Outcome != "voided") || r.WinningRecordHash == "" {
		return RecoveryResult{}, false, ErrRecoveryConflict
	}
	if old, ok := p.results[r.Seq]; ok {
		if old.Outcome != r.Outcome || old.WinningRecordHash != r.WinningRecordHash {
			return old, false, ErrRecoveryConflict
		}
		return old, false, nil
	}
	r.CompletedAt = m.now()
	p.results[r.Seq] = r
	return r, true, nil
}

func (m *Mem) RecordByRecordID(projectID, recordID string) (Record, bool, error) {
	if err := m.checkProject(projectID); err != nil {
		return Record{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.proj(projectID).records {
		if recordIDOf(r.JSON) == recordID {
			return r, true, nil
		}
	}
	return Record{}, false, nil
}
