package store

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrRecoveryConflict = errors.New("store: recovery operation conflicts with an immutable fence or result")
var ErrRecoveryFenced = errors.New("store: grant reservation is permanently fenced for recovery")

func recoveryTombstoneInsert(raw, idem string, fence RecoveryFence) bool {
	if idem != fmt.Sprintf("grant-void:%d", fence.Seq) || !validRecoveryWinner(raw, fence, "voided") {
		return false
	}
	var r struct {
		Extensions struct {
			Broker struct {
				VoidEvidence map[string]json.RawMessage `json:"void_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(raw), &r) != nil {
		return false
	}
	_, actor := r.Extensions.Broker.VoidEvidence["actor_id"]
	_, op := r.Extensions.Broker.VoidEvidence["operation_id"]
	return actor && op // old unattributed tombstones may be repaired, never newly inserted after a fence.
}

func validRecoveryWinner(raw string, f RecoveryFence, outcome string) bool {
	var r struct {
		ProjectID string `json:"project_id"`
		RecordID  string `json:"record_id"`
		SessionID string `json:"session_id"`
		EventType string `json:"event_type"`
		Authority struct {
			Source           string `json:"source"`
			EnforcementPoint string `json:"enforcement_point"`
			GrantID          string `json:"grant_id"`
		} `json:"authority"`
		Extensions struct {
			Broker struct {
				Kind          string `json:"kind"`
				GrantEvidence struct {
					BrokerSeq int64 `json:"broker_seq"`
				} `json:"grant_evidence"`
				VoidEvidence map[string]json.RawMessage `json:"void_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(raw), &r) != nil || r.ProjectID != f.ProjectID || r.RecordID != f.GrantID ||
		r.Authority.Source != "gateway_enforced" || r.Authority.EnforcementPoint != "credential_broker" ||
		r.Authority.GrantID != f.GrantID {
		return false
	}
	b := r.Extensions.Broker
	if outcome == "recorded" {
		return r.EventType == "credential_grant" && b.Kind == "grant" && b.GrantEvidence.BrokerSeq == f.Seq
	}
	if outcome != "voided" || r.EventType != "credential_grant_void" || b.Kind != "grant_void" {
		return false
	}
	var domain, project, grant, actor, op, reason string
	var seq int64
	ev := b.VoidEvidence
	if json.Unmarshal(ev["domain"], &domain) != nil || domain != "averin.broker.grant_void.v1" ||
		json.Unmarshal(ev["project_id"], &project) != nil || project != f.ProjectID ||
		json.Unmarshal(ev["grant_id"], &grant) != nil || grant != f.GrantID ||
		json.Unmarshal(ev["broker_seq"], &seq) != nil || seq != f.Seq {
		return false
	}
	_, hasActor := ev["actor_id"]
	_, hasOp := ev["operation_id"]
	if !hasActor && !hasOp {
		return true
	}
	return hasActor && hasOp && r.SessionID == f.SessionID &&
		json.Unmarshal(ev["actor_id"], &actor) == nil && actor != "" && actor == f.ActorID &&
		json.Unmarshal(ev["operation_id"], &op) == nil && op != "" && op == f.OperationID &&
		json.Unmarshal(ev["reason"], &reason) == nil && reason == f.Reason
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
	reserved, exists := p.brokerSeq[f.GrantID]
	if !exists || f.Seq < 1 || reserved != f.Seq || f.Generation != 1 {
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
	winning := false
	for _, rec := range p.records {
		if rec.ContentHash == r.WinningRecordHash && validRecoveryWinner(rec.JSON, f, r.Outcome) {
			winning = true
			break
		}
	}
	if !winning {
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
			r.Parents = append([]string(nil), r.Parents...)
			return r, true, nil
		}
	}
	return Record{}, false, nil
}
