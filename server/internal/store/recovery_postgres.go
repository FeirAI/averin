package store

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const fenceColumns = `project_id,seq,grant_id,generation,operation_id,actor_id,session_id,reason,request_digest,fenced_at`
const resultColumns = `project_id,seq,generation,outcome,winning_record_hash,completed_at`

func scanFence(row pgx.Row) (RecoveryFence, bool, error) {
	var f RecoveryFence
	err := row.Scan(&f.ProjectID, &f.Seq, &f.GrantID, &f.Generation, &f.OperationID, &f.ActorID, &f.SessionID, &f.Reason, &f.RequestDigest, &f.FencedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RecoveryFence{}, false, nil
	}
	return f, err == nil, err
}

func scanResult(row pgx.Row) (RecoveryResult, bool, error) {
	var r RecoveryResult
	err := row.Scan(&r.ProjectID, &r.Seq, &r.Generation, &r.Outcome, &r.WinningRecordHash, &r.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RecoveryResult{}, false, nil
	}
	return r, err == nil, err
}

func (p *Postgres) PendingGrantByGrant(projectID, grantID string) (PendingGrant, bool, error) {
	if err := p.checkProject(projectID); err != nil {
		return PendingGrant{}, false, err
	}
	var row PendingGrant
	err := p.queries().QueryRow(p.callContext(), `SELECT grant_id,payload,created_at FROM pending_grants WHERE project_id=$1 AND grant_id=$2 ORDER BY created_at DESC LIMIT 1`, projectID, grantID).Scan(&row.GrantID, &row.Payload, &row.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingGrant{}, false, nil
	}
	return row, err == nil, err
}

func (p *Postgres) RecoveryFenceAt(projectID string, seq int64) (RecoveryFence, bool, error) {
	if err := p.checkProject(projectID); err != nil {
		return RecoveryFence{}, false, err
	}
	return scanFence(p.queries().QueryRow(p.callContext(), `SELECT `+fenceColumns+` FROM broker_seq_recovery_fence WHERE project_id=$1 AND seq=$2`, projectID, seq))
}

func (p *Postgres) RecoveryFenceByGrant(projectID, grantID string) (RecoveryFence, bool, error) {
	if err := p.checkProject(projectID); err != nil {
		return RecoveryFence{}, false, err
	}
	return scanFence(p.queries().QueryRow(p.callContext(), `SELECT `+fenceColumns+` FROM broker_seq_recovery_fence WHERE project_id=$1 AND grant_id=$2`, projectID, grantID))
}

func (p *Postgres) PutRecoveryFence(f RecoveryFence) (RecoveryFence, bool, error) {
	if p.tx == nil {
		return RecoveryFence{}, false, errors.New("store: recovery fence requires project transaction")
	}
	if err := p.checkProject(f.ProjectID); err != nil {
		return RecoveryFence{}, false, err
	}
	row := p.tx.QueryRow(p.callContext(), `INSERT INTO broker_seq_recovery_fence (project_id,seq,grant_id,generation,operation_id,actor_id,session_id,reason,request_digest)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9 WHERE EXISTS (SELECT 1 FROM broker_seq WHERE project_id=$1 AND seq=$2 AND grant_id=$3)
		ON CONFLICT DO NOTHING RETURNING `+fenceColumns,
		f.ProjectID, f.Seq, f.GrantID, f.Generation, f.OperationID, f.ActorID, f.SessionID, f.Reason, f.RequestDigest)
	stored, created, err := scanFence(row)
	if err != nil {
		return RecoveryFence{}, false, fmt.Errorf("store: insert recovery fence: %w", err)
	}
	if created {
		return stored, true, nil
	}
	stored, found, err := p.RecoveryFenceAt(f.ProjectID, f.Seq)
	if err != nil {
		return RecoveryFence{}, false, err
	}
	if !found || !sameFence(stored, f) {
		return stored, false, ErrRecoveryConflict
	}
	return stored, false, nil
}

func (p *Postgres) RecoveryResultAt(projectID string, seq int64) (RecoveryResult, bool, error) {
	if err := p.checkProject(projectID); err != nil {
		return RecoveryResult{}, false, err
	}
	return scanResult(p.queries().QueryRow(p.callContext(), `SELECT `+resultColumns+` FROM broker_seq_recovery_result WHERE project_id=$1 AND seq=$2`, projectID, seq))
}

func (p *Postgres) PutRecoveryResult(r RecoveryResult) (RecoveryResult, bool, error) {
	if p.tx == nil {
		return RecoveryResult{}, false, errors.New("store: recovery result requires project transaction")
	}
	if err := p.checkProject(r.ProjectID); err != nil {
		return RecoveryResult{}, false, err
	}
	f, found, err := p.RecoveryFenceAt(r.ProjectID, r.Seq)
	if err != nil {
		return RecoveryResult{}, false, err
	}
	if !found || f.Generation != r.Generation {
		return RecoveryResult{}, false, ErrRecoveryConflict
	}
	var winning string
	err = p.tx.QueryRow(p.callContext(), `SELECT json FROM records WHERE project_id=$1 AND content_hash=$2`, r.ProjectID, r.WinningRecordHash).Scan(&winning)
	if errors.Is(err, pgx.ErrNoRows) {
		return RecoveryResult{}, false, ErrRecoveryConflict
	}
	if err != nil {
		return RecoveryResult{}, false, err
	}
	if !validRecoveryWinner(winning, f, r.Outcome) {
		return RecoveryResult{}, false, ErrRecoveryConflict
	}
	stored, created, err := scanResult(p.tx.QueryRow(p.callContext(), `INSERT INTO broker_seq_recovery_result (project_id,seq,generation,outcome,winning_record_hash)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING `+resultColumns,
		r.ProjectID, r.Seq, r.Generation, r.Outcome, r.WinningRecordHash))
	if err != nil {
		return RecoveryResult{}, false, fmt.Errorf("store: insert recovery result: %w", err)
	}
	if created {
		return stored, true, nil
	}
	stored, found, err = p.RecoveryResultAt(r.ProjectID, r.Seq)
	if err != nil {
		return RecoveryResult{}, false, err
	}
	if !found || stored.Generation != r.Generation || stored.Outcome != r.Outcome || stored.WinningRecordHash != r.WinningRecordHash {
		return stored, false, ErrRecoveryConflict
	}
	return stored, false, nil
}

func (p *Postgres) RecordByRecordID(projectID, recordID string) (Record, bool, error) {
	if err := p.checkProject(projectID); err != nil {
		return Record{}, false, err
	}
	var r Record
	err := p.queries().QueryRow(p.callContext(), `SELECT json,content_hash,session_id,parents FROM records
		WHERE project_id=$1 AND md5(json::jsonb ->> 'record_id')=md5($2) AND json::jsonb ->> 'record_id'=$2 LIMIT 1`, projectID, recordID).
		Scan(&r.JSON, &r.ContentHash, &r.SessionID, &r.Parents)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, false, nil
	}
	return r, err == nil, err
}
