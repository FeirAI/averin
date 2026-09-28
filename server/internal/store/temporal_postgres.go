package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Plan 009 Postgres implementation (schema v7). The authorization order lives on the plan 007
// project guard row, which every write transaction locks first, so allocation is serialized per
// project across replicas and pools and rolls back with its transaction.

func (p *Postgres) IsRevoked(projectID, grantID string) (bool, error) {
	if err := p.operationalProject(projectID, false); err != nil {
		return false, err
	}
	var revoked bool
	err := p.queries().QueryRow(p.callContext(), `SELECT EXISTS(SELECT 1 FROM revocation_events WHERE project_id=$1 AND grant_id=$2) OR EXISTS(SELECT 1 FROM records WHERE project_id=$1 AND md5(json::jsonb ->> 'record_id')=md5($2) AND json::jsonb ->> 'record_id'=$2 AND json::jsonb #>> '{extensions,broker,kind}'='grant_void')`, projectID, grantID).Scan(&revoked)
	if err != nil {
		return false, fmt.Errorf("store: revocation lookup: %w", err)
	}
	return revoked, nil
}

func (p *Postgres) RevokeGrant(projectID, grantID string) (bool, error) {
	_, created, err := p.PutRevocationEvent(RevocationEvent{
		ProjectID: projectID, GrantID: grantID, Mode: RevocationTotal, Issuer: "averin", Reason: "total",
	})
	return created, err
}

func (p *Postgres) RevokedGrantIDs(projectID string) ([]string, error) {
	if err := p.operationalProject(projectID, false); err != nil {
		return nil, err
	}
	rows, err := p.queries().Query(p.callContext(), `SELECT DISTINCT grant_id FROM revocation_events WHERE project_id=$1 ORDER BY grant_id`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: revoked grant IDs: %w", err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func scanRevocationEvent(row pgx.Row, projectID string) (RevocationEvent, error) {
	ev := RevocationEvent{ProjectID: projectID}
	var cutoff *int64
	if err := row.Scan(&ev.GrantID, &ev.Mode, &cutoff, &ev.Issuer, &ev.Reason, &ev.Created); err != nil {
		return RevocationEvent{}, err
	}
	if cutoff != nil {
		ev.CutoffOrder = *cutoff
	}
	return ev, nil
}

func (p *Postgres) PutRevocationEvent(ev RevocationEvent) (RevocationEvent, bool, error) {
	if err := validateRevocationEvent(ev); err != nil {
		return RevocationEvent{}, false, err
	}
	tx, err := p.projectTx(ev.ProjectID)
	if err != nil {
		return RevocationEvent{}, false, err
	}
	ctx := p.callContext()
	const cols = `grant_id, mode, cutoff_order, issuer, reason, created_at`
	prior, err := scanRevocationEvent(tx.QueryRow(ctx, `SELECT `+cols+` FROM revocation_events WHERE project_id=$1 AND grant_id=$2 AND mode=$3`, ev.ProjectID, ev.GrantID, ev.Mode), ev.ProjectID)
	if err == nil {
		return prior, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return RevocationEvent{}, false, fmt.Errorf("store: revocation event lookup: %w", err)
	}
	var cutoff *int64
	if ev.Mode == RevocationProspective {
		if ev.CutoffOrder == 0 {
			// The cutoff is the next ordinal in the same serialization domain as every receipt.
			if ev.CutoffOrder, err = p.AllocateAuthorizationOrder(ev.ProjectID); err != nil {
				return RevocationEvent{}, false, err
			}
		}
		cutoff = &ev.CutoffOrder
	}
	stored, err := scanRevocationEvent(tx.QueryRow(ctx, `INSERT INTO revocation_events(project_id, grant_id, format, mode, cutoff_order, issuer, reason)
		SELECT $1,$2,$3,$4,$5,$6,$7
		WHERE $5::bigint IS NULL OR $5::bigint <= (SELECT authorization_order FROM project_write_guard WHERE project_id=$1)
		RETURNING `+cols, ev.ProjectID, ev.GrantID, RevocationEventFormat, ev.Mode, cutoff, ev.Issuer, ev.Reason), ev.ProjectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RevocationEvent{}, false, errors.New("store: prospective cutoff beyond the allocated authorization order")
	}
	if err != nil {
		return RevocationEvent{}, false, fmt.Errorf("store: put revocation event: %w", err)
	}
	return stored, true, nil
}

func (p *Postgres) RevocationEvents(projectID string) ([]RevocationEvent, error) {
	if err := p.operationalProject(projectID, false); err != nil {
		return nil, err
	}
	rows, err := p.queries().Query(p.callContext(), `SELECT grant_id, mode, cutoff_order, issuer, reason, created_at FROM revocation_events WHERE project_id=$1 ORDER BY grant_id, mode`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: revocation events: %w", err)
	}
	defer rows.Close()
	out := []RevocationEvent{}
	for rows.Next() {
		ev, err := scanRevocationEvent(rows, projectID)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (p *Postgres) AllocateAuthorizationOrder(projectID string) (int64, error) {
	tx, err := p.projectTx(projectID)
	if err != nil {
		return 0, err
	}
	// WithProjectWrite already holds this row FOR UPDATE; the UPDATE cannot interleave
	// with another transaction's allocation for the project.
	var ordinal int64
	if err := tx.QueryRow(p.callContext(), `UPDATE project_write_guard SET authorization_order = authorization_order + 1 WHERE project_id=$1 RETURNING authorization_order`, projectID).Scan(&ordinal); err != nil {
		return 0, fmt.Errorf("store: allocate authorization order: %w", err)
	}
	return ordinal, nil
}

func (p *Postgres) PutAuthorizationReceipt(projectID string, r AuthorizationReceipt) error {
	tx, err := p.projectTx(projectID)
	if err != nil {
		return err
	}
	// The ordinal must already have been allocated from this project's order.
	tag, err := tx.Exec(p.callContext(), `INSERT INTO authorization_receipts(project_id, ordinal, record_id, grant_id, kind)
		SELECT $1,$2,$3,$4,$5 WHERE $2::bigint <= (SELECT authorization_order FROM project_write_guard WHERE project_id=$1)`,
		projectID, r.Ordinal, r.RecordID, r.GrantID, r.Kind)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrAuthorizationOrderConflict
	}
	if err != nil {
		return fmt.Errorf("store: put authorization receipt: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("store: authorization receipt ordinal %d was never allocated", r.Ordinal)
	}
	return nil
}

// SnapshotBoundary reads now(), the transaction start time. PostgreSQL takes a repeatable-read
// snapshot at the transaction's first statement, never before BEGIN, so every transaction that
// committed before this boundary is visible in the snapshot the export reads.
func (p *Postgres) SnapshotBoundary(projectID string) (time.Time, int64, error) {
	if err := p.checkProject(projectID); err != nil {
		return time.Time{}, 0, err
	}
	if p.tx == nil {
		return time.Time{}, 0, errors.New("store: snapshot boundary requires a project transaction")
	}
	var at time.Time
	var watermark int64
	err := p.tx.QueryRow(p.callContext(), `SELECT now(), COALESCE((SELECT authorization_order FROM project_write_guard WHERE project_id=$1), 0)`, projectID).Scan(&at, &watermark)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("store: snapshot boundary: %w", err)
	}
	return at.UTC(), watermark, nil
}
