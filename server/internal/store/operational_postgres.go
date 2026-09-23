package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func (p *Postgres) operationalProject(projectID string, write bool) error {
	if err := p.checkProject(projectID); err != nil {
		return err
	}
	if write && p.tx == nil {
		return errors.New("store: operational write requires project transaction")
	}
	return nil
}

func (p *Postgres) PendingGrant(projectID, idemKey string) (PendingGrant, bool, error) {
	if err := p.operationalProject(projectID, false); err != nil {
		return PendingGrant{}, false, err
	}
	var row PendingGrant
	err := p.queries().QueryRow(p.callContext(), `SELECT grant_id,payload,created_at FROM pending_grants WHERE project_id=$1 AND idem_key=$2`, projectID, idemKey).Scan(&row.GrantID, &row.Payload, &row.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingGrant{}, false, nil
	}
	if err != nil {
		return PendingGrant{}, false, fmt.Errorf("store: pending grant: %w", err)
	}
	return row, true, nil
}

func (p *Postgres) PutPendingGrant(projectID, idemKey string, row PendingGrant) (PendingGrant, bool, error) {
	if err := p.operationalProject(projectID, true); err != nil {
		return PendingGrant{}, false, err
	}
	ctx := p.callContext()
	var createdAt time.Time
	err := p.tx.QueryRow(ctx, `INSERT INTO pending_grants(project_id,idem_key,grant_id,payload,created_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT(project_id,idem_key) DO NOTHING RETURNING created_at`, projectID, idemKey, row.GrantID, row.Payload).Scan(&createdAt)
	if err == nil {
		row.Created = createdAt
		return row, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PendingGrant{}, false, fmt.Errorf("store: put pending grant: %w", err)
	}
	prior, found, err := p.PendingGrant(projectID, idemKey)
	if err != nil {
		return PendingGrant{}, false, err
	}
	if !found {
		return PendingGrant{}, false, errors.New("store: pending conflict did not resolve")
	}
	return prior, false, nil
}

func (p *Postgres) DeletePendingGrant(projectID, idemKey string) error {
	if err := p.operationalProject(projectID, true); err != nil {
		return err
	}
	_, err := p.tx.Exec(p.callContext(), `DELETE FROM pending_grants WHERE project_id=$1 AND idem_key=$2`, projectID, idemKey)
	if err != nil {
		return fmt.Errorf("store: delete pending grant: %w", err)
	}
	return nil
}

func (p *Postgres) PendingGrantLive(projectID, grantID string, _ time.Time, ttl time.Duration) (bool, error) {
	if err := p.operationalProject(projectID, false); err != nil {
		return false, err
	}
	var live bool
	err := p.queries().QueryRow(p.callContext(), `SELECT EXISTS(SELECT 1 FROM pending_grants WHERE project_id=$1 AND grant_id=$2 AND created_at >= now() - make_interval(secs => $3))`, projectID, grantID, ttl.Seconds()).Scan(&live)
	if err != nil {
		return false, fmt.Errorf("store: pending grant live: %w", err)
	}
	return live, nil
}

func (p *Postgres) IsRevoked(projectID, grantID string) (bool, error) {
	if err := p.operationalProject(projectID, false); err != nil {
		return false, err
	}
	var revoked bool
	err := p.queries().QueryRow(p.callContext(), `SELECT EXISTS(SELECT 1 FROM revocations WHERE project_id=$1 AND grant_id=$2) OR EXISTS(SELECT 1 FROM records WHERE project_id=$1 AND md5(json::jsonb ->> 'record_id')=md5($2) AND json::jsonb ->> 'record_id'=$2 AND json::jsonb #>> '{extensions,broker,kind}'='grant_void')`, projectID, grantID).Scan(&revoked)
	if err != nil {
		return false, fmt.Errorf("store: revocation lookup: %w", err)
	}
	return revoked, nil
}

func (p *Postgres) RevokeGrant(projectID, grantID string) (bool, error) {
	if err := p.operationalProject(projectID, true); err != nil {
		return false, err
	}
	var created bool
	err := p.tx.QueryRow(p.callContext(), `INSERT INTO revocations(project_id,grant_id) VALUES($1,$2) ON CONFLICT(project_id,grant_id) DO NOTHING RETURNING true`, projectID, grantID).Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: revoke grant: %w", err)
	}
	return true, nil
}

func (p *Postgres) RevokedGrantIDs(projectID string) ([]string, error) {
	if err := p.operationalProject(projectID, false); err != nil {
		return nil, err
	}
	rows, err := p.queries().Query(p.callContext(), `SELECT grant_id FROM revocations WHERE project_id=$1 ORDER BY grant_id`, projectID)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}
