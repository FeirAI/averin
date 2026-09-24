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
