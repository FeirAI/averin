package store

import (
	"context"
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

// PruneExpiredPendingGrants deletes pending_grants rows that no prepare or finalize can still use, one
// project at a time under that project's write transaction (guard row held), and returns the number
// removed. maxProjects bounds one sweep; later sweeps pick up the rest.
//
// A row is live for a guarded prepare/finalize while created_at >= now() - ttl, where now() is that
// transaction's start. Every project write transaction ends within its 45 s session bound, so any
// transaction that could still judge a row live started no earlier than clock_timestamp() - grace when
// grace exceeds that bound. Deleting only rows older than clock_timestamp() - ttl - grace (database clock,
// read after the guard is held) therefore never removes a row a finalize could legitimately use.
func (p *Postgres) PruneExpiredPendingGrants(ctx context.Context, ttl, grace time.Duration, maxProjects int) (int64, error) {
	if p.tx != nil {
		return 0, errors.New("store: pending sweep must run on the root store")
	}
	if ttl <= 0 || grace < 45*time.Second || maxProjects < 1 {
		return 0, errors.New("store: pending sweep needs positive ttl, grace >= the 45s transaction bound, and a project budget")
	}
	horizon := (ttl + grace).Seconds()
	rows, err := p.pool.Query(ctx, `SELECT DISTINCT project_id FROM pending_grants
		WHERE created_at < clock_timestamp() - make_interval(secs => $1) ORDER BY project_id LIMIT $2`, horizon, maxProjects)
	if err != nil {
		return 0, fmt.Errorf("store: pending sweep candidates: %w", err)
	}
	var projects []string
	for rows.Next() {
		var project string
		if err := rows.Scan(&project); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: pending sweep candidates: %w", err)
		}
		projects = append(projects, project)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: pending sweep candidates: %w", err)
	}
	var removed int64
	for _, project := range projects {
		var n int64
		err := p.WithProjectWrite(ctx, project, func(st Store) error {
			bound, ok := st.(*Postgres)
			if !ok || bound.tx == nil {
				return errors.New("store: pending sweep lost its project transaction")
			}
			tag, err := bound.tx.Exec(bound.callContext(), `DELETE FROM pending_grants
				WHERE project_id=$1 AND created_at < clock_timestamp() - make_interval(secs => $2)`, project, horizon)
			if err != nil {
				return fmt.Errorf("store: pending sweep delete: %w", err)
			}
			n = tag.RowsAffected()
			return nil
		})
		if err != nil {
			return removed, err
		}
		removed += n
	}
	return removed, nil
}
