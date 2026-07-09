// Package pgdurable is a durable, Postgres-backed backing store for averin's two security-relevant
// pieces of state that were previously IN-MEMORY ONLY (Phase-1): the M5 revoked-grant set
// (server/internal/api/revocation_server.go) and the M6/M2 online two-phase grant PENDING mint state
// held between /v2/grants/prepare and /v2/grants/finalize (server/internal/api/grant_twophase.go).
//
// Both were lost on a pod restart or SIGTERM: a revoke issued just before restart was forgotten (a
// fail-open — the verifier would then accept a grant an operator believed was blocked), and a pending
// two-phase mint (broker-signed, awaiting cosignatures/delegation hops) could no longer be finalized.
//
// This package is OPT-IN, mirroring pgledger's persist-before-serve pattern: wired only when
// AVERIN_DATABASE_URL is set (server/cmd/averin-server/main.go). The api.Server keeps its existing
// in-memory map/set as the hot-path READ cache (unchanged read logic); every WRITE goes through here
// FIRST — if the Postgres write fails, the caller must not update the in-memory cache and must not
// report success (fail-closed). At boot, api.Server.WithDurable rehydrates both in-memory structures
// from these tables.
package pgdurable

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// opTimeout bounds each op so a hung/degraded DB fails the caller fast — fail-CLOSED — instead of
// hanging a /v2/revoke or /v2/grants/prepare request forever. Mirrors pgledger's opTimeout.
const opTimeout = 10 * time.Second

// schemaSQL is applied idempotently at startup (CREATE ... IF NOT EXISTS), matching the store and
// pgledger packages' auto-migrate-on-boot pattern so `docker compose up` / a k8s rollout stays turnkey.
//
// Neither table is integrity-bearing (the DAG + anchor remain the sole integrity root; a signed,
// exported revocation_list is what the offline verifier trusts, not this table directly) — these are
// operational durability for state the RUNNING server needs to survive a restart. revocations is
// insert-only/idempotent (revocation is monotone-add, never un-revoked). pending_grants IS mutated by
// DELETE once a grant finalizes or its TTL expires — that is expected churn, not a security concern
// (the finalized grant's durable record of truth is the sealed Decision Record in the main store).
const schemaSQL = `
CREATE TABLE IF NOT EXISTS revocations (
	project_id text        NOT NULL,
	grant_id   text        NOT NULL,
	revoked_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (project_id, grant_id)
);

CREATE TABLE IF NOT EXISTS pending_grants (
	project_id text        NOT NULL,
	idem_key   text        NOT NULL,
	grant_id   text        NOT NULL,
	payload    text        NOT NULL, -- JSON-encoded pendingGrant DTO (broker.Prepared + broker.Request + the wire grantRequest)
	created_at timestamptz NOT NULL,
	PRIMARY KEY (project_id, idem_key)
);
`

// Store is the Postgres-backed durability layer. The caller owns the lifecycle and must call Close.
type Store struct {
	pool *pgxpool.Pool
}

// New connects to dsn, applies the (idempotent) schema, and returns a ready Store.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgdurable: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgdurable: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgdurable: schema: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the underlying connection pool. Safe to call once.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Ping reports whether the pool can reach the database, bounded by ctx. Used by /readyz — callers
// MUST pass a short-timeout ctx so a hung/degraded database fails the probe fast rather than hanging
// the readiness check.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// PoolStat is a point-in-time snapshot of the connection pool's health, exposed for /metrics gauges.
type PoolStat struct {
	TotalConns    int32
	AcquiredConns int32
	IdleConns     int32
	MaxConns      int32
}

// PoolStat returns a snapshot of the pool's connection counts.
func (s *Store) PoolStat() PoolStat {
	st := s.pool.Stat()
	return PoolStat{
		TotalConns:    st.TotalConns(),
		AcquiredConns: st.AcquiredConns(),
		IdleConns:     st.IdleConns(),
		MaxConns:      st.MaxConns(),
	}
}

// Revoke durably records grant_id revoked for a project. Idempotent (ON CONFLICT DO NOTHING) —
// revocation is monotone-add, so a re-revoke of an already-revoked id is a safe no-op.
func (s *Store) Revoke(projectID, grantID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO revocations (project_id, grant_id) VALUES ($1, $2)
		ON CONFLICT (project_id, grant_id) DO NOTHING
	`, projectID, grantID); err != nil {
		return fmt.Errorf("pgdurable: revoke: %w", err)
	}
	return nil
}

// LoadRevocations returns every durably-revoked grant, projectID -> set of revoked grant_ids, for
// rehydrating the in-memory revoked set at boot. Never nil.
func (s *Store) LoadRevocations(ctx context.Context) (map[string]map[string]struct{}, error) {
	rows, err := s.pool.Query(ctx, `SELECT project_id, grant_id FROM revocations`)
	if err != nil {
		return nil, fmt.Errorf("pgdurable: load revocations: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]struct{}{}
	for rows.Next() {
		var projectID, grantID string
		if err := rows.Scan(&projectID, &grantID); err != nil {
			return nil, fmt.Errorf("pgdurable: scan revocation: %w", err)
		}
		set := out[projectID]
		if set == nil {
			set = map[string]struct{}{}
			out[projectID] = set
		}
		set[grantID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgdurable: iterate revocations: %w", err)
	}
	return out, nil
}

// PutPending durably records a freshly-minted pending two-phase grant (the state held between
// /v2/grants/prepare and /v2/grants/finalize). Idempotent on (project_id, idem_key): a re-prepare of an
// already-pending idempotency key does NOT re-mint (the api layer only calls this on the first mint), so
// the ON CONFLICT path is a safety net, not the expected path — EXCEPT under multi-replica averin sharing
// one AVERIN_DATABASE_URL (a normal HA topology), where two replicas can race a first mint for the SAME
// idem key. Unlike revocations (a monotone-add boolean fact, safe under a blind DO NOTHING), pending_grants
// carries a MUTABLE payload: broker.Prepared bakes call-time now into nbf/iat/exp/credential_binding, so
// two mints of the same idem key produce DIFFERENT challenges. Silently discarding the losing write (the
// old behavior) would let the losing replica cache + serve its own local challenge while a DIFFERENT row
// is durable — a client that signs cosignatures over the losing challenge then fails finalize after a
// restart/rehydrate loads the winning row instead. So on conflict we load the WINNING row and return it
// (payload + created_at) instead of the caller's own — mirroring store/postgres.go's PutRecord idiom
// (INSERT ... ON CONFLICT DO NOTHING RETURNING <col>, then pgx.ErrNoRows means "someone else already
// inserted"). The caller must serve/cache what THIS returns, not what it originally minted.
func (s *Store) PutPending(projectID, idemKey, grantID string, payload []byte, created time.Time) ([]byte, time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	created = created.UTC()

	var won bool
	err := s.pool.QueryRow(ctx, `
		INSERT INTO pending_grants (project_id, idem_key, grant_id, payload, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (project_id, idem_key) DO NOTHING
		RETURNING true
	`, projectID, idemKey, grantID, payload, created).Scan(&won)
	switch {
	case err == nil:
		// Single-writer fast path: our insert won, our payload is the durable truth.
		return payload, created, nil
	case errors.Is(err, pgx.ErrNoRows):
		// Lost the race — load the winning writer's durable row instead of trusting our own mint.
		var storedPayload []byte
		var storedCreated time.Time
		if lerr := s.pool.QueryRow(ctx, `
			SELECT payload, created_at FROM pending_grants WHERE project_id = $1 AND idem_key = $2
		`, projectID, idemKey).Scan(&storedPayload, &storedCreated); lerr != nil {
			return nil, time.Time{}, fmt.Errorf("pgdurable: put pending: load winning row after conflict: %w", lerr)
		}
		return storedPayload, storedCreated, nil
	default:
		return nil, time.Time{}, fmt.Errorf("pgdurable: put pending: %w", err)
	}
}

// DeletePending removes a pending grant's durable row — called once it finalizes (committed to the main
// store, so the pending state is moot) or its TTL expires. Best-effort from the caller's perspective: a
// row left behind after a finalize is harmless (RecordByIdem is checked BEFORE the pending map on both
// prepare and finalize, so a stale rehydrated pending entry for an already-committed grant is simply
// never reached) — but errors are still returned so the caller can log them.
func (s *Store) DeletePending(projectID, idemKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM pending_grants WHERE project_id = $1 AND idem_key = $2
	`, projectID, idemKey); err != nil {
		return fmt.Errorf("pgdurable: delete pending: %w", err)
	}
	return nil
}

// PendingRow is one durably-stored pending two-phase grant, as loaded at boot.
type PendingRow struct {
	ProjectID string
	IdemKey   string
	Payload   []byte
	Created   time.Time
}

// LoadPending returns every durably-stored pending grant, for rehydrating the in-memory pending map at
// boot. Never nil.
func (s *Store) LoadPending(ctx context.Context) ([]PendingRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT project_id, idem_key, payload, created_at FROM pending_grants`)
	if err != nil {
		return nil, fmt.Errorf("pgdurable: load pending: %w", err)
	}
	defer rows.Close()
	out := []PendingRow{}
	for rows.Next() {
		var row PendingRow
		if err := rows.Scan(&row.ProjectID, &row.IdemKey, &row.Payload, &row.Created); err != nil {
			return nil, fmt.Errorf("pgdurable: scan pending: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgdurable: iterate pending: %w", err)
	}
	return out, nil
}
