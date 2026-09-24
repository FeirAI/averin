// Package pgledger owns ledger maintenance. Request claims live in the project
// transaction (internal/store), together with the signed receipt.
package pgledger

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// opTimeout bounds each ledger op so a hung/severely-degraded DB fails the consume (and thus the use)
// fast — fail-CLOSED — instead of hanging /v2/use forever while holding the ingest lock. Generous: a
// healthy consume is sub-millisecond, so this only fires on a genuine outage, where failing is correct.
const opTimeout = 10 * time.Second

// SchemaSQL is the ledger's baseline DDL. It is applied ONCE by the versioned migration runner
// (internal/pgschema), which folds it with the store and pgdurable schemas under a single
// schema_migrations version — New no longer applies it, so a steady-state boot issues no DDL.
//
// The ledger is OPERATIONAL state (consumed nonces/jtis), not evidence — it permits DELETE (the
// pre-persistence Release rollback), so unlike the evidence store it is NOT append-only / REVOKE'd.
const SchemaSQL = `
CREATE TABLE IF NOT EXISTS consume_ledger (
	kind        text        NOT NULL,  -- 'nonce' (PoP replay) | 'jti' (double-spend key: grant_id or grant_id#usn)
	consume_key text        NOT NULL,
	consumed_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (kind, consume_key)
);
-- Index consumed_at for the periodic TTL sweep (SweepConsumed): a range DELETE of aged rows is otherwise a
-- full scan on a ledger that only ever grows between sweeps.
CREATE INDEX IF NOT EXISTS consume_ledger_consumed_at_idx ON consume_ledger (consumed_at);`

// Ledger provides sweeper and readiness access to the already-migrated database.
type Ledger struct {
	pool *pgxpool.Pool
}

// New opens a connection pool to dsn. The ledger table is created by the versioned migration runner
// (internal/pgschema.Migrate) at startup, not here — so a steady-state boot issues no DDL and the
// runtime role needs no CREATE. pgxpool.New is lazy, so we Ping to fail fast (fail-CLOSED) if the DSN
// is unreachable rather than surfacing it on the first consume. The caller must Close it.
func New(ctx context.Context, dsn string) (*Ledger, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgledger: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgledger: ping: %w", err)
	}
	return &Ledger{pool: pool}, nil
}

// Close releases the connection pool.
func (l *Ledger) Close() { l.pool.Close() }

// Ping reports whether the pool can reach the database, bounded by ctx. Used by /readyz — callers
// MUST pass a short-timeout ctx so a hung/degraded database fails the probe fast rather than hanging
// the readiness check.
func (l *Ledger) Ping(ctx context.Context) error {
	var rows int
	if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM nonce_ledger_cutover WHERE singleton AND legacy_exclusion_until>cutover_at`).Scan(&rows); err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("pgledger: cutover metadata missing or invalid")
	}
	return nil
}

// PoolStat is a point-in-time snapshot of the connection pool's health, exposed for /metrics gauges.
type PoolStat struct {
	TotalConns    int32
	AcquiredConns int32
	IdleConns     int32
	MaxConns      int32
}

// PoolStat returns a snapshot of the pool's connection counts.
func (l *Ledger) PoolStat() PoolStat {
	st := l.pool.Stat()
	return PoolStat{
		TotalConns:    st.TotalConns(),
		AcquiredConns: st.AcquiredConns(),
		IdleConns:     st.IdleConns(),
		MaxConns:      st.MaxConns(),
	}
}

// SweepConsumed deletes ledger entries whose consumed_at is older than `retention`, returning the number
// removed. It bounds the ledger's otherwise-unbounded growth (one row per PoP nonce + per jti, forever) using
// the consumed_at column that was placed for exactly this purpose.
//
// CORRECTNESS CONSTRAINT (load-bearing, not tuning): `retention` MUST exceed the LONGEST credential validity
// window. A consumed nonce/jti only needs to stay recorded while a credential that could replay it is still
// valid; once every credential minted before the cutoff has expired, the entry can never gate a live replay, so
// pruning it is safe. Set `retention` BELOW the max credential lifetime and a still-live nonce/jti is deleted —
// reopening the single-use replay window this ledger exists to close. Callers enforce a safe floor (see main.go
// AVERIN_LEDGER_RETENTION; broker.MaxTTL is 1h, so the default is orders of magnitude larger).
func (l *Ledger) SweepConsumed(ctx context.Context, retention time.Duration) (int64, error) {
	// DB-side now() (not a Go-computed cutoff) so the comparison is immune to app↔DB clock skew.
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("pgledger: begin sweep: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var removed int64
	for _, table := range []string{"consumed_nonces", "consumed_jtis"} {
		tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE consumed_at < now() - make_interval(secs => $1)`, retention.Seconds())
		if err != nil {
			return 0, fmt.Errorf("pgledger: sweep %s: %w", table, err)
		}
		removed += tag.RowsAffected()
	}
	err = tx.Commit(ctx)
	if err != nil {
		return 0, fmt.Errorf("pgledger: sweep consumed: %w", err)
	}
	return removed, nil
}

// StartSweeper runs SweepConsumed on a background ticker every `interval` until ctx is cancelled (process
// exit). `retention` MUST satisfy SweepConsumed's correctness constraint. Best-effort: a sweep failure is
// LOGGED, never fatal — a deferred prune only defers reclaiming space, it can never reopen a replay window (the
// aged rows simply remain). Returns immediately; the ticker runs in its own goroutine.
func (l *Ledger) StartSweeper(ctx context.Context, retention, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sctx, cancel := context.WithTimeout(ctx, opTimeout)
				n, err := l.SweepConsumed(sctx, retention)
				cancel()
				if err != nil {
					log.Printf("WARNING: consume_ledger sweep failed (aged rows retained; no replay risk, only deferred space reclaim): %v", err)
				} else if n > 0 {
					log.Printf("consume_ledger sweep removed %d entries older than %s", n, retention)
				}
			}
		}
	}()
}
