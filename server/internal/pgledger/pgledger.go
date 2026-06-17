// Package pgledger is a durable, atomically-consistent consume-before-act ledger
// (resourceshim.Ledger) backed by Postgres. It closes the volatile-MemLedger residual: consumed PoP
// nonces and credential double-spend keys survive a process restart, so a single-use (or bounded_reuse)
// capability cannot be replayed across a restart. Each consume is a single
// `INSERT ... ON CONFLICT DO NOTHING` — atomic and safe under concurrency without a read-then-write.
package pgledger

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/feir-dev/feir/server/internal/resourceshim"
)

// opTimeout bounds each ledger op so a hung/severely-degraded DB fails the consume (and thus the use)
// fast — fail-CLOSED — instead of hanging /v2/use forever while holding the ingest lock. Generous: a
// healthy consume is sub-millisecond, so this only fires on a genuine outage, where failing is correct.
const opTimeout = 10 * time.Second

// The ledger is OPERATIONAL state (consumed nonces/jtis), not evidence — it permits DELETE (the
// pre-persistence Release rollback), so unlike the evidence store it is NOT append-only / REVOKE'd.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS consume_ledger (
	kind        text        NOT NULL,  -- 'nonce' (PoP replay) | 'jti' (double-spend key: grant_id or grant_id#usn)
	consume_key text        NOT NULL,
	consumed_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (kind, consume_key)
);`

// Ledger is a Postgres-backed resourceshim.Ledger.
type Ledger struct {
	pool *pgxpool.Pool
}

var _ resourceshim.Ledger = (*Ledger)(nil)

// New opens a connection pool to dsn and ensures the ledger table exists (idempotent, so it is safe
// under `docker compose up`). The caller must Close it.
func New(ctx context.Context, dsn string) (*Ledger, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgledger: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgledger: schema: %w", err)
	}
	return &Ledger{pool: pool}, nil
}

// Close releases the connection pool.
func (l *Ledger) Close() { l.pool.Close() }

// consume atomically claims (kind, consume_key). ON CONFLICT DO NOTHING + RETURNING: a returned row
// means THIS statement inserted the row (the first claim — consumed now); pgx.ErrNoRows means the row
// already existed (a replay / double-spend -> ErrConsumed). A real DB error is surfaced so the caller
// fails closed (a use must never proceed when the ledger is unavailable — that would open a replay
// window). Like the store, this never reads-then-writes, so it is correct under concurrency.
func (l *Ledger) consume(kind, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	var got string
	err := l.pool.QueryRow(ctx,
		`INSERT INTO consume_ledger (kind, consume_key) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING consume_key`,
		kind, key).Scan(&got)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return resourceshim.ErrConsumed
	default:
		return fmt.Errorf("pgledger: consume %s: %w", kind, err)
	}
}

// ConsumeNonce marks a PoP nonce consumed (replay protection); ErrConsumed if already seen.
func (l *Ledger) ConsumeNonce(nonce string) error { return l.consume("nonce", nonce) }

// ConsumeJTI marks a credential double-spend key consumed; ErrConsumed if already spent.
func (l *Ledger) ConsumeJTI(jti string) error { return l.consume("jti", jti) }

// release best-effort rolls back a consumption (the receipt definitively did not persist, so an honest
// retry may re-validate). A failure here OVER-burns (the entry stays consumed) — which is safe (it can
// never cause a double-spend, only a needless re-validation failure) — so it is logged, not propagated
// (the interface is void, mirroring MemLedger's no-op-on-missing semantics).
func (l *Ledger) release(kind, key string) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if _, err := l.pool.Exec(ctx,
		`DELETE FROM consume_ledger WHERE kind = $1 AND consume_key = $2`, kind, key); err != nil {
		log.Printf("WARNING: pgledger release of %s failed (entry stays consumed — no double-spend risk, but an honest retry cannot re-validate): %v", kind, err)
	}
}

// ReleaseNonce rolls back a ConsumeNonce. ReleaseJTI rolls back a ConsumeJTI.
func (l *Ledger) ReleaseNonce(nonce string) { l.release("nonce", nonce) }
func (l *Ledger) ReleaseJTI(jti string)     { l.release("jti", jti) }
