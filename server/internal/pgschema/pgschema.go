// Package pgschema owns the ONE versioned schema migration for averin's Postgres database.
//
// averin's three Postgres-backed stores — the append-only evidence store (internal/store), the
// consume-before-act ledger (internal/pgledger), and the durable revocation / two-phase grant state
// (internal/pgdurable) — all share a single AVERIN_DATABASE_URL. Historically each applied its own
// idempotent `CREATE ... IF NOT EXISTS` DDL on every boot, so (a) the operator saw no single schema
// version, (b) the runtime role needed CREATE/ALTER forever, and (c) a first shape-altering release
// could neither detect an out-of-date DB nor refuse a newer-than-binary one.
//
// This package folds all three DDLs under ONE advisory-lock-guarded, version-stamped runner writing a
// single `schema_migrations(version int PRIMARY KEY, applied_at timestamptz)` ledger for the whole
// averin DB. (The table is named schema_migrations, NOT schema_version — averin already uses
// `schema_version` as the flight-recorder RECORD JSON field; see internal/api/server.go.)
//
// The runner reads the stored version (absent ⇒ 0/baseline) and branches:
//
//   - stored  > CurrentSchemaVersion: REFUSE to open, loudly (fail-closed). averin's evidence is
//     immutable; a binary older than the DB must never re-migrate it backward or risk MISREADING it.
//   - stored  < CurrentSchemaVersion: apply the ordered forward steps (stored+1 .. current), each
//     stamped in the SAME transaction as its DDL, so a crash can never leave version-ahead-of-schema.
//   - stored == CurrentSchemaVersion: no-op. A steady-state boot issues ZERO DDL — which is exactly
//     what lets the runtime role drop CREATE/ALTER.
//
// An existing UNSTAMPED averin DB reads as version 0 and adopts version 1, whose step is EXACTLY
// today's idempotent baseline DDL (records/checkpoints/... + consume_ledger + revocations/pending_grants).
// Because that DDL is `CREATE ... IF NOT EXISTS`, adopting the stamp is a no-op on existing data — no
// rebuild, no drop, no data loss.
//
// The whole check-and-migrate holds a transaction-scoped pg_advisory_xact_lock, so two averin replicas
// booting against one DB (a rolling deploy / HA topology) cannot race the DDL. The lock auto-releases on
// COMMIT/ROLLBACK, so there is no unlock to leak.
//
// Adding a migration is not a framework: bump CurrentSchemaVersion and append ONE ordered DDL string to
// `steps` (plus a line in UPGRADING). The version and its DDL then commit together on the next boot.
package pgschema

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/feirai/averin/server/internal/pgdurable"
	"github.com/feirai/averin/server/internal/pgledger"
	"github.com/feirai/averin/server/migrations"
)

// CurrentSchemaVersion is the schema version this binary understands. A stored version above this is a
// fail-closed refusal to open; a stored version below it is migrated forward, step by step, to this.
const CurrentSchemaVersion = 1

// advisoryLockKey serializes the check-and-migrate across concurrently-booting replicas sharing one
// AVERIN_DATABASE_URL. Its value is an arbitrary, stable, averin-private token (the ASCII of "AVERINSC")
// — an internal serialization token, never persisted; its only requirement is not colliding with another
// advisory-lock user on the same DB, so it is namespaced rather than a small integer.
const advisoryLockKey int64 = 0x41564552494e5343 // "AVERINSC"

// baselineV1 is the version-1 baseline: every table averin's Postgres stores need, as today's EXACT
// idempotent DDL, concatenated from the three historical per-store schemas so one version covers the
// whole DB. Because every statement is `CREATE ... IF NOT EXISTS`, applying it to an existing unstamped
// DB is a no-op on data — adopting the v1 stamp never rebuilds or drops anything.
//
//   - migrations.Schema     — records, checkpoints, anchors, disclosures, display_seq, broker_seq +
//     the append-only REVOKE block (internal/store).
//   - pgledger.SchemaSQL    — consume_ledger (internal/pgledger).
//   - pgdurable.SchemaSQL   — revocations, pending_grants (internal/pgdurable).
var baselineV1 = migrations.Schema + "\n" + pgledger.SchemaSQL + "\n" + pgdurable.SchemaSQL

// steps[i] migrates the DB from version i to version i+1; steps[0] is the v0→v1 baseline. len(steps)
// must equal CurrentSchemaVersion.
var steps = []string{
	baselineV1,
}

// Migrate brings the averin Postgres DB at dsn up to CurrentSchemaVersion under a single advisory lock,
// idempotently and fail-closed. It is called ONCE at startup (before any store opens its pool); every
// store then runs against an already-migrated DB and applies no DDL of its own. Opening a short-lived
// pool here keeps the runner self-contained. Callers MUST treat a returned error as fatal (fail-closed):
// a newer-than-binary DB, or a DB that cannot be migrated, must never be served against.
func Migrate(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("pgschema: connect: %w", err)
	}
	defer pool.Close()

	// One transaction for the whole check-and-migrate: the advisory lock, the version read, and the
	// stamped steps all commit (or roll back) together. Begin also forces a real connection, so an
	// unreachable DSN fails fast here (pgxpool.New is lazy).
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pgschema: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after a successful commit is a no-op.

	// Serialize concurrently-booting replicas. Taken FIRST so the version read happens under the lock;
	// a transaction-scoped lock auto-releases on COMMIT/ROLLBACK (nothing to unlock, nothing to leak).
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey); err != nil {
		return fmt.Errorf("pgschema: advisory lock: %w", err)
	}

	// The version ledger itself. Guarded by an existence probe so a steady-state boot issues ZERO DDL —
	// the table is created only the first time averin ever migrates this DB. Under the advisory lock only
	// one replica can be in the reg==nil branch at a time, so the plain create is race-free.
	var reg *string
	if err := tx.QueryRow(ctx, `SELECT to_regclass('schema_migrations')::text`).Scan(&reg); err != nil {
		return fmt.Errorf("pgschema: probe schema_migrations: %w", err)
	}
	if reg == nil {
		if _, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version    int         PRIMARY KEY,
				applied_at timestamptz NOT NULL DEFAULT now()
			)`); err != nil {
			return fmt.Errorf("pgschema: create schema_migrations: %w", err)
		}
	}

	var stored int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&stored); err != nil {
		return fmt.Errorf("pgschema: read version: %w", err)
	}

	switch {
	case stored > CurrentSchemaVersion:
		// FAIL CLOSED: the stored DB is NEWER than this binary understands. averin's evidence is
		// immutable; a downgrade must never re-migrate it backward or risk misreading migrated data.
		// Refuse to open, loudly — the caller turns this into a fatal.
		return fmt.Errorf("pgschema: database schema version %d is NEWER than this binary supports (%d) — refusing to open (evidence is never re-migrated backward across a downgrade); run the matching or a newer averin release", stored, CurrentSchemaVersion)
	case stored == CurrentSchemaVersion:
		// Steady state: nothing to migrate, no DDL. Commit the (lock-only) tx to release the lock.
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("pgschema: commit (steady state): %w", err)
		}
		return nil
	}

	// stored < CurrentSchemaVersion: apply the ordered forward steps, stamping each in THIS tx so the
	// version and its DDL commit together — a crash can never leave version-ahead-of-schema (which would
	// then read as "already migrated" and skip real work) or schema-ahead-of-version (which would re-run).
	for v := stored + 1; v <= CurrentSchemaVersion; v++ {
		if _, err := tx.Exec(ctx, steps[v-1]); err != nil {
			return fmt.Errorf("pgschema: apply step v%d: %w", v, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, v); err != nil {
			return fmt.Errorf("pgschema: stamp v%d: %w", v, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pgschema: commit: %w", err)
	}
	return nil
}
