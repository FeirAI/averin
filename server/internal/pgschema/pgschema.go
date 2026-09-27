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
// Ordinary startup bootstraps only a truly empty database. An existing schema,
// including an unstamped one, requires the explicit maintenance cutover command.
// The runner reads the stored version and branches:
//
//   - stored  > CurrentSchemaVersion: REFUSE to open, loudly (fail-closed). averin's evidence is
//     immutable; a binary older than the DB must never re-migrate it backward or risk MISREADING it.
//   - stored  < CurrentSchemaVersion: ordinary startup refuses; the maintenance
//     command validates retired-writer barriers, then applies and stamps steps
//     in the SAME transaction as their DDL.
//   - stored == CurrentSchemaVersion: no-op. A steady-state boot issues ZERO DDL — which is exactly
//     what lets the runtime role drop CREATE/ALTER.
//
// Existing UNSTAMPED databases retain all data and adopt the baseline only
// through the maintenance command. Historical global ledger claims remain
// explicit unknown-owner exclusions at v6.
//
// The whole check-and-migrate holds a transaction-scoped pg_advisory_xact_lock, so two averin replicas
// booting against one DB (a rolling deploy / HA topology) cannot race the DDL. The lock auto-releases on
// COMMIT/ROLLBACK, so there is no unlock to leak.
//
// Adding a migration: bump CurrentSchemaVersion and append its ordered DDL to
// steps. Existing deployments must run the maintenance barrier again; a prior
// cutover does not authorize later schema transitions.
package pgschema

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/pgdurable"
	"github.com/feirai/averin/server/internal/pgledger"
	"github.com/feirai/averin/server/migrations"
)

// CurrentSchemaVersion is the schema version this binary understands. A stored version above this is a
// fail-closed refusal to open; a stored version below it is migrated forward, step by step, to this.
const CurrentSchemaVersion = 7

// LegacyExclusionFloor is stamped using the database clock by migration 0006.
// It must exceed every capability accepted by the new resource shim.
const LegacyExclusionFloor = 24 * time.Hour

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
//
//   - v2 (migrations.RecordIDUnique): per-project record_id uniqueness backstop — an expression index over the
//     sealed JSON's record_id (UNIQUE unless historical duplicates already exist; see the migration header).
//   - v3 (migrations.BrokerSeqVoid): broker_seq.allocated_at + the insert-only broker_seq_void table behind the
//     operator's POST /v2/broker-seq/void remediation for a reserved-but-never-recorded broker_seq.
//   - v7 (migrations.TemporalRevocation): the per-project authorization order on the project guard,
//     immutable revocation events (pre-v7 revocations become total) and the receipt-ordinal backstop.
//     It needs its own validated writer barrier even after a v6 cutover (plan 009).
var steps = []string{
	baselineV1,
	migrations.RecordIDUnique,
	migrations.BrokerSeqVoid,
	migrations.ProjectTransactions,
	migrations.BrokerSeqRecovery,
	migrations.TenantNonceLedger,
	migrations.TemporalRevocation,
}

// Migrate brings the averin Postgres DB at dsn up to CurrentSchemaVersion under a single advisory lock,
// idempotently and fail-closed. It is called ONCE at startup (before any store opens its pool); every
// store then runs against an already-migrated DB and applies no DDL of its own. Opening a short-lived
// pool here keeps the runner self-contained. Callers MUST treat a returned error as fatal (fail-closed):
// a newer-than-binary DB, or a DB that cannot be migrated, must never be served against.
func Migrate(ctx context.Context, dsn string) error { return migrate(ctx, dsn, nil, false) }

// MigrateForRuntime is the ordinary server-startup entry point. It behaves like Migrate on an existing
// database (steady-state no-op, fail-closed on a newer or older version) but REFUSES to bootstrap a truly
// empty one: the server's runtime credential would then own every table it creates, and CheckRuntime
// refuses an owning runtime forever. A fresh database is initialized once with `averin-migrate --init`
// under the migration credential; the operator then grants the runtime role its least privileges.
func MigrateForRuntime(ctx context.Context, dsn string) error { return migrate(ctx, dsn, nil, true) }

// Cutover applies an existing database's forward transitions (v6 nonce ledger,
// v7 temporal revocation) only after the operator has retired every explicitly
// named old runtime identity. The barrier is re-validated for every advancing
// run, even when an earlier version was already cut over. It never manages
// roles or sessions itself; failed barriers leave the schema unchanged.
func Cutover(ctx context.Context, dsn string, oldRoles []string, newRole string) error {
	if len(oldRoles) == 0 || newRole == "" {
		return fmt.Errorf("pgschema: cutover requires old runtime roles and a new runtime role")
	}
	return migrate(ctx, dsn, &cutoverRoles{old: oldRoles, next: newRole}, false)
}

type cutoverRoles struct {
	old  []string
	next string
}

func migrate(ctx context.Context, dsn string, roles *cutoverRoles, refuseFresh bool) error {
	if broker.MaxTTL+broker.RequestClockSkew > LegacyExclusionFloor {
		return fmt.Errorf("pgschema: accepted capability lifetime and skew exceed v6 legacy exclusion hold")
	}
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
	var hasTables bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=current_schema() AND c.relkind IN ('r','p'))`).Scan(&hasTables); err != nil {
		return fmt.Errorf("pgschema: probe existing tables: %w", err)
	}
	fresh := reg == nil && !hasTables
	if refuseFresh && fresh {
		return fmt.Errorf("pgschema: empty database: ordinary server startup does not bootstrap the schema (its runtime credential would own every table and fail the least-privilege check); run `averin-migrate --init` with AVERIN_MIGRATION_DATABASE_URL, grant the runtime role (docs/dev/CONFIGURATION.md), then start the server")
	}
	if roles == nil && reg == nil && hasTables {
		return fmt.Errorf("pgschema: existing unstamped database requires explicit averin-migrate cutover; ordinary startup refuses legacy writers")
	}
	if roles != nil && fresh {
		return fmt.Errorf("pgschema: cutover requires an existing database; use ordinary startup for a fresh database")
	}
	if roles != nil {
		if err := validateCutoverRoles(ctx, tx, *roles); err != nil {
			return err
		}
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
	if roles == nil && !fresh {
		return fmt.Errorf("pgschema: database schema version %d requires explicit averin-migrate maintenance cutover to v%d; stop old writers first", stored, CurrentSchemaVersion)
	}

	// Only an advancing cutover needs the new runtime idle; a re-run at the current version is a no-op.
	if roles != nil {
		if err := validateNewRuntimeIdle(ctx, tx, roles.next); err != nil {
			return err
		}
		if err := validateNoOtherWriters(ctx, tx, roles.next); err != nil {
			return err
		}
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

func validateCutoverRoles(ctx context.Context, tx pgx.Tx, roles cutoverRoles) error {
	var migrating string
	if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&migrating); err != nil {
		return fmt.Errorf("pgschema: cutover current user: %w", err)
	}
	if roles.next == migrating {
		return fmt.Errorf("pgschema: new runtime role must differ from migration identity")
	}
	var nextCanLogin bool
	if err := tx.QueryRow(ctx, `SELECT rolcanlogin FROM pg_roles WHERE rolname=$1`, roles.next).Scan(&nextCanLogin); err != nil || !nextCanLogin {
		return fmt.Errorf("pgschema: new runtime role %q must exist and be LOGIN: %v", roles.next, err)
	}
	seen := map[string]bool{}
	for _, old := range roles.old {
		if old == "" || old == roles.next || old == migrating || seen[old] {
			return fmt.Errorf("pgschema: old runtime role %q is empty, repeated, or overlaps migration/new runtime", old)
		}
		seen[old] = true
		var canLogin, super bool
		if err := tx.QueryRow(ctx, `SELECT rolcanlogin, rolsuper FROM pg_roles WHERE rolname=$1`, old).Scan(&canLogin, &super); err != nil {
			return fmt.Errorf("pgschema: old runtime role %q must exist: %w", old, err)
		}
		if canLogin || super {
			return fmt.Errorf("pgschema: old runtime role %q must be NOLOGIN and non-superuser", old)
		}
		var sessions, prepared int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename=$1`, old).Scan(&sessions); err != nil {
			return fmt.Errorf("pgschema: old runtime sessions: %w", err)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_prepared_xacts WHERE owner=$1`, old).Scan(&prepared); err != nil {
			return fmt.Errorf("pgschema: old runtime prepared transactions: %w", err)
		}
		if sessions != 0 || prepared != 0 {
			return fmt.Errorf("pgschema: old runtime role %q has %d sessions and %d prepared transactions", old, sessions, prepared)
		}
		var writable string
		err := tx.QueryRow(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname=current_schema() AND c.relkind IN ('r','p')
			AND (c.relowner=(SELECT oid FROM pg_roles WHERE rolname=$1) OR
			     has_table_privilege($1,c.oid,'INSERT') OR has_table_privilege($1,c.oid,'UPDATE') OR
			     has_table_privilege($1,c.oid,'DELETE') OR has_table_privilege($1,c.oid,'TRUNCATE'))
			LIMIT 1`, old).Scan(&writable)
		if err == nil {
			return fmt.Errorf("pgschema: old runtime role %q retains effective write privilege on %s", old, writable)
		}
		if err != pgx.ErrNoRows {
			return fmt.Errorf("pgschema: inspect old runtime privileges: %w", err)
		}
	}
	return nil
}

// validateNewRuntimeIdle is the schema-cutover-only part of the barrier (plan 009 review). The
// new runtime starts only after the cutover commits, so a live session of it now would be an old
// binary reusing that identity: it could keep writing unordered receipts or untyped revocations
// across the step. Any prepared transaction in this database, whatever its owner, would commit
// against the old schema. (PurgeLegacy runs later, with the new runtime live, and skips this.)
func validateNewRuntimeIdle(ctx context.Context, tx pgx.Tx, next string) error {
	var nextSessions, prepared int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename=$1`, next).Scan(&nextSessions); err != nil {
		return fmt.Errorf("pgschema: new runtime sessions: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()`).Scan(&prepared); err != nil {
		return fmt.Errorf("pgschema: prepared transactions: %w", err)
	}
	if nextSessions != 0 || prepared != 0 {
		return fmt.Errorf("pgschema: new runtime role %q has %d sessions and the database has %d prepared transactions; start new runtimes only after the cutover", next, nextSessions, prepared)
	}
	return nil
}

// validateNoOtherWriters closes the gap the named-role checks leave (review S-M4): a LOGIN role that is a
// member of a retired role (GRANT old TO app_login, then SET ROLE old) is not itself named, so it passes
// validateCutoverRoles. An advancing cutover therefore also refuses while
//
//   - any other client backend is connected to this database, whatever its role; and
//   - any LOGIN, non-superuser role other than the migration identity, the new runtime and the table
//     owner holds effective INSERT/UPDATE/DELETE on a table in this schema, directly, by inheritance, or
//     through any role it is a member of (so SET ROLE membership counts).
//
// Superusers are exempt from the privilege check because no privilege can be revoked from them; they are
// covered only by the session check at this instant, and must be controlled operationally.
func validateNoOtherWriters(ctx context.Context, tx pgx.Tx, next string) error {
	// pg_stat_activity hides backend_type (and most columns) of other roles' sessions from a role
	// that is neither a superuser nor has the privileges of pg_read_all_stats, so the count below
	// would silently miss them. Fail closed unless the migrator can see every session. USAGE, not
	// MEMBER: the visibility check uses the role's privileges, which a NOINHERIT membership does
	// not confer without SET ROLE.
	var canSee bool
	if err := tx.QueryRow(ctx, `SELECT r.rolsuper OR pg_has_role(current_user, 'pg_read_all_stats', 'USAGE')
		FROM pg_roles r WHERE r.rolname=current_user`).Scan(&canSee); err != nil {
		return fmt.Errorf("pgschema: inspect migration identity: %w", err)
	}
	if !canSee {
		return fmt.Errorf("pgschema: the migration identity must be a superuser or have the privileges of pg_read_all_stats (GRANT pg_read_all_stats TO <migration role>) so the cutover barrier can see every other session; without it other roles' sessions are invisible and the barrier would pass unsafely")
	}
	var others int
	var users *string
	// Conservative: a row counts unless it is positively identified as a non-client backend.
	if err := tx.QueryRow(ctx, `SELECT count(*), string_agg(DISTINCT COALESCE(usename, '<unknown>'), ', ' ORDER BY COALESCE(usename, '<unknown>'))
		FROM pg_stat_activity
		WHERE datname=current_database() AND pid<>pg_backend_pid()
		  AND (backend_type IS NULL OR backend_type='client backend')`).Scan(&others, &users); err != nil {
		return fmt.Errorf("pgschema: inspect client sessions: %w", err)
	}
	if others != 0 {
		names := ""
		if users != nil {
			names = *users
		}
		return fmt.Errorf("pgschema: %d other client backend(s) are connected to this database (roles: %s); disconnect every client before an advancing cutover", others, names)
	}
	var role, table string
	err := tx.QueryRow(ctx, `SELECT r.rolname, c.relname
		FROM pg_roles r
		CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=current_schema() AND c.relkind IN ('r','p')
		  AND r.rolcanlogin AND NOT r.rolsuper
		  AND r.rolname <> current_user AND r.rolname <> $1 AND r.oid <> c.relowner
		  AND EXISTS (
			SELECT 1 FROM pg_roles g
			WHERE pg_has_role(r.oid, g.oid, 'MEMBER')
			  AND (has_table_privilege(g.oid, c.oid, 'INSERT') OR has_table_privilege(g.oid, c.oid, 'UPDATE')
			       OR has_table_privilege(g.oid, c.oid, 'DELETE'))
		  )
		ORDER BY r.rolname, c.relname
		LIMIT 1`, next).Scan(&role, &table)
	if err == nil {
		return fmt.Errorf("pgschema: LOGIN role %q can write %s (directly or through role membership); revoke it or its membership before an advancing cutover", role, table)
	}
	if err != pgx.ErrNoRows {
		return fmt.Errorf("pgschema: inspect other writers: %w", err)
	}
	return nil
}

// PurgeLegacy is a separate, controlled maintenance operation. It is never
// called by startup or the ordinary sweep. The table and immutable triggers
// remain after rows are removed so old prepared SQL still fails closed.
func PurgeLegacy(ctx context.Context, dsn string, oldRoles []string, newRole string) (int64, error) {
	if len(oldRoles) == 0 || newRole == "" {
		return 0, fmt.Errorf("pgschema: legacy purge requires cutover role barrier")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return 0, err
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey); err != nil {
		return 0, err
	}
	if err := validateCutoverRoles(ctx, tx, cutoverRoles{old: oldRoles, next: newRole}); err != nil {
		return 0, err
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, err
	}
	if version != CurrentSchemaVersion {
		return 0, fmt.Errorf("pgschema: legacy purge requires current schema version %d, found %d", CurrentSchemaVersion, version)
	}
	var mature bool
	if err := tx.QueryRow(ctx, `SELECT statement_timestamp() >= legacy_exclusion_until FROM nonce_ledger_cutover WHERE singleton`).Scan(&mature); err != nil {
		return 0, err
	}
	if !mature {
		return 0, fmt.Errorf("pgschema: legacy exclusion hold has not elapsed by database time")
	}
	// ALTER takes an exclusive lock for the whole transaction. Disable only the
	// row trigger long enough for this privileged DELETE, then re-enable before
	// commit. Concurrent old prepared statements cannot interleave.
	if _, err := tx.Exec(ctx, `ALTER TABLE legacy_consume_exclusions DISABLE TRIGGER legacy_consume_rows_immutable`); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM legacy_consume_exclusions`)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE legacy_consume_exclusions ENABLE TRIGGER legacy_consume_rows_immutable`); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CheckRuntime refuses to serve v6 with a migration/owner credential or a
// runtime role unable to read exclusions and atomically insert/release claims.
// The operator grants these narrowly after the maintenance cutover.
func CheckRuntime(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	var name string
	var super bool
	if err := pool.QueryRow(ctx, `SELECT current_user, rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&name, &super); err != nil {
		return fmt.Errorf("pgschema: runtime identity: %w", err)
	}
	if super {
		return fmt.Errorf("pgschema: runtime role %q must not be superuser", name)
	}
	// Every table in the schema, not a fixed list: owning any Averin table lets the runtime ALTER it,
	// disable its immutability triggers or grant itself back what the migration revoked.
	var owned string
	err = pool.QueryRow(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=current_schema() AND c.relkind IN ('r','p')
		AND pg_has_role(current_user,c.relowner,'MEMBER')
		ORDER BY c.relname LIMIT 1`).Scan(&owned)
	if err == nil {
		return fmt.Errorf("pgschema: runtime role %q owns or inherits owner membership for %s; use a distinct least-privilege identity", name, owned)
	}
	if err != pgx.ErrNoRows {
		return fmt.Errorf("pgschema: runtime ownership: %w", err)
	}
	var version int
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil || version != CurrentSchemaVersion {
		return fmt.Errorf("pgschema: runtime schema version %d, want %d: %v", version, CurrentSchemaVersion, err)
	}
	var cutoverRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM nonce_ledger_cutover
		WHERE singleton AND legacy_exclusion_until>cutover_at`).Scan(&cutoverRows); err != nil || cutoverRows != 1 {
		return fmt.Errorf("pgschema: runtime cutover metadata is missing or invalid: rows=%d err=%v", cutoverRows, err)
	}
	// Append-only and immutable tables: the runtime must hold NO mutation privilege, effective through any
	// inherited role (has_table_privilege), even though triggers also guard some of them. This mirrors the
	// migrations' REVOKEs: broker_seq keeps DELETE (ReleaseBrokerSeq frees an unrecorded max allocation),
	// display_seq and project_write_guard keep UPDATE (counter / authorization order).
	appendOnly := []struct {
		table     string
		forbidden []string
	}{
		{"records", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"checkpoints", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"anchors", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"disclosures", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"broker_seq", []string{"UPDATE", "TRUNCATE"}},
		{"broker_seq_void", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"broker_seq_recovery_fence", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"broker_seq_recovery_result", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"display_seq", []string{"DELETE", "TRUNCATE"}},
		{"project_write_guard", []string{"DELETE", "TRUNCATE"}},
		{"authorization_receipts", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"revocation_events", []string{"UPDATE", "DELETE", "TRUNCATE"}},
		{"legacy_boolean_revocations", []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"}},
		{"legacy_consume_exclusions", []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"}},
		{"nonce_ledger_cutover", []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"}},
		{"schema_migrations", []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE"}},
	}
	for _, t := range appendOnly {
		var present bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, t.table).Scan(&present); err != nil {
			return fmt.Errorf("pgschema: runtime append-only probe %s: %w", t.table, err)
		}
		if !present {
			return fmt.Errorf("pgschema: append-only table %s is missing at schema version %d", t.table, version)
		}
		for _, privilege := range t.forbidden {
			var held bool
			if err := pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,to_regclass($1),$2)`, t.table, privilege).Scan(&held); err != nil {
				return fmt.Errorf("pgschema: runtime privilege %s on %s: %w", privilege, t.table, err)
			}
			if held {
				return fmt.Errorf("pgschema: runtime role %q holds %s on append-only table %s (directly or through a role); revoke it before serving", name, privilege, t.table)
			}
		}
	}
	for table, privileges := range map[string][]string{
		"schema_migrations":         {"SELECT"},
		"legacy_consume_exclusions": {"SELECT"},
		"nonce_ledger_cutover":      {"SELECT"},
		"consumed_nonces":           {"SELECT", "INSERT", "DELETE"},
		"consumed_jtis":             {"SELECT", "INSERT", "DELETE"},
		"records":                   {"SELECT", "INSERT"},
		"broker_seq":                {"SELECT", "INSERT"},
		"project_write_guard":       {"SELECT", "INSERT", "UPDATE"},
		"authorization_receipts":    {"SELECT", "INSERT"},
		"revocation_events":         {"SELECT", "INSERT"},
	} {
		for _, privilege := range privileges {
			var allowed bool
			if err := pool.QueryRow(ctx, `SELECT COALESCE(has_table_privilege(current_user,to_regclass($1),$2),false)`, table, privilege).Scan(&allowed); err != nil {
				return fmt.Errorf("pgschema: runtime privilege %s on %s: %w", privilege, table, err)
			}
			if !allowed {
				return fmt.Errorf("pgschema: runtime role %q needs %s on %s", name, privilege, table)
			}
		}
	}
	return nil
}
