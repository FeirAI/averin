package pgschema

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests require a real Postgres. They are hermetic: each creates a private, randomly named
// DATABASE holding a private schema (via search_path so the migration's unqualified table names resolve
// there), runs against it, and drops it. A database per test is needed because an advancing cutover
// refuses while ANY other client is connected to its database (review S-M4); other packages' tests share
// the base database. Set AVERIN_TEST_DATABASE_URL (a role with CREATEDB and CREATEROLE) to enable.

const adminAppName = "averin_pgschema_admin"

// quiesce records, per scoped DSN, how to close the test's own admin connections before an advancing
// cutover (whose barrier refuses any other client backend in the database).
var quiesce sync.Map // scoped DSN -> func(t *testing.T)

// newTestSchema creates an isolated database + schema and returns a DSN scoped to it (for Migrate), a pool
// also scoped to it (for assertions), and a cleanup that closes the pool and drops the database.
func newTestSchema(t *testing.T) (scopedDSN string, admin *pgxpool.Pool, cleanup func()) {
	t.Helper()
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run Postgres-backed pgschema tests")
	}
	suffix := time.Now().UnixNano()
	dbName := fmt.Sprintf("averin_pgschema_db_%d", suffix)
	schema := fmt.Sprintf("averin_pgschema_test_%d", suffix)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	root, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect (root): %v", err)
	}
	if _, err := root.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		root.Close()
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		root.Close()
		t.Fatalf("parse base dsn: %v", err)
	}
	u.Path = "/" + dbName
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	scopedDSN = u.String()
	q.Set("application_name", adminAppName)
	u.RawQuery = q.Encode()
	admin, err = pgxpool.New(ctx, u.String())
	if err != nil {
		root.Close()
		t.Fatalf("connect (scoped): %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		root.Close()
		t.Fatalf("create schema: %v", err)
	}
	quiesce.Store(scopedDSN, func(t *testing.T) {
		t.Helper()
		admin.Reset()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var n int
			if err := root.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
				WHERE datname=$1 AND application_name=$2`, dbName, adminAppName).Scan(&n); err != nil {
				t.Fatalf("inspect admin sessions: %v", err)
			}
			if n == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d admin session(s) still connected", n)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	cleanup = func() {
		quiesce.Delete(scopedDSN)
		admin.Close()
		dctx, dcancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer dcancel()
		if _, err := root.Exec(dctx, "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)"); err != nil {
			t.Logf("cleanup: drop database %s: %v", dbName, err)
		}
		root.Close()
	}
	return scopedDSN, admin, cleanup
}

// cutover runs an advancing (or no-op) maintenance cutover after closing this test's own admin
// connections; the admin pool reconnects on its next use.
func cutover(t *testing.T, dsn string, oldRoles []string, next string) error {
	t.Helper()
	if q, ok := quiesce.Load(dsn); ok {
		q.(func(*testing.T))(t)
	}
	return Cutover(context.Background(), dsn, oldRoles, next)
}

func maxVersion(t *testing.T, admin *pgxpool.Pool) int {
	t.Helper()
	var v int
	if err := admin.QueryRow(context.Background(), `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		t.Fatalf("read max version: %v", err)
	}
	return v
}

func regExists(t *testing.T, admin *pgxpool.Pool, name string) bool {
	t.Helper()
	var reg *string
	if err := admin.QueryRow(context.Background(), `SELECT to_regclass($1)::text`, name).Scan(&reg); err != nil {
		t.Fatalf("to_regclass(%q): %v", name, err)
	}
	return reg != nil
}

func migrateExisting(t *testing.T, dsn string, admin *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	old, next := "averin_old_"+suffix, "averin_new_"+suffix
	for _, sql := range []string{"CREATE ROLE " + old + " NOLOGIN", "CREATE ROLE " + next + " LOGIN"} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+old)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+next)
	}()
	if err := cutover(t, dsn, []string{old}, next); err != nil {
		t.Fatalf("maintenance cutover: %v", err)
	}
}

// TestMigrateFreshAdoptsCurrentAndIsIdempotent: a fresh DB migrates to CurrentSchemaVersion, creating
// every baseline table, and a SECOND migrate is a steady-state no-op — it issues no DDL and does NOT
// re-stamp (the row count and the v1 applied_at are unchanged), which is what lets the runtime role drop
// CREATE/ALTER.
func TestMigrateFreshAdoptsCurrentAndIsIdempotent(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()

	if err := Migrate(ctx, scoped); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if got := maxVersion(t, admin); got != CurrentSchemaVersion {
		t.Fatalf("version after migrate = %d, want %d", got, CurrentSchemaVersion)
	}
	// Every baseline table from all three folded stores must exist under the single version.
	for _, tbl := range []string{"records", "checkpoints", "anchors", "disclosures", "display_seq", "broker_seq", "legacy_consume_exclusions", "consumed_nonces", "consumed_jtis", "nonce_ledger_cutover", "legacy_boolean_revocations", "revocation_events", "authorization_receipts", "pending_grants", "broker_seq_recovery_fence", "broker_seq_recovery_result"} {
		if !regExists(t, admin, tbl) {
			t.Fatalf("baseline table %q missing after migrate", tbl)
		}
	}
	if regExists(t, admin, "consume_ledger") {
		t.Fatal("old writable ledger relation survives v6")
	}
	if regExists(t, admin, "revocations") {
		t.Fatal("old boolean revocation relation survives v7")
	}

	// Capture the steady-state fingerprint: one stamp per version, and v1's applied_at.
	var rowCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != CurrentSchemaVersion {
		t.Fatalf("schema_migrations row count = %d, want %d (exactly one stamp per applied version)", rowCount, CurrentSchemaVersion)
	}
	var appliedAt time.Time
	if err := admin.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version=$1`, CurrentSchemaVersion).Scan(&appliedAt); err != nil {
		t.Fatalf("read applied_at: %v", err)
	}

	// Steady state: a second migrate must succeed as a pure no-op — no new stamp, no changed timestamp.
	if err := Migrate(ctx, scoped); err != nil {
		t.Fatalf("second (steady-state) migrate: %v", err)
	}
	var rowCount2 int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&rowCount2); err != nil {
		t.Fatalf("count rows (2): %v", err)
	}
	if rowCount2 != rowCount {
		t.Fatalf("steady-state migrate changed schema_migrations row count %d -> %d (it re-stamped)", rowCount, rowCount2)
	}
	var appliedAt2 time.Time
	if err := admin.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version=$1`, CurrentSchemaVersion).Scan(&appliedAt2); err != nil {
		t.Fatalf("read applied_at (2): %v", err)
	}
	if !appliedAt2.Equal(appliedAt) {
		t.Fatalf("steady-state migrate re-stamped v%d (applied_at %v -> %v); it must be a no-op", CurrentSchemaVersion, appliedAt, appliedAt2)
	}
}

// TestMigrateBaselineAdoptIsNoOpOnExistingData: an existing UNSTAMPED store (today's baseline DDL applied
// directly, carrying data, with no schema_migrations) reads as v0 and adopts v1 WITHOUT touching data —
// the adopt must never rebuild or drop, because the v1 step is exactly today's idempotent DDL.
func TestMigrateBaselineAdoptIsNoOpOnExistingData(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()

	// Simulate a pre-migration averin DB: today's baseline DDL applied directly, no version stamp.
	if _, err := admin.Exec(ctx, baselineV1); err != nil {
		t.Fatalf("apply baseline (existing store): %v", err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json)
		VALUES ('p','k','sha256:pre','s','{}','{}')`); err != nil {
		t.Fatalf("seed pre-existing record: %v", err)
	}
	if regExists(t, admin, "schema_migrations") {
		t.Fatal("precondition failed: schema_migrations must not exist yet (this simulates an unstamped store)")
	}

	// Adopt the stamp (v0 -> v1). Must be a no-op on data.
	migrateExisting(t, scoped, admin)
	if got := maxVersion(t, admin); got != CurrentSchemaVersion {
		t.Fatalf("version after adopt = %d, want %d", got, CurrentSchemaVersion)
	}
	var n int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM records WHERE content_hash='sha256:pre'`).Scan(&n); err != nil {
		t.Fatalf("count pre-existing record: %v", err)
	}
	if n != 1 {
		t.Fatalf("pre-existing record lost on adopt (count=%d, want 1) — baseline adopt must be non-destructive", n)
	}
}

// TestMigrateNewerVersionFailsClosed: a DB stamped by a NEWER averin than this binary must be a loud,
// fail-CLOSED refusal — never re-migrated backward, never silently opened. The stored (future) stamp
// must be left untouched.
func TestMigrateNewerVersionFailsClosed(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()

	if err := Migrate(ctx, scoped); err != nil {
		t.Fatalf("initial migrate: %v", err)
	}
	// Stamp a version above what this binary understands, as a newer averin release would.
	future := CurrentSchemaVersion + 1
	if _, err := admin.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, future); err != nil {
		t.Fatalf("insert future version: %v", err)
	}

	if err := Migrate(ctx, scoped); err == nil {
		t.Fatal("migrate against a NEWER stored version must fail closed, got nil error")
	}
	// Fail-closed means refuse-and-leave: the future stamp must not have been rewritten or removed.
	if got := maxVersion(t, admin); got != future {
		t.Fatalf("version after fail-closed refusal = %d, want %d (must not mutate the ledger)", got, future)
	}
}

// TestMigrateV2RecordIDUniqueness: the v1→v2 step builds the per-project record_id UNIQUE backstop on a clean
// DB (a second record under the same (project_id, record_id) is then rejected by the database itself), and on
// a DB that ALREADY holds a historical duplicate it must still migrate (never refuse to boot over immutable
// evidence) — building the non-unique index instead.
func TestMigrateV2RecordIDUniqueness(t *testing.T) {
	ctx := context.Background()
	stampV1 := func(t *testing.T, admin *pgxpool.Pool) {
		t.Helper()
		if _, err := admin.Exec(ctx, baselineV1); err != nil {
			t.Fatalf("apply v1 baseline: %v", err)
		}
		if _, err := admin.Exec(ctx, `CREATE TABLE schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
			INSERT INTO schema_migrations (version) VALUES (1)`); err != nil {
			t.Fatalf("stamp v1: %v", err)
		}
	}
	insert := func(admin *pgxpool.Pool, hash, recordID string) error {
		_, err := admin.Exec(ctx, `INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json)
			VALUES ('p', $1, $1, 's', '{}', $2)`, hash, fmt.Sprintf(`{"record_id":%q}`, recordID))
		return err
	}

	t.Run("clean", func(t *testing.T) {
		scoped, admin, cleanup := newTestSchema(t)
		defer cleanup()
		stampV1(t, admin)
		if err := insert(admin, "sha256:a", "r1"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		migrateExisting(t, scoped, admin)
		if got := maxVersion(t, admin); got != CurrentSchemaVersion {
			t.Fatalf("version = %d, want %d", got, CurrentSchemaVersion)
		}
		if !regExists(t, admin, "records_project_record_id_uniq") {
			t.Fatal("clean DB must get the UNIQUE record_id index")
		}
		if err := insert(admin, "sha256:b", "r1"); err == nil {
			t.Fatal("the database must reject a second record under the same (project_id, record_id)")
		}
	})
	t.Run("long historical record_id", func(t *testing.T) {
		// Review finding 4: a pre-cap record with a 3200-byte INCOMPRESSIBLE record_id exceeds the btree row limit
		// (~2704 bytes), so an index over the raw id aborted this step and every replica refused to boot. The index
		// is over md5(record_id): the migration must succeed and the UNIQUE backstop must still hold for it.
		scoped, admin, cleanup := newTestSchema(t)
		defer cleanup()
		stampV1(t, admin)
		raw := make([]byte, 1600)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		long := hex.EncodeToString(raw) // 3200 random hex chars: pglz cannot compress it under the limit
		if err := insert(admin, "sha256:a", long); err != nil {
			t.Fatalf("seed long record_id: %v", err)
		}
		migrateExisting(t, scoped, admin)
		if got := maxVersion(t, admin); got != CurrentSchemaVersion {
			t.Fatalf("version = %d, want %d", got, CurrentSchemaVersion)
		}
		if !regExists(t, admin, "records_project_record_id_uniq") {
			t.Fatal("a clean DB with a long record_id must still get the UNIQUE record_id index")
		}
		if err := insert(admin, "sha256:b", long); err == nil {
			t.Fatal("the database must reject a second record under the same long record_id")
		}
		if err := insert(admin, "sha256:c", long+"x"); err != nil {
			t.Fatalf("a DIFFERENT long record_id must insert: %v", err)
		}
	})
	t.Run("historical duplicate", func(t *testing.T) {
		scoped, admin, cleanup := newTestSchema(t)
		defer cleanup()
		stampV1(t, admin)
		if err := insert(admin, "sha256:a", "r1"); err != nil {
			t.Fatalf("seed a: %v", err)
		}
		if err := insert(admin, "sha256:b", "r1"); err != nil {
			t.Fatalf("seed historical duplicate: %v", err)
		}
		migrateExisting(t, scoped, admin)
		if got := maxVersion(t, admin); got != CurrentSchemaVersion {
			t.Fatalf("version = %d, want %d", got, CurrentSchemaVersion)
		}
		if regExists(t, admin, "records_project_record_id_uniq") || !regExists(t, admin, "records_project_record_id_idx") {
			t.Fatal("a DB with a historical duplicate must get the NON-unique record_id index")
		}
	})
}

// TestMigrateV3BrokerSeqVoid: the v2→v3 step adds broker_seq.allocated_at (existing reservations take the migration
// time, so a pre-upgrade orphan becomes voidable one safety age later) and the insert-only broker_seq_void marker,
// without touching existing broker_seq rows.
func TestMigrateV3BrokerSeqVoid(t *testing.T) {
	ctx := context.Background()
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	if _, err := admin.Exec(ctx, baselineV1+"\n"+steps[1]); err != nil {
		t.Fatalf("apply v1+v2: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
		INSERT INTO schema_migrations (version) VALUES (1), (2);
		INSERT INTO broker_seq (project_id, grant_id, seq) VALUES ('p', 'g-orphan', 1)`); err != nil {
		t.Fatalf("stamp v2 + seed an orphan reservation: %v", err)
	}
	migrateExisting(t, scoped, admin)
	if got := maxVersion(t, admin); got != CurrentSchemaVersion {
		t.Fatalf("version = %d, want %d", got, CurrentSchemaVersion)
	}
	var seq int64
	var allocatedAt time.Time
	if err := admin.QueryRow(ctx, `SELECT seq, allocated_at FROM broker_seq WHERE project_id='p' AND grant_id='g-orphan'`).Scan(&seq, &allocatedAt); err != nil {
		t.Fatalf("the pre-existing reservation must survive with an allocated_at: %v", err)
	}
	if seq != 1 || allocatedAt.IsZero() {
		t.Fatalf("reservation = seq %d allocated_at %v", seq, allocatedAt)
	}
	if !regExists(t, admin, "broker_seq_void") {
		t.Fatal("v3 must create broker_seq_void")
	}
}

func TestTenantNonceCutoverV3V4V5PreservesUnknownOwners(t *testing.T) {
	for _, version := range []int{3, 4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			scoped, admin, cleanup := newTestSchema(t)
			defer cleanup()
			ctx := context.Background()
			for v := 1; v <= version; v++ {
				if _, err := admin.Exec(ctx, steps[v-1]); err != nil {
					t.Fatalf("apply v%d: %v", v, err)
				}
			}
			if _, err := admin.Exec(ctx, `CREATE TABLE schema_migrations(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
				t.Fatal(err)
			}
			for v := 1; v <= version; v++ {
				if _, err := admin.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, v); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := admin.Exec(ctx, `INSERT INTO consume_ledger(kind,consume_key) VALUES ('nonce','unknown-owner'),('jti','used-jti')`); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(ctx, scoped); err == nil {
				t.Fatal("ordinary startup migrated a live legacy schema without maintenance barrier")
			}
			if maxVersion(t, admin) != version {
				t.Fatal("refused startup changed schema version")
			}
			oldConn, err := pgx.Connect(ctx, scoped)
			if err != nil {
				t.Fatal(err)
			}
			defer oldConn.Close(context.Background())
			if _, err := oldConn.Prepare(ctx, "old-insert", `INSERT INTO consume_ledger(kind,consume_key) VALUES ('nonce','old-prepared')`); err != nil {
				t.Fatal(err)
			}
			if _, err := oldConn.Prepare(ctx, "old-delete", `DELETE FROM consume_ledger WHERE consume_key='old-prepared-delete'`); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(ctx, `INSERT INTO consume_ledger(kind,consume_key) VALUES ('nonce','old-prepared-delete')`); err != nil {
				t.Fatal(err)
			}
			if _, err := oldConn.Exec(ctx, `EXECUTE "old-insert"`); err != nil {
				t.Fatalf("old prepared insert did not work before cutover: %v", err)
			}
			deleted, err := oldConn.Exec(ctx, `EXECUTE "old-delete"`)
			if err != nil || deleted.RowsAffected() != 1 {
				t.Fatalf("old prepared delete failed before cutover: rows=%d err=%v", deleted.RowsAffected(), err)
			}
			if _, err := admin.Exec(ctx, `INSERT INTO consume_ledger(kind,consume_key) VALUES ('nonce','old-prepared-delete')`); err != nil {
				t.Fatal(err)
			}
			// A still-connected old writer session blocks the advancing cutover outright (review S-M4), so
			// its prepared statements can never run across the schema step.
			oldRole, nextRole := fmt.Sprintf("averin_blocked_old_%d", time.Now().UnixNano()), fmt.Sprintf("averin_blocked_new_%d", time.Now().UnixNano())
			for _, sql := range []string{"CREATE ROLE " + oldRole + " NOLOGIN", "CREATE ROLE " + nextRole + " LOGIN"} {
				if _, err := admin.Exec(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			defer func() {
				_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+oldRole)
				_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+nextRole)
			}()
			if err := cutover(t, scoped, []string{oldRole}, nextRole); err == nil || !strings.Contains(err.Error(), "client backend") {
				t.Fatalf("cutover proceeded while an old writer session was connected: %v", err)
			}
			if maxVersion(t, admin) != version {
				t.Fatal("refused cutover changed schema version")
			}
			if err := oldConn.Close(ctx); err != nil {
				t.Fatal(err)
			}
			migrateExisting(t, scoped, admin)
			if maxVersion(t, admin) != CurrentSchemaVersion || regExists(t, admin, "consume_ledger") {
				t.Fatal("cutover did not remove old writable relation")
			}
			var legacyCount int
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM legacy_consume_exclusions`).Scan(&legacyCount); err != nil || legacyCount != 4 {
				t.Fatalf("historical rows lost/assigned count=%d err=%v", legacyCount, err)
			}
			for _, sql := range []string{
				`INSERT INTO legacy_consume_exclusions(kind,consume_key) VALUES ('nonce','bypass')`,
				`UPDATE legacy_consume_exclusions SET consume_key='bypass' WHERE consume_key='unknown-owner'`,
				`DELETE FROM legacy_consume_exclusions WHERE consume_key='unknown-owner'`,
				`TRUNCATE legacy_consume_exclusions`,
				`INSERT INTO consume_ledger(kind,consume_key) VALUES ('nonce','old-ordinary')`,
			} {
				if _, err := admin.Exec(ctx, sql); err == nil {
					t.Fatalf("old writer SQL accepted after cutover: %s", sql)
				}
			}
			var retained int
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM legacy_consume_exclusions WHERE consume_key='old-prepared-delete'`).Scan(&retained); err != nil || retained != 1 {
				t.Fatalf("prepared delete removed inherited exclusion: count=%d err=%v", retained, err)
			}
			var before, after time.Time
			if err := admin.QueryRow(ctx, `SELECT legacy_exclusion_until FROM nonce_ledger_cutover`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(ctx, scoped); err != nil {
				t.Fatalf("steady-state migrate: %v", err)
			}
			if err := admin.QueryRow(ctx, `SELECT legacy_exclusion_until FROM nonce_ledger_cutover`).Scan(&after); err != nil || !after.Equal(before) {
				t.Fatalf("repeat migration reset hold before=%v after=%v err=%v", before, after, err)
			}
		})
	}
}

func TestTenantNonceCutoverInterruptedBeforeCommitRetriesOnce(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	for v := 1; v <= 5; v++ {
		if _, err := admin.Exec(ctx, steps[v-1]); err != nil {
			t.Fatalf("apply v%d: %v", v, err)
		}
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE schema_migrations(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for v := 1; v <= 5; v++ {
		if _, err := admin.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, v); err != nil {
			t.Fatal(err)
		}
	}
	var original time.Time
	if err := admin.QueryRow(ctx, `INSERT INTO consume_ledger(kind,consume_key,consumed_at)
		VALUES('nonce','unknown-owner',clock_timestamp()-interval '1 hour') RETURNING consumed_at`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	// A test-owned function conflicts with v6's CREATE FUNCTION, after its
	// ALTER TABLE RENAME has already run. Exercise the real selected Cutover
	// runner and force its transaction to roll back mid-step.
	if _, err := admin.Exec(ctx, `CREATE FUNCTION legacy_consume_reject_mutation() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$`); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	old, next := "averin_old_"+suffix, "averin_new_"+suffix
	for _, sql := range []string{"CREATE ROLE " + old + " NOLOGIN", "CREATE ROLE " + next + " LOGIN"} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+old)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+next)
	}()
	if err := cutover(t, scoped, []string{old}, next); err == nil || !strings.Contains(err.Error(), "apply step v6") {
		t.Fatalf("conflicting function did not abort real v6 cutover: %v", err)
	}
	if got := maxVersion(t, admin); got != 5 {
		t.Fatalf("interrupted cutover left version %d, want v5", got)
	}
	if !regExists(t, admin, "consume_ledger") || regExists(t, admin, "legacy_consume_exclusions") ||
		regExists(t, admin, "consumed_nonces") || regExists(t, admin, "consumed_jtis") ||
		regExists(t, admin, "nonce_ledger_cutover") {
		t.Fatal("interrupted cutover leaked a renamed relation, new claims, or cutoff marker")
	}
	var preserved time.Time
	if err := admin.QueryRow(ctx, `SELECT consumed_at FROM consume_ledger WHERE kind='nonce' AND consume_key='unknown-owner'`).Scan(&preserved); err != nil || !preserved.Equal(original) {
		t.Fatalf("interrupted cutover altered old exclusion: got=%v original=%v err=%v", preserved, original, err)
	}
	if _, err := admin.Exec(ctx, `DROP FUNCTION legacy_consume_reject_mutation()`); err != nil {
		t.Fatal(err)
	}
	// A real authorized retry migrates once; its DB clock marker and the old
	// exclusion remain unchanged on a later steady-state startup.
	if err := cutover(t, scoped, []string{old}, next); err != nil {
		t.Fatalf("retry cutover: %v", err)
	}
	if got := maxVersion(t, admin); got != CurrentSchemaVersion || regExists(t, admin, "consume_ledger") {
		t.Fatalf("retry left version %d or old writable relation", got)
	}
	if err := admin.QueryRow(ctx, `SELECT consumed_at FROM legacy_consume_exclusions WHERE kind='nonce' AND consume_key='unknown-owner'`).Scan(&preserved); err != nil || !preserved.Equal(original) {
		t.Fatalf("retry lost old exclusion: got=%v original=%v err=%v", preserved, original, err)
	}
	var stamped int
	var cutoff time.Time
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=6`).Scan(&stamped); err != nil || stamped != 1 {
		t.Fatalf("retry stamped v6 %d times: %v", stamped, err)
	}
	if err := admin.QueryRow(ctx, `SELECT legacy_exclusion_until FROM nonce_ledger_cutover WHERE singleton`).Scan(&cutoff); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, scoped); err != nil {
		t.Fatal(err)
	}
	var cutoffAfter time.Time
	if err := admin.QueryRow(ctx, `SELECT legacy_exclusion_until FROM nonce_ledger_cutover WHERE singleton`).Scan(&cutoffAfter); err != nil || !cutoffAfter.Equal(cutoff) {
		t.Fatalf("steady-state startup reset cutoff: before=%v after=%v err=%v", cutoff, cutoffAfter, err)
	}
}

func TestTenantNonceCutoverRejectsLiveAndInheritedOldWriter(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	for v := 1; v <= 5; v++ {
		if _, err := admin.Exec(ctx, steps[v-1]); err != nil {
			t.Fatalf("apply v%d: %v", v, err)
		}
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE schema_migrations(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
		INSERT INTO schema_migrations(version) VALUES (1),(2),(3),(4),(5)`); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	old, next, inherited := "averin_live_"+suffix, "averin_next_"+suffix, "averin_group_"+suffix
	for _, sql := range []string{
		"CREATE ROLE " + old + " LOGIN PASSWORD 'temporary-test-only'",
		"CREATE ROLE " + next + " LOGIN",
		"CREATE ROLE " + inherited + " NOLOGIN",
		"GRANT INSERT ON records TO " + inherited,
		"GRANT " + inherited + " TO " + old,
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP OWNED BY "+old+","+next+","+inherited)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+old)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+next)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+inherited)
	}()
	cutover := func() error { return cutover(t, scoped, []string{old}, next) }
	if err := cutover(); err == nil {
		t.Fatal("LOGIN old runtime accepted")
	}
	cfg, err := pgx.ParseConfig(scoped)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = old, "temporary-test-only"
	oldConn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "ALTER ROLE "+old+" NOLOGIN PASSWORD 'rotated-unusable'"); err != nil {
		t.Fatal(err)
	}
	if err := cutover(); err == nil || !strings.Contains(err.Error(), "sessions") {
		t.Fatalf("established old session did not block cutover: %v", err)
	}
	if err := oldConn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cutover(); err == nil || !strings.Contains(err.Error(), "write privilege") {
		t.Fatalf("inherited write privilege did not block cutover: %v", err)
	}
	if _, err := admin.Exec(ctx, "REVOKE "+inherited+" FROM "+old); err != nil {
		t.Fatal(err)
	}
	if err := cutover(); err != nil {
		t.Fatalf("retired old runtime refused: %v", err)
	}
}

func TestTenantNonceRuntimeReadinessRequiresLeastPrivilege(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	if err := Migrate(ctx, scoped); err != nil {
		t.Fatal(err)
	}
	if err := CheckRuntime(ctx, scoped); err == nil {
		t.Fatal("schema owner accepted as runtime")
	}
	role := fmt.Sprintf("averin_runtime_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD 'test-only-password'"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+role)
	}()
	u, err := url.Parse(scoped)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "test-only-password")
	if err := CheckRuntime(ctx, u.String()); err == nil {
		t.Fatal("unprivileged runtime passed readiness")
	}
	var schema string
	if err := admin.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT ON schema_migrations,legacy_consume_exclusions,nonce_ledger_cutover TO " + role,
		"GRANT SELECT,INSERT,DELETE ON consumed_nonces,consumed_jtis TO " + role,
		"GRANT SELECT,INSERT ON records,broker_seq TO " + role,
		"GRANT SELECT,INSERT,UPDATE ON project_write_guard TO " + role,
		"GRANT SELECT,INSERT ON authorization_receipts,revocation_events TO " + role,
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckRuntime(ctx, u.String()); err != nil {
		t.Fatalf("least-privilege runtime not ready: %v", err)
	}
	var owner string
	if err := admin.QueryRow(ctx, `SELECT current_user`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "GRANT "+owner+" TO "+role); err != nil {
		t.Fatal(err)
	}
	if err := CheckRuntime(ctx, u.String()); err == nil || !strings.Contains(err.Error(), "owner membership") {
		t.Fatalf("runtime inherited migration ownership: %v", err)
	}
	if _, err := admin.Exec(ctx, "REVOKE "+owner+" FROM "+role); err != nil {
		t.Fatal(err)
	}
	if err := CheckRuntime(ctx, u.String()); err != nil {
		t.Fatalf("restored least-privilege runtime not ready: %v", err)
	}

	// Review S-M3: no effective mutation privilege on any append-only table, however it is held.
	group := role + "_grp"
	if _, err := admin.Exec(ctx, "CREATE ROLE "+group+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP OWNED BY "+group)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+group)
	}()
	for _, tc := range []struct{ grant, revoke, want string }{
		{"GRANT ALL ON records TO " + role, "REVOKE ALL ON records FROM " + role + "; GRANT SELECT,INSERT ON records TO " + role, "append-only table records"},
		{"GRANT ALL ON ALL TABLES IN SCHEMA " + schema + " TO " + role, "REVOKE ALL ON ALL TABLES IN SCHEMA " + schema + " FROM " + role +
			"; GRANT SELECT ON schema_migrations,legacy_consume_exclusions,nonce_ledger_cutover TO " + role +
			"; GRANT SELECT,INSERT,DELETE ON consumed_nonces,consumed_jtis TO " + role +
			"; GRANT SELECT,INSERT ON records,broker_seq TO " + role +
			"; GRANT SELECT,INSERT,UPDATE ON project_write_guard TO " + role +
			"; GRANT SELECT,INSERT ON authorization_receipts,revocation_events TO " + role, "append-only table"},
		{"GRANT UPDATE ON revocation_events TO " + group + "; GRANT " + group + " TO " + role, "REVOKE " + group + " FROM " + role, "UPDATE on append-only table revocation_events"},
		{"GRANT TRUNCATE ON broker_seq_void TO " + role, "REVOKE TRUNCATE ON broker_seq_void FROM " + role, "TRUNCATE on append-only table broker_seq_void"},
		{"GRANT INSERT ON schema_migrations TO " + role, "REVOKE INSERT ON schema_migrations FROM " + role, "INSERT on append-only table schema_migrations"},
		// Review M1: a column-level grant writes rows too, and a non-inherited membership is usable by SET ROLE.
		{"GRANT UPDATE (json) ON records TO " + role, "REVOKE UPDATE (json) ON records FROM " + role, "UPDATE on append-only table records"},
		{"GRANT INSERT (version) ON schema_migrations TO " + role, "REVOKE INSERT (version) ON schema_migrations FROM " + role, "INSERT on append-only table schema_migrations"},
		{"GRANT DELETE ON anchors TO " + group + "; GRANT " + group + " TO " + role + " WITH INHERIT FALSE", "REVOKE " + group + " FROM " + role, "DELETE on append-only table anchors (through role \"" + group + "\""},
		// Owning ANY table (not just the originally listed nine) is refused.
		{"ALTER TABLE anchors OWNER TO " + role, "ALTER TABLE anchors OWNER TO " + owner, "owns or inherits owner membership for anchors"},
		{"ALTER TABLE pending_grants OWNER TO " + group + "; GRANT " + group + " TO " + role, "REVOKE " + group + " FROM " + role + "; ALTER TABLE pending_grants OWNER TO " + owner, "pending_grants"},
	} {
		if _, err := admin.Exec(ctx, tc.grant); err != nil {
			t.Fatalf("%s: %v", tc.grant, err)
		}
		if err := CheckRuntime(ctx, u.String()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("after %q CheckRuntime = %v, want refusal naming %q", tc.grant, err, tc.want)
		}
		if _, err := admin.Exec(ctx, tc.revoke); err != nil {
			t.Fatalf("%s: %v", tc.revoke, err)
		}
		if err := CheckRuntime(ctx, u.String()); err != nil {
			t.Fatalf("after %q the runtime is not ready again: %v", tc.revoke, err)
		}
	}
}

// Review S-L2: ordinary startup never bootstraps an empty database (the runtime would own the schema and
// fail CheckRuntime forever); `averin-migrate --init` (Migrate) does, and startup then proceeds.
func TestOrdinaryStartupRefusesFreshBootstrap(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	if err := MigrateForRuntime(ctx, scoped); err == nil || !strings.Contains(err.Error(), "averin-migrate --init") {
		t.Fatalf("ordinary startup on an empty database = %v, want refusal naming averin-migrate --init", err)
	}
	if regExists(t, admin, "schema_migrations") || regExists(t, admin, "records") {
		t.Fatal("refused startup created schema objects")
	}
	if initialized, err := Initialize(ctx, scoped); err != nil || !initialized {
		t.Fatalf("init of an empty database: initialized=%v err=%v", initialized, err)
	}
	// A rerun at the current version is a reported no-op (averin-migrate logs "already initialized").
	if initialized, err := Initialize(ctx, scoped); err != nil || initialized {
		t.Fatalf("second init: initialized=%v err=%v, want a no-op", initialized, err)
	}
	if err := MigrateForRuntime(ctx, scoped); err != nil {
		t.Fatalf("ordinary startup after init: %v", err)
	}
}

// Review S-M4: a LOGIN member of a retired role is not named in the barrier. An advancing cutover still
// refuses while it (or any client) is connected, and while it can write through its own grants or any
// role membership, including a non-inherited one reachable only by SET ROLE.
func TestCutoverRefusesUnnamedMemberWriter(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	seedV6(t, admin)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	old, next, member, writers := "averin_v6_group_"+suffix, "averin_v7_rt_"+suffix, "averin_app_login_"+suffix, "averin_writers_"+suffix
	var schema string
	if err := admin.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"CREATE ROLE " + old + " NOLOGIN",
		"CREATE ROLE " + next + " LOGIN",
		"CREATE ROLE " + writers + " NOLOGIN",
		"CREATE ROLE " + member + " LOGIN PASSWORD 'temporary-test-only'",
		"GRANT USAGE ON SCHEMA " + schema + " TO " + member,
		"GRANT " + old + " TO " + member,
		"GRANT SELECT, INSERT ON records TO " + member,
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	defer func() {
		for _, r := range []string{member, writers, next, old} {
			_, _ = admin.Exec(context.Background(), "DROP OWNED BY "+r)
			_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+r)
		}
	}()
	cfg, err := pgx.ParseConfig(scoped)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = member, "temporary-test-only"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SET ROLE "+old); err != nil {
		t.Fatal(err)
	}
	if err := cutover(t, scoped, []string{old}, next); err == nil || !strings.Contains(err.Error(), "client backend") || !strings.Contains(err.Error(), member) {
		t.Fatalf("cutover with a connected member of the retired role = %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cutover(t, scoped, []string{old}, next); err == nil || !strings.Contains(err.Error(), member) || !strings.Contains(err.Error(), "records") {
		t.Fatalf("cutover with a disconnected but still-writable member login = %v", err)
	}
	// Only a non-inherited membership remains: has_table_privilege(member) is false, but SET ROLE writes.
	for _, sql := range []string{
		"REVOKE INSERT ON records FROM " + member,
		"GRANT INSERT ON broker_seq TO " + writers,
		"GRANT " + writers + " TO " + member + " WITH INHERIT FALSE",
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if err := cutover(t, scoped, []string{old}, next); err == nil || !strings.Contains(err.Error(), member) || !strings.Contains(err.Error(), "broker_seq") {
		t.Fatalf("cutover with a SET ROLE-reachable writer = %v", err)
	}
	if maxVersion(t, admin) != 6 {
		t.Fatal("refused cutovers changed the schema version")
	}
	if _, err := admin.Exec(ctx, "REVOKE "+writers+" FROM "+member); err != nil {
		t.Fatal(err)
	}
	if err := cutover(t, scoped, []string{old}, next); err != nil {
		t.Fatalf("cutover after retiring every writer: %v", err)
	}
	if maxVersion(t, admin) != CurrentSchemaVersion {
		t.Fatal("authorized cutover did not advance")
	}
}

func TestTenantNonceLegacyPurgeRequiresDBTimeHold(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	if err := Migrate(ctx, scoped); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	old, next := "averin_purge_old_"+suffix, "averin_purge_new_"+suffix
	for _, sql := range []string{"CREATE ROLE " + old + " NOLOGIN", "CREATE ROLE " + next + " LOGIN"} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+old)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+next)
	}()
	for _, sql := range []string{
		`ALTER TABLE legacy_consume_exclusions DISABLE TRIGGER legacy_consume_rows_immutable`,
		`INSERT INTO legacy_consume_exclusions(kind,consume_key) VALUES ('nonce','unowned')`,
		`ALTER TABLE legacy_consume_exclusions ENABLE TRIGGER legacy_consume_rows_immutable`,
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := PurgeLegacy(ctx, scoped, []string{old}, next); err == nil {
		t.Fatal("legacy exclusion purged before database-time hold elapsed")
	}
	for _, sql := range []string{
		`ALTER TABLE nonce_ledger_cutover DISABLE TRIGGER nonce_cutover_rows_immutable`,
		`UPDATE nonce_ledger_cutover SET cutover_at=clock_timestamp()-interval '25 hours', legacy_exclusion_until=clock_timestamp()-interval '1 hour'`,
		`ALTER TABLE nonce_ledger_cutover ENABLE TRIGGER nonce_cutover_rows_immutable`,
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	n, err := PurgeLegacy(ctx, scoped, []string{old}, next)
	if err != nil || n != 1 {
		t.Fatalf("mature purge rows=%d err=%v", n, err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO legacy_consume_exclusions(kind,consume_key) VALUES ('nonce','old-writer')`); err == nil {
		t.Fatal("legacy table became writable after maintenance purge")
	}
}

func TestTenantNonceOrdinaryStartupRefusesEmptyLegacyVersionTable(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := admin.Exec(ctx, `CREATE TABLE schema_migrations(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, scoped); err == nil {
		t.Fatal("preexisting empty version table bypassed maintenance cutover")
	}
	if regExists(t, admin, "records") {
		t.Fatal("refused migration changed legacy schema")
	}
}
