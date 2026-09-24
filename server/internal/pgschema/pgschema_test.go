package pgschema

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests require a real Postgres. They are hermetic: each creates a private, randomly named schema
// (via search_path so the migration's unqualified table names resolve there), runs against it, and drops
// it. Set AVERIN_TEST_DATABASE_URL (e.g. postgres://postgres:postgres@localhost:5432/postgres) to enable.

// newTestSchema creates an isolated schema and returns a DSN scoped to it (for Migrate), a pool also
// scoped to it (for assertions), and a cleanup that closes the pool and drops the schema.
func newTestSchema(t *testing.T) (scopedDSN string, admin *pgxpool.Pool, cleanup func()) {
	t.Helper()
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run Postgres-backed pgschema tests")
	}
	schema := fmt.Sprintf("averin_pgschema_test_%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	root, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect (root): %v", err)
	}
	if _, err := root.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		root.Close()
		t.Fatalf("create schema: %v", err)
	}

	scopedDSN = base + "&search_path=" + schema
	admin, err = pgxpool.New(ctx, scopedDSN)
	if err != nil {
		root.Close()
		t.Fatalf("connect (scoped): %v", err)
	}
	cleanup = func() {
		admin.Close()
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		if _, err := root.Exec(dctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Logf("cleanup: drop schema %s: %v", schema, err)
		}
		root.Close()
	}
	return scopedDSN, admin, cleanup
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
	for _, tbl := range []string{"records", "checkpoints", "anchors", "disclosures", "display_seq", "broker_seq", "consume_ledger", "revocations", "pending_grants", "broker_seq_recovery_fence", "broker_seq_recovery_result"} {
		if !regExists(t, admin, tbl) {
			t.Fatalf("baseline table %q missing after migrate", tbl)
		}
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
	if err := Migrate(ctx, scoped); err != nil {
		t.Fatalf("adopt migrate: %v", err)
	}
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
		if err := Migrate(ctx, scoped); err != nil {
			t.Fatalf("migrate v1->current: %v", err)
		}
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
		if err := Migrate(ctx, scoped); err != nil {
			t.Fatalf("a long historical record_id must NOT make the migration refuse to boot: %v", err)
		}
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
		if err := Migrate(ctx, scoped); err != nil {
			t.Fatalf("a historical duplicate must NOT make the migration refuse to boot: %v", err)
		}
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
	if err := Migrate(ctx, scoped); err != nil {
		t.Fatalf("migrate v2->v3: %v", err)
	}
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
