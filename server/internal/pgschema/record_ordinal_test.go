package pgschema

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRecordOrdinalBackfillFromV7 migrates a stamped v7 database that already holds records to v8 and
// proves the documented backfill: per project, ordinals 1..n in (inserted_at, ctid) order (the order the
// store read records until now, the one every existing checkpoint's record_count was cut against), not in
// physical insert order; one project's numbering is independent of the other's; the column is NOT NULL and
// unique afterwards; and a record inserted after the migration continues the numbering with no gap.
func TestRecordOrdinalBackfillFromV7(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	for v := 1; v <= 7; v++ {
		if _, err := admin.Exec(ctx, steps[v-1]); err != nil {
			t.Fatalf("apply v%d: %v", v, err)
		}
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (1),(2),(3),(4),(5),(6),(7) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if regColumn(t, admin, "records", "ord") {
		t.Fatal("precondition: v7 must not have records.ord")
	}
	// Physical insert order differs from inserted_at order on purpose; an inserted_at tie is broken by ctid.
	for _, r := range []struct{ project, hash, at string }{
		{"pa", "a-late", "2026-03-01"},
		{"pb", "b-1", "2026-01-01"},
		{"pa", "a-early", "2026-01-01"},
		{"pa", "a-mid", "2026-02-01"},
		{"pa", "a-mid-tie", "2026-02-01"},
		{"pb", "b-0", "2025-12-01"},
	} {
		if _, err := admin.Exec(ctx, `INSERT INTO records(project_id, idempotency_key, content_hash, session_id, json, inserted_at)
			VALUES ($1, $2, $2, 's', '{}', $3::timestamptz)`, r.project, r.hash, r.at); err != nil {
			t.Fatal(err)
		}
	}
	migrateExisting(t, scoped, admin)
	if got := maxVersion(t, admin); got != CurrentSchemaVersion {
		t.Fatalf("version = %d, want %d", got, CurrentSchemaVersion)
	}
	order := func(project string) string {
		rows, err := admin.Query(ctx, `SELECT content_hash, ord FROM records WHERE project_id=$1 ORDER BY ord`, project)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		s := ""
		for rows.Next() {
			var h string
			var o int64
			if err := rows.Scan(&h, &o); err != nil {
				t.Fatal(err)
			}
			s += fmt.Sprintf("%d=%s ", o, h)
		}
		return s
	}
	if got, want := order("pa"), "1=a-early 2=a-mid 3=a-mid-tie 4=a-late "; got != want {
		t.Fatalf("pa backfill = %q, want %q", got, want)
	}
	if got, want := order("pb"), "1=b-0 2=b-1 "; got != want {
		t.Fatalf("pb backfill = %q, want %q", got, want)
	}
	// Positive and unique: a bad explicit ordinal is rejected.
	for _, sql := range []string{
		`INSERT INTO records(project_id, idempotency_key, content_hash, session_id, json, ord) VALUES ('pa','x2','x2','s','{}',0)`,
		`INSERT INTO records(project_id, idempotency_key, content_hash, session_id, json, ord) VALUES ('pa','x3','x3','s','{}',2)`,
	} {
		if _, err := admin.Exec(ctx, sql); err == nil {
			t.Fatalf("accepted a record with a bad ordinal: %s", sql)
		}
	}
	// A record without an ordinal is numbered by the trigger: max+1 of its project, no gap.
	if _, err := admin.Exec(ctx, `INSERT INTO records(project_id, idempotency_key, content_hash, session_id, json) VALUES ('pa','x1','x1','s','{}')`); err != nil {
		t.Fatal(err)
	}
	var notNull bool
	if err := admin.QueryRow(ctx, `SELECT attnotnull FROM pg_attribute WHERE attrelid='records'::regclass AND attname='ord'`).Scan(&notNull); err != nil || !notNull {
		t.Fatalf("records.ord NOT NULL = %v (%v)", notNull, err)
	}
	var assigned int64
	if err := admin.QueryRow(ctx, `SELECT ord FROM records WHERE content_hash='x1'`).Scan(&assigned); err != nil || assigned != 5 {
		t.Fatalf("trigger-assigned ordinal = %d (%v), want 5 (max+1, no gap)", assigned, err)
	}
	// A record in a project with no history starts at 1.
	if _, err := admin.Exec(ctx, `INSERT INTO records(project_id, idempotency_key, content_hash, session_id, json) VALUES ('pc','c1','c1','s','{}')`); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT ord FROM records WHERE content_hash='c1'`).Scan(&assigned); err != nil || assigned != 1 {
		t.Fatalf("first ordinal of a new project = %d (%v), want 1", assigned, err)
	}
}

func regColumn(t *testing.T, admin *pgxpool.Pool, table, col string) bool {
	t.Helper()
	var n int
	if err := admin.QueryRow(context.Background(), `SELECT count(*) FROM pg_attribute WHERE attrelid=$1::regclass AND attname=$2 AND NOT attisdropped`, table, col).Scan(&n); err != nil {
		t.Fatalf("column probe: %v", err)
	}
	return n > 0
}
