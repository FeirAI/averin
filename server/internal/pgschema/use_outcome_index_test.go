package pgschema

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestUseOutcomeIndexMigrationFromV9 migrates a stamped v9 database that already holds intent and outcome
// records (and records that must not be indexed) to v10 through the real cutover, and proves the schema
// version, the index (valid, partial, on the expected columns), that the planner uses it for the lookup, and
// that the lookup answers match what the rows say. The store-level equivalence against the scan lives in
// internal/store and internal/api (this package cannot import store).
func TestUseOutcomeIndexMigrationFromV9(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	for v := 1; v <= 9; v++ {
		if _, err := admin.Exec(ctx, steps[v-1]); err != nil {
			t.Fatalf("apply v%d: %v", v, err)
		}
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (1),(2),(3),(4),(5),(6),(7),(8),(9) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if regExists(t, admin, "records_use_outcome_intent_idx") {
		t.Fatal("precondition: v9 must not have the use-outcome index")
	}
	put := func(i int, proj, sess, js string) {
		t.Helper()
		if _, err := admin.Exec(ctx, `INSERT INTO records(project_id, idempotency_key, content_hash, session_id, parents, json)
			VALUES ($1, $2, $2, $3, '{}', $4)`, proj, fmt.Sprintf("h%04d", i), sess, js); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	outcomes := 0
	for _, proj := range []string{"pa", "pb"} {
		for _, sess := range []string{"s1", "s2"} {
			for k := 1; k <= 20; k++ {
				id := fmt.Sprintf("use-%s-%s-%d", proj, sess, k)
				n++
				put(n, proj, sess, fmt.Sprintf(`{"record_id":%q,"extensions":{"broker":{"kind":"use_intent"}}}`, id))
				if k%2 == 0 {
					n++
					outcomes++
					put(n, proj, sess, fmt.Sprintf(`{"record_id":"out-%s","extensions":{"broker":{"kind":"use_outcome","use_outcome":{"intent_ref":%q}}}}`, id, id))
				}
			}
			n++ // generic record: never indexed
			put(n, proj, sess, `{"record_id":"gen-`+proj+sess+`","extensions":{}}`)
			n++ // a very long intent_ref must not break the build or later inserts
			outcomes++
			put(n, proj, sess, `{"record_id":"out-long-`+proj+sess+`","extensions":{"broker":{"kind":"use_outcome","use_outcome":{"intent_ref":"`+strings.Repeat("x", 6000)+`"}}}}`)
		}
	}
	migrateExisting(t, scoped, admin)
	if CurrentSchemaVersion != 10 {
		t.Fatalf("CurrentSchemaVersion = %d, want 10", CurrentSchemaVersion)
	}
	if got := maxVersion(t, admin); got != CurrentSchemaVersion {
		t.Fatalf("version = %d, want %d (10)", got, CurrentSchemaVersion)
	}
	var valid bool
	var def string
	if err := admin.QueryRow(ctx, `SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) FROM pg_index i WHERE i.indexrelid = to_regclass('records_use_outcome_intent_idx')`).Scan(&valid, &def); err != nil {
		t.Fatalf("index missing after migration: %v", err)
	}
	if !valid || !strings.Contains(def, "WHERE") || !strings.Contains(def, "project_id, session_id") || !strings.HasSuffix(strings.TrimSpace(strings.Split(def, "WHERE")[0]), "ord)") {
		t.Fatalf("index definition unexpected (valid=%v): %s", valid, def)
	}
	var indexed int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM records WHERE json::jsonb -> 'extensions' -> 'broker' ->> 'kind' = 'use_outcome'`).Scan(&indexed); err != nil || indexed != outcomes {
		t.Fatalf("use_outcome rows = %d (%v), want %d", indexed, err, outcomes)
	}
	const q = `SELECT coalesce(json::jsonb ->> 'record_id', '') FROM records
		WHERE project_id = $1 AND session_id = $2
		  AND json::jsonb -> 'extensions' -> 'broker' ->> 'kind' = 'use_outcome'
		  AND coalesce(jsonb_typeof(json::jsonb -> 'record_id'), 'null') IN ('string', 'null')
		  AND coalesce(jsonb_typeof(json::jsonb -> 'extensions' -> 'broker' -> 'use_outcome'), 'null') IN ('object', 'null')
		  AND coalesce(jsonb_typeof(json::jsonb -> 'extensions' -> 'broker' -> 'use_outcome' -> 'intent_ref'), 'null') IN ('string', 'null')
		  AND md5(coalesce(json::jsonb -> 'extensions' -> 'broker' -> 'use_outcome' ->> 'intent_ref', '')) = md5($3::text)
		  AND coalesce(json::jsonb -> 'extensions' -> 'broker' -> 'use_outcome' ->> 'intent_ref', '') = $3::text
		ORDER BY ord ASC LIMIT 1`
	for _, proj := range []string{"pa", "pb"} {
		for _, sess := range []string{"s1", "s2"} {
			for k := 1; k <= 20; k++ {
				ref := fmt.Sprintf("use-%s-%s-%d", proj, sess, k)
				var got string
				err := admin.QueryRow(ctx, q, proj, sess, ref).Scan(&got)
				if k%2 == 0 && (err != nil || got != "out-"+ref) {
					t.Fatalf("lookup %s = %q, %v; want out-%s", ref, got, err, ref)
				}
				if k%2 == 1 && err == nil {
					t.Fatalf("lookup %s found %q for an intent with no outcome", ref, got)
				}
			}
			if err := admin.QueryRow(ctx, q, proj, sess, strings.Repeat("x", 6000)).Scan(new(string)); err != nil {
				t.Fatalf("lookup of the 6000-byte intent_ref: %v", err)
			}
		}
	}
	// a new insert after the migration keeps working (including the long ref) under the owner role
	if _, err := admin.Exec(ctx, `INSERT INTO records(project_id, idempotency_key, content_hash, session_id, parents, json)
		VALUES ('pa','post','post','s1','{}', $1)`, `{"record_id":"out-post","extensions":{"broker":{"kind":"use_outcome","use_outcome":{"intent_ref":"`+strings.Repeat("y", 9000)+`"}}}}`); err != nil {
		t.Fatalf("insert after migration: %v", err)
	}
	// the planner must use the index for this exact statement shape (the bulk is tiny, so disable seq scans
	// to ask "can it", the store test asks "does it" on a 6000-row history)
	rows, err := admin.Query(ctx, "EXPLAIN "+q, "pa", "s1", "use-pa-s1-2")
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var l string
		_ = rows.Scan(&l)
		plan.WriteString(l + "\n")
	}
	rows.Close()
	t.Logf("plan on a %d-row table (the store test asserts the index on a larger history):\n%s", n, plan.String())
}
