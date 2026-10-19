package pgschema

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSessionHeadsBackfillFromV8 migrates a stamped v8 database that already holds a random DAG (forks,
// merges, parents in another session, duplicate parents, dangling references, several projects and
// sessions) to v9 and proves the backfilled session_heads equals the full-scan definition for every
// (project, session), and that the runtime-facing shape is right: composite primary key, no extra rows.
func TestSessionHeadsBackfillFromV8(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	for v := 1; v <= 8; v++ {
		if _, err := admin.Exec(ctx, steps[v-1]); err != nil {
			t.Fatalf("apply v%d: %v", v, err)
		}
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (1),(2),(3),(4),(5),(6),(7),(8) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if regTable(t, admin, "session_heads") {
		t.Fatal("precondition: v8 must not have session_heads")
	}
	rng := rand.New(rand.NewSource(7))
	projects := []string{"pa", "pb", "pc"}
	sessions := []string{"s1", "s2", "s3"}
	const n = 300
	placed := map[string][]string{}
	for i := 1; i <= n; i++ {
		proj := projects[rng.Intn(len(projects))]
		sess := sessions[rng.Intn(len(sessions))]
		hash := fmt.Sprintf("h%04d", i)
		var parents []string
		for k := rng.Intn(4); k > 0; k-- {
			switch rng.Intn(4) {
			case 0, 1: // an earlier record of the project, any session (cross-session when it differs)
				if ps := placed[proj]; len(ps) > 0 {
					parents = append(parents, ps[rng.Intn(len(ps))])
				}
			case 2: // duplicate of what is already listed
				parents = append(parents, parents...)
			case 3: // dangling forward reference
				parents = append(parents, fmt.Sprintf("h%04d", i+1+rng.Intn(10)))
			}
		}
		if parents == nil {
			parents = []string{}
		}
		if _, err := admin.Exec(ctx, `INSERT INTO records(project_id, idempotency_key, content_hash, session_id, parents, json)
			VALUES ($1, $2, $2, $3, $4, '{}')`, proj, hash, sess, parents); err != nil {
			t.Fatal(err)
		}
		placed[proj] = append(placed[proj], hash)
	}
	migrateExisting(t, scoped, admin)
	if got := maxVersion(t, admin); got != CurrentSchemaVersion {
		t.Fatalf("version = %d, want %d", got, CurrentSchemaVersion)
	}
	total := 0
	for _, proj := range projects {
		for _, sess := range sessions {
			got := sessionHeadsRows(t, admin, proj, sess)
			want := fullHeads(t, admin, proj, sess)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("session_heads(%s,%s) = %v, full scan = %v", proj, sess, got, want)
			}
			total += len(got)
		}
	}
	var rows int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM session_heads`).Scan(&rows); err != nil || rows != total {
		t.Fatalf("session_heads has %d rows, the checked sessions account for %d (%v)", rows, total, err)
	}
	if total == 0 {
		t.Fatal("vacuous: the generated history has no heads")
	}
	if _, err := admin.Exec(ctx, `INSERT INTO session_heads(project_id, session_id, content_hash) VALUES ('pa','s1','dup'),('pa','s1','dup')`); err == nil {
		t.Fatal("session_heads accepted a duplicate (project, session, content_hash)")
	}
}

func regTable(t *testing.T, admin *pgxpool.Pool, table string) bool {
	t.Helper()
	var ok bool
	if err := admin.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

func sessionHeadsRows(t *testing.T, admin *pgxpool.Pool, proj, sess string) []string {
	t.Helper()
	return collect(t, admin, `SELECT content_hash FROM session_heads WHERE project_id=$1 AND session_id=$2 ORDER BY content_hash`, proj, sess)
}

// fullHeads is the pre-0009 Heads() query: the definition the table must equal.
func fullHeads(t *testing.T, admin *pgxpool.Pool, proj, sess string) []string {
	t.Helper()
	return collect(t, admin, `SELECT DISTINCT r.content_hash FROM records r
		WHERE r.project_id=$1 AND r.session_id=$2
		  AND NOT EXISTS (SELECT 1 FROM records c WHERE c.project_id=$1 AND c.session_id=$2 AND c.parents @> ARRAY[r.content_hash])
		ORDER BY r.content_hash ASC`, proj, sess)
}

func collect(t *testing.T, admin *pgxpool.Pool, sql string, args ...any) []string {
	t.Helper()
	rows, err := admin.Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		out = append(out, h)
	}
	return out
}
