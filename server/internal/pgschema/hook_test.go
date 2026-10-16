package pgschema

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests cover Hook (the body of `averin-migrate --hook`) against a real Postgres, one private
// database per test (see newTestSchema).

func legacyV5Database(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
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
}

func hookRoles(t *testing.T, admin *pgxpool.Pool) (old, next string) {
	t.Helper()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	old, next = "averin_old_"+suffix, "averin_new_"+suffix
	for _, sql := range []string{"CREATE ROLE " + old + " NOLOGIN", "CREATE ROLE " + next + " LOGIN"} {
		if _, err := admin.Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+old)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+next)
	})
	return old, next
}

// migrate-hook: Inspect tells an empty database from an initialized one, with SELECTs only.
func TestInspectReadsStateWithoutChangingIt(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	st, err := Inspect(ctx, scoped)
	if err != nil || !st.Fresh() || st.Stored != 0 {
		t.Fatalf("empty database: %+v, %v", st, err)
	}
	if regExists(t, admin, "schema_migrations") {
		t.Fatal("Inspect created the ledger: it must issue no DDL")
	}
	if _, err := Initialize(ctx, scoped); err != nil {
		t.Fatal(err)
	}
	st, err = Inspect(ctx, scoped)
	if err != nil || st.Fresh() || !st.HasLedger || !st.HasTables || st.Stored != CurrentSchemaVersion {
		t.Fatalf("initialized database: %+v, %v", st, err)
	}
}

// migrate-hook: Hook initializes an empty database, and a rerun changes nothing and says so.
func TestHookFreshInitializesThenIsANoop(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	res, err := Hook(ctx, scoped, nil, "")
	if err != nil {
		t.Fatalf("hook on an empty database: %v", err)
	}
	if res.Action != HookInitialized || res.Before != 0 || res.After != CurrentSchemaVersion || res.Current != CurrentSchemaVersion || res.Plane != "averin" {
		t.Fatalf("first run = %+v", res)
	}
	var stampedAt time.Time
	if err := admin.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version=$1`, CurrentSchemaVersion).Scan(&stampedAt); err != nil {
		t.Fatal(err)
	}
	again, err := Hook(ctx, scoped, nil, "")
	if err != nil || again.Action != HookNoop || again.Before != CurrentSchemaVersion || again.After != CurrentSchemaVersion {
		t.Fatalf("rerun = %+v, %v; want a no-op at the current version", again, err)
	}
	var restamped time.Time
	if err := admin.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version=$1`, CurrentSchemaVersion).Scan(&restamped); err != nil || !restamped.Equal(stampedAt) {
		t.Fatalf("a no-op hook restamped the ledger: %v -> %v (%v)", stampedAt, restamped, err)
	}
	// Roles given at the current version are ignored: nothing to cut over.
	if res, err := Hook(ctx, scoped, []string{"x"}, "y"); err != nil || res.Action != HookNoop {
		t.Fatalf("roles at the current version = %+v, %v; want a no-op", res, err)
	}
}

// migrate-hook, advisory lock: concurrent hooks on an empty database serialize. Exactly one reports
// initialized, every other reports a no-op, nobody errors, and the ledger holds each version once.
func TestHookConcurrentRunsInitializeOnce(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	const n = 6
	results := make([]HookResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			results[i], errs[i] = Hook(ctx, scoped, nil, "")
		}(i)
	}
	close(start)
	wg.Wait()
	initialized := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("run %d: %v", i, errs[i])
		}
		switch results[i].Action {
		case HookInitialized:
			initialized++
		case HookNoop:
		default:
			t.Fatalf("run %d action = %q", i, results[i].Action)
		}
		if results[i].After != CurrentSchemaVersion {
			t.Fatalf("run %d after = %d", i, results[i].After)
		}
	}
	if initialized != 1 {
		t.Fatalf("%d runs reported initialized, want exactly 1", initialized)
	}
	var rows int
	if err := admin.QueryRow(context.Background(), `SELECT count(*) FROM schema_migrations`).Scan(&rows); err != nil || rows != CurrentSchemaVersion {
		t.Fatalf("ledger rows = %d (%v), want %d", rows, err, CurrentSchemaVersion)
	}
}

// migrate-hook: a database behind the binary is never advanced without the cutover roles. The hook
// reports cutover_required, returns ErrCutoverRequired and changes nothing; with the roles it runs
// the validated cutover; a rerun is then a no-op.
func TestHookBehindNeedsTheCutoverRoles(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	legacyV5Database(t, admin)

	res, err := Hook(ctx, scoped, nil, "")
	if !errors.Is(err, ErrCutoverRequired) || res.Action != HookCutoverRequired || res.Before != 5 || res.After != 5 {
		t.Fatalf("behind, no roles = %+v, %v", res, err)
	}
	if got := maxVersion(t, admin); got != 5 {
		t.Fatalf("a refused hook changed the schema version to %d", got)
	}
	// One role alone is not a barrier.
	if _, err := Hook(ctx, scoped, []string{"averin_old_x"}, ""); !errors.Is(err, ErrCutoverRequired) {
		t.Fatalf("old role without a new role = %v, want ErrCutoverRequired", err)
	}

	old, next := hookRoles(t, admin)
	if q, ok := quiesce.Load(scoped); ok {
		q.(func(*testing.T))(t)
	}
	res, err = Hook(ctx, scoped, []string{old}, next)
	if err != nil || res.Action != HookCutover || res.Before != 5 || res.After != CurrentSchemaVersion {
		t.Fatalf("behind, with roles = %+v, %v", res, err)
	}
	if got := maxVersion(t, admin); got != CurrentSchemaVersion {
		t.Fatalf("cutover left version %d", got)
	}
	res, err = Hook(ctx, scoped, []string{old}, next)
	if err != nil || res.Action != HookNoop {
		t.Fatalf("rerun after the cutover = %+v, %v", res, err)
	}
}

// migrate-hook: an unstamped database that already holds tables (a legacy deployment) is not
// "fresh": the hook must not bootstrap over it.
func TestHookRefusesToBootstrapOverAnUnstampedLegacySchema(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := admin.Exec(ctx, `CREATE TABLE records (id int)`); err != nil {
		t.Fatal(err)
	}
	res, err := Hook(ctx, scoped, nil, "")
	if !errors.Is(err, ErrCutoverRequired) || res.Action != HookCutoverRequired {
		t.Fatalf("unstamped legacy tables = %+v, %v; want cutover_required", res, err)
	}
	if regExists(t, admin, "schema_migrations") {
		t.Fatal("the hook created the ledger over a legacy schema")
	}
}

// migrate-hook: a database NEWER than the binary is refused and left unchanged.
func TestHookRefusesANewerDatabase(t *testing.T) {
	scoped, admin, cleanup := newTestSchema(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := Hook(ctx, scoped, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, CurrentSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if _, err := Hook(ctx, scoped, nil, ""); err == nil || !strings.Contains(err.Error(), "NEWER") {
		t.Fatalf("newer database = %v, want the downgrade refusal", err)
	}
	if got := maxVersion(t, admin); got != CurrentSchemaVersion+1 {
		t.Fatalf("a refused hook changed the ledger (max %d)", got)
	}
}
