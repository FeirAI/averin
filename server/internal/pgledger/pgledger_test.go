package pgledger_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/pgledger"
	"github.com/feirai/averin/server/internal/pgschema"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPostgresLedgerMaintenance proves that the runtime maintenance pool sees
// the migrated schema, prunes only new expired claims, and never sweeps unknown-
// owner legacy exclusions. Request claims themselves are transaction-bound in
// internal/store, not exposed by pgledger.
func TestPostgresLedgerMaintenance(t *testing.T) {
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL for real Postgres ledger test")
	}
	ctx := context.Background()
	root, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	schema := fmt.Sprintf("averin_ledger_%d", time.Now().UnixNano())
	if _, err := root.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") //nolint:errcheck
	dsn := base + "&search_path=" + schema
	if err := pgschema.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	l, err := pgledger.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `INSERT INTO consumed_nonces(project_id,resource_id,nonce,owner_id,consumed_at)
		VALUES ('p','r','old','00000000000000000000000000000000',clock_timestamp()-interval '2 days'),
		('p','r','fresh','11111111111111111111111111111111',clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO consumed_jtis(consume_key,owner_id,consumed_at)
		VALUES ('old','00000000000000000000000000000000',clock_timestamp()-interval '2 days'),
		('fresh','11111111111111111111111111111111',clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	// Privileged fixture setup simulates aged rows inherited at cutover. Disable
	// the immutable row trigger only inside this transaction, then restore it
	// before exercising the ordinary runtime sweeper.
	fixture, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Rollback(ctx) //nolint:errcheck
	if _, err := fixture.Exec(ctx, `ALTER TABLE legacy_consume_exclusions DISABLE TRIGGER legacy_consume_rows_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.Exec(ctx, `INSERT INTO legacy_consume_exclusions(kind,consume_key,consumed_at)
		VALUES ('nonce','legacy-old-nonce',clock_timestamp()-interval '2 days'),
		('jti','legacy-old-jti',clock_timestamp()-interval '2 days')`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.Exec(ctx, `ALTER TABLE legacy_consume_exclusions ENABLE TRIGGER legacy_consume_rows_immutable`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	legacyBefore := make(map[string]time.Time)
	rows, err := pool.Query(ctx, `SELECT kind || ':' || consume_key, consumed_at FROM legacy_consume_exclusions`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var key string
		var consumed time.Time
		if err := rows.Scan(&key, &consumed); err != nil {
			t.Fatal(err)
		}
		legacyBefore[key] = consumed
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(legacyBefore) != 2 {
		t.Fatalf("legacy fixture rows=%d err=%v", len(legacyBefore), err)
	}
	removed, err := l.SweepConsumed(ctx, 24*time.Hour)
	if err != nil || removed != 2 {
		t.Fatalf("sweep removed=%d err=%v, want exactly two aged new rows", removed, err)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM consumed_nonces) +
		(SELECT count(*) FROM consumed_jtis)`).Scan(&left); err != nil || left != 2 {
		t.Fatalf("fresh claims after sweep=%d err=%v", left, err)
	}
	rows, err = pool.Query(ctx, `SELECT kind || ':' || consume_key, consumed_at FROM legacy_consume_exclusions`)
	if err != nil {
		t.Fatal(err)
	}
	legacyAfter := make(map[string]time.Time)
	for rows.Next() {
		var key string
		var consumed time.Time
		if err := rows.Scan(&key, &consumed); err != nil {
			t.Fatal(err)
		}
		legacyAfter[key] = consumed
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(legacyAfter) != len(legacyBefore) {
		t.Fatalf("legacy rows after sweep=%d err=%v", len(legacyAfter), err)
	}
	for key, before := range legacyBefore {
		if !legacyAfter[key].Equal(before) {
			t.Fatalf("legacy exclusion %q changed during ordinary sweep", key)
		}
	}
}
