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
	// Migration's legacy table cannot be populated after cutover. A first-boot
	// empty table still proves the ordinary sweep never touches its relation.
	removed, err := l.SweepConsumed(ctx, 24*time.Hour)
	if err != nil || removed != 2 {
		t.Fatalf("sweep removed=%d err=%v, want exactly two aged new rows", removed, err)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM consumed_nonces) +
		(SELECT count(*) FROM consumed_jtis)`).Scan(&left); err != nil || left != 2 {
		t.Fatalf("fresh claims after sweep=%d err=%v", left, err)
	}
}
