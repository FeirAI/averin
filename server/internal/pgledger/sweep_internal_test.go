package pgledger

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/feirai/averin/server/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSweepFailureRetainsClaims(t *testing.T) {
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
	schema := fmt.Sprintf("averin_sweep_%d", time.Now().UnixNano())
	if _, err := root.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") //nolint:errcheck
	dsn := base + "&search_path=" + schema
	l, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.pool.Exec(ctx, SchemaSQL+"\n"+migrations.TenantNonceLedger); err != nil {
		t.Fatal(err)
	}
	if _, err := l.pool.Exec(ctx, `INSERT INTO consumed_nonces(project_id,resource_id,nonce,owner_id,consumed_at)
		VALUES ('p','r','old','00000000000000000000000000000000',clock_timestamp()-interval '2 days')`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.pool.Exec(ctx, `ALTER TABLE consumed_jtis RENAME TO unavailable_jtis`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.SweepConsumed(ctx, 24*time.Hour); err == nil {
		t.Fatal("missing JTI table did not fail the atomic sweep")
	}
	var count int
	if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM consumed_nonces WHERE nonce='old'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed sweep removed nonce count=%d err=%v", count, err)
	}
}
