package pgledger

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestSweepConsumedDeletesOnlyAgedRows (averin#9): the periodic TTL sweep removes entries whose consumed_at is
// older than retention and LEAVES fresher ones (so a still-live nonce/jti is never pruned into a replay). It is
// an INTERNAL test (package pgledger) so it can insert rows with explicit consumed_at timestamps via the pool —
// one aged, one fresh — and assert selectivity without sleeping. Postgres-gated like the other ledger tests.
func TestSweepConsumedDeletesOnlyAgedRows(t *testing.T) {
	dsn := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run the Postgres ledger sweep test")
	}
	ctx := context.Background()
	l, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	oldKey := "sweep-old-" + suffix
	freshKey := "sweep-fresh-" + suffix

	if _, err := l.pool.Exec(ctx,
		`INSERT INTO consume_ledger (kind, consume_key, consumed_at) VALUES ('nonce', $1, now() - interval '100 days')`, oldKey); err != nil {
		t.Fatalf("insert aged row: %v", err)
	}
	if _, err := l.pool.Exec(ctx,
		`INSERT INTO consume_ledger (kind, consume_key, consumed_at) VALUES ('nonce', $1, now())`, freshKey); err != nil {
		t.Fatalf("insert fresh row: %v", err)
	}
	defer func() {
		_, _ = l.pool.Exec(context.Background(), `DELETE FROM consume_ledger WHERE consume_key IN ($1, $2)`, oldKey, freshKey)
	}()

	// retention 30 days: the 100-day-old row ages out; the fresh row survives.
	removed, err := l.SweepConsumed(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed < 1 {
		t.Fatalf("sweep should have removed at least the aged row, removed=%d", removed)
	}

	exists := func(key string) bool {
		var n int
		if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM consume_ledger WHERE consume_key = $1`, key).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", key, err)
		}
		return n > 0
	}
	if exists(oldKey) {
		t.Fatalf("aged row %s should have been swept", oldKey)
	}
	if !exists(freshKey) {
		t.Fatalf("fresh row %s must NOT be swept (retention not elapsed)", freshKey)
	}
}
