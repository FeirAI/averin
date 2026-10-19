package api_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/feirai/averin/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCheckpointCutCostIsConstantPostgres: the same constant-cost assertion on the real store, with the history
// loaded in bulk (backdated, ordinals as the write path assigns them). Skips without AVERIN_TEST_DATABASE_URL.
func TestCheckpointCutCostIsConstantPostgres(t *testing.T) {
	runCostScale(t, func(t *testing.T) (store.Store, func(int)) {
		pg, admin := newVoidTestPostgres(t)
		return pg, func(n int) { pgBulkHistory(t, admin, n) }
	}, 300, 50)
}

// TestCheckpointCutDifferentialPostgres: incremental equals full on random histories on the real store.
func TestCheckpointCutDifferentialPostgres(t *testing.T) {
	for _, brokerID := range []string{"", "b1"} {
		for seed := int64(1); seed <= 3; seed++ {
			t.Run(fmt.Sprintf("broker=%q/seed=%d", brokerID, seed), func(t *testing.T) {
				pg, _ := newVoidTestPostgres(t)
				runDifferential(t, pg, brokerID, seed, 25)
			})
		}
	}
}

// pgBulkHistory loads n backdated chained records for project "p" with ordinals as the write path assigns them.
func pgBulkHistory(t *testing.T, admin *pgxpool.Pool, n int) {
	t.Helper()
	_, err := admin.Exec(context.Background(), `
		INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json, inserted_at, ord)
		SELECT 'p', 'bulk'||g, 'sha256:p-'||lpad(g::text, 6, '0'), 's'||(g % 5),
		       CASE WHEN g=1 THEN '{}'::text[] ELSE ARRAY['sha256:p-'||lpad((g-1)::text, 6, '0')] END,
		       '{"extensions":{}}', now() - make_interval(mins => ($1 - g) * 40), g
		FROM generate_series(1, $1) g`, n)
	if err != nil {
		t.Fatal(err)
	}
}

// TestIncrementalReadCostIsConstantInHistoryPostgres: the same assertion on the real store (the read is an ordinal
// index range there). Skips without AVERIN_TEST_DATABASE_URL.
func TestIncrementalReadCostIsConstantInHistoryPostgres(t *testing.T) {
	runReadScale(t, func(t *testing.T) (store.Store, func(int)) {
		pg, admin := newVoidTestPostgres(t)
		return pg, func(n int) { pgBulkHistory(t, admin, n) }
	}, 300, 50)
}

// TestIncrementalReadRefusesOrdinalGapPostgres: the owner role deletes the record at ordinal 5 of 10; every page
// that spans the hole is a 500 (it would otherwise repeat record 7 and hide record 5 under a 200).
func TestIncrementalReadRefusesOrdinalGapPostgres(t *testing.T) {
	pg, admin := newVoidTestPostgres(t)
	pgBulkHistory(t, admin, 10)
	if _, err := admin.Exec(context.Background(), `DELETE FROM records WHERE project_id='p' AND ord=5`); err != nil {
		t.Fatal(err)
	}
	checkGapRefused(t, cutServer(t, pg, "").Routes())
}

// TestIncrementalReadSnapshotHoldsUnderConcurrentCutPostgres: the same interleaving on the repeatable-read store.
func TestIncrementalReadSnapshotHoldsUnderConcurrentCutPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	checkSnapshotUnderCut(t, pg)
}
