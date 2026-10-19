package api_test

import (
	"context"
	"fmt"
	"strings"
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
	checkSnapshotUnderCut(t, func(t *testing.T) store.Store {
		pg, _ := newVoidTestPostgres(t)
		return pg
	})
}

// TestCheckpointCutRefusesADeletedRecordPostgres: the probe from the PR3 review. Checkpoint at 10, ordinals 11..1110,
// then the owner role deletes ordinal 500 (inside the first HeadsPageSize page): the page is one row short, the cut
// used to read the next page one row early and sign record_count 1110 over 1109 rows, folding 1001 twice. It must
// refuse, and cut again once the history is whole.
func TestCheckpointCutRefusesADeletedRecordPostgres(t *testing.T) {
	pg, admin := newVoidTestPostgres(t)
	s := cutServer(t, pg, "")
	h := newCutHistory(t, pg, "p", 4)
	for i := 0; i < 10; i++ {
		h.plain()
	}
	if _, err := cutOnce(t, s, pg, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(context.Background(), `
		INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json, inserted_at, ord)
		SELECT 'p', 'bulk'||g, 'sha256:q-'||lpad(g::text, 6, '0'), 's'||(g % 5),
		       CASE WHEN g=11 THEN '{}'::text[] ELSE ARRAY['sha256:q-'||lpad((g-1)::text, 6, '0')] END,
		       '{"extensions":{}}', now(), g
		FROM generate_series(11, 1110) g`); err != nil {
		t.Fatal(err)
	}
	if tag, err := admin.Exec(context.Background(), `DELETE FROM records WHERE project_id='p' AND ord=500`); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("owner delete of ord 500: %v %v", tag, err)
	}
	cp, err := cutOnce(t, s, pg, "p")
	if err == nil || !strings.Contains(err.Error(), "ordinals are not contiguous") {
		t.Fatalf("a deleted record in a non-last page must refuse the cut, got %+v %v", cp, err)
	}
	// The history is made whole again (the same row put back at ordinal 500): the next cut signs.
	if _, err := admin.Exec(context.Background(), `
		INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json, inserted_at, ord)
		SELECT 'p', 'bulk'||g, 'sha256:q-'||lpad(g::text, 6, '0'), 's'||(g % 5),
		       ARRAY['sha256:q-'||lpad((g-1)::text, 6, '0')],
		       '{"extensions":{}}', now(), g
		FROM generate_series(500, 500) g`); err != nil {
		t.Fatal(err)
	}
	cp, err = cutOnce(t, s, pg, "p")
	if err != nil {
		t.Fatalf("the cut over a whole history must sign: %v", err)
	}
	if cp.Seq != 1 {
		t.Fatalf("signed seq %d after the refusal, want 1 (the refused seq is retried)", cp.Seq)
	}
}
