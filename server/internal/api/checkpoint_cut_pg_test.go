package api_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/store"
)

// TestCheckpointCutCostIsConstantPostgres: the same constant-cost assertion on the real store, with the history
// loaded in bulk (backdated, ordinals as the write path assigns them). Skips without AVERIN_TEST_DATABASE_URL.
func TestCheckpointCutCostIsConstantPostgres(t *testing.T) {
	runCostScale(t, func(t *testing.T) (store.Store, func(int)) {
		pg, admin := newVoidTestPostgres(t)
		return pg, func(n int) {
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
}
