package api_test

import (
	"net/http"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/store"
)

// TestBatchAuthorityRejectionIsAllOrNothing: with AVERIN_REQUIRE_PINNED_AUTHORITY on (the default), a batch
// [ok, {authority.source: policy_engine_signed} (unpinned)] used to STORE item 1 and then 500 on item 2 — a
// deterministic partial commit (a retry fails identically while item 1 stays persisted). The pre-pass must
// dry-run the authority decision so the whole batch is rejected (same documented retryable 500) and NOTHING is
// sealed; a batch of plain items still commits.
func TestBatchAuthorityRejectionIsAllOrNothing(t *testing.T) {
	h := api.New(mustCore(t), store.NewMem(), "k0").WithRequirePinnedAuthority(true).Routes()
	batch := `[{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"ok"},
	           {"idempotency_key":"k2","project_id":"p1","session_id":"s1","authority":{"source":"policy_engine_signed"}}]`
	if code, resp := do(t, h, "POST", "/v2/records", batch); code != http.StatusInternalServerError {
		t.Fatalf("a batch with a rejected authority elevation must 500 (documented), got %d: %s", code, resp)
	}
	// item 1 was NOT committed by the rejected batch.
	if _, created := postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"ok"}`); !created {
		t.Fatal("the first item of the rejected batch must not have been sealed")
	}
}
