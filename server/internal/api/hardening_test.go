package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
)

// TestWithResourcePanicsOnSigningKeyOverlap (F12): WithResource fail-fasts an embedder that reuses the
// server signing key as the resource recording key (R2 role separation), which the offline verifier
// would otherwise reject as a fatal config error.
func TestWithResourcePanicsOnSigningKeyOverlap(t *testing.T) {
	c, _ := core.New(seed)
	rcSame, _ := core.New(seed) // SAME key as the server signing key -> R2 violation
	defer func() {
		if recover() == nil {
			t.Fatal("WithResource must panic when the resource key equals the server signing key (R2)")
		}
	}()
	api.New(c, store.NewMem(), "k0").WithResource(rcSame, "orders-db")
}

// TestBatchRecordsAtomicOnMalformedItem (F14): a /v2/records batch whose LATER item fails a DEEP
// deterministic validation (here: missing session_id — caught only by the shared validateGenericRecordItem
// the up-front pre-pass now runs, not the cheap decode/idempotency checks) must reject the WHOLE batch
// with NO earlier item partially persisted.
func TestBatchRecordsAtomicOnMalformedItem(t *testing.T) {
	h := newServer(t).Routes()
	batch := `[{"idempotency_key":"ok-1","project_id":"p1","session_id":"s1","action":"db.read"},` +
		`{"idempotency_key":"ok-2","project_id":"p1","action":"db.write"}]` // 2nd item: has idem, but NO session_id
	if code, _ := do(t, h, "POST", "/v2/records", batch); code != http.StatusBadRequest {
		t.Fatalf("a batch with a deeply-malformed item must be 400, got %d", code)
	}
	// The first (valid) item must NOT have persisted.
	_, dag := do(t, h, "GET", "/v2/dag?project=p1&session=s1", "")
	if strings.Contains(dag, "db.read") {
		t.Fatalf("an earlier batch item must not persist when a later item is rejected (F14); dag: %s", dag)
	}
}
