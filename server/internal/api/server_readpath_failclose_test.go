package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// failReadStore injects read errors on the export/session/DAG/use-outcome read paths, to prove they FAIL
// CLOSED (averin#3/#14): a transient store error must surface as 500 — never a silently-empty bundle (which
// handleExport would then METER/bill) or an empty 200 (an apparently-empty history read during an outage).
type failReadStore struct {
	store.Store
	failAll, failCheckpoints, failSessions, failSessionRecords bool
}

func (f *failReadStore) bound(st store.Store) *failReadStore {
	return &failReadStore{Store: st, failAll: f.failAll, failCheckpoints: f.failCheckpoints, failSessions: f.failSessions, failSessionRecords: f.failSessionRecords}
}

func (f *failReadStore) WithProjectRead(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return f.Store.WithProjectRead(ctx, projectID, func(st store.Store) error { return fn(f.bound(st)) })
}

func (f *failReadStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return f.Store.WithProjectWrite(ctx, projectID, func(st store.Store) error { return fn(f.bound(st)) })
}

func (f *failReadStore) AllRecords(p string) ([]store.Record, error) {
	if f.failAll {
		return nil, errors.New("injected AllRecords failure")
	}
	return f.Store.AllRecords(p)
}

func (f *failReadStore) Checkpoints(p string) ([]store.Checkpoint, error) {
	if f.failCheckpoints {
		return nil, errors.New("injected Checkpoints failure")
	}
	return f.Store.Checkpoints(p)
}

func (f *failReadStore) Sessions(p string) ([]string, error) {
	if f.failSessions {
		return nil, errors.New("injected Sessions failure")
	}
	return f.Store.Sessions(p)
}

func (f *failReadStore) SessionRecords(p, s string) ([]store.Record, error) {
	if f.failSessionRecords {
		return nil, errors.New("injected SessionRecords failure")
	}
	return f.Store.SessionRecords(p, s)
}

func billableExports(t *testing.T, h http.Handler) int {
	t.Helper()
	_, r := do(t, h, "GET", "/v2/usage?project=p1", "")
	var u struct {
		BillableExports int `json:"billable_exports"`
	}
	if err := json.Unmarshal([]byte(r), &u); err != nil {
		t.Fatalf("decode usage: %v\n%s", err, r)
	}
	return u.BillableExports
}

// TestExportVerifyFailClosedOnStoreReadError (averin#3): a transient AllRecords/Checkpoints read error inside
// buildBundle must abort /v2/export and /v2/verify with 500 — NOT build an empty bundle. Because handleExport
// meters ExportIssued only AFTER buildBundle succeeds, the failed export must never bill (empty-billing closes).
func TestExportVerifyFailClosedOnStoreReadError(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	fs := &failReadStore{Store: store.NewMem()}
	h := api.New(c, fs, "k0").Routes()

	postRecord(t, h, `{"idempotency_key":"e1","project_id":"p1","session_id":"s1","action":"a"}`)
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}

	// AllRecords error -> export/verify 500, and the failed export must NOT have metered a (zero-record) export.
	fs.failAll = true
	if code, r := do(t, h, "GET", "/v2/export?project=p1", ""); code != http.StatusInternalServerError {
		t.Fatalf("export must 500 on an AllRecords error, got %d: %s", code, r)
	}
	if code, r := do(t, h, "GET", "/v2/verify?project=p1", ""); code != http.StatusInternalServerError {
		t.Fatalf("verify must 500 on an AllRecords error, got %d: %s", code, r)
	}
	if b := billableExports(t, h); b != 0 {
		t.Fatalf("a failed export must NOT bill; billable_exports=%d", b)
	}

	// Checkpoints error -> export 500 too.
	fs.failAll = false
	fs.failCheckpoints = true
	if code, r := do(t, h, "GET", "/v2/export?project=p1", ""); code != http.StatusInternalServerError {
		t.Fatalf("export must 500 on a Checkpoints error, got %d: %s", code, r)
	}

	// Recovered: export succeeds and NOW bills exactly once.
	fs.failCheckpoints = false
	if code, r := do(t, h, "GET", "/v2/export?project=p1", ""); code != http.StatusOK {
		t.Fatalf("export must succeed once the store recovers, got %d: %s", code, r)
	}
	if b := billableExports(t, h); b != 1 {
		t.Fatalf("a successful export must bill exactly once; billable_exports=%d", b)
	}
}

// TestSessionsDAGFailClosedOnStoreReadError (averin#3): /v2/sessions and /v2/dag must 500 on a store read error
// rather than answer an empty 200 (which would read as "no sessions / empty DAG" during a transient outage).
func TestSessionsDAGFailClosedOnStoreReadError(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	fs := &failReadStore{Store: store.NewMem()}
	h := api.New(c, fs, "k0").Routes()
	postRecord(t, h, `{"idempotency_key":"s1r","project_id":"p1","session_id":"s1","action":"a"}`)

	fs.failSessions = true
	if code, r := do(t, h, "GET", "/v2/sessions?project=p1", ""); code != http.StatusInternalServerError {
		t.Fatalf("/v2/sessions must 500 on a Sessions store error (not empty 200), got %d: %s", code, r)
	}
	fs.failSessions = false

	fs.failSessionRecords = true
	if code, r := do(t, h, "GET", "/v2/dag?project=p1&session=s1", ""); code != http.StatusInternalServerError {
		t.Fatalf("/v2/dag must 500 on a SessionRecords store error (not empty 200), got %d: %s", code, r)
	}
}

// TestUseOutcomeFailsClosedOnSessionRecordsError (averin#14): existingReceipt (the intent lookup for
// /v2/use-outcome) reads SessionRecords; a store error there must become a RETRYABLE 500, not the 400
// "intent_record_id not found" — which would make the client abandon the outcome and permanently break the
// intent→outcome pairing (leaving a false intent_without_outcome).
func TestUseOutcomeFailsClosedOnSessionRecordsError(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	fs := &failReadStore{Store: store.NewMem()}
	h := api.New(c, fs, "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()

	ob, _ := json.Marshal(map[string]any{
		"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1",
		"intent_record_id": "use-does-not-exist", "status": "ok",
	})

	// Baseline: with the store healthy, an unknown intent is a client 400 (the SessionRecords read succeeded,
	// the intent genuinely is not there).
	if code, r := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusBadRequest {
		t.Fatalf("unknown intent (healthy store) must be 400, got %d: %s", code, r)
	}
	// FAIL CLOSED: the SAME request under a SessionRecords error must be 500, not 400.
	fs.failSessionRecords = true
	if code, r := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusInternalServerError {
		t.Fatalf("a SessionRecords read error must be a retryable 500, got %d: %s", code, r)
	}
}

// TestIngestBudgetThrottles (averin#20): with an ingest budget configured, state-mutating POST /v2/* ingest is
// capped per project — a saturated bucket answers 429 (bounding billable, append-only DB growth from a leaked
// token). GET reads are never throttled, and with NO budget set the routes are unlimited (prior behavior).
func TestIngestBudgetThrottles(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	// Tiny per-project burst so the third rapid POST saturates; a generous global ceiling so per-project is the
	// limiter under test.
	h := api.New(c, store.NewMem(), "k0").WithIngestBudget(api.IngestBudget{
		PerProjectPerSec: 1, PerProjectBurst: 2, GlobalPerSec: 1000, GlobalBurst: 1000,
	}).Routes()

	body := func(idem string) string {
		return `{"idempotency_key":"` + idem + `","project_id":"p1","session_id":"s1","action":"a"}`
	}
	if code, r := do(t, h, "POST", "/v2/records?project=p1", body("i1")); code != http.StatusCreated {
		t.Fatalf("POST #1 should pass the budget, got %d: %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/records?project=p1", body("i2")); code != http.StatusCreated {
		t.Fatalf("POST #2 should pass the budget, got %d: %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/records?project=p1", body("i3")); code != http.StatusTooManyRequests {
		t.Fatalf("POST #3 should be rate-limited (429), got %d: %s", code, r)
	}
	// GET reads bypass the ingest budget even while it is saturated.
	if code, r := do(t, h, "GET", "/v2/usage?project=p1", ""); code != http.StatusOK {
		t.Fatalf("GET reads must not be rate-limited, got %d: %s", code, r)
	}

	// A DIFFERENT project has its own bucket (fairness) — one project's saturation must not throttle another.
	other := `{"idempotency_key":"o1","project_id":"p2","session_id":"s1","action":"a"}`
	if code, r := do(t, h, "POST", "/v2/records?project=p2", other); code != http.StatusCreated {
		t.Fatalf("a different project must not be throttled by p1's saturation, got %d: %s", code, r)
	}
}

// TestNoIngestBudgetIsUnlimited (averin#20 back-compat): with no budget configured, a burst of ingest is NOT
// throttled — the change must be opt-in and never brick an existing deployment.
func TestNoIngestBudgetIsUnlimited(t *testing.T) {
	h := newSrv(t)
	for i := 0; i < 8; i++ {
		body := `{"idempotency_key":"n` + string(rune('0'+i)) + `","project_id":"p1","session_id":"s1","action":"a"}`
		if code, r := do(t, h, "POST", "/v2/records?project=p1", body); code != http.StatusCreated {
			t.Fatalf("unbudgeted ingest must never be throttled, POST #%d got %d: %s", i, code, r)
		}
	}
}
