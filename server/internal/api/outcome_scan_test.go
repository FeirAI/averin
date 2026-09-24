package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// sessionScanCounter counts full-session reads (SessionRecords), the O(session) scan /v2/use-outcome does under the
// process-wide ingestMu.
type sessionScanCounter struct {
	store.Store
	scans  int
	parent *sessionScanCounter
}

func (c *sessionScanCounter) SessionRecords(projectID, sessionID string) ([]store.Record, error) {
	if c.parent != nil {
		c.parent.scans++
	} else {
		c.scans++
	}
	return c.Store.SessionRecords(projectID, sessionID)
}

func (c *sessionScanCounter) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return c.Store.WithProjectWrite(ctx, projectID, func(st store.Store) error {
		return fn(&sessionScanCounter{Store: st, parent: c})
	})
}

// TestUseOutcomeScansSessionOnce (review, low): resolving the intent an outcome completes and checking that no other
// outcome already completes it used to be TWO full session scans per /v2/use-outcome, both under ingestMu. One pass
// answers both; the exactly-one-outcome rule still holds (a second outcome for the intent is a 409).
func TestUseOutcomeScansSessionOnce(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	sc := &sessionScanCounter{Store: store.NewMem()}
	h := api.New(c, sc, "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()
	ak := grantAgentKey()

	grantID, capb := mkGrant(t, h, ak, "idem-grant")
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", capb, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(resp), &intent)

	outcome := func(idem, status string) (int, string) {
		ob, _ := json.Marshal(map[string]any{"idempotency_key": idem, "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": status})
		return do(t, h, "POST", "/v2/use-outcome", string(ob))
	}
	sc.scans = 0
	if code, r := outcome("idem-outcome", "ok"); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, r)
	}
	if sc.scans != 1 {
		t.Fatalf("/v2/use-outcome read the whole session %d times; want 1", sc.scans)
	}
	if code, r := outcome("idem-outcome-2", "failed"); code != http.StatusConflict {
		t.Fatalf("a second outcome for the same intent must 409 (got %d): %s", code, r)
	}
}
