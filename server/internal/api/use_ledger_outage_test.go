package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/feirai/averin/server/internal/store"
)

// ledgerOutageStore fails the replay-ledger claims with an infrastructure error once armed.
type ledgerOutageStore struct {
	store.Store
	armed *bool
}

func (f ledgerOutageStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return f.Store.WithProjectWrite(ctx, projectID, func(st store.Store) error { return fn(ledgerOutageStore{Store: st, armed: f.armed}) })
}

func (f ledgerOutageStore) ConsumeNonce(c resourceshim.NonceClaim) error {
	if *f.armed {
		return errors.New("store: consume nonce: timeout: context deadline exceeded")
	}
	return f.Store.ConsumeNonce(c)
}

// TestUseLedgerOutageIsNotADeny (S-L1): a consume-ledger store failure is a retryable 503, not a 400
// replay rejection, and is not counted as a deny; the credential stays usable once the ledger recovers.
func TestUseLedgerOutageIsNotADeny(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	armed := false
	h := api.New(c, ledgerOutageStore{Store: store.NewMem(), armed: &armed}, "k0").
		WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()
	ak := grantAgentKey()
	grantID, capability := mkGrant(t, h, ak, "idem-grant")

	armed = true
	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capability, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusServiceUnavailable || !strings.Contains(resp, "ledger unavailable") {
		t.Fatalf("ledger outage = %d %s, want 503 ledger unavailable", code, resp)
	}
	_, metrics := do(t, h, "GET", "/metrics", "")
	if strings.Contains(metrics, `averin_use_requests_total{outcome="deny"}`) {
		t.Fatalf("ledger outage counted as a deny:\n%s", metrics)
	}

	armed = false
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capability, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("use after ledger recovery = %d %s", code, resp)
	}
	// A genuine replay is still the caller's 4xx.
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use-2", capability, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusBadRequest {
		t.Fatalf("replay = %d %s, want 400", code, resp)
	}
	if _, metrics := do(t, h, "GET", "/metrics", ""); !strings.Contains(metrics, `averin_use_requests_total{outcome="deny"} 1`) {
		t.Fatalf("the replay was not counted as exactly one deny:\n%s", metrics)
	}
}

// ledgerInvariantStore makes the replay ledger refuse the claim as invalid once armed.
type ledgerInvariantStore struct {
	store.Store
	armed *bool
}

func (f ledgerInvariantStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return f.Store.WithProjectWrite(ctx, projectID, func(st store.Store) error { return fn(ledgerInvariantStore{Store: st, armed: f.armed}) })
}

func (f ledgerInvariantStore) ConsumeNonce(c resourceshim.NonceClaim) error {
	if *f.armed {
		return fmt.Errorf("%w: store: transaction for project %q cannot access %q", resourceshim.ErrInvalidLedgerClaim, "other", c.ProjectID)
	}
	return f.Store.ConsumeNonce(c)
}

// TestUseLedgerInvariantIs500 (review L3): a claim the ledger refuses as invalid is a server bug: 500
// (not the retryable 503, not a 400 replay) and not counted as a deny.
func TestUseLedgerInvariantIs500(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	armed := false
	h := api.New(c, ledgerInvariantStore{Store: store.NewMem(), armed: &armed}, "k0").
		WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()
	ak := grantAgentKey()
	grantID, capability := mkGrant(t, h, ak, "idem-grant")
	armed = true
	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capability, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusInternalServerError || strings.Contains(resp, "ledger unavailable") {
		t.Fatalf("ledger invariant violation = %d %s, want 500 (not the 503 outage)", code, resp)
	}
	if _, metrics := do(t, h, "GET", "/metrics", ""); strings.Contains(metrics, `averin_use_requests_total{outcome="deny"}`) {
		t.Fatalf("ledger invariant violation counted as a deny:\n%s", metrics)
	}
	armed = false
	if code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capability, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("use after the invariant failure = %d %s", code, resp)
	}
}
