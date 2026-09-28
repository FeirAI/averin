package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/feirai/averin/server/internal/store"
)

// A resource use must consume replay claims from the same project Store that
// commits its signed receipt. There is no separate injectable ledger.
func TestWithResourceUsesProjectStoreLedger(t *testing.T) {
	base := store.NewMem()
	resourceCore, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(mustCore(t), base, "k0").WithBroker(brokerIssuingKey()).WithResource(resourceCore, "orders-db").Routes()
	ak := grantAgentKey()
	grantID, capability := mkGrant(t, h, ak, "idem-ledger")
	claim, err := resourceshim.NewNonceClaim("p1", "orders-db", "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := base.WithProjectWrite(context.Background(), "p1", func(st store.Store) error { return st.ConsumeNonce(claim) }); err != nil {
		t.Fatal(err)
	}
	if code, response := do(t, h, "POST", "/v2/use", useBody(t, "idem-use-1", capability, grantID, ak, "SELECT 1", "nonce-1")); code == http.StatusCreated {
		t.Fatalf("store-consumed nonce accepted: %s", response)
	}
	if code, response := do(t, h, "POST", "/v2/use", useBody(t, "idem-use-2", capability, grantID, ak, "SELECT 1", "nonce-2")); code != http.StatusCreated {
		t.Fatalf("fresh nonce after rejected replay (%d): %s", code, response)
	}
}
