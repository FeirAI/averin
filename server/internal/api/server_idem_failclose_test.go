package api_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
)

// failIdemStore wraps a store and can inject a RecordByIdem read error, to prove the use paths FAIL CLOSED
// on an ambiguous idempotency lookup (never consuming the single-use credential before the lookup resolves).
type failIdemStore struct {
	store.Store
	fail bool
}

func (f *failIdemStore) RecordByIdem(projectID, idemKey string) (store.Record, bool, error) {
	if f.fail {
		return store.Record{}, false, errors.New("injected RecordByIdem failure")
	}
	return f.Store.RecordByIdem(projectID, idemKey)
}

// TestUseFailsClosedOnIdemStoreError (Codex C1): a RecordByIdem store error during /v2/use must abort with
// 500 BEFORE ValidateUse consumes the single-use credential — so a transient read failure never burns a
// nonce/jti and leave no receipt. After the store recovers, the SAME credential still validates (proof it
// was never consumed during the failed attempt).
func TestUseFailsClosedOnIdemStoreError(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	fs := &failIdemStore{Store: store.NewMem()}
	h := api.New(c, fs, "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()

	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant") // grant minted while the store is healthy

	fs.fail = true
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusInternalServerError {
		t.Fatalf("a RecordByIdem store error must fail closed as 500 BEFORE consuming the credential, got %d: %s", code, r)
	}

	// the credential/nonce was NOT consumed: with the store healthy, the SAME nonce still validates + seals.
	fs.fail = false
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("after the store recovers, the un-consumed credential must still seal a receipt, got %d: %s", code, r)
	}
}
