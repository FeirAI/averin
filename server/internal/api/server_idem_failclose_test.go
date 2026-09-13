package api_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
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

// TestUseFailsClosedOnIdemStoreError (adversarial review C1): a RecordByIdem store error during /v2/use must abort with
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

// failHeadsStore injects a Heads() read error, to prove sealAndStore FAILS CLOSED on a frontier-read failure
// (averin#4): a swallowed Heads() error would seal the record as a DETACHED, parentless DAG root — a permanent
// forgery of the causal chain. The error must instead abort the seal.
type failHeadsStore struct {
	store.Store
	fail bool
}

func (f *failHeadsStore) Heads(projectID, sessionID string) ([]string, error) {
	if f.fail {
		return nil, errors.New("injected Heads failure")
	}
	return f.Store.Heads(projectID, sessionID)
}

// TestSealFailsClosedOnHeadsStoreError (averin#4): a Heads() store error inside sealAndStore must abort the
// seal with 500 — NEVER seal a record against an empty (nil→[]) frontier as a detached parentless root. Driven
// via /v2/use (sealAndStore's Heads() call is on every seal path); the error is pre-commit, so the consumed
// credential is released and the SAME credential re-validates + seals once the store recovers (proof nothing
// was sealed during the failed attempt).
func TestSealFailsClosedOnHeadsStoreError(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	fh := &failHeadsStore{Store: store.NewMem()}
	h := api.New(c, fh, "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()

	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant") // grant seals while Heads is healthy

	fh.fail = true
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusInternalServerError {
		t.Fatalf("a Heads() store error must fail closed as 500 (no detached-root seal), got %d: %s", code, r)
	}

	// nothing was sealed and the credential was NOT consumed: with the store healthy the SAME nonce seals.
	fh.fail = false
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("after the store recovers, the un-consumed credential must seal a receipt, got %d: %s", code, r)
	}
}

// failContentStore injects a content-store Put failure, to drive a buildUseRecord error AFTER ValidateUse
// has consumed the credential (the use receipt stores its params content-addressed during construction).
type failContentStore struct {
	content.Store
	fail bool
}

func (f *failContentStore) Put(ctx context.Context, data []byte) (content.Address, error) {
	if f.fail {
		return content.Address{}, errors.New("injected content store failure")
	}
	return f.Store.Put(ctx, data)
}

// failPutStore injects a PutRecord error that is NOT store.ErrCommitAmbiguous (a pre-commit store failure:
// begin/select/insert/disclosure), to test that the use path releases the consumed credential there.
type failPutStore struct {
	store.Store
	fail bool
}

func (f *failPutStore) PutRecord(projectID, idemKey string, rec store.Record) (store.Record, bool, error) {
	if f.fail {
		return store.Record{}, false, errors.New("injected pre-commit store failure")
	}
	return f.Store.PutRecord(projectID, idemKey, rec)
}

// TestUseReleasesCredentialOnPreCommitPutFailure (adversarial review pass-10 high): a PutRecord error that is NOT
// store.ErrCommitAmbiguous persists nothing (a begin/select/insert/disclosure failure), so the consumed
// nonce/jti must be RELEASED — only a genuinely commit-ambiguous fresh-insert commit is held.
func TestUseReleasesCredentialOnPreCommitPutFailure(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	fp := &failPutStore{Store: store.NewMem()}
	h := api.New(c, fp, "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant") // grant stores while PutRecord is healthy

	fp.fail = true
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusInternalServerError {
		t.Fatalf("a pre-commit PutRecord failure should be 500, got %d: %s", code, r)
	}
	// the credential was RELEASED (the error is not commit-ambiguous): the SAME nonce re-validates + seals.
	fp.fail = false
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("after the store recovers, the released credential must seal a receipt, got %d: %s", code, r)
	}
}

// failSealCore wraps a Sealer and can inject a SealRecord failure — a PRE-commit error inside sealAndStore
// (before PutRecord), to test that the use path releases the credential there too (not only on buildUseRecord).
type failSealCore struct {
	api.Sealer
	fail bool
}

func (f *failSealCore) SealRecord(bodyJSON string) (string, error) {
	if f.fail {
		return "", errors.New("injected seal failure")
	}
	return f.Sealer.SealRecord(bodyJSON)
}

// TestUseReleasesCredentialOnSealFailure (adversarial review pass-9 high): a SealRecord failure inside sealAndStore is a
// PRE-commit error (nothing reached PutRecord), so — like a buildUseRecord failure — the consumed nonce/jti
// must be released. ValidateUse succeeds, then SealRecord fails; the credential must survive for an honest retry.
func TestUseReleasesCredentialOnSealFailure(t *testing.T) {
	realCore, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	fsc := &failSealCore{Sealer: realCore}
	h := api.New(fsc, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant") // grant seals while SealRecord is healthy

	fsc.fail = true
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusInternalServerError {
		t.Fatalf("a pre-commit SealRecord failure should be 500, got %d: %s", code, r)
	}
	// the credential was RELEASED (pre-commit failure, nothing persisted): the SAME nonce re-validates + seals.
	fsc.fail = false
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("after the sealer recovers, the released credential must seal a receipt, got %d: %s", code, r)
	}
}

// TestUseReleasesCredentialOnReceiptBuildFailure (adversarial review pass-8 high): if receipt construction fails AFTER
// ValidateUse consumed the single-use credential but BEFORE anything persisted (here the content store fails
// while storing the use params), the nonce/jti must be RELEASED — the caller got a 500 and never acted, so a
// retry must be able to re-validate. Otherwise a transient build error burns the credential.
func TestUseReleasesCredentialOnReceiptBuildFailure(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	fc := &failContentStore{Store: content.NewMemStore()}
	h := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").WithContent(fc).Routes()
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant") // grant minted while the content store is healthy

	fc.fail = true
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusInternalServerError {
		t.Fatalf("a receipt-build failure (content store) should be 500, got %d: %s", code, r)
	}
	// the single-use credential was RELEASED, not burned: with the content store healthy the SAME nonce
	// re-validates and seals a receipt.
	fc.fail = false
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("after the content store recovers, the released credential must seal a receipt, got %d: %s", code, r)
	}
}
