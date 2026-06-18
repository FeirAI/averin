package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
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

// TestBatchRecordsAtomicOnDeepCanonFailure (F14): a batch whose LATER item passes the shallow checks but
// carries a value the SEAL's RCP canonicalizer rejects (a float in a signed field) must reject the WHOLE
// batch up front — the pre-pass now dry-runs the canonicalizer, so an earlier item never partially persists.
func TestBatchRecordsAtomicOnDeepCanonFailure(t *testing.T) {
	h := newServer(t).Routes()
	batch := `[{"idempotency_key":"ok-1","project_id":"p1","session_id":"s1","action":"db.read"},` +
		`{"idempotency_key":"ok-2","project_id":"p1","session_id":"s1","cost":1.5}]` // 2nd item: float -> RCP-rejected at seal
	if code, body := do(t, h, "POST", "/v2/records", batch); code != http.StatusBadRequest {
		t.Fatalf("a batch with a deep RCP-canon failure must be 400, got %d: %s", code, body)
	}
	_, dag := do(t, h, "GET", "/v2/dag?project=p1&session=s1", "")
	if strings.Contains(dag, "db.read") {
		t.Fatalf("an earlier batch item must not persist when a later RCP-canon failure is rejected (F14); dag: %s", dag)
	}
}

// TestBatchPrePassMirrorsSealFieldDisposition (F14): the canon dry-run must NOT false-reject a batch the
// seal would accept. A non-string in a server-overwritten/defaulted field (agent_id, display_seq) is
// replaced by the seal, so the batch is accepted; a float in an arbitrary CALLER field reaches the seal
// verbatim and is rejected. This pins the pre-pass to the seal's exact field disposition (no batch-vs-single
// inconsistency).
func TestBatchPrePassMirrorsSealFieldDisposition(t *testing.T) {
	h := newServer(t).Routes()
	// non-string in overwritten/defaulted fields -> seal overwrites -> MUST be accepted (no false reject).
	okBatch := `[{"idempotency_key":"fp1","project_id":"p2","session_id":"s2","agent_id":1.5,"display_seq":9.9}]`
	if code, body := do(t, h, "POST", "/v2/records", okBatch); code != http.StatusCreated {
		t.Fatalf("a non-string in an overwritten field must NOT false-reject (the seal overwrites it), got %d: %s", code, body)
	}
	// float in an arbitrary caller field -> reaches the seal verbatim -> MUST be rejected.
	if code, _ := do(t, h, "POST", "/v2/records", `[{"idempotency_key":"fp2","project_id":"p2","session_id":"s2","cost":1.5}]`); code != http.StatusBadRequest {
		t.Fatalf("a float in a caller field must be 400, got %d", code)
	}
}

// TestWithBrokerPanicsOnResourceKeyOverlapEvenResourceFirst (F12): the broker/resource R2 disjointness
// check must be order-independent. WithResource's broker check is skipped when brokerKey is still nil
// (WithResource-before-WithBroker), so WithBroker carries the reciprocal check against the resource key.
func TestWithBrokerPanicsOnResourceKeyOverlapEvenResourceFirst(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	rawResource, _ := hex.DecodeString(resourceSeed)
	brokerSameAsResource := ed25519.NewKeyFromSeed(rawResource) // broker issuing key == resource recording key
	defer func() {
		if recover() == nil {
			t.Fatal("WithBroker must panic when the broker key equals the resource key, even WithResource-first (R2)")
		}
	}()
	api.New(c, store.NewMem(), "k0").WithResource(rc, "orders-db").WithBroker(brokerSameAsResource)
}
