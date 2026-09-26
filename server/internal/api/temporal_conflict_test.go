package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/feirai/averin/server/internal/store"
)

// hideIdemStore makes the idempotency lookup miss, as when a concurrent same-key insert races
// past it, so the handler reaches its collapse branch after allocating an ordinal.
type hideIdemStore struct{ store.Store }
type hideIdemBound struct{ store.Store }

func (h *hideIdemStore) WithProjectWrite(ctx context.Context, p string, fn func(store.Store) error) error {
	return h.Store.WithProjectWrite(ctx, p, func(b store.Store) error { return fn(&hideIdemBound{b}) })
}
func (h *hideIdemStore) WithProjectRead(ctx context.Context, p string, fn func(store.Store) error) error {
	return h.Store.WithProjectRead(ctx, p, func(b store.Store) error { return fn(&hideIdemBound{b}) })
}
func (h *hideIdemBound) RecordByIdem(string, string) (store.Record, bool, error) {
	return store.Record{}, false, nil
}

func watermark(t *testing.T, st store.Store) int64 {
	t.Helper()
	var w int64
	if err := st.WithProjectRead(context.Background(), "p1", func(b store.Store) error {
		var err error
		_, w, err = b.SnapshotBoundary("p1")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

// seedRecordID stores a foreign record that already holds recordID under another idempotency key.
func seedRecordID(t *testing.T, st store.Store, recordID string) {
	t.Helper()
	body := fmt.Sprintf(`{"record_id":%q,"project_id":"p1","session_id":"s1"}`, recordID)
	if err := st.WithProjectWrite(context.Background(), "p1", func(b store.Store) error {
		_, _, err := b.PutRecord("p1", "foreign-"+recordID, store.Record{JSON: body, ContentHash: "sha256:" + fmt.Sprintf("%064x", len(recordID)), SessionID: "s1"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// exerciseNoBurnedOrdinal checks every non-success branch after allocation (plan 009 review L2):
// a record-id conflict and an idempotency collapse, for uses and native introspection. None may
// leave the project's authorization order advanced.
func exerciseNoBurnedOrdinal(t *testing.T, st store.Store) {
	t.Helper()
	h := temporalServer(t, st, true)
	hidden := temporalServer(t, &hideIdemStore{st}, true)
	ak := grantAgentKey()

	// Learn the deterministic ids from a scratch server, then pre-seed them as foreign records.
	scratch := temporalServer(t, store.NewMem(), true)
	gs, cs := mkGrant(t, scratch, ak, "scratch-grant")
	_, body := do(t, scratch, "POST", "/v2/use", useBody(t, "idem-taken", cs, gs, ak, "SELECT 1", "nonce-s"))
	var u struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(body), &u)
	sg, sexp := nativeGrant(t, scratch, "n-scratch", 3600)
	_, body = do(t, scratch, "POST", "/v2/introspection", introspectBody("intro-taken", sg, "lease-n-scratch", "read:orders", sexp, 0))
	var in struct {
		RecordID string `json:"record_id"`
	}
	json.Unmarshal([]byte(body), &in)
	seedRecordID(t, st, u.UseID)
	seedRecordID(t, st, in.RecordID)

	g1, c1 := mkGrant(t, h, ak, "g1")
	if code, body := do(t, h, "POST", "/v2/use", useBody(t, "idem-taken", c1, g1, ak, "SELECT 1", "nonce-1")); code != http.StatusConflict {
		t.Fatalf("use record-id conflict: %d %s", code, body)
	}
	if w := watermark(t, st); w != 0 {
		t.Fatalf("use record-id conflict burned an ordinal: watermark %d", w)
	}
	ng, nexp := nativeGrant(t, h, "n1", 3600)
	if code, body := do(t, h, "POST", "/v2/introspection", introspectBody("intro-taken", ng, "lease-n1", "read:orders", nexp, 0)); code != http.StatusConflict {
		t.Fatalf("introspection record-id conflict: %d %s", code, body)
	}
	if w := watermark(t, st); w != 0 {
		t.Fatalf("introspection record-id conflict burned an ordinal: watermark %d", w)
	}

	// A committed use and transcript, then a different request under the same key whose lookup
	// misses (a raced insert): the insert collapses onto the committed row and must roll back.
	if code, body := do(t, h, "POST", "/v2/use", useBody(t, "idem-a", c1, g1, ak, "SELECT 1", "nonce-a")); code != http.StatusCreated {
		t.Fatalf("use: %d %s", code, body)
	}
	if code, body := do(t, h, "POST", "/v2/introspection", introspectBody("intro-a", ng, "lease-n1", "read:orders", nexp, 0)); code != http.StatusCreated {
		t.Fatalf("introspection: %d %s", code, body)
	}
	if w := watermark(t, st); w != 2 {
		t.Fatalf("watermark %d after two receipts", w)
	}
	g2, c2 := mkGrant(t, h, ak, "g2")
	if code, body := do(t, hidden, "POST", "/v2/use", useBody(t, "idem-a", c2, g2, ak, "SELECT 2", "nonce-b")); code != http.StatusConflict {
		t.Fatalf("use collapse conflict: %d %s", code, body)
	}
	if code, body := do(t, hidden, "POST", "/v2/introspection", introspectBody("intro-a", ng, "lease-n1", "write:orders", nexp, 0)); code != http.StatusConflict {
		t.Fatalf("introspection collapse conflict: %d %s", code, body)
	}
	if w := watermark(t, st); w != 2 {
		t.Fatalf("a collapsed request burned an ordinal: watermark %d, want 2", w)
	}
	// The collapsed use rolled back its credential claims: the second grant is still usable.
	if code, body := do(t, h, "POST", "/v2/use", useBody(t, "idem-b", c2, g2, ak, "SELECT 2", "nonce-b")); code != http.StatusCreated || watermark(t, st) != 3 {
		t.Fatalf("use after rolled-back collapse: %d %s", code, body)
	}
}

func TestTemporalConflictsBurnNoOrdinal(t *testing.T) {
	exerciseNoBurnedOrdinal(t, store.NewMem())
}

func TestTemporalConflictsBurnNoOrdinalPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	exerciseNoBurnedOrdinal(t, pg)
}

// failGrantLookupStore fails the native-grant lookup inside the write transaction.
type failGrantLookupStore struct{ store.Store }
type failGrantLookupBound struct{ store.Store }

func (f *failGrantLookupStore) WithProjectWrite(ctx context.Context, p string, fn func(store.Store) error) error {
	return f.Store.WithProjectWrite(ctx, p, func(b store.Store) error { return fn(&failGrantLookupBound{b}) })
}
func (f *failGrantLookupBound) RecordByRecordID(string, string) (store.Record, bool, error) {
	return store.Record{}, false, fmt.Errorf("injected database failure")
}

// Review L3: a store failure while validating the native grant is a retryable 5xx, never a
// client refusal, and nothing is signed or ordered.
func TestTemporalIntrospectionStoreErrorIsServerError(t *testing.T) {
	st := store.NewMem()
	h := temporalServer(t, st, true)
	g, exp := nativeGrant(t, h, "n-fail", 3600)
	failing := temporalServer(t, &failGrantLookupStore{st}, true)
	code, body := do(t, failing, "POST", "/v2/introspection", introspectBody("intro-fail", g, "lease-n-fail", "read:orders", exp, 0))
	if code != http.StatusInternalServerError {
		t.Fatalf("store failure during grant validation answered %d: %s", code, body)
	}
	if w := watermark(t, st); w != 0 {
		t.Fatalf("failed introspection ordered: watermark %d", w)
	}
}
