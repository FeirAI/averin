package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F5 — BATCH IDEMPOTENCY COLLAPSES DISTINCT EVIDENCE.
//
// store.PutRecord dedups per (project_id, idempotency_key): a second Put under a key already used returns the
// FIRST row with created=false. A /v2/records batch resolved each item's key as
// `item.idempotency_key OR the Idempotency-Key HEADER`, and never checked the resolved keys were distinct —
// so a multi-item batch posted with only a header key made every item after the first collapse onto the
// first. The 201 response still carried one result per item (each echoing record #1), so the caller saw
// "all accepted" while records 2..N were SILENTLY DISCARDED from an append-only flight recorder.
//
// Same class as the convergent-write replay defects closed in govder: one idempotency key covering writes
// with distinct content.

// doWithHeader posts a body with an Idempotency-Key header (the plain `do` helper sends no headers, which is
// exactly why no existing test exercised this path).
func doWithHeader(t *testing.T, h http.Handler, method, path, body, idemHeader string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if idemHeader != "" {
		req.Header.Set("Idempotency-Key", idemHeader)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func recordTotal(t *testing.T, h http.Handler, project string) int {
	t.Helper()
	code, list := do(t, h, "GET", "/v2/records?project="+project, "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, list)
	}
	var out struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(list), &out); err != nil {
		t.Fatalf("decode list: %v\n%s", err, list)
	}
	return out.Total
}

// TestBatchWithOnlyHeaderIdempotencyKeyIsRejected (F5): two DISTINCT records in one batch, keyed only by the
// Idempotency-Key header, must be rejected as a whole — not collapsed onto one stored record with a 201 that
// claims both were accepted.
func TestBatchWithOnlyHeaderIdempotencyKeyIsRejected(t *testing.T) {
	h := newSrv(t)
	batch := `[{"project_id":"p1","session_id":"s1","action":"db.read","event_type":"decision"},` +
		`{"project_id":"p1","session_id":"s1","action":"db.write","event_type":"decision"}]`

	code, resp := doWithHeader(t, h, "POST", "/v2/records", batch, "one-key-for-the-whole-batch")
	if code != http.StatusBadRequest {
		t.Fatalf("a multi-item batch sharing ONE idempotency key must be rejected 400 (it would collapse and "+
			"silently drop the later record's evidence), got %d: %s", code, resp)
	}
	if !strings.Contains(resp, "share idempotency_key") {
		t.Fatalf("the 400 must name the collapsing key: %s", resp)
	}
	if n := recordTotal(t, h, "p1"); n != 0 {
		t.Fatalf("a rejected batch must seal NOTHING, got total=%d", n)
	}
}

// TestBatchWithDuplicateExplicitIdempotencyKeysIsRejected (F5): the same collapse via duplicated per-item
// idempotency_key fields.
func TestBatchWithDuplicateExplicitIdempotencyKeysIsRejected(t *testing.T) {
	h := newSrv(t)
	batch := `[{"idempotency_key":"dup","project_id":"p1","session_id":"s1","action":"db.read","event_type":"decision"},` +
		`{"idempotency_key":"dup","project_id":"p1","session_id":"s1","action":"db.write","event_type":"decision"}]`

	code, resp := do(t, h, "POST", "/v2/records", batch)
	if code != http.StatusBadRequest {
		t.Fatalf("two batch items sharing an explicit idempotency_key must be rejected 400, got %d: %s", code, resp)
	}
	if n := recordTotal(t, h, "p1"); n != 0 {
		t.Fatalf("a rejected batch must seal NOTHING, got total=%d", n)
	}
}

// TestBatchWithDistinctIdempotencyKeysSealsEveryRecord (F5, no false rejection): a well-formed batch still
// seals EVERY item, and each result is that item's own record — the property the collapse violated.
func TestBatchWithDistinctIdempotencyKeysSealsEveryRecord(t *testing.T) {
	h := newSrv(t)
	batch := `[{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"db.read","event_type":"decision"},` +
		`{"idempotency_key":"k2","project_id":"p1","session_id":"s1","action":"db.write","event_type":"decision"},` +
		`{"idempotency_key":"k3","project_id":"p1","session_id":"s1","action":"db.delete","event_type":"decision"}]`

	code, resp := do(t, h, "POST", "/v2/records", batch)
	if code != http.StatusCreated {
		t.Fatalf("a batch with distinct keys must be accepted, got %d: %s", code, resp)
	}
	var out struct {
		Results []struct {
			Created bool           `json:"created"`
			Record  map[string]any `json:"record"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, resp)
	}
	if len(out.Results) != 3 {
		t.Fatalf("want 3 results, got %d: %s", len(out.Results), resp)
	}
	seen := map[string]bool{}
	for i, r := range out.Results {
		if !r.Created {
			t.Fatalf("result %d: created=false — the item collapsed onto an earlier record: %s", i, resp)
		}
		ch, _ := r.Record["content_hash"].(string)
		if ch == "" || seen[ch] {
			t.Fatalf("result %d: duplicate/absent content_hash %q — distinct evidence collapsed: %s", i, ch, resp)
		}
		seen[ch] = true
	}
	if n := recordTotal(t, h, "p1"); n != 3 {
		t.Fatalf("want 3 stored records, got %d", n)
	}
}

// TestSingleRecordStillAcceptsHeaderIdempotencyKey (F5, back-compat): the header key remains the supported
// way to key a SINGLE record — the uniqueness rule only constrains multi-item batches. A repeat of the same
// single record under the same header key still collapses idempotently (created=false), which is correct:
// same key, same evidence.
func TestSingleRecordStillAcceptsHeaderIdempotencyKey(t *testing.T) {
	h := newSrv(t)
	body := `{"project_id":"p1","session_id":"s1","action":"db.read","event_type":"decision"}`

	code, resp := doWithHeader(t, h, "POST", "/v2/records", body, "hdr-1")
	if code != http.StatusCreated || !strings.Contains(resp, `"created":true`) {
		t.Fatalf("a single record keyed by the header must seal, got %d: %s", code, resp)
	}
	code, resp = doWithHeader(t, h, "POST", "/v2/records", body, "hdr-1")
	if code != http.StatusCreated || !strings.Contains(resp, `"created":false`) {
		t.Fatalf("an honest retry under the same header key must collapse idempotently, got %d: %s", code, resp)
	}
	if n := recordTotal(t, h, "p1"); n != 1 {
		t.Fatalf("want 1 stored record after an idempotent retry, got %d", n)
	}
}

// TestBatchIdempotencyIsScopedPerProject (F5, no false rejection): the store dedups per (project_id, key), so
// the SAME key under DIFFERENT project_ids does not collide and must not be rejected.
func TestBatchIdempotencyIsScopedPerProject(t *testing.T) {
	h := newSrv(t)
	batch := `[{"idempotency_key":"same","project_id":"p1","session_id":"s1","action":"db.read","event_type":"decision"},` +
		`{"idempotency_key":"same","project_id":"p2","session_id":"s1","action":"db.read","event_type":"decision"}]`

	code, resp := do(t, h, "POST", "/v2/records", batch)
	if code != http.StatusCreated {
		t.Fatalf("one key under two DIFFERENT projects does not collide and must be accepted, got %d: %s", code, resp)
	}
	if n := recordTotal(t, h, "p1"); n != 1 {
		t.Fatalf("p1: want 1 record, got %d", n)
	}
	if n := recordTotal(t, h, "p2"); n != 1 {
		t.Fatalf("p2: want 1 record, got %d", n)
	}
}
