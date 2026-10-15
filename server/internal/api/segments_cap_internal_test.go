package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/store"
)

// A project whose whole history would exceed the verifier's single-bundle cap is refused with 413 and a pointer to
// the month endpoints, instead of producing a file no verifier accepts. A month over the cap is refused too.
func TestOverTheCapIsRefusedWithAPointerToMonths(t *testing.T) {
	now := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := New(testCore(t), store.NewMem().WithClock(clock), "k0").WithClock(clock)
	h := s.Routes()
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code, rec.Body.String()
	}
	post := func(path, body string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return rec.Code
	}
	if c := post("/v2/records", `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","record_id":"r1"}`); c != http.StatusCreated {
		t.Fatalf("record: %d", c)
	}
	if c := post("/v2/checkpoints?project=p1", ""); c != http.StatusCreated {
		t.Fatalf("checkpoint: %d", c)
	}
	if code, body := get("/v2/export?project=p1"); code != http.StatusOK {
		t.Fatalf("under the cap: %d %s", code, body)
	}

	old := maxSingleBundleBytes
	maxSingleBundleBytes = 10
	defer func() { maxSingleBundleBytes = old }()
	for _, path := range []string{"/v2/export?project=p1", "/v2/verify?project=p1"} {
		code, body := get(path)
		if code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "/v2/segments") {
			t.Fatalf("%s over the cap: %d %s", path, code, body)
		}
	}
	// a month that is itself over the cap is refused too, with its own message
	for _, path := range []string{"/v2/export?project=p1&month=2026-06", "/v2/verify?project=p1&month=2026-06"} {
		code, body := get(path)
		if code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "this month") {
			t.Fatalf("%s: a month over the cap must be refused: %d %s", path, code, body)
		}
	}
	// ... and served again once it fits
	maxSingleBundleBytes = old
	for _, path := range []string{"/v2/export?project=p1&month=2026-06", "/v2/verify?project=p1&month=2026-06"} {
		if code, body := get(path); code != http.StatusOK {
			t.Fatalf("%s must be served under the cap: %d %s", path, code, body)
		}
	}
}

// The cap is on the serialized bundle, not on the records alone: with the cap one byte under the real export, the
// records themselves still fit but the bundle (checkpoints and keys included) does not, so it must be refused.
func TestOverTheCapCountsTheSerializedBundleNotJustTheRecords(t *testing.T) {
	now := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := New(testCore(t), store.NewMem().WithClock(clock), "k0").WithClock(clock)
	h := s.Routes()
	do := func(method, path, body string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code, rec.Body.String()
	}
	if c, b := do("POST", "/v2/records", `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","record_id":"r1"}`); c != http.StatusCreated {
		t.Fatalf("record: %d %s", c, b)
	}
	if c, b := do("POST", "/v2/checkpoints?project=p1", ""); c != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", c, b)
	}
	whole, _, err := s.buildBundleView(context.Background(), "p1", false, "")
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	recs, err := s.st.AllRecords("p1")
	if err != nil {
		t.Fatal(err)
	}
	recBytes := 0
	for _, r := range recs {
		recBytes += len(r.JSON)
	}
	if recBytes >= len(whole)-1 {
		t.Fatalf("test premise: records (%d) must be smaller than the bundle (%d)", recBytes, len(whole))
	}
	old := maxSingleBundleBytes
	maxSingleBundleBytes = len(whole) - 1
	defer func() { maxSingleBundleBytes = old }()
	if _, _, err := s.buildBundleView(context.Background(), "p1", false, ""); !errors.Is(err, errBundleTooBig) {
		t.Fatalf("a bundle one byte over the cap must be refused: %v", err)
	}
	maxSingleBundleBytes = len(whole)
	if _, _, err := s.buildBundleView(context.Background(), "p1", false, ""); err != nil {
		t.Fatalf("a bundle exactly at the cap is served: %v", err)
	}
}
