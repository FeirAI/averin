package api

import (
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
