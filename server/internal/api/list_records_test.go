package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/feirai/averin/server/internal/auth"
)

func TestListRecordsNewestFirstAndTruncation(t *testing.T) {
	h := newSrv(t)
	postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"first"}`)
	postRecord(t, h, `{"idempotency_key":"k2","project_id":"p1","session_id":"s1","action":"second"}`)
	postRecord(t, h, `{"idempotency_key":"k3","project_id":"p1","session_id":"s1","action":"third"}`)
	code, resp := do(t, h, "GET", "/v2/records?project=p1&limit=2", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, resp)
	}
	var out struct {
		Records   []json.RawMessage `json:"records"`
		Total     int               `json:"total"`
		Truncated bool              `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 2 || out.Total != 3 || !out.Truncated {
		t.Fatalf("want 2 newest of 3 truncated, got len=%d total=%d truncated=%v", len(out.Records), out.Total, out.Truncated)
	}
	if len(out.Records) < 2 {
		t.Fatal("expected 2 records")
	}
	var first map[string]any
	_ = json.Unmarshal(out.Records[0], &first)
	if first["action"] != "third" {
		t.Fatalf("first record should be newest (action=third), got %v", first["action"])
	}
	code, resp = do(t, h, "GET", "/v2/records?project=p1&limit=100", "")
	if code != http.StatusOK {
		t.Fatalf("list all: %d", code)
	}
	_ = json.Unmarshal([]byte(resp), &out)
	if len(out.Records) != 3 || out.Truncated {
		t.Fatalf("limit=100: got %d truncated=%v", len(out.Records), out.Truncated)
	}
}

func TestListRecordsRequiresProject(t *testing.T) {
	h := newSrv(t)
	if code, _ := do(t, h, "GET", "/v2/records", ""); code != http.StatusBadRequest {
		t.Fatalf("no project: want 400, got %d", code)
	}
	if code, _ := do(t, h, "GET", "/v2/records?project=p1&limit=abc", ""); code != http.StatusBadRequest {
		t.Fatalf("bad limit: want 400, got %d", code)
	}
	if code, _ := do(t, h, "GET", "/v2/records?project=p1&limit=0", ""); code != http.StatusBadRequest {
		t.Fatalf("zero limit: want 400, got %d", code)
	}
}

func TestListRecordsProjectIsolation(t *testing.T) {
	h := newSrv(t)
	postRecord(t, h, `{"idempotency_key":"p1k","project_id":"p1","session_id":"s1","action":"a"}`)
	postRecord(t, h, `{"idempotency_key":"p2k","project_id":"p2","session_id":"s1","action":"a"}`)
	code, resp := do(t, h, "GET", "/v2/records?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("list p1: %d", code)
	}
	var out struct {
		Records []json.RawMessage `json:"records"`
		Total   int               `json:"total"`
	}
	_ = json.Unmarshal([]byte(resp), &out)
	if out.Total != 1 {
		t.Fatalf("p1 should have 1 record, got %d", out.Total)
	}
}

func TestListRecordsAuthGates(t *testing.T) {
	srv := newServer(t).WithAuth(auth.NewMapStore(map[string][]string{"p1": {"s3cret"}}))
	h := srv.Routes()
	if code, _ := do(t, h, "GET", "/v2/records?project=p1", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", code)
	}
	req := httptest.NewRequest("GET", "/v2/records?project=p1", nil)
	req.Header.Set("X-Api-Key", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: want 200, got %d", rec.Code)
	}
	req2 := httptest.NewRequest("GET", "/v2/records?project=other", nil)
	req2.Header.Set("X-Api-Key", "s3cret")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong project: want 401, got %d", rec2.Code)
	}
}
