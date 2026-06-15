package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
)

const seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func newSrv(t *testing.T) http.Handler {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	return api.New(c, store.NewMem(), "k0").Routes()
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// postRecord returns the sealed record object and the created flag.
func postRecord(t *testing.T, h http.Handler, body string) (map[string]any, bool) {
	t.Helper()
	code, resp := do(t, h, "POST", "/v2/records", body)
	if code != http.StatusCreated {
		t.Fatalf("ingest failed (%d): %s", code, resp)
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
	return out.Results[0].Record, out.Results[0].Created
}

func TestIngestSealCheckpointVerifyExport(t *testing.T) {
	h := newSrv(t)
	r1, _ := postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"db.read"}`)
	if !strings.HasPrefix(r1["content_hash"].(string), "sha256:") {
		t.Fatalf("no content_hash: %v", r1)
	}
	if !strings.HasPrefix(r1["sig"].(string), "ed25519:") {
		t.Fatalf("no sig: %v", r1)
	}
	// second record links causally to the first
	r2, _ := postRecord(t, h, `{"idempotency_key":"k2","project_id":"p1","session_id":"s1","action":"db.write"}`)
	parents, _ := r2["causal_prev_hashes"].([]any)
	if len(parents) != 1 || parents[0] != r1["content_hash"] {
		t.Fatalf("expected r2 to link to r1, got parents=%v", parents)
	}

	// checkpoint, then verify the whole project offline via the Rust core
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint failed (%d): %s", code, resp)
	}
	code, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("verify not ok (%d): %s", code, report)
	}
	if !strings.Contains(report, `"records_proven":2`) {
		t.Fatalf("expected 2 proven: %s", report)
	}

	// export carries an honest gap_report
	code, exp := do(t, h, "GET", "/v2/export?project=p1&mode=proof_only", "")
	if code != http.StatusOK || !strings.Contains(exp, "gap_report") {
		t.Fatalf("export missing gap_report (%d): %s", code, exp)
	}
}

func TestIdempotencyCollapsesRetries(t *testing.T) {
	h := newSrv(t)
	a, createdA := postRecord(t, h, `{"idempotency_key":"dup","project_id":"p1","session_id":"s1","action":"charge"}`)
	b, createdB := postRecord(t, h, `{"idempotency_key":"dup","project_id":"p1","session_id":"s1","action":"charge-RETRY"}`)
	if !createdA || createdB {
		t.Fatalf("retry must not create a new record: createdA=%v createdB=%v", createdA, createdB)
	}
	if a["content_hash"] != b["content_hash"] {
		t.Fatalf("idempotent retry returned a different record")
	}
}

func TestAuthorityIsDeclaredNotSilentlyVerified(t *testing.T) {
	h := newSrv(t)
	// client LIES that authority is policy_engine_signed — even WITH a bogus evidence_sig the server
	// must not promote it (no server-side evidence verification in Phase 1).
	rec, _ := postRecord(t, h,
		`{"idempotency_key":"a1","project_id":"p1","session_id":"s1","authority":{"source":"policy_engine_signed","decision_basis":"policy_allowed","evidence_sig":"ed25519:bogus"}}`)
	auth, _ := rec["authority"].(map[string]any)
	if auth["source"] != "caller_declared" {
		t.Fatalf("unverified authority must be caller_declared, got %v", auth["source"])
	}
}

func TestDAGEndpointReturnsSessionRecords(t *testing.T) {
	h := newSrv(t)
	postRecord(t, h, `{"idempotency_key":"d1","project_id":"p1","session_id":"s1","action":"a"}`)
	postRecord(t, h, `{"idempotency_key":"d2","project_id":"p1","session_id":"s1","action":"b"}`)
	postRecord(t, h, `{"idempotency_key":"d3","project_id":"p1","session_id":"other","action":"c"}`)
	code, resp := do(t, h, "GET", "/v2/dag?project=p1&session=s1", "")
	if code != http.StatusOK {
		t.Fatalf("dag %d: %s", code, resp)
	}
	var out struct {
		Records []map[string]any `json:"records"`
	}
	json.Unmarshal([]byte(resp), &out)
	if len(out.Records) != 2 {
		t.Fatalf("expected 2 records in session s1, got %d", len(out.Records))
	}
}

func TestEmptyBatchRejected(t *testing.T) {
	h := newSrv(t)
	if code, _ := do(t, h, "POST", "/v2/records", `[]`); code != http.StatusBadRequest {
		t.Fatalf("empty batch must be 400, got %d", code)
	}
}

func TestClockSkewServerTimestampWins(t *testing.T) {
	h := newSrv(t)
	rec, _ := postRecord(t, h,
		`{"idempotency_key":"c1","project_id":"p1","session_id":"s1","agent_ts":"2099-01-01T00:00:00.000Z","action":"x"}`)
	if rec["agent_ts"] != "2099-01-01T00:00:00.000Z" {
		t.Fatalf("agent_ts should be preserved (untrusted): %v", rec["agent_ts"])
	}
	if rec["received_ts"] == rec["agent_ts"] {
		t.Fatalf("received_ts must be the server clock, not the agent's claimed time")
	}
}

func TestIncompleteRecordIsSealed(t *testing.T) {
	h := newSrv(t)
	rec, _ := postRecord(t, h,
		`{"idempotency_key":"i1","project_id":"p1","session_id":"s1","event_type":"incomplete","status":"incomplete","action":"partial-stream"}`)
	if rec["event_type"] != "incomplete" || rec["status"] != "incomplete" {
		t.Fatalf("incomplete record not preserved: %v", rec)
	}
	if !strings.HasPrefix(rec["sig"].(string), "ed25519:") {
		t.Fatalf("incomplete record must still be sealed")
	}
}

func TestMissingIdempotencyKeyRejected(t *testing.T) {
	h := newSrv(t)
	code, _ := do(t, h, "POST", "/v2/records", `{"project_id":"p1","session_id":"s1"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("missing idempotency_key must be rejected, got %d", code)
	}
}
