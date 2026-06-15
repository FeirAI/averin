package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/auth"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
	"github.com/feir-dev/feir/server/internal/witness"
)

const seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func newSrv(t *testing.T) http.Handler {
	t.Helper()
	return newServer(t).Routes()
}

func newServer(t *testing.T) *api.Server {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	return api.New(c, store.NewMem(), "k0")
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

func TestOTelIngestSealsRecords(t *testing.T) {
	h := newSrv(t)
	otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[
	  {"name":"db.query","spanId":"sp1","attributes":[{"key":"session.id","value":{"stringValue":"run-9"}},{"key":"db.system","value":{"stringValue":"pg"}}]}
	]}]}]}`
	code, resp := do(t, h, "POST", "/v2/otel/traces?project=p1", otlp)
	if code != http.StatusCreated || !strings.Contains(resp, `"ingested":1`) {
		t.Fatalf("otel ingest failed (%d): %s", code, resp)
	}
	// the span became a sealed record in session run-9
	_, dag := do(t, h, "GET", "/v2/dag?project=p1&session=run-9", "")
	if !strings.Contains(dag, `"observed_via":"otel"`) || !strings.Contains(dag, `"sig":"ed25519:`) {
		t.Fatalf("otel span not sealed into session: %s", dag)
	}
}

func TestAuthGatesRoutes(t *testing.T) {
	srv := newServer(t).WithAuth(auth.NewMapStore(map[string][]string{"p1": {"s3cret"}}))
	h := srv.Routes()
	// no token -> 401
	if code, _ := do(t, h, "GET", "/v2/sessions?project=p1", ""); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", code)
	}
	// right token -> 200
	req := httptest.NewRequest("GET", "/v2/sessions?project=p1", nil)
	req.Header.Set("X-Api-Key", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %d", rec.Code)
	}
	// wrong project for the token -> 401
	req2 := httptest.NewRequest("GET", "/v2/sessions?project=other", nil)
	req2.Header.Set("X-Api-Key", "s3cret")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("token must not be valid for a different project, got %d", rec2.Code)
	}
}

func TestCheckpointWrittenToWitness(t *testing.T) {
	w := witness.NewMemWitness()
	srv := newServer(t).WithWitness(w)
	h := srv.Routes()
	postRecord(t, h, `{"idempotency_key":"w1","project_id":"p1","session_id":"s1","action":"a"}`)
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint failed (%d): %s", code, resp)
	}
	entries, err := w.List(context.Background(), "p1")
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 witnessed checkpoint, got %d (err %v)", len(entries), err)
	}
}

// failOnceWitness fails the first Append, then delegates to a real MemWitness.
type failOnceWitness struct {
	inner  *witness.MemWitness
	failed bool
}

func (f *failOnceWitness) Append(ctx context.Context, project string, cp []byte) error {
	if !f.failed {
		f.failed = true
		return errors.New("transient witness outage")
	}
	return f.inner.Append(ctx, project, cp)
}
func (f *failOnceWitness) List(ctx context.Context, project string) ([][]byte, error) {
	return f.inner.List(ctx, project)
}

func TestCheckpointSurvivesWitnessFailure(t *testing.T) {
	w := &failOnceWitness{inner: witness.NewMemWitness()}
	h := newServer(t).WithWitness(w).Routes()
	postRecord(t, h, `{"idempotency_key":"x","project_id":"p1","session_id":"s1","action":"a"}`)

	// first checkpoint: witness fails -> still 201, with a warning (checkpoint IS created)
	code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	if code != http.StatusCreated || !strings.Contains(resp, "warning") {
		t.Fatalf("expected 201+warning on witness failure, got %d: %s", code, resp)
	}
	// second checkpoint must NOT be wedged: seq advanced, witness now succeeds
	code2, resp2 := do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	if code2 != http.StatusCreated || strings.Contains(resp2, "warning") {
		t.Fatalf("checkpointing wedged after a witness failure: %d %s", code2, resp2)
	}
}

func TestConcurrentCheckpointsDoNotFork(t *testing.T) {
	h := newServer(t).Routes()
	postRecord(t, h, `{"idempotency_key":"x","project_id":"p1","session_id":"s1","action":"a"}`)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); do(t, h, "POST", "/v2/checkpoints?project=p1", "") }()
	}
	wg.Wait()
	// the chain must still verify (serialized seqs, no fork)
	_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
	if !strings.Contains(report, `"chain_ok":true`) {
		t.Fatalf("concurrent checkpoints forked the chain: %s", report)
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

func TestUsageMetering(t *testing.T) {
	h := newSrv(t)
	postRecord(t, h, `{"idempotency_key":"u1","project_id":"p1","session_id":"s1","action":"a"}`)
	postRecord(t, h, `{"idempotency_key":"u1","project_id":"p1","session_id":"s1","action":"a"}`) // retry, not billed
	postRecord(t, h, `{"idempotency_key":"u2","project_id":"p1","session_id":"s1","action":"b"}`)
	do(t, h, "GET", "/v2/export?project=p1", "")

	code, resp := do(t, h, "GET", "/v2/usage?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("usage %d: %s", code, resp)
	}
	var out struct {
		Usage struct {
			Records int64 `json:"records"`
			Exports int64 `json:"exports"`
		} `json:"usage"`
	}
	json.Unmarshal([]byte(resp), &out)
	if out.Usage.Records != 2 { // 2 unique records (the retry collapsed, not metered)
		t.Fatalf("expected 2 metered records, got %d", out.Usage.Records)
	}
	if out.Usage.Exports != 1 {
		t.Fatalf("expected 1 export, got %d", out.Usage.Exports)
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
