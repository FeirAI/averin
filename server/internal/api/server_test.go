package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/averin-dev/averin/server/internal/api"
	"github.com/averin-dev/averin/server/internal/auth"
	"github.com/averin-dev/averin/server/internal/content"
	"github.com/averin-dev/averin/server/internal/core"
	"github.com/averin-dev/averin/server/internal/store"
	"github.com/averin-dev/averin/server/internal/witness"
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

func TestContentCommitmentAndSelectiveDisclosure(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	srv := api.New(c, store.NewMem(), "k0")
	h := srv.Routes()

	// Ingest a record carrying raw low-entropy fields (input + output).
	rec, _ := postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"db.query","input":"SELECT balance FROM accounts WHERE id=42","output":"balance=1204"}`)

	// The sealed record must carry commitments, NOT the plaintext.
	if _, leaked := rec["input"]; leaked {
		t.Fatalf("raw input leaked into the signed record: %v", rec)
	}
	if _, leaked := rec["output"]; leaked {
		t.Fatalf("raw output leaked into the signed record: %v", rec)
	}
	ic, _ := rec["input_commit"].(map[string]any)
	if ic == nil || !strings.HasPrefix(asString(ic["commitment"]), "sha256:") {
		t.Fatalf("no input_commit: %v", rec)
	}
	if _, ok := rec["output_commit"]; !ok {
		t.Fatalf("no output_commit: %v", rec)
	}
	extensions, _ := rec["extensions"].(map[string]any)
	evidence, _ := extensions["feir_evidence"].(map[string]any)
	payloads, _ := evidence["payloads"].(map[string]any)
	inputRef, _ := payloads["input"].(map[string]any)
	if !strings.HasPrefix(asString(inputRef["commitment"]), "sha256:") {
		t.Fatalf("signed record is missing the retained input commitment: %v", rec)
	}
	// The retained reference must be the NONCE'D commitment, never the plain content digest:
	// an unsalted sha256 of a low-entropy value in the always-exported body is dictionary-
	// reversible (threat #6). Grumble if the plain digest sneaks back into the sealed body.
	plainDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("SELECT balance FROM accounts WHERE id=42")))
	if recJSON, _ := json.Marshal(rec); strings.Contains(string(recJSON), plainDigest) {
		t.Fatalf("sealed record contains the plain content digest of a low-entropy value: %s", recJSON)
	}
	// Lineage/authority are stamped after the server defaults, so the sealed evidence block
	// must agree with the record's own span_id/observed_via (no null lineage on the SDK path).
	lineage, _ := evidence["lineage"].(map[string]any)
	if asString(lineage["span_id"]) == "" || asString(lineage["span_id"]) != asString(rec["span_id"]) {
		t.Fatalf("sealed lineage span_id %v disagrees with record span_id %v", lineage["span_id"], rec["span_id"])
	}
	if asString(evidence["capture_authority"]) != asString(rec["observed_via"]) {
		t.Fatalf("sealed capture_authority %v disagrees with record observed_via %v", evidence["capture_authority"], rec["observed_via"])
	}

	// A retry under the same idempotency key must NOT create a second set of disclosures.
	if _, created := postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"db.query","input":"SELECT balance FROM accounts WHERE id=42","output":"balance=1204"}`); created {
		t.Fatal("retry under the same idempotency key created a new record")
	}

	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, resp)
	}

	// proof_only: commitments only, nothing disclosed.
	_, proof := do(t, h, "GET", "/v2/export?project=p1&mode=proof_only", "")
	if strings.Contains(proof, `"disclosures"`) {
		t.Fatalf("proof_only must not disclose raw values: %s", proof)
	}
	if !strings.Contains(proof, `"raw_content_available":false`) {
		t.Fatalf("proof_only should report raw_content_available:false: %s", proof)
	}

	// selective_disclosure: both fields disclosed, and the offline verifier confirms both against the
	// sealed commitments (still a single retry => exactly 2 disclosures, not 4).
	code, exp := do(t, h, "GET", "/v2/export?project=p1&mode=selective_disclosure", "")
	if code != http.StatusOK {
		t.Fatalf("export (%d): %s", code, exp)
	}
	if !strings.Contains(exp, `"raw_content_available":true`) {
		t.Fatalf("selective_disclosure should report raw_content_available:true: %s", exp)
	}
	report := c.VerifyBundle(exp)
	if !strings.Contains(report, `"ok":true`) {
		t.Fatalf("disclosing bundle should verify ok:\nbundle=%s\nreport=%s", exp, report)
	}
	if !strings.Contains(report, `"disclosures_total":2`) || !strings.Contains(report, `"disclosures_verified":2`) {
		t.Fatalf("both disclosures should verify: %s", report)
	}

	// Tamper: substitute a disclosed value -> the verifier must reject the bundle.
	tampered := tamperFirstDisclosure(t, exp)
	if rep := c.VerifyBundle(tampered); strings.Contains(rep, `"ok":true`) {
		t.Fatalf("a tampered disclosure must fail the bundle, got ok:true: %s", rep)
	} else if !strings.Contains(rep, "does not match") {
		t.Fatalf("expected a commitment-mismatch issue, got: %s", rep)
	}
}

func TestSelectiveDisclosureSurvivesRawRetentionDeletion(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	contentStore, err := content.NewEncryptedFSStore(t.TempDir(), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("content store: %v", err)
	}
	srv := api.New(c, store.NewMem(), "k0").WithContent(contentStore)
	h := srv.Routes()
	postRecord(t, h, `{"idempotency_key":"retention-1","project_id":"p1","session_id":"s1","action":"llm.call","input":"visible prompt"}`)
	if removed, err := contentStore.PurgeOlderThan(time.Now().Add(time.Hour)); err != nil || removed != 1 {
		t.Fatalf("purge removed=%d err=%v", removed, err)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, resp)
	}
	code, exported := do(t, h, "GET", "/v2/export?project=p1&mode=selective_disclosure", "")
	if code != http.StatusOK {
		t.Fatalf("post-retention export failed (%d): %s", code, exported)
	}
	if strings.Contains(exported, `"value_b64"`) || !strings.Contains(exported, `"raw_content_available":false`) {
		t.Fatalf("post-retention export must retain proof without claiming raw availability: %s", exported)
	}
	if !strings.Contains(exported, `"payload_reference":"averin-commit:sha256:`) {
		t.Fatalf("post-retention proof lost its sealed payload reference: %s", exported)
	}
}

func asString(v any) string { s, _ := v.(string); return s }

// tamperFirstDisclosure replaces disclosures[0].value_b64 with a different value, returning the
// re-serialized bundle.
func tamperFirstDisclosure(t *testing.T, bundle string) string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bundle), &obj); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	var disc []map[string]any
	if err := json.Unmarshal(obj["disclosures"], &disc); err != nil || len(disc) == 0 {
		t.Fatalf("unmarshal disclosures: %v (%s)", err, obj["disclosures"])
	}
	disc[0]["value_b64"] = "ZG9jdG9yZWQ" // base64url("doctored"), not the committed value
	obj["disclosures"], _ = json.Marshal(disc)
	out, _ := json.Marshal(obj)
	return string(out)
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
	// A client LIES that authority is policy_engine_signed, with a bogus evidence_sig and NO key pinned.
	// F3: under the DEFAULT (fail-closed) posture this is REJECTED outright — the forged claim never enters
	// the append-only store at all. Previously this test asserted only that the lie was *downgraded* and
	// sealed, which is exactly why the fail-open default went unnoticed: the assertion passed either way.
	body := `{"idempotency_key":"a1","project_id":"p1","session_id":"s1","authority":{"source":"policy_engine_signed","decision_basis":"policy_allowed","evidence_sig":"ed25519:bogus"}}`
	h := newSrv(t)
	if code, resp := do(t, h, "POST", "/v2/records", body); code != http.StatusInternalServerError {
		t.Fatalf("by DEFAULT an unverifiable elevated-authority claim must be REJECTED (500), got %d: %s", code, resp)
	}
	_, list := do(t, h, "GET", "/v2/records?project=p1", "")
	if !strings.Contains(list, `"total":0`) {
		t.Fatalf("a rejected forged-authority claim must seal NOTHING: %s", list)
	}

	// With the explicit fail-OPEN opt-out (AVERIN_REQUIRE_PINNED_AUTHORITY=0) the Phase-1 behavior is
	// preserved: the record seals, but never at the claimed source — it is forced to caller_declared.
	hOpen := newServer(t).WithRequirePinnedAuthority(false).Routes()
	rec, _ := postRecord(t, hOpen, body)
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

func TestCheckpointAnchoredWithTSA(t *testing.T) {
	srv := newServer(t).WithTSA(witness.StubTSA{})
	h := srv.Routes()
	postRecord(t, h, `{"idempotency_key":"a1","project_id":"p1","session_id":"s1","action":"a"}`)
	code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	if code != http.StatusCreated {
		t.Fatalf("checkpoint failed (%d): %s", code, resp)
	}
	if strings.Contains(resp, "un-anchored") {
		t.Fatalf("unexpected anchor warning: %s", resp)
	}

	// The anchor is decoupled — joined into the checkpoint at export. (The StubTSA token is not
	// crypto-valid; full anchor verification is covered in the Rust core — here we assert the wiring
	// attaches a well-formed rfc3161 anchor block and that it does not disturb the sealed hash/sig.)
	_, exp := do(t, h, "GET", "/v2/export?project=p1&mode=proof_only", "")
	var bundle struct {
		Checkpoints []map[string]json.RawMessage `json:"checkpoints"`
	}
	if err := json.Unmarshal([]byte(exp), &bundle); err != nil || len(bundle.Checkpoints) == 0 {
		t.Fatalf("decode export: %v\n%s", err, exp)
	}
	anchorRaw, ok := bundle.Checkpoints[0]["anchor"]
	if !ok {
		t.Fatalf("exported checkpoint missing anchor block: %s", exp)
	}
	var anchor struct {
		Scheme   string `json:"scheme"`
		TokenB64 string `json:"token_b64"`
	}
	if err := json.Unmarshal(anchorRaw, &anchor); err != nil {
		t.Fatalf("decode anchor: %v", err)
	}
	if anchor.Scheme != "rfc3161" || anchor.TokenB64 == "" {
		t.Fatalf("bad anchor block: %+v", anchor)
	}
	if _, report := do(t, h, "GET", "/v2/verify?project=p1", ""); !strings.Contains(report, `"ok":true`) {
		t.Fatalf("anchored checkpoint should still verify (anchor excluded from hash): %s", report)
	}
}

// failTSA always fails, so the checkpoint is stored un-anchored with a warning (best-effort anchor).
type failTSA struct{}

func (failTSA) Stamp(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("TSA unreachable")
}

func TestCheckpointSurvivesTSAFailure(t *testing.T) {
	h := newServer(t).WithTSA(failTSA{}).Routes()
	postRecord(t, h, `{"idempotency_key":"t1","project_id":"p1","session_id":"s1","action":"a"}`)
	code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	if code != http.StatusCreated {
		t.Fatalf("a TSA failure must not fail checkpoint creation (%d): %s", code, resp)
	}
	if !strings.Contains(resp, "un-anchored") {
		t.Fatalf("expected an un-anchored warning, got: %s", resp)
	}
	// No anchor joined at export, but the checkpoint is sealed, chained, and verifiable.
	_, exp := do(t, h, "GET", "/v2/export?project=p1&mode=proof_only", "")
	if strings.Contains(exp, `"anchor"`) {
		t.Fatalf("a failed TSA must not produce an anchor: %s", exp)
	}
	if _, report := do(t, h, "GET", "/v2/verify?project=p1", ""); !strings.Contains(report, `"ok":true`) {
		t.Fatalf("un-anchored checkpoint should still verify: %s", report)
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

// TestGenericRecordCannotForgeBrokerExtension proves the D6 head-poisoning guard: a generic /v2/records
// caller that forges extensions.broker (e.g. kind=grant + a fake broker_seq) is REJECTED, so it can
// never be folded into the broker grant-transparency head (ADR 0004 D6).
func TestGenericRecordCannotForgeBrokerExtension(t *testing.T) {
	h := newSrv(t)
	body := `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"x",` +
		`"extensions":{"broker":{"kind":"grant","grant_evidence":{"broker_seq":99}}}}`
	code, resp := do(t, h, "POST", "/v2/records", body)
	if code != http.StatusBadRequest {
		t.Fatalf("a forged extensions.broker record must be rejected (400), got %d: %s", code, resp)
	}
	if !strings.Contains(resp, "extensions.broker is reserved") {
		t.Fatalf("expected reserved-extensions rejection, got: %s", resp)
	}
}
