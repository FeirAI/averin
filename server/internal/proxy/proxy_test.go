package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type stubRecorder struct {
	records []map[string]any
	got     chan struct{}
}

func newStub() *stubRecorder { return &stubRecorder{got: make(chan struct{}, 8)} }

func (s *stubRecorder) Record(body map[string]any) error {
	s.records = append(s.records, body)
	s.got <- struct{}{}
	return nil
}

// wait blocks until n records have arrived (or fails). Recording runs in the request goroutine
// after the response body is flushed, so the client can return before it completes.
func (s *stubRecorder) wait(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-s.got:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for record %d/%d", i+1, n)
		}
	}
}

func TestProxyForwardsAndRecordsScrubbed(t *testing.T) {
	// upstream returns a completion that echoes a secret + carries usage
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("upstream should still receive the client's Authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"your key sk-abcdefghijklmnop1234"}}],"usage":{"prompt_tokens":12,"completion_tokens":7}}`))
	}))
	defer upstream.Close()

	rec := newStub()
	p := New(upstream.URL, "p1", rec)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"my token is sk-zzzzzzzzzzzzzzzz1234"}]}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-secret-upstream-key-123456")
	req.Header.Set("X-Feir-Session-Id", "run-7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// client gets the upstream response verbatim
	if !strings.Contains(string(out), `"completion_tokens":7`) {
		t.Fatalf("client did not get upstream body: %s", out)
	}

	rec.wait(t, 1)
	if len(rec.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(rec.records))
	}
	r := rec.records[0]
	if r["observed_via"] != "proxy" || r["event_type"] != "llm_call" || r["session_id"] != "run-7" {
		t.Fatalf("bad record metadata: %v", r)
	}
	if r["agent_id"] != "gpt-4o" {
		t.Fatalf("model not extracted: %v", r["agent_id"])
	}
	toks := r["tokens"].(map[string]any)
	if toks["in"] != 12 || toks["out"] != 7 {
		t.Fatalf("usage not extracted: %v", toks)
	}
	preview := r["extensions"].(map[string]any)["content_preview"].(map[string]any)
	in := preview["input"].(string)
	outStr := preview["output"].(string)
	// secrets must be redacted in BOTH directions, and the upstream Authorization never recorded
	if strings.Contains(in, "sk-zzzz") || strings.Contains(outStr, "sk-abcdef") {
		t.Fatalf("secret leaked into record: in=%q out=%q", in, outStr)
	}
	if !strings.Contains(in, "[REDACTED:") {
		t.Fatalf("expected redaction marker in input: %q", in)
	}
	for _, v := range r {
		if s, ok := v.(string); ok && strings.Contains(s, "sk-secret-upstream-key") {
			t.Fatalf("upstream Authorization leaked into record")
		}
	}
}

func TestSSESecretSplitAcrossChunksIsScrubbed(t *testing.T) {
	// A secret split across two SSE deltas matches no per-chunk regex; reassembly catches it.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"your key is sk-abcd\"}}]}\n\n"))
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"efghijklmnop1234\"}}]}\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	rec := newStub()
	srv := httptest.NewServer(New(upstream.URL, "p1", rec).Handler())
	defer srv.Close()

	resp, _ := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"gpt-4o","stream":true}`))
	io.ReadAll(resp.Body)
	resp.Body.Close()

	rec.wait(t, 1)
	out := rec.records[0]["extensions"].(map[string]any)["content_preview"].(map[string]any)["output"].(string)
	if strings.Contains(out, "sk-abcdefghijklmnop1234") {
		t.Fatalf("reassembled secret leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:openai]") {
		t.Fatalf("expected redaction of the reassembled key, got: %q", out)
	}
}

func TestNonCompletionPathForwardedButNotRecorded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()
	rec := newStub()
	srv := httptest.NewServer(New(upstream.URL, "p1", rec).Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/v1/models")
	resp.Body.Close()
	time.Sleep(50 * time.Millisecond) // give any (erroneous) async record a chance to land
	if len(rec.records) != 0 {
		t.Fatalf("non-completion path should not be recorded, got %d", len(rec.records))
	}
}
