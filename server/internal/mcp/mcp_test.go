package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func req(t *testing.T, method, params string) Request {
	t.Helper()
	return Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method, Params: json.RawMessage(params)}
}

func TestInitializeAndToolsList(t *testing.T) {
	s := New("http://unused")
	init := s.Handle(req(t, "initialize", `{}`))
	if init.Error != nil {
		t.Fatalf("initialize error: %v", init.Error)
	}
	res := init.Result.(map[string]any)
	if res["protocolVersion"] != protocolVersion {
		t.Fatalf("bad protocol version")
	}

	list := s.Handle(req(t, "tools/list", `{}`))
	tools := list.Result.(map[string]any)["tools"].([]map[string]any)
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl["name"].(string)] = true
	}
	for _, want := range []string{"record_decision", "get_session_trace", "verify_record", "request_export"} {
		if !names[want] {
			t.Fatalf("missing tool %s", want)
		}
	}
}

func TestRecordDecisionToolCallsAverin(t *testing.T) {
	var gotPath, gotBody string
	averin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		gotBody = string(b)
		w.Write([]byte(`{"results":[{"created":true,"record":{"content_hash":"sha256:abc"}}]}`))
	}))
	defer averin.Close()

	s := New(averin.URL)
	resp := s.Handle(req(t, "tools/call",
		`{"name":"record_decision","arguments":{"project_id":"p1","session_id":"s1","action":"db.write","rationale":"why"}}`))
	if resp.Error != nil {
		t.Fatalf("tool error: %v", resp.Error)
	}
	if gotPath != "/v2/records" {
		t.Fatalf("expected POST /v2/records, got %s", gotPath)
	}
	if !strings.Contains(gotBody, `"action":"db.write"`) || !strings.Contains(gotBody, `"rationale":"why"`) {
		t.Fatalf("body missing fields: %s", gotBody)
	}
	content := resp.Result.(map[string]any)["content"].([]map[string]any)
	if !strings.Contains(content[0]["text"].(string), "sha256:abc") {
		t.Fatalf("tool result missing sealed hash: %v", content)
	}
}

func TestRequestExportReturnsURL(t *testing.T) {
	s := New("http://averin.example")
	resp := s.Handle(req(t, "tools/call", `{"name":"request_export","arguments":{"project_id":"p1"}}`))
	text := resp.Result.(map[string]any)["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, "http://averin.example/v2/export?project=p1&mode=proof_only") {
		t.Fatalf("bad export url: %s", text)
	}
}

func TestUnknownMethod(t *testing.T) {
	s := New("http://x")
	resp := s.Handle(req(t, "nonsense", `{}`))
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("expected method-not-found, got %v", resp.Error)
	}
}
