// Package mcp is an experimental Model Context Protocol server (stdio, JSON-RPC 2.0) exposing averin
// to agents as tools: record_decision, get_session_trace, verify_record, request_export. It is a
// thin client over the averin app API — all sealing/verification still runs in the Rust core.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const protocolVersion = "2024-11-05"

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Server struct {
	averinURL string
	client    *http.Client
}

func New(averinURL string) *Server {
	return &Server{averinURL: strings.TrimRight(averinURL, "/"), client: &http.Client{Timeout: 15 * time.Second}}
}

// Serve runs the stdio loop: newline-delimited JSON-RPC in, newline-delimited out.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		resp := s.Handle(req)
		if resp != nil { // notifications (no id) get no response
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

func (s *Server) Handle(req Request) *Response {
	switch req.Method {
	case "initialize":
		return ok(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "averin", "version": "0.1.0"},
		})
	case "notifications/initialized":
		return nil // notification
	case "tools/list":
		return ok(req.ID, map[string]any{"tools": toolDefs()})
	case "tools/call":
		return s.callTool(req)
	default:
		if len(req.ID) == 0 {
			return nil
		}
		return fail(req.ID, -32601, "method not found: "+req.Method)
	}
}

func toolDefs() []map[string]any {
	str := map[string]any{"type": "string"}
	obj := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	return []map[string]any{
		{"name": "record_decision", "description": "Record a tamper-evident decision (tool call / rationale / declared authority) for an agent run.",
			"inputSchema": obj(map[string]any{"project_id": str, "session_id": str, "action": str, "event_type": str, "rationale": str}, "project_id", "session_id", "action")},
		{"name": "get_session_trace", "description": "Fetch the causal trace (DAG) of a session's recorded decisions.",
			"inputSchema": obj(map[string]any{"project_id": str, "session_id": str}, "project_id", "session_id")},
		{"name": "verify_record", "description": "Verify a project's sealed records + checkpoint chain offline; returns the trust report.",
			"inputSchema": obj(map[string]any{"project_id": str}, "project_id")},
		{"name": "request_export", "description": "Get a signed evidence-bundle export URL for a project.",
			"inputSchema": obj(map[string]any{"project_id": str, "mode": str}, "project_id")},
	}
}

func (s *Server) callTool(req Request) *Response {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(req.ID, -32602, "invalid params")
	}
	arg := func(k string) string { s, _ := p.Arguments[k].(string); return s }

	switch p.Name {
	case "record_decision":
		body := map[string]any{
			"idempotency_key": fmt.Sprintf("mcp-%d", time.Now().UnixNano()),
			"project_id":      arg("project_id"), "session_id": arg("session_id"),
			"action": arg("action"), "observed_via": "sdk",
		}
		if et := arg("event_type"); et != "" {
			body["event_type"] = et
		}
		if r := arg("rationale"); r != "" {
			body["extensions"] = map[string]any{"content_preview": map[string]any{"rationale": r}}
		}
		out, err := s.post("/v2/records", body)
		return s.toolResult(req.ID, out, err)
	case "get_session_trace":
		// escape every argument so a crafted project_id/session_id cannot smuggle extra query params.
		out, err := s.get(fmt.Sprintf("/v2/dag?project=%s&session=%s",
			url.QueryEscape(arg("project_id")), url.QueryEscape(arg("session_id"))))
		return s.toolResult(req.ID, out, err)
	case "verify_record":
		out, err := s.get("/v2/verify?project=" + url.QueryEscape(arg("project_id")))
		return s.toolResult(req.ID, out, err)
	case "request_export":
		mode := arg("mode")
		if mode == "" {
			mode = "proof_only"
		}
		exportURL := fmt.Sprintf("%s/v2/export?project=%s&mode=%s",
			s.averinURL, url.QueryEscape(arg("project_id")), url.QueryEscape(mode))
		return s.toolResult(req.ID, `{"export_url":"`+exportURL+`"}`, nil)
	default:
		return fail(req.ID, -32602, "unknown tool: "+p.Name)
	}
}

func (s *Server) toolResult(id json.RawMessage, text string, err error) *Response {
	if err != nil {
		return ok(id, map[string]any{"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}}, "isError": true})
	}
	return ok(id, map[string]any{"content": []map[string]any{{"type": "text", "text": text}}})
}

func (s *Server) post(path string, body map[string]any) (string, error) {
	b, _ := json.Marshal(body)
	resp, err := s.client.Post(s.averinURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out), nil
}

func (s *Server) get(path string) (string, error) {
	resp, err := s.client.Get(s.averinURL + path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out), nil
}

func ok(id json.RawMessage, result any) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Result: result}
}
func fail(id json.RawMessage, code int, msg string) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}
