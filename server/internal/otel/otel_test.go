package otel

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// twoSpanOTLP is a minimal but realistic ExportTraceServiceRequest: a root tool_call span with a
// session.id resource attribute, plus a child llm_call span (gen_ai attrs) whose parent is the tool
// span. Note OTLP/JSON proto3 conventions: intValue and *UnixNano are JSON *strings*.
const twoSpanOTLP = `{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "agent-svc"}},
          {"key": "session.id", "value": {"stringValue": "sess-42"}}
        ]
      },
      "scopeSpans": [
        {
          "spans": [
            {
              "traceId": "0af7651916cd43dd8448eb211c80319c",
              "spanId": "b7ad6b7169203331",
              "name": "search_db",
              "startTimeUnixNano": "1700000000000000000",
              "attributes": [
                {"key": "db.system", "value": {"stringValue": "postgres"}},
                {"key": "tool.name", "value": {"stringValue": "search"}},
                {"key": "retries", "value": {"intValue": "3"}}
              ],
              "status": {"code": 1}
            },
            {
              "traceId": "0af7651916cd43dd8448eb211c80319c",
              "spanId": "00f067aa0ba902b7",
              "parentSpanId": "b7ad6b7169203331",
              "name": "chat.completion",
              "startTimeUnixNano": "1700000001500000000",
              "attributes": [
                {"key": "gen_ai.system", "value": {"stringValue": "openai"}},
                {"key": "llm.model_name", "value": {"stringValue": "gpt-4"}}
              ]
            }
          ]
        }
      ]
    }
  ]
}`

func mustMap(t *testing.T, jsonStr, projectID string) []map[string]any {
	t.Helper()
	recs, err := MapSpansToRecords([]byte(jsonStr), projectID)
	if err != nil {
		t.Fatalf("MapSpansToRecords: unexpected error: %v", err)
	}
	return recs
}

func TestMapSpans_TwoSpans(t *testing.T) {
	recs := mustMap(t, twoSpanOTLP, "proj-1")
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}

	tool, llm := recs[0], recs[1]

	// ---- tool_call span (root) ----
	checks := map[string]any{
		"project_id":     "proj-1",
		"session_id":     "sess-42", // from resource session.id, not traceId
		"action":         "search_db",
		"event_type":     "tool_call", // tool./db. attrs present
		"span_id":        "b7ad6b7169203331",
		"observed_via":   "otel",
		"status":         "ok", // status code 1 == OK
		"agent_ts":       "2023-11-14T22:13:20.000Z",
		"parent_span_id": nil, // root span
	}
	for k, want := range checks {
		if got := tool[k]; got != want {
			t.Errorf("tool[%q] = %#v, want %#v", k, got, want)
		}
	}

	// otel_attrs must preserve the raw attributes, including the integer as a real integer.
	ext, ok := tool["extensions"].(map[string]any)
	if !ok {
		t.Fatalf("tool extensions missing/wrong type: %#v", tool["extensions"])
	}
	otelAttrs, ok := ext["otel_attrs"].(map[string]any)
	if !ok {
		t.Fatalf("otel_attrs missing/wrong type: %#v", ext["otel_attrs"])
	}
	if v, ok := otelAttrs["retries"].(int64); !ok || v != 3 {
		t.Errorf("otel_attrs.retries = %#v, want int64(3)", otelAttrs["retries"])
	}
	// resource attr merged in
	if otelAttrs["service.name"] != "agent-svc" {
		t.Errorf("otel_attrs.service.name = %#v, want agent-svc", otelAttrs["service.name"])
	}

	// ---- llm_call span (child) ----
	llmChecks := map[string]any{
		"session_id":     "sess-42", // resource attr propagates to child too
		"action":         "chat.completion",
		"event_type":     "llm_call", // gen_ai./llm. attrs present
		"span_id":        "00f067aa0ba902b7",
		"parent_span_id": "b7ad6b7169203331",
		"status":         "ok", // no status block -> ok
		"agent_ts":       "2023-11-14T22:13:21.500Z",
	}
	for k, want := range llmChecks {
		if got := llm[k]; got != want {
			t.Errorf("llm[%q] = %#v, want %#v", k, got, want)
		}
	}
}

func TestFeirVisiblePayloadsAreExtractedAndSecretsScrubbed(t *testing.T) {
	otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"t","spanId":"s","name":"model","attributes":[` +
		`{"key":"feir.agent_id","value":{"stringValue":"agent-1"}},` +
		`{"key":"feir.assurance","value":{"stringValue":"framework-enforced"}},` +
		`{"key":"gen_ai.prompt","value":{"stringValue":"use sk-proj-abcdefghijklmnop"}},` +
		`{"key":"gen_ai.completion","value":{"stringValue":"visible output"}},` +
		`{"key":"http.request.header.authorization","value":{"stringValue":"Bearer abcdefghijklmnop"}}]}]}]}]}`
	rec := mustMap(t, otlp, "tenant")[0]
	if rec["agent_id"] != "agent-1" {
		t.Fatalf("agent_id = %#v", rec["agent_id"])
	}
	if strings.Contains(rec["input"].(string), "sk-proj-") {
		t.Fatal("prompt secret was not scrubbed")
	}
	if rec["output"] != "visible output" {
		t.Fatalf("output = %#v", rec["output"])
	}
	attrs := rec["extensions"].(map[string]any)["otel_attrs"].(map[string]any)
	if _, ok := attrs["gen_ai.prompt"]; ok {
		t.Fatal("prompt duplicated into plaintext attributes")
	}
	if attrs["http.request.header.authorization"] != "[REDACTED:attribute]" {
		t.Fatal("authorization header not redacted")
	}
}

// OpenInference and older GenAI semconv emit prompts/completions as INDEXED attributes.
// They must be folded into the committed payload, never left in plaintext otel_attrs —
// otherwise the raw prompt is sealed in cleartext in the record body, bypassing the
// commitment/encryption path entirely.
func TestIndexedPayloadAttributesAreFoldedNotLeaked(t *testing.T) {
	otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"t","spanId":"s","name":"model","attributes":[` +
		`{"key":"llm.input_messages.0.message.content","value":{"stringValue":"full secret prompt"}},` +
		`{"key":"llm.input_messages.0.message.role","value":{"stringValue":"user"}},` +
		`{"key":"gen_ai.completion.0.content","value":{"stringValue":"full completion text"}},` +
		`{"key":"llm.model_name","value":{"stringValue":"gpt-4.1"}}]}]}]}]}`
	rec := mustMap(t, otlp, "tenant")[0]
	input, _ := rec["input"].(string)
	if !strings.Contains(input, "full secret prompt") || !strings.Contains(input, "llm.input_messages.0.message.content") {
		t.Fatalf("indexed prompt not folded into input: %#v", rec["input"])
	}
	output, _ := rec["output"].(string)
	if !strings.Contains(output, "full completion text") {
		t.Fatalf("indexed completion not folded into output: %#v", rec["output"])
	}
	attrs := rec["extensions"].(map[string]any)["otel_attrs"].(map[string]any)
	for key := range attrs {
		if strings.HasPrefix(key, "llm.input_messages.") || strings.HasPrefix(key, "gen_ai.completion.") {
			t.Fatalf("indexed payload attribute %q left in plaintext otel_attrs", key)
		}
	}
	if attrs["llm.model_name"] != "gpt-4.1" {
		t.Fatalf("non-payload attribute must be preserved: %#v", attrs["llm.model_name"])
	}
	// The exact-key extraction still wins when both shapes are present.
	both := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"t","spanId":"s2","name":"model","attributes":[` +
		`{"key":"gen_ai.prompt","value":{"stringValue":"canonical prompt"}},` +
		`{"key":"gen_ai.prompt.0.content","value":{"stringValue":"indexed duplicate"}}]}]}]}]}`
	rec2 := mustMap(t, both, "tenant")[0]
	if rec2["input"] != "canonical prompt" {
		t.Fatalf("exact key must win over indexed fallback: %#v", rec2["input"])
	}
	attrs2 := rec2["extensions"].(map[string]any)["otel_attrs"].(map[string]any)
	if _, ok := attrs2["gen_ai.prompt.0.content"]; ok {
		t.Fatal("indexed duplicate left in plaintext otel_attrs when exact key present")
	}
}

func TestEventTypeInference(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string]any
		want  string
	}{
		{"explicit averin.event_type wins", map[string]any{"averin.event_type": "checkpoint", "tool.name": "x"}, "checkpoint"},
		{"tool prefix -> tool_call", map[string]any{"tool.name": "search"}, "tool_call"},
		{"db prefix -> tool_call", map[string]any{"db.system": "pg"}, "tool_call"},
		{"llm prefix -> llm_call", map[string]any{"llm.model_name": "gpt-4"}, "llm_call"},
		{"gen_ai prefix -> llm_call", map[string]any{"gen_ai.system": "openai"}, "llm_call"},
		{"tool wins over llm (checked first)", map[string]any{"tool.name": "x", "llm.model_name": "y"}, "tool_call"},
		{"unknown -> decision", map[string]any{"http.method": "GET"}, "decision"},
		{"empty -> decision", map[string]any{}, "decision"},
		{"substring is not a prefix match", map[string]any{"my_tool_thing": "x"}, "decision"},
		{"bare prefix key matches", map[string]any{"tool": "x"}, "tool_call"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventType(tt.attrs); got != tt.want {
				t.Errorf("eventType(%v) = %q, want %q", tt.attrs, got, tt.want)
			}
		})
	}
}

func TestErrorStatusMapping(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"numeric error", `{"code": 2}`, "error"},
		{"enum-name error", `{"code": "STATUS_CODE_ERROR"}`, "error"},
		{"short enum error", `{"code": "ERROR"}`, "error"},
		{"numeric ok", `{"code": 1}`, "ok"},
		{"numeric unset", `{"code": 0}`, "ok"},
		{"enum-name unset", `{"code": "STATUS_CODE_UNSET"}`, "ok"},
		{"missing status", ``, "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusJSON := ``
			if tt.body != "" {
				statusJSON = `, "status": ` + tt.body
			}
			otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"spanId":"a1","name":"op","startTimeUnixNano":"1700000000000000000"` + statusJSON + `}]}]}]}`
			recs := mustMap(t, otlp, "p")
			if len(recs) != 1 {
				t.Fatalf("got %d records, want 1", len(recs))
			}
			if got := recs[0]["status"]; got != tt.want {
				t.Errorf("status = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSessionIDFallback(t *testing.T) {
	tests := []struct {
		name string
		otlp string
		want string
	}{
		{
			"session.id attr",
			`{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"t-1","spanId":"s1","name":"op","attributes":[{"key":"session.id","value":{"stringValue":"S-A"}}]}]}]}]}`,
			"S-A",
		},
		{
			"averin.session attr",
			`{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"t-2","spanId":"s1","name":"op","attributes":[{"key":"averin.session","value":{"stringValue":"S-B"}}]}]}]}]}`,
			"S-B",
		},
		{
			"fallback to traceId",
			`{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"trace-xyz","spanId":"s1","name":"op"}]}]}]}`,
			"trace-xyz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recs := mustMap(t, tt.otlp, "p")
			if got := recs[0]["session_id"]; got != tt.want {
				t.Errorf("session_id = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestMalformedJSONReturnsError(t *testing.T) {
	bads := []string{
		`{not json`,
		`{"resourceSpans": "should be array"}`,
		``,
		`[]`, // top-level array, not the request object
	}
	for _, b := range bads {
		t.Run(b, func(t *testing.T) {
			recs, err := MapSpansToRecords([]byte(b), "p")
			if err == nil {
				t.Errorf("expected error for %q, got recs=%#v", b, recs)
			}
			if recs != nil {
				t.Errorf("expected nil recs on error, got %#v", recs)
			}
		})
	}
}

func TestEmptyPayloadReturnsEmptySlice(t *testing.T) {
	recs, err := MapSpansToRecords([]byte(`{"resourceSpans":[]}`), "p")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recs == nil {
		t.Fatal("expected non-nil empty slice")
	}
	if len(recs) != 0 {
		t.Fatalf("got %d records, want 0", len(recs))
	}
}

// TestIntegersStayIntegers guards the RCP "no floats" rule: every numeric value the mapper emits
// must marshal as an integer literal (no decimal point / exponent).
func TestIntegersStayIntegers(t *testing.T) {
	recs := mustMap(t, twoSpanOTLP, "p")
	b, err := json.Marshal(recs[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// re-decode using json.Number and assert any number is integral.
	var generic any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertNoFloats(t, generic)
}

func TestNonIntegerAttrsArePreservedAsStrings(t *testing.T) {
	// double / array / bytes attrs must survive as RCP-safe strings (a float anywhere in the body
	// would make the Rust seal reject the whole record); nothing is dropped.
	otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"x","spanId":"s","attributes":[
	  {"key":"temp","value":{"doubleValue":3.14}},
	  {"key":"tags","value":{"arrayValue":{"values":[{"stringValue":"a"}]}}},
	  {"key":"blob","value":{"bytesValue":"aGk="}}
	]}]}]}]}`
	recs := mustMap(t, otlp, "p")
	attrs := recs[0]["extensions"].(map[string]any)["otel_attrs"].(map[string]any)
	if _, ok := attrs["temp"].(string); !ok {
		t.Fatalf("doubleValue must be a string, got %T (%v)", attrs["temp"], attrs["temp"])
	}
	if _, ok := attrs["tags"].(string); !ok {
		t.Fatalf("arrayValue must be preserved as a string, got %T", attrs["tags"])
	}
	if attrs["blob"] != "aGk=" {
		t.Fatalf("bytesValue lost: %v", attrs["blob"])
	}
	// and the whole record must contain no floats
	b, _ := json.Marshal(recs[0])
	var generic any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	dec.Decode(&generic)
	assertNoFloats(t, generic)
}

func TestAgentTSUnparseable(t *testing.T) {
	tests := []struct {
		name string
		nano string
		want string
	}{
		{"absent", ``, ""},
		{"zero", `"0"`, ""},
		{"non-numeric", `"abc"`, ""},
		{"valid", `"1700000000000000000"`, "2023-11-14T22:13:20.000Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			field := ``
			if tt.nano != "" {
				field = `, "startTimeUnixNano": ` + tt.nano
			}
			otlp := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"spanId":"s1","name":"op"` + field + `}]}]}]}`
			recs := mustMap(t, otlp, "p")
			if got := recs[0]["agent_ts"]; got != tt.want {
				t.Errorf("agent_ts = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// assertNoFloats walks a decoded JSON value and fails if any number is non-integral or a float64
// (guards the RCP "no floats" rule end to end).
func assertNoFloats(t *testing.T, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			assertNoFloats(t, e)
		}
	case []any:
		for _, e := range x {
			assertNoFloats(t, e)
		}
	case json.Number:
		if _, err := strconv.ParseInt(x.String(), 10, 64); err != nil {
			t.Errorf("non-integer number in record body: %q", x.String())
		}
	case float64:
		t.Errorf("found float64 %v in record body (RCP forbids floats)", x)
	}
}
