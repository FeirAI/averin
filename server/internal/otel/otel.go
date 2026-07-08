// Package otel maps OpenTelemetry / OpenInference trace spans (an OTLP/JSON
// ExportTraceServiceRequest) into averin record bodies tagged observed_via="otel".
//
// This is a Level-2 *observation* bridge: spans are third-party telemetry the agent emitted, not
// records averin sealed at the decision point. We therefore translate honestly and conservatively —
// every span becomes a record body whose semantic claims are only what the span itself asserts. We
// never invent authority, never upgrade a declared event to a verified one, and we preserve the raw
// OTel attributes verbatim under extensions.otel_attrs so a later auditor can see exactly what the
// instrumentation reported (stated, not implied; cf. api.normalizeAuthority).
//
// The output is map[string]any bodies in the same shape api.ingestOne expects: the caller feeds
// them to POST /v2/records, where the server still assigns server-controlled fields (received_ts,
// causal_prev_hashes, key block, etc.) and the Rust core does the canonicalize/seal. Nothing here
// signs or trusts anything.
package otel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/averin-dev/averin/server/internal/scrub"
)

// MapSpansToRecords parses an OTLP/JSON ExportTraceServiceRequest and returns one averin record body
// per span, suitable for POSTing to /v2/records. projectID is stamped onto every body (the OTLP
// payload is not trusted to name its own averin project — that is a server-side authorization concern).
//
// Malformed JSON returns an error and never panics. Spans missing a name/spanId still map (with
// empty strings) rather than aborting the whole batch, so one bad span can't drop a trace.
// MaxSpansPerRequest bounds the spans mapped from one OTLP export (memory back-pressure).
const MaxSpansPerRequest = 50000

func MapSpansToRecords(otlpJSON []byte, projectID string) ([]map[string]any, error) {
	var req exportTraceServiceRequest
	// UseNumber so 64-bit nanos / intValues never round-trip through float64 (RCP forbids floats and
	// would lose precision on large timestamps); we convert each to a real integer below.
	dec := json.NewDecoder(bytes.NewReader(otlpJSON))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return nil, fmt.Errorf("otel: parse OTLP/JSON: %w", err)
	}

	var out []map[string]any
	for _, rs := range req.ResourceSpans {
		// resource-level attributes (e.g. service.name, session.id) apply to every span under it.
		resAttrs := flattenAttrs(rs.Resource.Attributes)
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				if len(out) >= MaxSpansPerRequest { // bound memory on a single export request
					return out, fmt.Errorf("otel: too many spans (>%d) in one export", MaxSpansPerRequest)
				}
				out = append(out, mapSpan(sp, resAttrs, projectID))
			}
		}
	}
	if out == nil {
		out = []map[string]any{} // empty payload -> empty slice, not nil
	}
	return out, nil
}

// ---- OTLP/JSON shapes (subset) ----
//
// We model only the fields we read. proto3 JSON encodes int64 fields (spanId bytes are base64, and
// fixed64/int64 nanos are *strings*) per the OTLP spec, so we accept json.RawMessage / strings and
// coerce ourselves rather than assuming numeric JSON.

type exportTraceServiceRequest struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

type resourceSpans struct {
	Resource   resource     `json:"resource"`
	ScopeSpans []scopeSpans `json:"scopeSpans"`
}

type resource struct {
	Attributes []attribute `json:"attributes"`
}

type scopeSpans struct {
	Spans []span `json:"spans"`
}

type span struct {
	TraceID string `json:"traceId"`
	SpanID  string `json:"spanId"`
	// ParentSpanID is "" for a root span.
	ParentSpanID string `json:"parentSpanId"`
	Name         string `json:"name"`
	// StartTimeUnixNano is a proto3-JSON int64-as-string ("1700..."), but some producers emit a raw
	// number; we take the bytes and coerce in agentTS so one malformed timestamp can't fail a whole
	// trace export (it just degrades to an empty agent_ts -> server defaults it to receipt time).
	StartTimeUnixNano json.RawMessage `json:"startTimeUnixNano"`
	Attributes        []attribute     `json:"attributes"`
	Status            *status         `json:"status"`
}

type status struct {
	// OTLP status code: 0=UNSET, 1=OK, 2=ERROR. proto3 JSON may emit it as the enum *name*
	// ("STATUS_CODE_ERROR") or the number, so Code is a RawMessage and we normalize in isError.
	Code json.RawMessage `json:"code"`
}

type attribute struct {
	Key   string         `json:"key"`
	Value attributeValue `json:"value"`
}

// attributeValue covers the AnyValue cases averin cares about. intValue is a string in proto3 JSON;
// boolValue/doubleValue are kept for faithful otel_attrs preservation. Array/kvlist/bytes (and any
// future) values are captured raw so they are never dropped. CRITICAL: every emitted value must be
// an RCP-safe primitive (string/integer/bool) because the whole record body is canonicalized + sealed
// by the Rust core, which REJECTS floats and arbitrary structures — so doubles and complex/unknown
// values are emitted as STRINGS, not numbers/objects.
type attributeValue struct {
	StringValue *string         `json:"stringValue"`
	IntValue    *json.Number    `json:"intValue"`
	BoolValue   *bool           `json:"boolValue"`
	DoubleValue *json.Number    `json:"doubleValue"`
	ArrayValue  json.RawMessage `json:"arrayValue"`
	KvlistValue json.RawMessage `json:"kvlistValue"`
	BytesValue  *string         `json:"bytesValue"`
}

// ---- mapping ----

func mapSpan(sp span, resAttrs map[string]any, projectID string) map[string]any {
	attrs := flattenAttrs(sp.Attributes)
	// span attributes win over resource attributes on key collision.
	merged := map[string]any{}
	for k, v := range resAttrs {
		merged[k] = v
	}
	for k, v := range attrs {
		merged[k] = v
	}
	input := takeFirstString(merged, "gen_ai.input.messages", "gen_ai.prompt", "llm.prompts", "tool.arguments", "input.value")
	output := takeFirstString(merged, "gen_ai.output.messages", "gen_ai.completion", "llm.completions", "tool.result", "output.value")
	rationale := takeFirstString(merged, "feir.reasoning_summary")
	// OpenInference and older GenAI semconv also emit the SAME payloads as indexed keys
	// (llm.input_messages.0.message.content, gen_ai.prompt.0.content, …). Fold them into the
	// committed/encrypted payload too — leaving them in otel_attrs would seal the raw prompt
	// in plaintext inside the record body, bypassing the commitment path entirely.
	inputIndexed := takeKeysWithPrefix(merged, "gen_ai.prompt.", "llm.input_messages.", "llm.prompts.")
	outputIndexed := takeKeysWithPrefix(merged, "gen_ai.completion.", "llm.output_messages.", "llm.completions.")
	if input == "" {
		input = inputIndexed
	}
	if output == "" {
		output = outputIndexed
	}
	scrubAttributes(merged)

	status := "ok"
	if isError(sp.Status) {
		status = "error"
	}

	body := map[string]any{
		"project_id":     projectID,
		"session_id":     sessionID(merged, sp.TraceID),
		"action":         sp.Name,
		"event_type":     eventType(merged),
		"span_id":        sp.SpanID,
		"parent_span_id": parentSpanID(sp.ParentSpanID),
		"observed_via":   "otel",
		"status":         status,
		"agent_ts":       agentTS(sp.StartTimeUnixNano),
		// Preserve the instrumentation's raw view, verbatim, so an auditor can reconstruct exactly
		// what was reported (we never silently drop signal — we just don't act on unknown attrs).
		"extensions": map[string]any{"otel_attrs": merged},
	}
	if agentID := strAttr(merged, "feir.agent_id"); agentID != "" {
		body["agent_id"] = agentID
	}
	if input != "" {
		body["input"] = scrub.Redact(input)
	}
	if output != "" {
		body["output"] = scrub.Redact(output)
	}
	if rationale != "" {
		body["rationale"] = scrub.Redact(rationale)
	}
	return body
}

func takeFirstString(attrs map[string]any, keys ...string) string {
	var selected string
	for _, key := range keys {
		if value, ok := attrs[key].(string); ok && selected == "" {
			selected = value
		}
		delete(attrs, key) // payload is committed/encrypted, never duplicated in attrs
	}
	return selected
}

// takeKeysWithPrefix removes every attribute under the given indexed-payload prefixes and
// returns them as one deterministic JSON object (encoding/json sorts map keys), so the
// payload is preserved for commitment instead of leaking in plaintext otel_attrs. Returns
// "" when no key matched.
func takeKeysWithPrefix(attrs map[string]any, prefixes ...string) string {
	taken := map[string]any{}
	for key, value := range attrs {
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				taken[key] = value
				delete(attrs, key)
				break
			}
		}
	}
	if len(taken) == 0 {
		return ""
	}
	b, err := json.Marshal(taken)
	if err != nil {
		return ""
	}
	return string(b)
}

func scrubAttributes(attrs map[string]any) {
	for key, value := range attrs {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "authorization") || strings.Contains(lower, "api_key") ||
			strings.Contains(lower, "api-key") || strings.Contains(lower, "api_token") ||
			strings.Contains(lower, "api-token") || strings.Contains(lower, "access_token") ||
			strings.Contains(lower, "refresh_token") || strings.Contains(lower, "password") ||
			strings.Contains(lower, "secret") || strings.Contains(lower, "cookie") ||
			strings.Contains(lower, "credential") {
			attrs[key] = "[REDACTED:attribute]"
			continue
		}
		if text, ok := value.(string); ok {
			attrs[key] = scrub.Redact(text)
		}
	}
}

// sessionID prefers an explicit session attribute, falling back to the OTel traceId so spans from
// one trace still group into one averin session.
func sessionID(attrs map[string]any, traceID string) string {
	if v := strAttr(attrs, "session.id"); v != "" {
		return v
	}
	if v := strAttr(attrs, "averin.session"); v != "" {
		return v
	}
	return traceID
}

// eventType maps the span to a averin event_type. An explicit "averin.event_type" attribute is
// authoritative; otherwise we infer from the instrumentation conventions (OpenInference / gen_ai /
// db). We DO NOT guess beyond these signals — an unrecognized span is a plain "decision", never a
// fabricated tool/LLM call.
func eventType(attrs map[string]any) string {
	if v := strAttr(attrs, "feir.event_type"); v != "" {
		return v
	}
	if v := strAttr(attrs, "averin.event_type"); v != "" {
		return v
	}
	if hasPrefixAttr(attrs, "tool") || hasPrefixAttr(attrs, "db") {
		return "tool_call"
	}
	if hasPrefixAttr(attrs, "llm") || hasPrefixAttr(attrs, "gen_ai") {
		return "llm_call"
	}
	return "decision"
}

// parentSpanID returns nil (JSON null) for a root span rather than an empty string, matching how the
// api server stores an absent parent_span_id.
func parentSpanID(p string) any {
	if p == "" {
		return nil
	}
	return p
}

// agentTS converts an OTLP startTimeUnixNano (nanoseconds since epoch) to an RFC3339 millisecond UTC
// timestamp. The agent clock is untrusted observation data; an absent, unparseable, or non-positive
// value yields "" so the server defaults agent_ts to receipt time (see api.ingestOne). Accepts both
// the proto3 JSON string form ("1700...") and a bare numeric form.
func agentTS(raw json.RawMessage) string {
	s := string(bytes.Trim(bytes.TrimSpace(raw), `"`))
	if s == "" {
		return ""
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return time.Unix(0, n).UTC().Format("2006-01-02T15:04:05.000Z")
}

// isError reports whether the span status is ERROR (code 2 / "STATUS_CODE_ERROR"). UNSET and OK
// both map to "ok": we only escalate to "error" on an explicit error signal.
func isError(st *status) bool {
	if st == nil || len(st.Code) == 0 {
		return false
	}
	// numeric form: 2
	var num json.Number
	if json.Unmarshal(st.Code, &num) == nil {
		if i, err := strconv.ParseInt(num.String(), 10, 64); err == nil {
			return i == 2
		}
	}
	// enum-name form: "STATUS_CODE_ERROR"
	var name string
	if json.Unmarshal(st.Code, &name) == nil {
		return name == "STATUS_CODE_ERROR" || name == "ERROR"
	}
	return false
}

// flattenAttrs turns the OTLP attribute list into a plain key->value map. Integer values become Go
// int64 (NOT float64) so they round-trip as JSON integers; unknown/typed values are preserved as
// best we can for otel_attrs. Deterministic: input order does not matter (map), and we resolve the
// last write on duplicate keys (OTLP keys should be unique anyway).
func flattenAttrs(attrs []attribute) map[string]any {
	out := map[string]any{}
	for _, a := range attrs {
		if a.Key == "" {
			continue
		}
		out[a.Key] = attrValue(a.Value)
	}
	return out
}

func attrValue(v attributeValue) any {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.IntValue != nil:
		// proto3 JSON encodes int64 as a string; coerce to a real integer so the sealed record
		// carries an integer literal (no float64, per RCP).
		if i, err := strconv.ParseInt(v.IntValue.String(), 10, 64); err == nil {
			return i
		}
		return v.IntValue.String()
	case v.BoolValue != nil:
		return *v.BoolValue
	case v.DoubleValue != nil:
		// stringify: a float in the body would make the Rust seal reject the whole record (RCP).
		return v.DoubleValue.String()
	case v.BytesValue != nil:
		return *v.BytesValue // already a base64 string in proto3 JSON
	case len(v.ArrayValue) > 0:
		return string(v.ArrayValue) // preserve verbatim as a JSON string (RCP-safe, not dropped)
	case len(v.KvlistValue) > 0:
		return string(v.KvlistValue)
	default:
		return "" // unknown/empty AnyValue — keep the key with an empty string, never a null/float
	}
}

func strAttr(attrs map[string]any, key string) string {
	if v, ok := attrs[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// hasPrefixAttr reports whether any attribute key equals prefix or starts with prefix+".". This
// matches OTel namespacing ("gen_ai.system", "llm.model_name", "tool.name", "db.statement") without
// matching unrelated keys that merely share a substring.
func hasPrefixAttr(attrs map[string]any, prefix string) bool {
	dotted := prefix + "."
	// sorted iteration is unnecessary for a boolean, but keeps behavior deterministic if extended.
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == prefix || len(k) > len(dotted) && k[:len(dotted)] == dotted {
			return true
		}
	}
	return false
}
