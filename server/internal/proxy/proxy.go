// Package proxy is the OpenAI-compatible reverse proxy — the lowest-friction wedge: the agent swaps
// its base_url to this proxy. It forwards requests (streaming preserved) to the upstream LLM and
// records a tamper-evident `llm_call` (observed_via=proxy) of the request/response, with all
// credentials scrubbed. It sees LLM I/O only — NOT tool calls/DB actions (Level-2 limit, spec §8).
package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/averin-dev/averin/server/internal/scrub"
)

// Recorder submits a record body to the averin ingestion API.
type Recorder interface {
	Record(body map[string]any) error
}

type Proxy struct {
	upstream     string // e.g. https://api.openai.com
	client       *http.Client
	rec          Recorder
	projectID    string
	inboundToken string // when set, inbound callers MUST present it (X-Averin-Proxy-Token or Bearer) — else open relay
}

func New(upstream, projectID string, rec Recorder) *Proxy {
	return &Proxy{
		upstream:  strings.TrimRight(upstream, "/"),
		client:    &http.Client{Timeout: 0}, // no timeout: streaming completions can be long
		rec:       rec,
		projectID: projectID,
	}
}

// WithInboundAuth requires every inbound request to present `token` (header `X-Averin-Proxy-Token: <token>` or
// `Authorization: Bearer <token>`) before the proxy forwards + records it. Without it the proxy is an open relay:
// any caller can drive the upstream LLM AND inject fabricated llm_call evidence under any X-Averin-Session-Id, so
// an unconfigured proxy MUST be bound to loopback / behind the agent's own trust boundary.
func (p *Proxy) WithInboundAuth(token string) *Proxy {
	p.inboundToken = token
	return p
}

func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/", p.handle)
	return mux
}

const (
	maxReqBody = 16 << 20  // 16 MiB request cap
	maxCapture = 512 << 10 // only buffer this much of the response for the recorded preview
	// maxPreview hard-caps each sealed extensions.content_preview side (input/output). These bodies are
	// append-only and permanently un-erasable (NOT routed through commitLowEntropyFields / the retention
	// purge — see SECURITY.md §Data retention & erasure), so a large prompt/completion would otherwise bloat
	// the store forever. Truncation only shortens the human-readable preview; it never affects verification
	// (content_preview is not committed or signed).
	maxPreview = 16 << 10 // 16 KiB per preview side
)

// hopByHop headers must not be forwarded to the upstream (RFC 7230 §6.1).
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true,
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	// Inbound auth (when configured): only an authorized caller may relay to the upstream AND inject a
	// session-scoped llm_call record. Without it the proxy is an open relay + evidence-injection surface.
	if p.inboundToken != "" && !p.inboundAuthOK(r) {
		http.Error(w, "unauthorized (set X-Averin-Proxy-Token or Authorization: Bearer)", http.StatusUnauthorized)
		return
	}
	// cap the request: read one extra byte to detect (and reject) over-limit bodies rather than
	// silently forwarding a truncated request.
	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, maxReqBody+1))
	r.Body.Close()
	if len(reqBody) > maxReqBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	up, err := http.NewRequest(r.Method, p.upstream+r.URL.Path, bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// forward headers (incl. the client's upstream Authorization — we never RECORD it), minus
	// hop-by-hop headers, Host, and our own X-Averin-* control headers.
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if hopByHop[lk] || lk == "host" || strings.HasPrefix(lk, "x-averin-") {
			continue
		}
		for _, v := range vs {
			up.Header.Add(k, v)
		}
	}

	resp, err := p.client.Do(up)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// stream to the client while tee-ing into a CAPPED buffer for the record (flush each chunk for
	// SSE). The cap keeps memory bounded; the client still receives the full stream.
	captured := &capWriter{limit: maxCapture}
	fw := &flushWriter{w: w}
	if f, ok := w.(http.Flusher); ok {
		fw.flusher = f
	}
	_, copyErr := io.Copy(fw, io.TeeReader(resp.Body, captured))

	if strings.Contains(r.URL.Path, "/chat/completions") || strings.Contains(r.URL.Path, "/completions") {
		p.recordCall(r, reqBody, captured.buf, resp.StatusCode, copyErr != nil || captured.truncated)
	}
}

func (p *Proxy) recordCall(r *http.Request, reqBody, respBody []byte, httpStatus int, incomplete bool) {
	if p.rec == nil {
		return
	}
	session := r.Header.Get("X-Averin-Session-Id")
	if session == "" {
		session = "proxy-default"
	}
	model := extractModel(reqBody)
	tin, tout := extractUsage(respBody)

	// For SSE, redact the REASSEMBLED completion text so a secret split across deltas cannot be
	// reconstructed from the stored stream; otherwise redact the (capped) raw body.
	var outText string
	if assembled, isSSE := assembleSSE(respBody); isSSE {
		outText = scrub.Redact(assembled)
	} else {
		outText = scrub.Redact(string(respBody))
	}
	outText = truncatePreview(outText)

	status := statusWord(httpStatus)
	eventType := "llm_call"
	if incomplete {
		status = "incomplete"
		eventType = "incomplete" // a partial/interrupted capture is sealed as a visible gap (#7)
	}

	rec := map[string]any{
		"project_id":   p.projectID,
		"session_id":   session,
		"event_type":   eventType,
		"action":       "chat.completions",
		"observed_via": "proxy",
		"status":       status,
		"agent_id":     model,
		"extensions": map[string]any{
			"content_preview": map[string]any{
				"input":  truncatePreview(scrub.Redact(string(reqBody))),
				"output": outText,
			},
		},
	}
	if tin >= 0 || tout >= 0 {
		rec["tokens"] = map[string]any{"in": max0(tin), "out": max0(tout)}
	}
	// Best-effort (never fail the user's LLM call because recording failed) but NOT silent: a dropped record is
	// a gap in the evidence trail, so a recording failure (incl. a averin auth 401, a 4xx/5xx, or averin being down)
	// is LOGGED rather than swallowed — otherwise the operator believes I/O is captured while it is discarded.
	if err := p.rec.Record(rec); err != nil {
		log.Printf("averin-proxy: WARNING — failed to record llm_call (session=%q, model=%q): %v — this LLM call is NOT in the evidence trail", session, model, err)
	}
}

// inboundAuthOK constant-time-compares the configured inbound token against X-Averin-Proxy-Token or a Bearer token.
func (p *Proxy) inboundAuthOK(r *http.Request) bool {
	tok := strings.TrimSpace(r.Header.Get("X-Averin-Proxy-Token"))
	if tok == "" {
		if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
	}
	return tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(p.inboundToken)) == 1
}

// ---- helpers ----

// capWriter retains at most `limit` bytes (for the recorded preview) but always reports a full
// write, so tee-ing it into io.Copy never interrupts the client stream.
type capWriter struct {
	buf       []byte
	limit     int
	truncated bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) <= room {
			c.buf = append(c.buf, p...)
		} else {
			c.buf = append(c.buf, p[:room]...)
			c.truncated = true
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}

// truncatePreview hard-caps a content_preview side to maxPreview bytes, trimming back to a UTF-8 rune
// boundary (so a stored preview never ends in a split multi-byte sequence) and appending a visible marker.
// These previews are permanent/un-erasable, so this is the ONLY bound on their stored size.
func truncatePreview(s string) string {
	if len(s) <= maxPreview {
		return s
	}
	cut := maxPreview
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…[averin: preview truncated]"
}

// assembleSSE concatenates the streamed completion text from an OpenAI-style SSE body. Returns
// (assembled, true) if the body looks like SSE, else ("", false).
func assembleSSE(raw []byte) (string, bool) {
	if !bytes.Contains(raw, []byte("data:")) {
		return "", false
	}
	var b strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(payload), &chunk) == nil {
			for _, ch := range chunk.Choices {
				b.WriteString(ch.Delta.Content)
			}
		}
	}
	return b.String(), true
}

type flushWriter struct {
	w       io.Writer
	flusher http.Flusher
}

func (f *flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if f.flusher != nil {
		f.flusher.Flush()
	}
	return n, err
}

func extractModel(reqBody []byte) string {
	var m struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(reqBody, &m)
	if m.Model == "" {
		return "unknown"
	}
	return m.Model
}

// extractUsage reads OpenAI-style usage.prompt_tokens/completion_tokens from a (non-stream) body, or
// the final usage chunk of an SSE stream. Returns (-1,-1) if absent.
func extractUsage(respBody []byte) (int, int) {
	type usage struct {
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	var u usage
	if json.Unmarshal(respBody, &u) == nil && (u.Usage.Prompt > 0 || u.Usage.Completion > 0) {
		return u.Usage.Prompt, u.Usage.Completion
	}
	// SSE: scan data: lines for the last one carrying usage
	in, out := -1, -1
	for _, line := range strings.Split(string(respBody), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" || payload == "" {
			continue
		}
		var u usage
		if json.Unmarshal([]byte(payload), &u) == nil && (u.Usage.Prompt > 0 || u.Usage.Completion > 0) {
			in, out = u.Usage.Prompt, u.Usage.Completion
		}
	}
	return in, out
}

func statusWord(code int) string {
	if code >= 200 && code < 300 {
		return "ok"
	}
	return "error"
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// HTTPRecorder posts records to a averin ingestion server.
type HTTPRecorder struct {
	URL    string // averin server base, e.g. http://localhost:8080
	Token  string // averin API token (sent as X-Api-Key) — REQUIRED when the averin server has AVERIN_API_KEYS auth on
	Client *http.Client
}

func (h *HTTPRecorder) Record(body map[string]any) error {
	if body["idempotency_key"] == nil {
		body["idempotency_key"] = randIdem()
	}
	b, _ := json.Marshal(body)
	c := h.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(h.URL, "/")+"/v2/records", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.Token != "" {
		req.Header.Set("X-Api-Key", h.Token) // so records aren't silently 401'd against an auth-enabled averin
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// A non-2xx (401 unauth, 400 reserved/malformed, 413 too-large, 5xx) means the record was NOT sealed — surface
	// it as an error so the caller logs the evidence gap instead of treating any HTTP response as success.
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("averin /v2/records returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func randIdem() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
