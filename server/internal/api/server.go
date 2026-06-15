// Package api is the feir ingestion + app HTTP server. It assigns server-controlled fields,
// derives the causal DAG links and the frontier, and routes all canonicalize/seal/verify work
// through the Rust core (the single source of truth). The store is append-only.
package api

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/feir-dev/feir/server/internal/store"
)

// Sealer is the subset of the Rust core the API needs.
type Sealer interface {
	SealRecord(bodyJSON string) (string, error)
	SealCheckpoint(bodyJSON string) (string, error)
	VerifyBundle(bundleJSON string) string
	PubKey() string
}

type Server struct {
	core         Sealer
	st           store.Store
	signingKeyID string
	keyValidFrom string
	now          func() time.Time // injectable clock for tests
	// ingestMu serializes the heads->seal->put critical section so concurrent ingests cannot read
	// a stale frontier and fork the DAG (the Postgres store will do this in a serializable tx).
	ingestMu sync.Mutex
}

func New(core Sealer, st store.Store, signingKeyID string) *Server {
	return &Server{
		core:         core,
		st:           st,
		signingKeyID: signingKeyID,
		keyValidFrom: "2026-01-01T00:00:00.000Z",
		now:          time.Now,
	}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("POST /v2/records", s.handleRecords)
	mux.HandleFunc("POST /v2/checkpoints", s.handleCheckpoint)
	mux.HandleFunc("GET /v2/sessions", s.handleSessions)
	mux.HandleFunc("GET /v2/verify", s.handleVerify)
	mux.HandleFunc("GET /v2/export", s.handleExport)
	return mux
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// decode preserves integer literals (json.Number) so cost_micros_usd etc. never round-trip through
// float64 (RCP forbids floats; the Rust core would reject a re-emitted exponent/precision-loss).
func decode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(v)
}

// ---- ingestion ----

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// accept a single record object or a batch array
	var items []json.RawMessage
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := decode(trimmed, &items); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid batch: "+err.Error())
			return
		}
	} else {
		items = []json.RawMessage{trimmed}
	}
	if len(items) == 0 {
		writeErr(w, http.StatusBadRequest, "empty batch")
		return
	}

	results := make([]map[string]any, 0, len(items))
	headerIdem := r.Header.Get("Idempotency-Key")
	for _, raw := range items {
		sealed, created, err := s.ingestOne(raw, headerIdem)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		results = append(results, map[string]any{"created": created, "record": json.RawMessage(sealed)})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"results": results})
}

func (s *Server) ingestOne(raw []byte, headerIdem string) (string, bool, error) {
	var rec map[string]any
	if err := decode(raw, &rec); err != nil {
		return "", false, fmt.Errorf("invalid record: %w", err)
	}
	// Serialize the frontier-read -> seal -> store sequence (threat: concurrent DAG fork).
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()
	idem := stringField(rec, "idempotency_key")
	if idem == "" {
		idem = headerIdem
	}
	if idem == "" {
		return "", false, fmt.Errorf("idempotency_key is required (field or Idempotency-Key header)")
	}
	delete(rec, "idempotency_key") // not part of the signed record

	projectID := stringField(rec, "project_id")
	sessionID := stringField(rec, "session_id")
	if projectID == "" || sessionID == "" {
		return "", false, fmt.Errorf("project_id and session_id are required")
	}

	now := s.now()
	// server-controlled fields (override anything the client sent)
	rec["schema_version"] = "2"
	rec["canon_version"] = "rcp-1"
	rec["domain"] = "flightrecorder.record.v2"
	rec["received_ts"] = ts(now)
	if stringField(rec, "agent_ts") == "" {
		rec["agent_ts"] = ts(now) // agent clock untrusted; default to receipt if absent
	}
	if stringField(rec, "record_id") == "" {
		rec["record_id"] = newUUID()
	}
	if stringField(rec, "span_id") == "" {
		rec["span_id"] = "span-" + newUUID()
	}
	if _, ok := rec["parent_span_id"]; !ok {
		rec["parent_span_id"] = nil
	}
	seq, _ := s.st.NextDisplaySeq(projectID, sessionID)
	rec["display_seq"] = seq

	// sensible defaults for required semantic fields so a minimal POST is still a valid record
	setDefault(rec, "agent_id", "unknown")
	setDefault(rec, "agent_version", "unknown")
	setDefault(rec, "event_type", "decision")
	setDefault(rec, "action", "")
	setDefault(rec, "observed_via", "sdk")
	setDefault(rec, "status", "ok")

	// causal DAG links = the session's current heads (server-derived, never client-trusted).
	// NOTE: heads+seal+put are not yet one atomic transaction in the in-memory store; the Postgres
	// store performs this in a single serializable transaction.
	heads, _ := s.st.Heads(projectID, sessionID)
	if heads == nil {
		heads = []string{} // marshal as [] not null (RCP arrays are not nullable here)
	}
	rec["causal_prev_hashes"] = heads

	// authority is declared by default — never silently presented as verified (threat #4).
	normalizeAuthority(rec)

	// signing key block
	rec["key"] = map[string]any{
		"signing_key_id": s.signingKeyID,
		"key_epoch":      0,
		"key_valid_from": s.keyValidFrom,
		"key_status":     "active",
	}

	bodyJSON, err := json.Marshal(rec)
	if err != nil {
		return "", false, err
	}
	sealed, err := s.core.SealRecord(string(bodyJSON))
	if err != nil {
		return "", false, fmt.Errorf("seal: %w", err)
	}

	ch, parents, sess := recordMeta(sealed)
	stored, created, err := s.st.PutRecord(projectID, idem, store.Record{
		JSON: sealed, ContentHash: ch, SessionID: sess, Parents: parents,
	})
	if err != nil {
		return "", false, err
	}
	return stored.JSON, created, nil
}

// normalizeAuthority enforces honest authority labeling. In Phase 1 the server does not yet verify
// `evidence_sig` against a policy engine's published key, so it NEVER labels authority as
// `policy_engine_signed`/`human_signed` on the client's say-so — it forces `caller_declared` while
// retaining any evidence fields for a future verifier to upgrade. (spec §11; coverage-limits.md)
func normalizeAuthority(rec map[string]any) {
	a, ok := rec["authority"].(map[string]any)
	if !ok {
		return
	}
	a["source"] = "caller_declared"
	rec["authority"] = a
}

// ---- checkpoints ----

func (s *Server) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	if projectID == "" {
		writeErr(w, http.StatusBadRequest, "project query param required")
		return
	}
	sealed, err := s.createCheckpoint(projectID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, json.RawMessage(sealed))
}

func (s *Server) createCheckpoint(projectID string) (string, error) {
	heads, _ := s.st.ProjectHeads(projectID)
	if heads == nil {
		heads = []string{}
	}
	count, _ := s.st.RecordCount(projectID)
	seq, _ := s.st.NextCheckpointSeq(projectID)
	prev, hasPrev, _ := s.st.LatestCheckpointHash(projectID)
	var prevVal any
	if hasPrev {
		prevVal = prev
	} else {
		prevVal = nil
	}
	body := map[string]any{
		"schema_version":       "2",
		"canon_version":        "rcp-1",
		"domain":               "flightrecorder.checkpoint.v2",
		"checkpoint_id":        newUUID(),
		"project_id":           projectID,
		"checkpoint_seq":       seq,
		"prev_checkpoint_hash": prevVal,
		"frontier":             heads,
		"record_count":         count,
		"created_ts":           ts(s.now()),
		"key": map[string]any{
			"signing_key_id": s.signingKeyID,
			"key_epoch":      0,
			"key_valid_from": s.keyValidFrom,
			"key_status":     "active",
		},
	}
	bodyJSON, _ := json.Marshal(body)
	sealed, err := s.core.SealCheckpoint(string(bodyJSON))
	if err != nil {
		return "", err
	}
	var cp struct {
		CheckpointHash string `json:"checkpoint_hash"`
		Seq            int64  `json:"checkpoint_seq"`
	}
	_ = json.Unmarshal([]byte(sealed), &cp)
	if err := s.st.PutCheckpoint(projectID, store.Checkpoint{JSON: sealed, CheckpointHash: cp.CheckpointHash, Seq: cp.Seq}); err != nil {
		return "", err
	}
	return sealed, nil
}

// ---- app / verify / export ----

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	sessions, _ := s.st.Sessions(projectID)
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	bundle, err := s.buildBundle(projectID, false)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	report := s.core.VerifyBundle(bundle)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(report))
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "proof_only"
	}
	bundle, err := s.buildBundle(projectID, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// attach an honest gap_report + mode (selective_disclosure / full_evidence raw blobs are stored
	// on customer infra; this dev store keeps commitments only — stated, not implied).
	var obj map[string]json.RawMessage
	_ = json.Unmarshal([]byte(bundle), &obj)
	// Honest gap_report: this deployment bundles commitments only; raw blobs live in the customer
	// content store and are NOT in the bundle (so raw_content_available is false until that store is
	// wired — we never claim disclosure we don't ship). spec §10.
	obj["mode"], _ = jsonRaw(mode)
	gaps := []string{"Level-2 observation scope is per-record; Level-3 completeness not claimed"}
	if mode != "proof_only" {
		gaps = append(gaps, "raw content (selective_disclosure/full_evidence) requires the customer content store, not configured in this deployment")
	}
	obj["gap_report"], _ = jsonRaw(map[string]any{
		"mapped_fields":         []string{"record integrity", "checkpoint chain", "declared authority"},
		"customer_supplied":     []string{"raw input/output/rationale blobs (content store)"},
		"gaps":                  gaps,
		"raw_content_available": false,
	})
	out, _ := json.Marshal(obj)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// buildBundle assembles the export/verify bundle: published key, all sealed records, and the full
// checkpoint history.
func (s *Server) buildBundle(projectID string, _ bool) (string, error) {
	recs, _ := s.st.AllRecords(projectID)
	checks, _ := s.st.Checkpoints(projectID)
	records := make([]json.RawMessage, len(recs))
	for i, r := range recs {
		records[i] = json.RawMessage(r.JSON)
	}
	checkpoints := make([]json.RawMessage, len(checks))
	for i, c := range checks {
		checkpoints[i] = json.RawMessage(c.JSON)
	}
	keyEntry := map[string]any{
		"signing_key_id": s.signingKeyID,
		"key_epoch":      0,
		"public_key":     s.core.PubKey(),
		"key_status":     "active",
	}
	bundle := map[string]any{
		"bundle_version": "1",
		"project_id":     projectID,
		"keys":           []any{keyEntry},
		"records":        records,
		"checkpoints":    checkpoints,
	}
	out, err := json.Marshal(bundle)
	return string(out), err
}

// ---- helpers ----

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, r.Body, 8<<20)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func stringField(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func setDefault(m map[string]any, k, val string) {
	if s, ok := m[k].(string); !ok || s == "" {
		m[k] = val
	}
}

func jsonRaw(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return json.RawMessage(b), err
}

func recordMeta(sealed string) (contentHash string, parents []string, session string) {
	var m struct {
		ContentHash string   `json:"content_hash"`
		Parents     []string `json:"causal_prev_hashes"`
		SessionID   string   `json:"session_id"`
	}
	_ = json.Unmarshal([]byte(sealed), &m)
	return m.ContentHash, m.Parents, m.SessionID
}
