// Package api is the feir ingestion + app HTTP server. It assigns server-controlled fields,
// derives the causal DAG links and the frontier, and routes all canonicalize/seal/verify work
// through the Rust core (the single source of truth). The store is append-only.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/feir-dev/feir/server/internal/auth"
	"github.com/feir-dev/feir/server/internal/meter"
	"github.com/feir-dev/feir/server/internal/otel"
	"github.com/feir-dev/feir/server/internal/store"
	"github.com/feir-dev/feir/server/internal/witness"
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
	meter        meter.Meter
	auth         auth.KeyStore  // nil = no per-project auth (dev/single-tenant)
	witness      witness.Witness // nil = no external witness configured
	signingKeyID string
	keyValidFrom string
	now          func() time.Time // injectable clock for tests
	// ingestMu serializes the heads->seal->put critical section so concurrent ingests cannot read
	// a stale frontier and fork the DAG (the Postgres store will do this in a serializable tx).
	ingestMu sync.Mutex
	// checkpointMu serializes checkpoint creation so concurrent calls cannot read the same
	// NextCheckpointSeq and fork the checkpoint chain.
	checkpointMu sync.Mutex
}

func New(core Sealer, st store.Store, signingKeyID string) *Server {
	return &Server{
		core:         core,
		st:           st,
		meter:        meter.NewMem(),
		signingKeyID: signingKeyID,
		keyValidFrom: "2026-01-01T00:00:00.000Z",
		now:          time.Now,
	}
}

// WithMeter swaps in a usage meter (e.g. a Stripe reporter). Returns the server for chaining.
func (s *Server) WithMeter(m meter.Meter) *Server {
	s.meter = m
	return s
}

// WithAuth gates the /v2/* routes behind project-scoped API-key auth.
func (s *Server) WithAuth(ks auth.KeyStore) *Server {
	s.auth = ks
	return s
}

// WithWitness appends every sealed checkpoint to a customer-controlled append-only witness
// (out-of-vendor-control) so omitting/rewriting it later is detectable (threats #1/#15).
func (s *Server) WithWitness(w witness.Witness) *Server {
	s.witness = w
	return s
}

func healthz(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("POST /v2/records", s.handleRecords)
	mux.HandleFunc("POST /v2/otel/traces", s.handleOTel)
	mux.HandleFunc("POST /v2/checkpoints", s.handleCheckpoint)
	mux.HandleFunc("GET /v2/sessions", s.handleSessions)
	mux.HandleFunc("GET /v2/dag", s.handleDAG)
	mux.HandleFunc("GET /v2/verify", s.handleVerify)
	mux.HandleFunc("GET /v2/export", s.handleExport)
	mux.HandleFunc("GET /v2/usage", s.handleUsage)

	if s.auth == nil || auth.IsOpen(s.auth) {
		return mux // dev/single-tenant: no per-project auth (documented Phase-1/dev posture)
	}
	// gate every /v2/* route behind project-scoped auth; /healthz stays open.
	gate := auth.Middleware(s.auth, "project")
	guarded := http.NewServeMux()
	guarded.HandleFunc("GET /healthz", healthz)
	guarded.Handle("/v2/", gate(mux))
	return guarded
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

	// With auth enabled the project is named in ?project= (checked by the middleware); bind it so a
	// token valid for project A cannot write to project B via the body's project_id. Validate the
	// WHOLE batch up front so a mismatched item cannot partially persist earlier items.
	queryProject := r.URL.Query().Get("project")
	if queryProject != "" {
		for _, raw := range items {
			var probe map[string]any
			if decode(raw, &probe) != nil || stringField(probe, "project_id") != queryProject {
				writeErr(w, http.StatusForbidden, "a record's project_id does not match the authorized ?project=")
				return
			}
		}
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
	if created {
		s.meter.RecordsIngested(projectID, 1) // billable per record beyond the free tier
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

// handleOTel ingests an OTLP/JSON trace export. The project comes from ?project= (NEVER the OTLP
// payload), each span becomes a sealed record (observed_via=otel).
func (s *Server) handleOTel(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	if project == "" {
		writeErr(w, http.StatusBadRequest, "project query param required")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	bodies, err := otel.MapSpansToRecords(body, project)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ingested, failed := 0, 0
	var errs []string
	for _, b := range bodies {
		raw, err := json.Marshal(b)
		if err != nil {
			failed++
			errs = append(errs, err.Error())
			continue
		}
		// content-addressed idempotency key (passed as the header arg so we marshal once and don't
		// mutate the body): a re-sent identical span collapses (#8), but two distinct spans — even
		// sharing a span_id across traces — never collide. A per-span failure does not abort the
		// rest (idempotency makes a whole-export retry safe), so partial success is reported honestly.
		sum := sha256.Sum256(raw)
		if _, _, err := s.ingestOne(raw, "otel-"+hex.EncodeToString(sum[:])); err != nil {
			failed++
			errs = append(errs, err.Error())
			continue
		}
		ingested++
	}
	code := http.StatusCreated
	if ingested == 0 && failed > 0 {
		code = http.StatusBadRequest
	}
	writeJSON(w, code, map[string]any{"ingested": ingested, "failed": failed, "errors": errs})
}

// ---- checkpoints ----

func (s *Server) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	if projectID == "" {
		writeErr(w, http.StatusBadRequest, "project query param required")
		return
	}
	sealed, witnessWarn, err := s.createCheckpoint(r.Context(), projectID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"checkpoint": json.RawMessage(sealed)}
	if witnessWarn != nil {
		resp["warning"] = witnessWarn.Error() // checkpoint created; witnessing is pending (backfill)
	}
	writeJSON(w, http.StatusCreated, resp)
}

// createCheckpoint seals the current frontier and stores it, then best-effort appends it to the
// witness. Returns (sealed, witnessWarning, fatalErr). Serialized so concurrent calls cannot read
// the same NextCheckpointSeq and fork the chain. Store-before-witness with a monotonic seq means a
// witness failure does NOT re-seal the same seq on retry (seq has already advanced) — so it can
// never wedge checkpointing; the un-witnessed checkpoint is reported via the warning and is
// backfillable. A deterministic checkpoint_id keeps the body reproducible for a given seq.
func (s *Server) createCheckpoint(ctx context.Context, projectID string) (string, error, error) {
	s.checkpointMu.Lock()
	defer s.checkpointMu.Unlock()

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
	}
	body := map[string]any{
		"schema_version":       "2",
		"canon_version":        "rcp-1",
		"domain":               "flightrecorder.checkpoint.v2",
		"checkpoint_id":        fmt.Sprintf("cp-%s-%d", projectID, seq), // deterministic per seq
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
		return "", nil, err
	}
	var cp struct {
		CheckpointHash string `json:"checkpoint_hash"`
		Seq            int64  `json:"checkpoint_seq"`
	}
	_ = json.Unmarshal([]byte(sealed), &cp)
	if err := s.st.PutCheckpoint(projectID, store.Checkpoint{JSON: sealed, CheckpointHash: cp.CheckpointHash, Seq: cp.Seq}); err != nil {
		return "", nil, err
	}
	// best-effort witness append (bounded so a hung witness can't block); a failure leaves the
	// checkpoint stored-but-un-witnessed (reported, backfillable) rather than wedging the chain.
	var witnessWarn error
	if s.witness != nil {
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := s.witness.Append(wctx, projectID, []byte(sealed)); err != nil {
			witnessWarn = fmt.Errorf("checkpoint stored but witness append failed (backfill needed): %w", err)
		}
	}
	return sealed, witnessWarn, nil
}

// ---- app / verify / export ----

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	sessions, _ := s.st.Sessions(projectID)
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	u := s.meter.Usage(projectID)
	billRecords, billExports := meter.Billable(u)
	writeJSON(w, http.StatusOK, map[string]any{
		"usage":            u,
		"free_tier":        meter.FreeTierRecords,
		"billable_records": billRecords,
		"billable_exports": billExports,
	})
}

// handleDAG returns a session's sealed records (the causal DAG) for the trace-waterfall view.
//
// PHASE-1 AUTHZ LIMIT: the app API has NO per-project authentication/authorization yet (RBAC/SSO is
// explicitly Phase 2, spec §3). A deployment MUST put feir behind its own auth (or run it single-
// tenant) until the authz layer lands — any caller who can reach this endpoint can read any
// project's data. Documented in docs/coverage-limits.md.
func (s *Server) handleDAG(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project")
	sessionID := r.URL.Query().Get("session")
	if projectID == "" || sessionID == "" {
		writeErr(w, http.StatusBadRequest, "project and session query params are required")
		return
	}
	recs, _ := s.st.SessionRecords(projectID, sessionID)
	out := make([]json.RawMessage, len(recs))
	for i, rec := range recs {
		out[i] = json.RawMessage(rec.JSON)
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out})
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
	s.meter.ExportIssued(projectID) // billable per export
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
