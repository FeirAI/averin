// Package api is the feir ingestion + app HTTP server. It assigns server-controlled fields,
// derives the causal DAG links and the frontier, and routes all canonicalize/seal/verify work
// through the Rust core (the single source of truth). The store is append-only.
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/feir-dev/feir/server/internal/auth"
	"github.com/feir-dev/feir/server/internal/broker"
	"github.com/feir-dev/feir/server/internal/content"
	"github.com/feir-dev/feir/server/internal/meter"
	"github.com/feir-dev/feir/server/internal/otel"
	"github.com/feir-dev/feir/server/internal/resourceshim"
	"github.com/feir-dev/feir/server/internal/store"
	"github.com/feir-dev/feir/server/internal/witness"
)

// Sealer is the subset of the Rust core the API needs.
type Sealer interface {
	SealRecord(bodyJSON string) (string, error)
	SealCheckpoint(bodyJSON string) (string, error)
	VerifyBundle(bundleJSON string) string
	// VerifyBundleWithAuthority pins authority keys (the broker recording key) so credential-broker
	// grants elevate to gateway_enforced (Level 3 Tier-A grant accountability).
	VerifyBundleWithAuthority(bundleJSON string, authorityPubKeys []string) string
	// VerifyBundleWithRoles pins broker + resource recording keys separately (ADR 0003 R2), so a
	// grant elevates only under a broker key and a use receipt only under a resource key.
	VerifyBundleWithRoles(bundleJSON string, brokerKeys, resourceKeys []string) string
	PubKey() string
	// content commitments (RCP §9.3): mint a nonce and commit a low-entropy field at ingest.
	RandomNonce() (string, error)
	Commit(domain string, value []byte, nonceHex string) (string, error)
	// authority evidence: the credential broker signs a gateway_enforced grant (RCP §11).
	SignEvidence(source, recordID, evidenceHash string) (string, error)
	// RcpEvidenceHash derives evidence_hash = sha256(RCP-canonicalize(payload)) so the verifier can
	// re-derive it from the embedded grant_evidence (ADR 0003 R1).
	RcpEvidenceHash(payloadJSON string) (string, error)
}

type Server struct {
	core         Sealer
	st           store.Store
	content      content.Store // raw low-entropy values (committed at ingest, revealed on disclosure)
	meter        meter.Meter
	auth         auth.KeyStore      // nil = no per-project auth (dev/single-tenant)
	witness      witness.Witness    // nil = no external witness configured
	tsa          witness.TSA        // nil = no external timestamp anchoring configured
	brokerKey    ed25519.PrivateKey // nil = credential broker (/v2/grants) disabled
	// Tier-B resource side (ADR 0003): the resource recording key signs use-receipt authority evidence
	// (role-separated from the broker key, R2); resourceID is this resource's audience; ledger is the
	// consume-before-act jti/nonce store. nil resourceCore = /v2/use disabled.
	resourceCore Sealer
	resourceID   string
	ledger       resourceshim.Ledger
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
		content:      content.NewMemStore(), // in-memory by default; WithContent for a durable store
		meter:        meter.NewMem(),
		signingKeyID: signingKeyID,
		keyValidFrom: "2026-01-01T00:00:00.000Z",
		now:          time.Now,
	}
}

// WithContent swaps in a durable content store (e.g. content.NewFSStore) for the raw low-entropy
// values committed at ingest. Defaults to in-memory.
func (s *Server) WithContent(c content.Store) *Server {
	s.content = c
	return s
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

// WithBroker enables the credential broker (POST /v2/grants) with the given Ed25519 issuing key
// (which signs the capabilities it mints; its public half is the descriptor kid). The recording key
// that signs the grant's gateway_enforced evidence is the server's own signing key (core). For the
// Tier-A prototype that is broker_trust: assumed — issuing and recording keys are NOT split into a
// reduced TCB (ADR 0002). Nil/unset disables the endpoint.
func (s *Server) WithBroker(issuingKey ed25519.PrivateKey) *Server {
	s.brokerKey = issuingKey
	return s
}

// WithResource enables the Tier-B resource gateway (POST /v2/use) for resourceID, signing use-receipt
// authority evidence with resourceCore's key — which MUST be DISTINCT from the server signing key and
// the broker key (R2 role separation; the verifier rejects a broker/resource key-set overlap). It
// requires the broker to be enabled (the resource verifies capabilities under the broker issuing
// key). The ledger is an in-memory consume-before-act store for the demonstrator; production injects a
// durable one. Nil resourceCore (unset) disables /v2/use.
func (s *Server) WithResource(resourceCore Sealer, resourceID string) *Server {
	s.resourceCore = resourceCore
	s.resourceID = resourceID
	s.ledger = resourceshim.NewMemLedger()
	return s
}

// WithTSA anchors every sealed checkpoint to a third-party RFC 3161 timestamp authority, attaching
// the returned token so a verifier can prove the checkpoint (and its causal ancestors) existed by
// the TSA-attested time (threat #3 backdating). Best-effort: a TSA failure stores the checkpoint
// un-anchored (reported), never wedging the chain.
func (s *Server) WithTSA(t witness.TSA) *Server {
	s.tsa = t
	return s
}

func healthz(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("POST /v2/records", s.handleRecords)
	mux.HandleFunc("POST /v2/grants", s.handleGrant)
	mux.HandleFunc("POST /v2/use", s.handleUse)
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

	// record_id must be assigned before commit-on-ingest binds disclosure secrets to it.
	if stringField(rec, "record_id") == "" {
		rec["record_id"] = newUUID()
	}

	// authority is declared by default — never silently presented as verified (threat #4).
	normalizeAuthority(rec)

	// Replace any raw input/output/rationale with a hiding commitment (RCP §9.3, threat #6); the
	// plaintext goes to the content store and never enters the signed body. The disclosure secrets
	// ride along on the Record so PutRecord persists them ATOMICALLY with the record (and only when
	// it creates it), so a committed field can never be sealed with no way to disclose it.
	disclosures, err := s.commitLowEntropyFields(rec, stringField(rec, "record_id"))
	if err != nil {
		return "", false, fmt.Errorf("commit fields: %w", err)
	}

	return s.sealAndStore(projectID, sessionID, idem, rec, disclosures)
}

// sealAndStore stamps the server-controlled fields, links the record into the session DAG (heads +
// display_seq), stamps the signing-key block, seals the record, and stores it (with any disclosure
// secrets, atomically). The caller MUST hold s.ingestMu (the frontier-read → seal → put critical
// section) and is responsible for any authority handling and commitments BEFORE calling — so both
// the generic ingest path (normalizeAuthority + commitLowEntropyFields) and the credential broker
// (its own gateway_enforced authority + input_commit) share these DAG/seal/store mechanics without
// the broker's verified authority being clobbered back to caller_declared.
func (s *Server) sealAndStore(projectID, sessionID, idem string, rec map[string]any, disclosures []store.DisclosureSecret) (string, bool, error) {
	now := s.now()
	// server-controlled fields (override anything the caller sent)
	rec["schema_version"] = "2"
	rec["canon_version"] = "rcp-1"
	rec["domain"] = "flightrecorder.record.v2"
	rec["received_ts"] = ts(now)
	if stringField(rec, "agent_ts") == "" {
		rec["agent_ts"] = ts(now) // agent clock untrusted; default to receipt if absent
	}
	if stringField(rec, "record_id") == "" {
		rec["record_id"] = newUUID() // safety net; callers normally set it before committing fields
	}
	if stringField(rec, "span_id") == "" {
		rec["span_id"] = "span-" + newUUID()
	}
	if _, ok := rec["parent_span_id"]; !ok {
		rec["parent_span_id"] = nil
	}
	seq, _ := s.st.NextDisplaySeq(projectID, sessionID)
	rec["display_seq"] = seq

	// sensible defaults for required semantic fields so a minimal record is still valid
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
		JSON: sealed, ContentHash: ch, SessionID: sess, Parents: parents, Disclosures: disclosures,
	})
	if err != nil {
		return "", false, err
	}
	if created {
		s.meter.RecordsIngested(projectID, 1) // billable per record beyond the free tier
	}
	return stored.JSON, created, nil
}

// ---- credential broker (Level 3 Tier-A: gateway_enforced grants, ADR 0002) ----

// grantRequest is the POST /v2/grants wire shape.
type grantRequest struct {
	IdempotencyKey  string   `json:"idempotency_key"`
	ProjectID       string   `json:"project_id"`
	SessionID       string   `json:"session_id"`
	AgentID         string   `json:"agent_id"`
	Action          string   `json:"action"`
	Resource        string   `json:"resource"`
	Scope           string   `json:"scope"`
	ScopeClass      string   `json:"scope_class"`
	AgentPubKey     string   `json:"agent_pubkey"`
	AgentSig        string   `json:"agent_sig"`
	Principal       string   `json:"authorizing_principal"`
	DelegationChain []string `json:"delegation_chain"`
	Justification   string   `json:"justification"`
	TTLSeconds      int      `json:"ttl_seconds"`
}

// uuidV5Shaped derives a DETERMINISTIC, UUIDv5-shaped id from (namespace, project, idempotency_key),
// so an honest retry re-derives the SAME id and collapses in the store. namespace domain-separates id
// spaces (grants vs uses) so they can never collide.
func uuidV5Shaped(namespace, projectID, idem string) string {
	sum := sha256.Sum256([]byte(namespace + "\x00" + projectID + "\x00" + idem))
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 (name-based)
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// deterministicGrantID is the grant's UUIDv5-shaped id — re-derived on retry so a lost-response grant
// never mints a second live credential (ADR 0002 idempotency).
func deterministicGrantID(projectID, idem string) string {
	return uuidV5Shaped("feir.grant.id.v1", projectID, idem)
}

// handleGrant issues a credential-broker grant: it RECORDS a signed gateway_enforced grant (sealed
// into the agent's session DAG) BEFORE returning the minted, sender-constrained, single-use
// capability — so a credential never exists without a durable, anchored grant (record-before-issue).
func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	if s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "credential broker not enabled (set FEIR_BROKER_ISSUING_SEED)")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var gr grantRequest
	if err := decode(body, &gr); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid grant request: "+err.Error())
		return
	}
	// With auth enabled the project is bound by ?project= (middleware); a body project_id must match.
	if qp := r.URL.Query().Get("project"); qp != "" && gr.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if gr.ProjectID == "" || gr.SessionID == "" {
		writeErr(w, http.StatusBadRequest, "project_id and session_id are required")
		return
	}
	// Idempotency is REQUIRED for issuance: without it a lost-response retry would mint a SECOND live
	// single-use credential. The key (body or Idempotency-Key header) deterministically fixes the
	// grant_id, so a retry collapses to the original grant + capability.
	idem := gr.IdempotencyKey
	if idem == "" {
		idem = r.Header.Get("Idempotency-Key")
	}
	if idem == "" {
		writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header) so a retry cannot double-issue a credential")
		return
	}
	grantID := deterministicGrantID(gr.ProjectID, idem) // also the credential jti + record_id

	req := broker.Request{
		AgentID:         gr.AgentID,
		Action:          gr.Action,
		Resource:        gr.Resource,
		Scope:           gr.Scope,
		ScopeClass:      broker.ScopeClass(gr.ScopeClass),
		AgentPubKey:     gr.AgentPubKey,
		AgentSig:        gr.AgentSig,
		Principal:       gr.Principal,
		DelegationChain: gr.DelegationChain,
		Justification:   gr.Justification,
		TTL:             time.Duration(gr.TTLSeconds) * time.Second,
	}
	// broker.Prepare validates the request (incl. proof-of-possession + forbidden scopes) and mints
	// the capability + the canonical evidence; a validation failure is the caller's (400). On an
	// idempotent retry this freshly-timed capability is DISCARDED in favour of the stored original.
	prepared, err := broker.Prepare(req, grantID, s.now(), s.brokerKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	rec, disclosures, err := s.buildGrantRecord(grantID, gr, req, prepared)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Record-before-issue: seal + store the grant under the DAG lock; only on success do we return
	// the capability. The lock is released via defer (panic-safe) so a core/store panic can't leak
	// the global ingest mutex and wedge all ingestion.
	var sealed string
	var created bool
	err = func() error {
		s.ingestMu.Lock()
		defer s.ingestMu.Unlock()
		var e error
		sealed, created, e = s.sealAndStore(gr.ProjectID, gr.SessionID, idem, rec, disclosures)
		return e
	}()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store grant: "+err.Error())
		return
	}

	capability := prepared.Capability
	if !created {
		// Idempotent retry: the grant already exists. Return the ORIGINAL capability, reconstructed
		// deterministically from the stored descriptor, NOT this call's freshly-timed one.
		capability, err = s.reconstructCapability(gr.ProjectID, grantID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "reconstruct capability: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"grant_id":    grantID,
		"capability":  capability, // the agent presents this to the resource
		"expires_at":  prepared.ExpiresAt,
		"scope_class": string(prepared.ScopeClass),
		"created":     created,
		"record":      json.RawMessage(sealed),
	})
}

// reconstructCapability re-mints the original capability for an existing grant from its stored
// credential descriptor (the bytes committed at issue), so an idempotent retry returns the SAME
// token rather than a new one. ed25519 signing is deterministic, so the re-mint is byte-identical.
func (s *Server) reconstructCapability(projectID, grantID string) (string, error) {
	secrets, err := s.st.Disclosures(projectID)
	if err != nil {
		return "", err
	}
	for _, d := range secrets {
		if d.RecordID == grantID && d.Field == "credential" {
			raw, err := s.content.Get(context.Background(), d.ValueDigest)
			if err != nil {
				return "", err
			}
			return broker.MintCapability(raw, s.brokerKey), nil
		}
	}
	return "", fmt.Errorf("no stored credential descriptor for grant %s", grantID)
}

// buildGrantRecord assembles the unsealed grant Decision Record: gateway_enforced authority with a
// broker-signed evidence_sig, a hiding commitment over the credential descriptor (revealable via
// selective disclosure), and the broker lifecycle fields under extensions.broker.
func (s *Server) buildGrantRecord(grantID string, gr grantRequest, req broker.Request, p broker.Prepared) (map[string]any, []store.DisclosureSecret, error) {
	// Derive evidence_hash = sha256(RCP-canonicalize(grant_evidence)) via the Rust core (ADR 0003 R1).
	// json.Marshal here only produces the bytes we hand to the core; the canonical hash is computed by
	// RCP inside RcpEvidenceHash (NOT from these Go-marshaled bytes), so the offline verifier re-derives
	// the SAME hash from the grant_evidence embedded below and confirms the signed hash commits to the
	// canonical match fields. The grant_evidence payload is carried verbatim under
	// extensions.broker.grant_evidence.
	evidenceJSON, err := json.Marshal(p.Evidence)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal grant evidence: %w", err)
	}
	evidenceHash, err := s.core.RcpEvidenceHash(string(evidenceJSON))
	if err != nil {
		return nil, nil, fmt.Errorf("derive grant evidence_hash: %w", err)
	}
	// Sign the gateway_enforced evidence (record_id-bound) — this is what the verifier elevates.
	evidenceSig, err := s.core.SignEvidence("gateway_enforced", grantID, evidenceHash)
	if err != nil {
		return nil, nil, fmt.Errorf("sign grant evidence: %w", err)
	}
	// Commit the credential descriptor (hiding) under the dedicated `credential` domain (ADR 0004 D1 —
	// a grant no longer overloads `input`): store the bytes content-addressed, mint a nonce, and commit.
	// Selective disclosure can later reveal the descriptor to prove the grant↔credential binding
	// without publishing it in the signed body.
	addr, err := s.content.Put(context.Background(), p.DescriptorBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("store credential descriptor: %w", err)
	}
	nonce, err := s.core.RandomNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}
	commitment, err := s.core.Commit("credential", p.DescriptorBytes, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("commit credential descriptor: %w", err)
	}

	delegation := gr.DelegationChain
	if delegation == nil {
		delegation = []string{}
	}
	rec := map[string]any{
		"record_id":     grantID,
		"project_id":    gr.ProjectID,
		"session_id":    gr.SessionID,
		"agent_id":      req.AgentID,
		"agent_version": "feir-broker",
		"event_type":    "credential_grant",
		"observed_via":  "broker",
		"action":        req.Action,
		"status":        "ok",
		"authority": map[string]any{
			"source":                "gateway_enforced",
			"enforcement_point":     "credential_broker",
			"grant_type":            broker.GrantTypeIDJAG,
			"grant_id":              grantID,
			"authorizing_principal": req.Principal,
			"delegation_chain":      delegation,
			"evidence_hash":         evidenceHash,
			"evidence_sig":          evidenceSig,
			"evaluated_at":          p.EvaluatedAt,
			"expires_at":            p.ExpiresAt,
		},
		"credential_commit": map[string]any{
			"alg":         "sha256",
			"commitment":  commitment,
			"low_entropy": true,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				// kind is the R2 role discriminator (with authority.enforcement_point=credential_broker
				// it classifies this record to the BROKER role; ADR 0003 R2).
				"kind":               "grant",
				"issuance_status":    "recorded",
				"scope_class":        string(p.ScopeClass),
				"conformance_level":  p.ConformanceLevel,
				"credential_binding": p.CredentialBinding,
				// The canonical grant_evidence the verifier re-derives evidence_hash from (ADR 0003 R1).
				"grant_evidence": p.Evidence,
			},
		},
	}
	disclosures := []store.DisclosureSecret{
		{RecordID: grantID, Field: "credential", ValueDigest: addr.Digest, NonceHex: nonce},
	}
	return rec, disclosures, nil
}

// ---- credential broker (Level 3 Tier-B: resource use receipts, ADR 0003) ----

// useRequest is the POST /v2/use wire shape: the agent presents the minted capability + a
// proof-of-possession (use_sig over the resource-bound PoP challenge) for an operation.
type useRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	ProjectID      string `json:"project_id"`
	SessionID      string `json:"session_id"`
	Capability     string `json:"capability"` // the minted, sender-constrained token
	UseSig         string `json:"use_sig"`    // base64url ed25519 PoP signature (signed with the cnf key)
	Action         string `json:"action"`     // the operation to perform (must equal the grant's action)
	Params         string `json:"params"`     // raw operation parameters (committed + PoP-bound)
	Nonce          string `json:"nonce"`      // the one-time PoP nonce
}

// deterministicUseID derives a stable use-receipt id from (project, idempotency_key), so an honest
// retry collapses in the store rather than sealing a second receipt (and re-consuming the credential).
func deterministicUseID(projectID, idem string) string {
	return "use-" + uuidV5Shaped("feir.use.id.v1", projectID, idem)
}

// sha256Prefixed returns "sha256:<hex>" over b (a deterministic digest used to bind the PoP to the
// operation params — both the agent and the resource compute it the same way).
func sha256Prefixed(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// handleUse records a Tier-B USE RECEIPT: the resource validates a presented capability + PoP at use
// time (resourceshim: capability sig, validity window, audience/action, PoP, consume-before-act), then
// seals a resource-signed receipt whose authority evidence the offline verifier joins to the grant.
func (s *Server) handleUse(w http.ResponseWriter, r *http.Request) {
	if s.resourceCore == nil || s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "resource gateway not enabled (set the resource recording key + broker issuing key)")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var ur useRequest
	if err := decode(body, &ur); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid use request: "+err.Error())
		return
	}
	if qp := r.URL.Query().Get("project"); qp != "" && ur.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if ur.ProjectID == "" || ur.SessionID == "" {
		// A use must land in the grant's session DAG; an unknown/empty session is malformed (ADR 0003
		// resolved open question 2).
		writeErr(w, http.StatusBadRequest, "project_id and session_id are required")
		return
	}
	idem := ur.IdempotencyKey
	if idem == "" {
		idem = r.Header.Get("Idempotency-Key")
	}
	if idem == "" {
		writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header) so a retry cannot re-consume the credential")
		return
	}
	useID := deterministicUseID(ur.ProjectID, idem)

	// params_commitment binds the PoP to the exact operation parameters (a deterministic digest both
	// the agent and the resource compute, so a captured use_sig can't be replayed against other params).
	rawParams := []byte(ur.Params)
	paramsCommitment := sha256Prefixed(rawParams)
	shim := resourceshim.New(s.brokerKey.Public().(ed25519.PublicKey), s.resourceID, s.ledger)

	// The idempotency check, the capability validation+consume, and the seal run as ONE critical
	// section. Critically, validation (which consumes the credential, a side effect) MUST be skipped on
	// a retry whose receipt already exists — re-running ValidateUse would re-consume the now-spent
	// nonce/jti and spuriously 400 an honest lost-response retry. Doing the existence check inside the
	// lock also makes concurrent retries safe: the second sees the stored receipt, not a consumed
	// credential. validateErr (caller's 400) is distinguished from a store/build error (500).
	var sealed, grantID string
	var idempotent bool
	var validateErr error
	storeErr := func() error {
		s.ingestMu.Lock()
		defer s.ingestMu.Unlock()
		if existing, gid, ok := s.existingReceipt(ur.ProjectID, ur.SessionID, useID); ok {
			sealed, grantID, idempotent = existing, gid, true
			return nil
		}
		ev, e := shim.ValidateUse(ur.Capability, ur.UseSig, resourceshim.Op{Action: ur.Action, ParamsCommitment: paramsCommitment}, ur.Nonce, s.now())
		if e != nil {
			validateErr = e // a forged/expired/replayed/wrong-scope use — the caller's fault
			return nil
		}
		grantID = ev.GrantID
		rec, disclosures, e := s.buildUseRecord(useID, ur, ev, rawParams)
		if e != nil {
			return e
		}
		sealed, _, e = s.sealAndStore(ur.ProjectID, ur.SessionID, idem, rec, disclosures)
		return e
	}()
	if validateErr != nil {
		writeErr(w, http.StatusBadRequest, "use rejected: "+validateErr.Error())
		return
	}
	if storeErr != nil {
		writeErr(w, http.StatusInternalServerError, "store use receipt: "+storeErr.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"use_id":     useID,
		"grant_id":   grantID,
		"record":     json.RawMessage(sealed),
		"idempotent": idempotent,
	})
}

// existingReceipt returns the sealed record (and its authority.grant_id) for a use already recorded
// under useID in the session, so an idempotent retry returns the original instead of re-running
// ValidateUse (which would re-consume the now-spent credential). Caller holds ingestMu.
func (s *Server) existingReceipt(projectID, sessionID, useID string) (string, string, bool) {
	recs, err := s.st.SessionRecords(projectID, sessionID)
	if err != nil {
		return "", "", false
	}
	for _, rec := range recs {
		var probe struct {
			RecordID  string `json:"record_id"`
			Authority struct {
				GrantID string `json:"grant_id"`
			} `json:"authority"`
		}
		if json.Unmarshal([]byte(rec.JSON), &probe) == nil && probe.RecordID == useID {
			return rec.JSON, probe.Authority.GrantID, true
		}
	}
	return "", "", false
}

// buildUseRecord assembles the unsealed use-receipt Decision Record: a tool_gateway-role authority
// with a RESOURCE-signed evidence_sig over the re-derivable use_evidence (R1/R2), a hiding commitment
// over the operation params, and the use lifecycle under extensions.broker (kind=use → resource role).
func (s *Server) buildUseRecord(useID string, ur useRequest, ev resourceshim.UseEvidence, rawParams []byte) (map[string]any, []store.DisclosureSecret, error) {
	// evidence_hash = sha256(RCP-canonicalize(use_evidence)) via the core (R1), signed by the RESOURCE
	// key (R2) and record_id-bound to this receipt.
	evidenceJSON, err := json.Marshal(ev)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal use evidence: %w", err)
	}
	evidenceHash, err := s.core.RcpEvidenceHash(string(evidenceJSON))
	if err != nil {
		return nil, nil, fmt.Errorf("derive use evidence_hash: %w", err)
	}
	evidenceSig, err := s.resourceCore.SignEvidence("gateway_enforced", useID, evidenceHash)
	if err != nil {
		return nil, nil, fmt.Errorf("sign use evidence (resource key): %w", err)
	}
	// Commit the operation params (hiding), revealable via selective disclosure.
	addr, err := s.content.Put(context.Background(), rawParams)
	if err != nil {
		return nil, nil, fmt.Errorf("store use params: %w", err)
	}
	nonce, err := s.core.RandomNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}
	commitment, err := s.core.Commit("input", rawParams, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("commit use params: %w", err)
	}

	// use_evidence is carried verbatim (the verifier re-derives evidence_hash from it). Round-trip the
	// typed struct through JSON into a generic map so it embeds as a JSON object in the record body.
	var useEvidence map[string]any
	if err := json.Unmarshal(evidenceJSON, &useEvidence); err != nil {
		return nil, nil, fmt.Errorf("use evidence to map: %w", err)
	}

	rec := map[string]any{
		"record_id":     useID,
		"project_id":    ur.ProjectID,
		"session_id":    ur.SessionID,
		"agent_id":      "feir-resource",
		"agent_version": "feir-resource",
		"event_type":    "tool_call",
		"observed_via":  "broker",
		"action":        ev.Action,
		"status":        "ok",
		"authority": map[string]any{
			"source":            "gateway_enforced",
			"enforcement_point": "tool_gateway",
			"grant_id":          ev.GrantID,
			"evidence_hash":     evidenceHash,
			"evidence_sig":      evidenceSig,
			"evaluated_at":      ts(s.now()),
		},
		"input_commit": map[string]any{
			"alg":         "sha256",
			"commitment":  commitment,
			"low_entropy": true,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				// kind=use + enforcement_point=tool_gateway classifies this to the RESOURCE role (R2).
				"kind":         "use",
				"grant_id":     ev.GrantID,
				"resource_id":  ev.ResourceID,
				"use_evidence": useEvidence,
			},
		},
	}
	disclosures := []store.DisclosureSecret{
		{RecordID: useID, Field: "input", ValueDigest: addr.Digest, NonceHex: nonce},
	}
	return rec, disclosures, nil
}

// commitLowEntropyFields replaces each raw input/output/rationale field in rec with a hiding
// commitment {alg, commitment, low_entropy}, storing the raw value content-addressed and minting a
// fresh nonce. It returns the disclosure secrets (bound to recordID) to persist atomically with the
// record. The plaintext is deleted from rec so it never enters the signed body (and would otherwise
// be rejected by the closed schema).
func (s *Server) commitLowEntropyFields(rec map[string]any, recordID string) ([]store.DisclosureSecret, error) {
	var out []store.DisclosureSecret
	for _, field := range []string{"input", "output", "rationale"} {
		v, ok := rec[field]
		if !ok {
			continue
		}
		raw, err := rawValueBytes(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		addr, err := s.content.Put(context.Background(), raw)
		if err != nil {
			return nil, fmt.Errorf("store %s content: %w", field, err)
		}
		nonce, err := s.core.RandomNonce()
		if err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
		commitment, err := s.core.Commit(field, raw, nonce)
		if err != nil {
			return nil, fmt.Errorf("commit %s: %w", field, err)
		}
		rec[field+"_commit"] = map[string]any{
			"alg":         "sha256",
			"commitment":  commitment,
			"low_entropy": true,
		}
		delete(rec, field)
		out = append(out, store.DisclosureSecret{
			RecordID: recordID, Field: field, ValueDigest: addr.Digest, NonceHex: nonce,
		})
	}
	return out, nil
}

// rawValueBytes is the byte form of a low-entropy field that gets committed: a string verbatim, any
// other JSON value as its marshaled bytes (so the disclosed value round-trips exactly what was sent).
func rawValueBytes(v any) ([]byte, error) {
	if s, ok := v.(string); ok {
		return []byte(s), nil
	}
	return json.Marshal(v)
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
	locked := true
	defer func() {
		if locked {
			s.checkpointMu.Unlock()
		}
	}()

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

	// Store the sealed checkpoint (un-anchored). Anchoring is DECOUPLED: the token is stored
	// separately (anchors table) and joined into the checkpoint's `anchor` block at export time, so
	// the third-party TSA network call happens OUTSIDE this global checkpoint lock and a checkpoint
	// that failed to anchor can be back-anchored later (the checkpoints table is append-only).
	if err := s.st.PutCheckpoint(projectID, store.Checkpoint{JSON: sealed, CheckpointHash: cp.CheckpointHash, Seq: cp.Seq}); err != nil {
		return "", nil, err
	}
	var warns []string
	// best-effort witness append (bounded so a hung witness can't block); a failure leaves the
	// checkpoint stored-but-un-witnessed (reported, backfillable) rather than wedging the chain.
	if s.witness != nil {
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := s.witness.Append(wctx, projectID, []byte(sealed)); err != nil {
			warns = append(warns, fmt.Sprintf("witness append failed (backfill needed): %v", err))
		}
		cancel()
	}

	// Release the checkpoint lock BEFORE the TSA round-trip so a slow/hung TSA cannot stall other
	// projects' checkpointing. Seq is already committed, so anchoring out-of-lock is race-free.
	s.checkpointMu.Unlock()
	locked = false

	if s.tsa != nil {
		if err := s.anchorCheckpoint(ctx, projectID, cp.Seq, cp.CheckpointHash); err != nil {
			warns = append(warns, fmt.Sprintf("checkpoint stored un-anchored (TSA failed, backfillable): %v", err))
		}
	}

	var warn error
	if len(warns) > 0 {
		warn = fmt.Errorf("checkpoint created; %s", strings.Join(warns, "; "))
	}
	return sealed, warn, nil
}

// anchorCheckpoint stamps a checkpoint_hash at a third-party RFC 3161 TSA and stores the returned
// token (keyed by seq) for the export to join. The TSA timestamps the SHA-256 of the checkpoint_hash
// STRING (what the verifier re-imprints). Runs OUT of the checkpoint critical section.
func (s *Server) anchorCheckpoint(ctx context.Context, projectID string, seq int64, checkpointHash string) error {
	imprint := sha256.Sum256([]byte(checkpointHash))
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	der, err := s.tsa.Stamp(tctx, imprint[:])
	if err != nil {
		return err
	}
	// base64url-no-pad to match the Rust verifier's token decoder.
	return s.st.PutAnchor(projectID, seq, base64.RawURLEncoding.EncodeToString(der))
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
	// Pin the broker recording key (== this server's signing key; broker_trust: assumed) so any
	// credential-broker grants in the bundle elevate to gateway_enforced (Tier-A grant accountability).
	// When the resource gateway is enabled, ALSO pin its (distinct) recording key as the resource role,
	// so use receipts elevate under the resource role (ADR 0003 R2). An EXTERNAL auditor pins both keys
	// out-of-band instead of trusting the server's self-view.
	var report string
	if s.resourceCore != nil {
		report = s.core.VerifyBundleWithRoles(bundle, []string{s.core.PubKey()}, []string{s.resourceCore.PubKey()})
	} else {
		report = s.core.VerifyBundleWithAuthority(bundle, []string{s.core.PubKey()})
	}
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
	var obj map[string]json.RawMessage
	_ = json.Unmarshal([]byte(bundle), &obj)
	obj["mode"], _ = jsonRaw(mode)

	// For a disclosing mode, attach the (value, nonce) for every committed field so an offline
	// verifier can confirm each disclosure against its record's commitment (RCP §9.3). proof_only
	// ships commitments only.
	rawAvailable := false
	gaps := []string{"Level-2 observation scope is per-record; Level-3 completeness not claimed"}
	if mode == "selective_disclosure" || mode == "full_evidence" {
		disclosures, err := s.buildDisclosures(projectID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		obj["disclosures"], _ = jsonRaw(disclosures)
		rawAvailable = len(disclosures) > 0
		if !rawAvailable {
			gaps = append(gaps, "no committed low-entropy fields were recorded for this project, so there is nothing to disclose")
		}
	}
	obj["gap_report"], _ = jsonRaw(map[string]any{
		"mapped_fields":         []string{"record integrity", "checkpoint chain", "declared authority"},
		"customer_supplied":     []string{"raw input/output/rationale blobs (content store)"},
		"gaps":                  gaps,
		"raw_content_available": rawAvailable,
	})
	out, _ := json.Marshal(obj)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// buildDisclosures turns the project's stored disclosure secrets into the bundle's `disclosures`
// array: {record_id, field, value_b64, nonce_hex}. The raw value is fetched from the content store
// (which re-verifies its digest on read) and re-encoded base64url-no-pad for the verifier. Never nil.
func (s *Server) buildDisclosures(projectID string) ([]map[string]any, error) {
	secrets, err := s.st.Disclosures(projectID)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(secrets))
	for _, d := range secrets {
		raw, err := s.content.Get(context.Background(), d.ValueDigest)
		if err != nil {
			return nil, fmt.Errorf("disclose %s/%s: %w", d.RecordID, d.Field, err)
		}
		out = append(out, map[string]any{
			"record_id": d.RecordID,
			"field":     d.Field,
			"value_b64": base64.RawURLEncoding.EncodeToString(raw),
			"nonce_hex": d.NonceHex,
		})
	}
	return out, nil
}

// buildBundle assembles the export/verify bundle: published key, all sealed records, and the full
// checkpoint history.
func (s *Server) buildBundle(projectID string, _ bool) (string, error) {
	recs, _ := s.st.AllRecords(projectID)
	checks, _ := s.st.Checkpoints(projectID)
	anchors, err := s.st.Anchors(projectID)
	if err != nil {
		return "", err
	}
	records := make([]json.RawMessage, len(recs))
	for i, r := range recs {
		records[i] = json.RawMessage(r.JSON)
	}
	checkpoints := make([]json.RawMessage, len(checks))
	for i, c := range checks {
		// Join the decoupled anchor (if any) into the checkpoint's `anchor` block. The anchor is
		// excluded from the checkpoint_hash/sig, so attaching it here does not affect verification.
		if tok, ok := anchors[c.Seq]; ok {
			withAnchor, err := attachAnchor(c.JSON, tok)
			if err != nil {
				return "", fmt.Errorf("attach anchor to checkpoint %d: %w", c.Seq, err)
			}
			checkpoints[i] = json.RawMessage(withAnchor)
		} else {
			checkpoints[i] = json.RawMessage(c.JSON)
		}
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

// attachAnchor adds an `anchor` block to a sealed checkpoint JSON. The anchor is excluded from the
// checkpoint_hash/sig (the verifier strips it and re-canonicalizes the body), so re-serializing here
// is safe — the body's RawMessage fields are preserved byte-for-byte.
func attachAnchor(checkpointJSON, tokenB64 string) (string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(checkpointJSON), &obj); err != nil {
		return "", fmt.Errorf("parse checkpoint: %w", err)
	}
	anchor, err := json.Marshal(map[string]any{"scheme": "rfc3161", "token_b64": tokenB64})
	if err != nil {
		return "", err
	}
	obj["anchor"] = anchor
	out, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(out), nil
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
