package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/store"
)

// WithIntrospection enables POST /v2/introspection (ADR 0005 M3 — Native/STS): the resource records a signed
// introspection transcript attesting an externally-minted credential's effective scope. rawResourceKey is the
// RAW resource recording key (the SAME key WithResource's resourceCore wraps) — needed to sign the structured
// averin.resource.introspection.v1 challenge over raw bytes (which the FFI core's tagged SignEvidence cannot do).
// Requires WithResource first; panics on a key mismatch (a configuration error).
func (s *Server) WithIntrospection(rawResourceKey ed25519.PrivateKey) *Server {
	if s.resourceCore == nil {
		panic("WithIntrospection requires WithResource first (the transcript is a resource-role record)")
	}
	want := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(rawResourceKey.Public().(ed25519.PublicKey))
	if want != s.resourceCore.PubKey() {
		panic("WithIntrospection: the raw resource key must match the resource recording key (resourceCore)")
	}
	s.resourceRawKey = rawResourceKey
	return s
}

// handleNativeGrant issues a native (token_exchange) grant: it records a signed gateway_enforced grant with
// grant_evidence.mode=="token_exchange" + lease_id (NO credential_binding, NO cnf PoP, NO minted capability) —
// the external IdP/STS holds the credential, the grant authorizes the exchange, and a later resource-signed
// introspection transcript binds the effective scope. Record-before-issue; the gapless broker_seq is
// allocated with the grant record inside the project transaction.
func (s *Server) handleNativeGrant(ctx context.Context, w http.ResponseWriter, gr grantRequest, idem, grantID string) {
	if gr.LeaseID == "" || gr.Action == "" || gr.Resource == "" || gr.Scope == "" {
		writeErr(w, http.StatusBadRequest, "a native (token_exchange) grant requires lease_id, action, resource, and scope")
		return
	}
	ttl := time.Duration(gr.TTLSeconds) * time.Second
	if ttl <= 0 {
		writeErr(w, http.StatusBadRequest, "ttl_seconds must be positive")
		return
	}
	issued := s.now()
	exp := issued.Add(ttl)

	var sealed string
	var created bool
	commitErr := s.withProjectWrite(ctx, gr.ProjectID, func(st store.Store) error {
		if existing, found, le := st.RecordByIdem(gr.ProjectID, idem); le != nil {
			return le
		} else if found {
			sealed, created = existing.JSON, false
			return nil
		}
		seq, _, aerr := st.AllocateBrokerSeq(gr.ProjectID, grantID)
		if aerr != nil {
			return fmt.Errorf("allocate broker_seq: %w", aerr)
		}
		if seq < 1 {
			return fmt.Errorf("store returned non-positive broker_seq %d", seq)
		}
		evidence := broker.NativeGrantEvidence(grantID, gr.Action, gr.Resource, gr.Scope, gr.LeaseID, seq, issued.Unix(), exp.Unix())
		if s.brokerID != "" {
			evidence["broker_id"] = s.brokerID // M4: tag the native grant with this broker's federation id
		}
		rec, e := s.buildNativeGrantRecord(gr, grantID, evidence)
		if e != nil {
			return e
		}
		var se error
		sealed, created, se = s.sealAndStore(st, gr.ProjectID, gr.SessionID, idem, rec, nil)
		return se
	})
	if commitErr != nil {
		if isVoidedGrant(commitErr) {
			writeErr(w, http.StatusConflict, commitErr.Error())
			return
		}
		if msg := grantIDTakenMsg(commitErr, grantID); msg != "" {
			writeErr(w, http.StatusConflict, msg)
			return
		}
		writeErr(w, http.StatusInternalServerError, "native grant: "+commitErr.Error())
		return
	}
	expOut, scopeClass, perr := storedGrantFields(sealed)
	if perr != nil {
		writeErr(w, http.StatusInternalServerError, perr.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"grant_id":    grantID,
		"mode":        "token_exchange",
		"lease_id":    gr.LeaseID,
		"expires_at":  ts(time.Unix(expOut, 0)),
		"scope_class": scopeClass,
		"created":     created,
		"record":      json.RawMessage(sealed),
	})
}

// buildNativeGrantRecord builds the unsealed record body for a native grant: broker-role, carrying the native
// grant_evidence, with NO credential commitment (there is no broker-minted descriptor).
func (s *Server) buildNativeGrantRecord(gr grantRequest, grantID string, evidence map[string]any) (map[string]any, error) {
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("marshal native grant evidence: %w", err)
	}
	evidenceHash, err := s.core.RcpEvidenceHash(string(evidenceJSON))
	if err != nil {
		return nil, fmt.Errorf("derive native grant evidence_hash: %w", err)
	}
	rec := map[string]any{
		"record_id":     grantID,
		"project_id":    gr.ProjectID,
		"session_id":    gr.SessionID,
		"agent_id":      gr.AgentID,
		"agent_version": "averin-broker",
		"event_type":    "credential_grant",
		"observed_via":  "broker",
		"action":        gr.Action,
		"status":        "ok",
		"authority": map[string]any{
			"source":            "gateway_enforced",
			"enforcement_point": "credential_broker",
			"grant_type":        "oauth-scope",
			"grant_id":          grantID,
			"evidence_hash":     evidenceHash,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				"kind":           "grant",
				"grant_evidence": evidence,
			},
		},
	}
	if err := s.signLocalAuthorityV3(rec, s.core); err != nil {
		return nil, err
	}
	return rec, nil
}

// introspectionRequest is the POST /v2/introspection wire shape (ADR 0005 M3).
type introspectionRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	ProjectID      string `json:"project_id"`
	SessionID      string `json:"session_id"`
	GrantID        string `json:"grant_id"`        // the native grant this transcript introspects
	CredentialRef  string `json:"credential_ref"`  // MUST equal the native grant's lease_id (verifier-enforced)
	EffectiveScope string `json:"effective_scope"` // the scope the resource observed (⊆ the grant scope)
	IntrospectedAt int64  `json:"introspected_at"` // unix; 0 -> now
	EffectiveExp   int64  `json:"effective_exp"`   // unix; the effective credential's expiry (<= grant exp)
	TranscriptHash string `json:"transcript_hash"` // sha256:<hex> of the action payload (rides the evidence)
}

// handleIntrospection records a resource-signed introspection transcript (ADR 0005 M3) for a native grant.
//
// Plan 009: a transcript is an authorization receipt. Inside ONE project transaction the handler first
// resolves an exact committed retry (returned even after the grant later expired or was revoked), then
// validates the actual native grant (a committed token_exchange grant of this resource whose lease is
// the credential_ref, whose scope contains the effective scope, whose expiry bounds the effective
// expiry and the introspection time, and which is neither revoked nor voided), allocates the next
// authorization ordinal and signs the transcript with it. Nothing is signed before validation.
func (s *Server) handleIntrospection(w http.ResponseWriter, r *http.Request) {
	if s.resourceCore == nil || s.resourceRawKey == nil {
		writeErr(w, http.StatusNotImplemented, "introspection not enabled (set AVERIN_RESOURCE_SEED + WithIntrospection)")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var ir introspectionRequest
	if err := decode(body, &ir); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid introspection request: "+err.Error())
		return
	}
	if qp := r.URL.Query().Get("project"); qp != "" && ir.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if ir.ProjectID == "" || ir.SessionID == "" || ir.IdempotencyKey == "" || ir.GrantID == "" || ir.CredentialRef == "" || ir.EffectiveScope == "" {
		writeErr(w, http.StatusBadRequest, "project_id, session_id, idempotency_key, grant_id, credential_ref, effective_scope are required")
		return
	}
	if err := s.rejectOpaqueIdentity("project_id", ir.ProjectID, "session_id", ir.SessionID, "idempotency_key", ir.IdempotencyKey, "grant_id", ir.GrantID, "credential_ref", ir.CredentialRef, "effective_scope", ir.EffectiveScope); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if reservedIdem(ir.IdempotencyKey) {
		writeErr(w, http.StatusBadRequest, reservedIdemMsg)
		return
	}
	if ir.EffectiveExp <= 0 || ir.IntrospectedAt < 0 {
		writeErr(w, http.StatusBadRequest, "effective_exp (unix seconds) is required and introspected_at must not be negative")
		return
	}
	transcriptHash := ir.TranscriptHash
	if transcriptHash == "" {
		h, e := s.core.RcpEvidenceHash(fmt.Sprintf(`{"g":%q,"s":%q}`, ir.GrantID, ir.EffectiveScope))
		if e != nil {
			writeErr(w, http.StatusInternalServerError, "transcript_hash: "+e.Error())
			return
		}
		transcriptHash = h
	}
	recordID := uuidV5Shaped("averin.introspection.id.v1", ir.ProjectID, ir.IdempotencyKey)

	var sealed string
	var created bool
	var clientErr, conflictErr error
	commitErr := s.withProjectWrite(r.Context(), ir.ProjectID, func(st store.Store) error {
		if existing, found, le := st.RecordByIdem(ir.ProjectID, ir.IdempotencyKey); le != nil {
			return le
		} else if found {
			if !s.storedIntrospectionMatches(existing.JSON, recordID, ir, transcriptHash) {
				conflictErr = errors.New("idempotency_key is already bound to a different record in this project (a key cannot be reused with a different introspection request)")
				return nil
			}
			sealed, created = existing.JSON, false
			return nil
		}
		now := s.now()
		introspectedAt := ir.IntrospectedAt
		if introspectedAt == 0 {
			introspectedAt = now.Unix()
		}
		refusal, e := s.validateNativeIntrospection(st, ir, introspectedAt, now)
		if e != nil {
			return e // a store/database failure is a retryable 5xx, never a client refusal
		}
		if refusal != nil {
			clientErr = refusal
			return nil
		}
		ordinal, e := st.AllocateAuthorizationOrder(ir.ProjectID)
		if e != nil {
			return e
		}
		// The resource signs the structured averin.resource.introspection.v1 challenge with its RAW key,
		// inside the transaction and only after the grant validated.
		ie := broker.IntrospectionEvidence(s.resourceRawKey, ir.GrantID, ir.CredentialRef, ir.EffectiveScope, s.resourceID, transcriptHash, introspectedAt, ir.EffectiveExp)
		ie["authorization_order"] = authorizationOrder(ir.ProjectID, ordinal)
		rec, e := s.buildIntrospectionRecord(ir, recordID, ie)
		if e != nil {
			return e
		}
		stored, c, se := s.sealAndStore(st, ir.ProjectID, ir.SessionID, ir.IdempotencyKey, rec, nil)
		if errors.Is(se, store.ErrRecordIDConflict) {
			conflictErr = se
			return errRollbackDecided // nothing of ours persisted: do not burn the ordinal
		}
		if se != nil {
			return se
		}
		if !c {
			// A same-key insert raced past the lookup: echo it only if it is this exact request.
			// Either way this transaction persisted nothing of its own: roll back the ordinal.
			if !s.storedIntrospectionMatches(stored, recordID, ir, transcriptHash) {
				conflictErr = errors.New("idempotency_key is already bound to a different record in this project")
			}
			sealed = stored
			return errRollbackDecided
		}
		sealed, created = stored, true
		return st.PutAuthorizationReceipt(ir.ProjectID, store.AuthorizationReceipt{
			Ordinal: ordinal, RecordID: recordID, GrantID: ir.GrantID, Kind: "introspection_transcript",
		})
	})
	commitErr = decidedRollback(commitErr)
	if conflictErr != nil {
		writeErr(w, http.StatusConflict, "introspection rejected: "+conflictErr.Error())
		return
	}
	if clientErr != nil {
		writeErr(w, http.StatusBadRequest, "introspection rejected: "+clientErr.Error())
		return
	}
	if commitErr != nil {
		writeErr(w, http.StatusInternalServerError, "introspection: "+commitErr.Error())
		return
	}
	// Identifiers come from the stored receipt, never from the new request.
	storedID, _, _, storedGrant := useReceiptIdentity(sealed)
	writeJSON(w, http.StatusCreated, map[string]any{
		"record_id": storedID,
		"grant_id":  storedGrant,
		"created":   created,
		"record":    json.RawMessage(sealed),
	})
}

// storedIntrospectionMatches is the exact-retry rule: the stored receipt must be this deterministic
// introspection record in this session, for this resource, carrying every immutable request field.
// An omitted (zero) introspected_at reuses the originally committed server-selected time; an explicit
// time must equal it.
func (s *Server) storedIntrospectionMatches(recordJSON, recordID string, ir introspectionRequest, transcriptHash string) bool {
	var p struct {
		RecordID   string `json:"record_id"`
		ProjectID  string `json:"project_id"`
		SessionID  string `json:"session_id"`
		Extensions struct {
			Broker struct {
				Kind     string `json:"kind"`
				Evidence struct {
					Kind           string `json:"kind"`
					GrantID        string `json:"grant_id"`
					CredentialRef  string `json:"credential_ref"`
					EffectiveScope string `json:"effective_scope"`
					ResourceID     string `json:"resource_id"`
					TranscriptHash string `json:"transcript_hash"`
					IntrospectedAt int64  `json:"introspected_at"`
					EffectiveExp   int64  `json:"effective_exp"`
				} `json:"introspection_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(recordJSON), &p) != nil {
		return false
	}
	e := p.Extensions.Broker.Evidence
	return p.RecordID == recordID && p.ProjectID == ir.ProjectID && p.SessionID == ir.SessionID &&
		p.Extensions.Broker.Kind == "introspection_transcript" && e.Kind == "introspection_transcript" &&
		e.GrantID == ir.GrantID && e.CredentialRef == ir.CredentialRef && e.EffectiveScope == ir.EffectiveScope &&
		e.ResourceID == s.resourceID && e.TranscriptHash == transcriptHash && e.EffectiveExp == ir.EffectiveExp &&
		(ir.IntrospectedAt == 0 || ir.IntrospectedAt == e.IntrospectedAt)
}

// validateNativeIntrospection checks the ACTUAL committed native grant before any ordinal or signature:
// a token_exchange grant of this resource, lease == credential_ref, effective scope within the grant
// scope, effective expiry and introspection time within the grant window, the grant not expired now,
// and no revocation (any mode) or terminal void.
func (s *Server) validateNativeIntrospection(st store.Store, ir introspectionRequest, introspectedAt int64, now time.Time) (refusal, err error) {
	grantRec, found, err := st.RecordByRecordID(ir.ProjectID, ir.GrantID)
	if err != nil {
		return nil, err
	}
	if !found {
		return fmt.Errorf("grant %q is not a committed native grant in this project", ir.GrantID), nil
	}
	var g struct {
		Extensions struct {
			Broker struct {
				Kind     string `json:"kind"`
				Evidence struct {
					GrantID    string `json:"grant_id"`
					Mode       string `json:"mode"`
					LeaseID    string `json:"lease_id"`
					ResourceID string `json:"resource_id"`
					Scope      string `json:"scope"`
					IssuedAt   int64  `json:"issued_at"`
					Exp        int64  `json:"exp"`
				} `json:"grant_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	if json.Unmarshal([]byte(grantRec.JSON), &g) != nil || g.Extensions.Broker.Kind != "grant" ||
		g.Extensions.Broker.Evidence.Mode != "token_exchange" || g.Extensions.Broker.Evidence.GrantID != ir.GrantID {
		return fmt.Errorf("grant %q is not a committed native (token_exchange) grant", ir.GrantID), nil
	}
	ge := g.Extensions.Broker.Evidence
	switch {
	case ge.ResourceID != s.resourceID:
		return fmt.Errorf("native grant %q is for resource %q, not this resource", ir.GrantID, ge.ResourceID), nil
	case ge.LeaseID != ir.CredentialRef:
		return fmt.Errorf("credential_ref does not match native grant %q's lease", ir.GrantID), nil
	case !scopeSubset(ir.EffectiveScope, ge.Scope):
		return fmt.Errorf("effective_scope is not within native grant %q's scope", ir.GrantID), nil
	case ir.EffectiveExp > ge.Exp:
		return fmt.Errorf("effective_exp outlives native grant %q", ir.GrantID), nil
	case introspectedAt < ge.IssuedAt || introspectedAt >= ge.Exp:
		return fmt.Errorf("introspected_at is outside native grant %q's validity window", ir.GrantID), nil
	case introspectedAt > now.Add(broker.RequestClockSkew).Unix():
		return errors.New("introspected_at is in the future"), nil
	case now.Unix() >= ge.Exp:
		return fmt.Errorf("native grant %q has expired", ir.GrantID), nil
	}
	if voided, err := s.terminalGrantVoided(st, ir.ProjectID, ir.GrantID); err != nil {
		return nil, err
	} else if voided {
		return fmt.Errorf("native grant %q is voided", ir.GrantID), nil
	}
	if revoked, err := st.IsRevoked(ir.ProjectID, ir.GrantID); err != nil {
		return nil, err
	} else if revoked {
		return fmt.Errorf("native grant %q is revoked", ir.GrantID), nil
	}
	return nil, nil
}

// scopeSubset reports whether every space-delimited token of sub is a token of sup (the verifier's
// OAuth scope-narrowing rule).
func scopeSubset(sub, sup string) bool {
	have := map[string]bool{}
	for _, t := range strings.Split(sup, " ") {
		if t != "" {
			have[t] = true
		}
	}
	for _, t := range strings.Split(sub, " ") {
		if t != "" && !have[t] {
			return false
		}
	}
	return true
}

// buildIntrospectionRecord builds the unsealed introspection_transcript record body — a RESOURCE-role record
// (tool_gateway), its evidence_sig signed by the resource recording key.
func (s *Server) buildIntrospectionRecord(ir introspectionRequest, recordID string, ie map[string]any) (map[string]any, error) {
	ieJSON, err := json.Marshal(ie)
	if err != nil {
		return nil, fmt.Errorf("marshal introspection evidence: %w", err)
	}
	evidenceHash, err := s.core.RcpEvidenceHash(string(ieJSON))
	if err != nil {
		return nil, fmt.Errorf("derive introspection evidence_hash: %w", err)
	}
	rec := map[string]any{
		"record_id":     recordID,
		"project_id":    ir.ProjectID,
		"session_id":    ir.SessionID,
		"agent_id":      "averin-resource",
		"agent_version": "averin-resource",
		"event_type":    "tool_call",
		"observed_via":  "broker",
		"action":        ir.EffectiveScope,
		"status":        "ok",
		"authority": map[string]any{
			"source":            "gateway_enforced",
			"enforcement_point": "tool_gateway",
			"grant_id":          ir.GrantID,
			"evidence_hash":     evidenceHash,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				"kind":                   "introspection_transcript",
				"grant_id":               ir.GrantID,
				"resource_id":            s.resourceID,
				"introspection_evidence": ie,
			},
		},
	}
	if err := s.signLocalAuthorityV3(rec, s.resourceCore); err != nil {
		return nil, err
	}
	return rec, nil
}
