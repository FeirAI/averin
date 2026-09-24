package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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
		s.noteSeqAttempt(gr.ProjectID, grantID)
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
	evidenceSig, err := s.core.SignEvidence("gateway_enforced", gr.ProjectID, grantID, evidenceHash)
	if err != nil {
		return nil, fmt.Errorf("sign native grant evidence: %w", err)
	}
	return map[string]any{
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
			"evidence_sig":      evidenceSig,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				"kind":           "grant",
				"grant_evidence": evidence,
			},
		},
	}, nil
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
	if ir.EffectiveExp <= 0 {
		writeErr(w, http.StatusBadRequest, "effective_exp (unix seconds) is required")
		return
	}
	introspectedAt := ir.IntrospectedAt
	if introspectedAt == 0 {
		introspectedAt = s.now().Unix()
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

	// The resource signs the structured averin.resource.introspection.v1 challenge with its RAW key.
	ie := broker.IntrospectionEvidence(s.resourceRawKey, ir.GrantID, ir.CredentialRef, ir.EffectiveScope, s.resourceID, transcriptHash, introspectedAt, ir.EffectiveExp)

	var sealed string
	var created bool
	commitErr := s.withProjectWrite(r.Context(), ir.ProjectID, func(st store.Store) error {
		if existing, found, le := st.RecordByIdem(ir.ProjectID, ir.IdempotencyKey); le != nil {
			return le
		} else if found {
			sealed, created = existing.JSON, false
			return nil
		}
		rec, e := s.buildIntrospectionRecord(ir, recordID, ie)
		if e != nil {
			return e
		}
		var se error
		sealed, created, se = s.sealAndStore(st, ir.ProjectID, ir.SessionID, ir.IdempotencyKey, rec, nil)
		return se
	})
	if commitErr != nil {
		writeErr(w, http.StatusInternalServerError, "introspection: "+commitErr.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"record_id": recordID,
		"grant_id":  ir.GrantID,
		"created":   created,
		"record":    json.RawMessage(sealed),
	})
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
	evidenceSig, err := s.resourceCore.SignEvidence("gateway_enforced", ir.ProjectID, recordID, evidenceHash)
	if err != nil {
		return nil, fmt.Errorf("sign introspection evidence (resource): %w", err)
	}
	return map[string]any{
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
			"evidence_sig":      evidenceSig,
		},
		"extensions": map[string]any{
			"broker": map[string]any{
				"kind":                   "introspection_transcript",
				"grant_id":               ir.GrantID,
				"resource_id":            s.resourceID,
				"introspection_evidence": ie,
			},
		},
	}, nil
}
