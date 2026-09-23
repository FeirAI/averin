package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/store"
)

// pendingGrant is a minted-but-uncommitted grant held between /v2/grants/prepare and /v2/grants/finalize.
// It carries NO committed broker_seq — that is allocated at finalize (see handleGrantFinalize). idemKey is
// carried alongside (not just implied by the `pending` map key) so a durable-store delete/prune can name
// the row without re-splitting pendingKey's project:idem encoding.
type pendingGrant struct {
	prepared broker.Prepared
	req      broker.Request
	gr       grantRequest
	created  time.Time
	idemKey  string
}

// WithCosigPolicy pins the SERVER-side M-of-N cosignature-approval policy for the online two-phase grant flow
// (ADR 0005 M6): a /v2/grants/finalize carrying cosignatures is accepted only if >= threshold DISTINCT keys in
// `approvers` signed the revealed CosigApprovalChallenge. These are role-separated governance keys (the offline
// verifier re-checks them under pinned cosig_approver_keys, disjoint from every other role). Never client-supplied.
func (s *Server) WithCosigPolicy(threshold int, approvers []ed25519.PublicKey) *Server {
	s.cosigThreshold = threshold
	s.cosigApprovers = approvers
	return s
}

const pendingTTL = 15 * time.Minute

// pendingKey namespaces a pending grant by project + idempotency key.
func pendingKey(projectID, idem string) string { return projectID + "\x00" + idem }

// grantRequestToBroker maps the wire grantRequest to a broker.Request (the same mapping handleGrant uses).
func grantRequestToBroker(gr grantRequest) broker.Request {
	return broker.Request{
		PoPVersion:       gr.PoPVersion,
		ProjectID:        gr.ProjectID,
		IdempotencyKey:   gr.IdempotencyKey,
		SessionID:        gr.SessionID,
		IssuedAt:         gr.IssuedAt,
		RequestExpiresAt: gr.RequestExpiresAt,
		AgentID:          gr.AgentID,
		Action:           gr.Action,
		Resource:         gr.Resource,
		Scope:            gr.Scope,
		ScopeClass:       broker.ScopeClass(gr.ScopeClass),
		UseLimit:         gr.UseLimit,
		AgentPubKey:      gr.AgentPubKey,
		AgentSig:         gr.AgentSig,
		Principal:        gr.Principal,
		DelegationChain:  gr.DelegationChain,
		Justification:    gr.Justification,
		TTL:              time.Duration(gr.TTLSeconds) * time.Second,
	}
}

// grantIdem resolves the idempotency key from the body field or the Idempotency-Key header.
func grantIdem(gr grantRequest, r *http.Request) (string, error) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) > 1 {
		return "", fmt.Errorf("multiple Idempotency-Key headers are not supported")
	}
	header := r.Header.Get("Idempotency-Key")
	if gr.IdempotencyKey != "" && header != "" && gr.IdempotencyKey != header {
		return "", fmt.Errorf("idempotency_key conflicts with Idempotency-Key header")
	}
	if gr.IdempotencyKey != "" {
		return gr.IdempotencyKey, nil
	}
	return header, nil
}

// copyEvidence shallow-copies a grant_evidence map. AttachCosignatures/AttachDelegation/the broker_seq overwrite
// only SET top-level keys (never mutate nested values), so a shallow copy fully isolates one finalize's mutations
// from the shared pending entry (and from a concurrent same-key finalize).
func copyEvidence(m map[string]any) map[string]any {
	c := make(map[string]any, len(m)+2)
	for k, v := range m {
		c[k] = v
	}
	return c
}

// handleGrantPrepare is PHASE 1 of the online two-phase grant flow (ADR 0005 M6 Cosig / M2 Delegation): it
// validates the request and MINTS the credential (broker.Prepare) WITHOUT allocating a broker_seq or committing,
// holds it in `pending`, and reveals the challenge inputs the approvers/delegators must sign — grant_id,
// credential_binding, exp, cnf_kid. A retry returns the SAME challenge (the pending state fixes the minted
// descriptor, so the revealed credential_binding/exp are stable). If the grant is already finalized, returns it.
func (s *Server) handleGrantPrepare(w http.ResponseWriter, r *http.Request) {
	if s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "credential broker not enabled (set AVERIN_BROKER_ISSUING_SEED)")
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
	if qp := r.URL.Query().Get("project"); qp != "" {
		if gr.ProjectID != "" && gr.ProjectID != qp {
			writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
			return
		}
		gr.ProjectID = qp
	}
	if gr.ProjectID == "" || gr.SessionID == "" {
		writeErr(w, http.StatusBadRequest, "project_id and session_id are required")
		return
	}
	idem, idemErr := grantIdem(gr, r)
	if idemErr != nil {
		writeErr(w, http.StatusBadRequest, idemErr.Error())
		return
	}
	if idem == "" {
		writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header) so a retry cannot double-issue a credential")
		return
	}
	if reservedIdem(idem) {
		writeErr(w, http.StatusBadRequest, reservedIdemMsg)
		return
	}
	if err := rejectNUL("project_id", gr.ProjectID, "idempotency_key", idem); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	grantID := deterministicGrantID(gr.ProjectID, idem)
	if gr.Mode != "" && gr.Mode != "capability" || gr.LeaseID != "" {
		writeErr(w, http.StatusBadRequest, "brokered grants require capability mode and no lease_id")
		return
	}
	if gr.TTLSeconds <= 0 || int64(gr.TTLSeconds) > (1<<63-1)/int64(time.Second) {
		writeErr(w, http.StatusBadRequest, "ttl_seconds must be positive and fit the server duration")
		return
	}
	gr.IdempotencyKey = idem

	req := grantRequestToBroker(gr)
	req.BrokerID = s.brokerID // M4: tag the grant with this broker's federation id ("" = single-broker)
	if req.PoPVersion != 2 {
		writeErr(w, http.StatusBadRequest, "online brokered grants require grant PoP v2")
		return
	}
	// Validate proof-of-possession + scope BEFORE anything else (same gate as the single-phase /v2/grants) — so
	// an unsigned/forbidden request can never read back a committed grant or a pending challenge by reusing a
	// known idempotency key.
	if e := req.Validate(); e != nil {
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}
	if _, e := broker.ClassifyScope(req.Scope, req.ScopeClass); e != nil {
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}

	// The durable project transaction arbitrates both committed and pending
	// idempotency across replicas. Local pending entries are only a cache.
	var p *pendingGrant
	var finalized string
	var conflict string
	var freshnessErr error
	err = s.withProjectWrite(r.Context(), gr.ProjectID, func(st store.Store) error {
		if existing, found, e := st.RecordByIdem(gr.ProjectID, idem); e != nil {
			return e
		} else if found {
			if same, pe := storedGrantMatchesRequest(existing.JSON, req); pe != nil || !same {
				conflict = "idempotency_key already used for a different record or grant request"
				return nil
			}
			finalized = existing.JSON
			return nil
		}
		if e := req.ValidateAt(s.now()); e != nil {
			freshnessErr = e
			return nil
		}
		row, found, e := st.PendingGrant(gr.ProjectID, idem)
		if e != nil {
			return e
		}
		if found {
			live, e := st.PendingGrantLive(gr.ProjectID, row.GrantID, s.now(), pendingTTL)
			if e != nil {
				return e
			}
			if live {
				var dto pendingGrantDTO
				if e := json.Unmarshal(row.Payload, &dto); e != nil {
					return e
				}
				dto.Created = row.Created
				p = dto.toPendingGrant(idem)
				if e := p.req.FreshAt(s.now()); e != nil {
					freshnessErr = fmt.Errorf("original pending grant proof expired: %w", e)
					return nil
				}
				if same, pe := pendingGrantMatchesRequest(p, req); pe != nil || !same {
					conflict = "idempotency_key already has a pending grant for a different grant request"
				}
				return nil
			}
			if e := st.DeletePendingGrant(gr.ProjectID, idem); e != nil {
				return e
			}
		}
		prepared, e := broker.Prepare(req, grantID, func() (int64, error) { return 1, nil }, s.now(), s.brokerKey)
		if e != nil {
			return e
		}
		p = &pendingGrant{prepared: prepared, req: req, gr: gr, created: s.now(), idemKey: idem}
		payload, e := json.Marshal(dtoFromPending(p))
		if e != nil {
			return e
		}
		winning, _, e := st.PutPendingGrant(gr.ProjectID, idem, store.PendingGrant{GrantID: grantID, Payload: payload, Created: p.created})
		if e != nil {
			return e
		}
		var dto pendingGrantDTO
		if e := json.Unmarshal(winning.Payload, &dto); e != nil {
			return e
		}
		dto.Created = winning.Created
		p = dto.toPendingGrant(idem)
		if same, pe := pendingGrantMatchesRequest(p, req); pe != nil || !same {
			conflict = "idempotency_key already has a pending grant for a different grant request"
		}
		return nil
	})
	if freshnessErr != nil {
		writeErr(w, http.StatusBadRequest, freshnessErr.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "prepare grant: "+err.Error())
		return
	}
	if conflict != "" {
		writeErr(w, http.StatusConflict, conflict)
		return
	}
	if finalized != "" {
		s.respondPreparedFromSealed(w, grantID, finalized, true)
		return
	}
	if p == nil {
		writeErr(w, http.StatusInternalServerError, "prepare grant: no pending result")
		return
	}
	pk := pendingKey(gr.ProjectID, idem)
	s.pendingMu.Lock()
	s.pending[pk] = p
	s.pendingMu.Unlock()
	resp := map[string]any{
		"grant_id":           p.prepared.GrantID,
		"credential_binding": p.prepared.CredentialBinding,
		"cnf_kid":            p.prepared.Evidence["cnf_kid"],
		"exp":                p.prepared.Evidence["exp"],
		"finalized":          false,
	}
	if s.cosigThreshold > 0 {
		resp["cosig_threshold"] = s.cosigThreshold // the M-of-N the approvers' cosignatures must meet
	}
	writeJSON(w, http.StatusOK, resp)
}

// grantFinalizeRequest is the POST /v2/grants/finalize wire shape (ADR 0005 M6/M2): the SAME grant request body
// posted to prepare (idempotency_key, project_id, session_id, the operation fields, and the agent_pubkey/
// agent_sig proof-of-possession) plus the collected approvals. The grant request is re-validated (PoP) and must
// match the pending mint / committed grant, so knowing an idempotency key alone never yields a capability.
type grantFinalizeRequest struct {
	grantRequest
	Cosignatures   []broker.Cosignature   `json:"cosignatures"`    // M6: collected over CosigApprovalChallenge
	DelegationHops []broker.DelegationHop `json:"delegation_hops"` // M2: collected over DelegationHopChallenge
}

// pendingGrantMatchesRequest reports whether req is the SAME grant request that minted the pending grant — the
// identical field-by-field rule storedGrantMatchesRequest applies to a committed grant, run over the pending
// mint's grant_evidence (so prepare-retry, finalize, and single-phase issuance share one definition of "same").
func pendingGrantMatchesRequest(p *pendingGrant, req broker.Request) (bool, error) {
	wrapped, err := json.Marshal(map[string]any{
		"extensions": map[string]any{"broker": map[string]any{"kind": "grant", "grant_evidence": p.prepared.Evidence}},
	})
	if err != nil {
		return false, err
	}
	return storedGrantMatchesRequest(string(wrapped), req)
}

// handleGrantFinalize is PHASE 2: it loads the pending mint, binds the collected cosignatures (M6) and/or
// delegation hops (M2) into the grant_evidence (broker.AttachCosignatures / AttachDelegation — each FAIL-CLOSED,
// re-verifying every signature), allocates the gapless broker_seq, seals + commits the grant, and returns the
// capability. Idempotent: a re-finalize returns the committed grant.
func (s *Server) handleGrantFinalize(w http.ResponseWriter, r *http.Request) {
	if s.brokerKey == nil {
		writeErr(w, http.StatusNotImplemented, "credential broker not enabled")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var fr grantFinalizeRequest
	if err := decode(body, &fr); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid finalize request: "+err.Error())
		return
	}
	if qp := r.URL.Query().Get("project"); qp != "" {
		if fr.ProjectID != "" && fr.ProjectID != qp {
			writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
			return
		}
		fr.ProjectID = qp
	}
	idem, idemErr := grantIdem(fr.grantRequest, r)
	if idemErr != nil {
		writeErr(w, http.StatusBadRequest, idemErr.Error())
		return
	}
	if fr.ProjectID == "" || idem == "" {
		writeErr(w, http.StatusBadRequest, "project_id and idempotency_key are required")
		return
	}
	if err := rejectNUL("project_id", fr.ProjectID, "idempotency_key", idem); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	grantID := deterministicGrantID(fr.ProjectID, idem)
	if fr.Mode != "" && fr.Mode != "capability" || fr.LeaseID != "" {
		writeErr(w, http.StatusBadRequest, "brokered grants require capability mode and no lease_id")
		return
	}
	if fr.TTLSeconds <= 0 || int64(fr.TTLSeconds) > (1<<63-1)/int64(time.Second) {
		writeErr(w, http.StatusBadRequest, "ttl_seconds must be positive and fit the server duration")
		return
	}
	fr.IdempotencyKey = idem

	// Proof-of-possession FIRST (mirroring single-phase /v2/grants): finalize returns a live capability, so the
	// caller must present the SAME PoP-signed grant request it prepared — project_id + idempotency_key alone
	// (both guessable/observable) must never retrieve or commit someone else's grant.
	req := grantRequestToBroker(fr.grantRequest)
	req.BrokerID = s.brokerID
	if req.PoPVersion != 2 {
		writeErr(w, http.StatusBadRequest, "online brokered grants require grant PoP v2")
		return
	}
	if e := req.Validate(); e != nil {
		writeErr(w, http.StatusBadRequest, "finalize must carry the prepared grant request with a valid agent_sig: "+e.Error())
		return
	}

	// Read the durable pending challenge for expensive signature checks, then
	// revalidate this exact row under the project transaction at commit.
	var row store.PendingGrant
	var found bool
	var existing store.Record
	var committed bool
	err = s.st.WithProjectRead(r.Context(), fr.ProjectID, func(st store.Store) error {
		var e error
		row, found, e = st.PendingGrant(fr.ProjectID, idem)
		if e != nil || found {
			return e
		}
		existing, committed, e = st.RecordByIdem(fr.ProjectID, idem)
		return e
	})
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "pending lookup: "+err.Error())
		return
	}
	if !found {
		if committed {
			if same, pe := storedGrantMatchesRequest(existing.JSON, req); pe != nil || !same {
				writeErr(w, http.StatusConflict, "idempotency_key already used for a different record or grant request")
				return
			}
			s.respondFinalized(w, fr.ProjectID, grantID, existing.JSON, false)
			return
		}
		writeErr(w, http.StatusConflict, "no pending grant for this idempotency_key — call /v2/grants/prepare first")
		return
	}
	if e := req.ValidateAt(s.now()); e != nil {
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}
	var dto pendingGrantDTO
	if e := json.Unmarshal(row.Payload, &dto); e != nil {
		writeErr(w, http.StatusServiceUnavailable, "invalid durable pending grant: "+e.Error())
		return
	}
	dto.Created = row.Created
	p := dto.toPendingGrant(idem)
	if e := p.req.FreshAt(s.now()); e != nil || !s.now().Before(p.created.Add(pendingTTL)) {
		writeErr(w, http.StatusBadRequest, "original pending grant deadline expired")
		return
	}
	if same, pe := pendingGrantMatchesRequest(p, req); pe != nil || !same {
		writeErr(w, http.StatusConflict, "the pending grant under this idempotency_key was prepared for a different grant request")
		return
	}
	// M6 producer policy: if the server pins a cosig requirement, a finalize MUST carry cosignatures — an
	// empty-cosignatures finalize must not silently mint an un-cosigned grant (defense-in-depth; the offline
	// verifier only gates grants that DECLARE cosig_threshold, so this is the broker honoring its own policy).
	if s.cosigThreshold > 0 && len(fr.Cosignatures) == 0 {
		writeErr(w, http.StatusBadRequest, "this broker pins a cosig policy (WithCosigPolicy) — finalize requires cosignatures")
		return
	}

	// Operate on a COPY of the prepared evidence: AttachCosignatures/AttachDelegation mutate the evidence map,
	// and `p` (the pending pointer) is shared — two concurrent same-key finalizes mutating it unlocked would be a
	// concurrent map write (a fatal crash). Copying makes each finalize independent (the store is idempotent per
	// grant_id, so a concurrent double-commit collapses to one record); the pending stays PRISTINE so a rejected
	// finalize can be retried cleanly. The other Prepared fields (GrantID/CredentialBinding/DescriptorBytes/
	// Capability) are immutable, so a shallow copy of the top-level evidence map suffices.
	prepared := p.prepared
	prepared.Evidence = copyEvidence(p.prepared.Evidence)

	// Bind the collected approvals/hops into the grant_evidence COPY (fail-closed, every signature re-verified
	// over the revealed credential_binding/grant_id). A rejection does NOT consume the pending grant.
	if len(fr.Cosignatures) > 0 {
		if s.cosigThreshold < 1 || len(s.cosigApprovers) == 0 {
			writeErr(w, http.StatusBadRequest, "cosignatures submitted but the server pins no cosig policy (WithCosigPolicy)")
			return
		}
		if e := broker.AttachCosignatures(&prepared, s.cosigThreshold, fr.Cosignatures, s.cosigApprovers); e != nil {
			writeErr(w, http.StatusBadRequest, "cosignatures rejected: "+e.Error())
			return
		}
	}
	if len(fr.DelegationHops) > 0 {
		if e := broker.AttachDelegation(&prepared, fr.DelegationHops); e != nil {
			writeErr(w, http.StatusBadRequest, "delegation chain rejected: "+e.Error())
			return
		}
	}
	credentialAddr, err := s.content.Put(content.WithTenant(r.Context(), fr.ProjectID), prepared.DescriptorBytes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store credential descriptor: "+err.Error())
		return
	}

	// The project lock spans final pending/idempotency checks, allocation,
	// frontier selection, seal, insert, and pending deletion on one connection.
	var sealed string
	var created bool
	var conflict string
	var freshnessErr error
	commitErr := s.withProjectWrite(r.Context(), fr.ProjectID, func(st store.Store) error {
		if existing, ok, e := st.RecordByIdem(fr.ProjectID, idem); e != nil {
			return e
		} else if ok {
			if same, pe := storedGrantMatchesRequest(existing.JSON, req); pe != nil || !same {
				conflict = "idempotency_key already used for a different record or grant request"
				return nil
			}
			sealed, created = existing.JSON, false
			return nil
		}
		current, ok, e := st.PendingGrant(fr.ProjectID, idem)
		if e != nil {
			return e
		}
		if !ok || !bytes.Equal(current.Payload, row.Payload) {
			conflict = "pending challenge changed; prepare again"
			return nil
		}
		live, e := st.PendingGrantLive(fr.ProjectID, grantID, s.now(), pendingTTL)
		if e != nil {
			return e
		}
		if !live {
			conflict = "pending challenge expired; prepare again"
			return nil
		}
		if e := req.ValidateAt(s.now()); e != nil {
			freshnessErr = e
			return nil
		}
		if e := p.req.FreshAt(s.now()); e != nil || !s.now().Before(p.created.Add(pendingTTL)) {
			freshnessErr = fmt.Errorf("original pending grant deadline expired")
			return nil
		}
		s.noteSeqAttempt(fr.ProjectID, grantID)
		seq, _, e := st.AllocateBrokerSeq(fr.ProjectID, grantID)
		if e != nil {
			return e
		}
		if seq < 1 {
			return fmt.Errorf("store returned non-positive broker_seq %d", seq)
		}
		prepared.Evidence["broker_seq"] = seq
		rec, disclosures, e := s.buildGrantRecord(grantID, p.gr, p.req, prepared, credentialAddr.Digest)
		if e != nil {
			return e
		}
		sealed, created, e = s.sealAndStore(st, fr.ProjectID, p.gr.SessionID, idem, rec, disclosures)
		if e != nil {
			return e
		}
		return st.DeletePendingGrant(fr.ProjectID, idem)
	})
	if freshnessErr != nil {
		writeErr(w, http.StatusBadRequest, freshnessErr.Error())
		return
	}
	if conflict != "" {
		writeErr(w, http.StatusConflict, conflict)
		return
	}
	if commitErr != nil {
		if isVoidedGrant(commitErr) {
			writeErr(w, http.StatusConflict, commitErr.Error())
			return
		}
		if msg := grantIDTakenMsg(commitErr, grantID); msg != "" {
			writeErr(w, http.StatusConflict, msg)
			return
		}
		writeErr(w, http.StatusServiceUnavailable, "finalize grant: "+commitErr.Error())
		return
	}
	// Invalidate the local cache after the transaction commits. It has no
	// authority over finalize, so a stale entry cannot authorize another grant.
	s.pendingMu.Lock()
	delete(s.pending, pendingKey(fr.ProjectID, idem))
	s.pendingMu.Unlock()

	s.respondFinalized(w, fr.ProjectID, grantID, sealed, created)
}

// respondPreparedFromSealed answers a prepare that found an already-finalized grant (the challenge is moot).
func (s *Server) respondPreparedFromSealed(w http.ResponseWriter, grantID, sealed string, finalized bool) {
	writeJSON(w, http.StatusOK, map[string]any{
		"grant_id":  grantID,
		"finalized": finalized,
		"record":    json.RawMessage(sealed),
	})
}

// respondFinalized answers a successful (or idempotent) finalize with the minted capability + the sealed record.
func (s *Server) respondFinalized(w http.ResponseWriter, projectID, grantID, sealed string, created bool) {
	capability, err := s.reconstructCapability(projectID, grantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "reconstruct capability: "+err.Error())
		return
	}
	exp, scopeClass, perr := storedGrantFields(sealed)
	if perr != nil {
		writeErr(w, http.StatusInternalServerError, perr.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"grant_id":    grantID,
		"capability":  capability,
		"expires_at":  ts(time.Unix(exp, 0)),
		"scope_class": scopeClass,
		"created":     created,
		"record":      json.RawMessage(sealed),
	})
}
