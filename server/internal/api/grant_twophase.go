package api

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/feir-dev/feir/server/internal/broker"
)

// pendingGrant is a minted-but-uncommitted grant held between /v2/grants/prepare and /v2/grants/finalize.
// It carries NO committed broker_seq — that is allocated at finalize (see handleGrantFinalize).
type pendingGrant struct {
	prepared broker.Prepared
	req      broker.Request
	gr       grantRequest
	created  time.Time
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
		AgentID:         gr.AgentID,
		Action:          gr.Action,
		Resource:        gr.Resource,
		Scope:           gr.Scope,
		ScopeClass:      broker.ScopeClass(gr.ScopeClass),
		UseLimit:        gr.UseLimit,
		AgentPubKey:     gr.AgentPubKey,
		AgentSig:        gr.AgentSig,
		Principal:       gr.Principal,
		DelegationChain: gr.DelegationChain,
		Justification:   gr.Justification,
		TTL:             time.Duration(gr.TTLSeconds) * time.Second,
	}
}

// grantIdem resolves the idempotency key from the body field or the Idempotency-Key header.
func grantIdem(gr grantRequest, r *http.Request) string {
	if gr.IdempotencyKey != "" {
		return gr.IdempotencyKey
	}
	return r.Header.Get("Idempotency-Key")
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

// prunePending drops pending grants older than pendingTTL (an abandoned prepare must not leak memory). The
// caller holds pendingMu.
func (s *Server) prunePending(now time.Time) {
	for k, p := range s.pending {
		if now.Sub(p.created) > pendingTTL {
			delete(s.pending, k)
		}
	}
}

// handleGrantPrepare is PHASE 1 of the online two-phase grant flow (ADR 0005 M6 Cosig / M2 Delegation): it
// validates the request and MINTS the credential (broker.Prepare) WITHOUT allocating a broker_seq or committing,
// holds it in `pending`, and reveals the challenge inputs the approvers/delegators must sign — grant_id,
// credential_binding, exp, cnf_kid. A retry returns the SAME challenge (the pending state fixes the minted
// descriptor, so the revealed credential_binding/exp are stable). If the grant is already finalized, returns it.
func (s *Server) handleGrantPrepare(w http.ResponseWriter, r *http.Request) {
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
	if qp := r.URL.Query().Get("project"); qp != "" && gr.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if gr.ProjectID == "" || gr.SessionID == "" {
		writeErr(w, http.StatusBadRequest, "project_id and session_id are required")
		return
	}
	idem := grantIdem(gr, r)
	if idem == "" {
		writeErr(w, http.StatusBadRequest, "idempotency_key is required (field or Idempotency-Key header) so a retry cannot double-issue a credential")
		return
	}
	if reservedIdem(idem) {
		writeErr(w, http.StatusBadRequest, "idempotency_key prefix \"denial:\" is reserved for the broker denied-grant log")
		return
	}
	grantID := deterministicGrantID(gr.ProjectID, idem)

	// Already finalized? (a prepare after a completed finalize) — return the committed grant, idempotently.
	if existing, found, le := s.st.RecordByIdem(gr.ProjectID, idem); le == nil && found {
		s.respondPreparedFromSealed(w, grantID, existing.JSON, true)
		return
	}

	req := grantRequestToBroker(gr)
	req.BrokerID = s.brokerID // M4: tag the grant with this broker's federation id ("" = single-broker)
	// Validate proof-of-possession + scope BEFORE minting (same gate as the single-phase /v2/grants).
	if e := req.Validate(); e != nil {
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}
	if _, e := broker.ClassifyScope(req.Scope, req.ScopeClass); e != nil {
		writeErr(w, http.StatusBadRequest, e.Error())
		return
	}

	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.prunePending(s.now())
	pk := pendingKey(gr.ProjectID, idem)
	// Idempotent prepare: an already-pending mint returns the SAME challenge (stable credential_binding/exp).
	p, ok := s.pending[pk]
	if !ok {
		// Mint WITHOUT a real broker_seq (the dummy 1 just satisfies Prepare's seq>=1 validation; it is
		// OVERWRITTEN with the gapless seq at finalize, so the seq order == the record commit order, D6).
		prepared, e := broker.Prepare(req, grantID, func() (int64, error) { return 1, nil }, s.now(), s.brokerKey)
		if e != nil {
			writeErr(w, http.StatusBadRequest, e.Error())
			return
		}
		p = &pendingGrant{prepared: prepared, req: req, gr: gr, created: s.now()}
		s.pending[pk] = p
	}
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

// grantFinalizeRequest is the POST /v2/grants/finalize wire shape (ADR 0005 M6/M2).
type grantFinalizeRequest struct {
	IdempotencyKey string                 `json:"idempotency_key"`
	ProjectID      string                 `json:"project_id"`
	SessionID      string                 `json:"session_id"`
	Cosignatures   []broker.Cosignature   `json:"cosignatures"`    // M6: collected over CosigApprovalChallenge
	DelegationHops []broker.DelegationHop `json:"delegation_hops"` // M2: collected over DelegationHopChallenge
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
	if qp := r.URL.Query().Get("project"); qp != "" && fr.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	idem := fr.IdempotencyKey
	if idem == "" {
		idem = r.Header.Get("Idempotency-Key")
	}
	if fr.ProjectID == "" || idem == "" {
		writeErr(w, http.StatusBadRequest, "project_id and idempotency_key are required")
		return
	}
	grantID := deterministicGrantID(fr.ProjectID, idem)

	// Idempotent re-finalize: the grant already committed — return it (do NOT re-allocate a seq).
	if existing, found, le := s.st.RecordByIdem(fr.ProjectID, idem); le == nil && found {
		s.respondFinalized(w, fr.ProjectID, grantID, existing.JSON, false)
		return
	}

	s.pendingMu.Lock()
	pk := pendingKey(fr.ProjectID, idem)
	p, ok := s.pending[pk]
	s.pendingMu.Unlock()
	if !ok {
		writeErr(w, http.StatusConflict, "no pending grant for this idempotency_key — call /v2/grants/prepare first (or it expired / the server restarted)")
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

	// Commit under the ingest lock: allocate the gapless broker_seq HERE (so seq order == commit order, D6),
	// overwrite the placeholder seq in the signed grant_evidence, build + seal + store. Mirrors handleGrant's
	// commit-ambiguity handling (a store error leaves the seq RESERVED, never released, so a retry reclaims it).
	sessionID := p.gr.SessionID
	var sealed string
	var created bool
	commitErr := func() error {
		s.ingestMu.Lock()
		defer s.ingestMu.Unlock()
		seq, aerr := s.st.AllocateBrokerSeq(fr.ProjectID, grantID)
		if aerr != nil {
			return fmt.Errorf("allocate broker_seq: %w", aerr)
		}
		if seq < 1 {
			return fmt.Errorf("store returned non-positive broker_seq %d", seq)
		}
		prepared.Evidence["broker_seq"] = seq // OVERWRITE the prepare-time placeholder with the real gapless seq
		rec, disclosures, e := s.buildGrantRecord(grantID, p.gr, p.req, prepared)
		if e != nil {
			return e
		}
		var se error
		sealed, created, se = s.sealAndStore(fr.ProjectID, sessionID, idem, rec, disclosures)
		if se != nil {
			if r2, found2, re := s.st.RecordByIdem(fr.ProjectID, idem); re == nil && found2 {
				sealed, created = r2.JSON, false
				return nil
			}
			return fmt.Errorf("%w — broker_seq left RESERVED (commit-ambiguous; a retry of this finalize reclaims it)", se)
		}
		return nil
	}()
	if commitErr != nil {
		writeErr(w, http.StatusInternalServerError, "finalize grant: "+commitErr.Error())
		return
	}

	// Committed — drop the pending entry (a re-finalize now hits the idempotent RecordByIdem path above).
	s.pendingMu.Lock()
	delete(s.pending, pk)
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
