package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/feir-dev/feir/server/internal/store"
)

// WithRevocation enables M5 revocation (ADR 0005): POST /v2/revoke records a grant_id as revoked, and every
// /v2/export carries a signed, time-bounded `revocation_list` over the project's revoked set (the offline
// verifier then blocks any use — brokered OR native — of a revoked grant). `revKey` is the revocation authority
// key; it MUST be role-separated from the broker (issuing + recording), resource, and attestation keys — the
// verifier rejects an overlap as a FATAL config error, so we fail-fast here (a key collision is a programming
// error → panic). The revoked set is in-memory (Phase-1; a production deployment persists it).
func (s *Server) WithRevocation(revKey ed25519.PrivateKey) *Server {
	pub := revKey.Public().(ed25519.PublicKey)
	collides := func(other string) bool {
		if k, err := decodePubKey(other); err == nil {
			return bytes.Equal(pub, k)
		}
		return false
	}
	if collides(s.core.PubKey()) {
		panic("WithRevocation: the revocation key must be role-separated from the broker recording/signing key (R2)")
	}
	if s.brokerKey != nil && bytes.Equal(pub, s.brokerKey.Public().(ed25519.PublicKey)) {
		panic("WithRevocation: the revocation key must be role-separated from the broker issuing key (R2)")
	}
	if s.resourceCore != nil && collides(s.resourceCore.PubKey()) {
		panic("WithRevocation: the revocation key must be role-separated from the resource recording key (R2)")
	}
	if s.attestKey != nil && bytes.Equal(pub, s.attestKey.Public().(ed25519.PublicKey)) {
		panic("WithRevocation: the revocation key must be role-separated from the attestation key (R2)")
	}
	// M6: also disjoint from every pinned cosig approver (the verifier rejects a revocation×cosig overlap as
	// fatal). The TSA key is held by an EXTERNAL RFC3161 service, not this server, so it cannot be checked here —
	// the verifier enforces the revocation×tsa disjointness against the auditor-pinned tsa_keys.
	for _, ap := range s.cosigApprovers {
		if bytes.Equal(pub, ap) {
			panic("WithRevocation: the revocation key must be role-separated from every cosig approver key (R2)")
		}
	}
	s.revocationKey = revKey
	s.revoked = map[string]map[string]struct{}{}
	if s.revocationValidity == 0 {
		s.revocationValidity = 7 * 24 * time.Hour // how long a revocation_list is honored past the bundle's anchor
	}
	return s
}

// revokeRequest is the POST /v2/revoke wire shape.
type revokeRequest struct {
	ProjectID string `json:"project_id"`
	GrantID   string `json:"grant_id"`
	Reason    string `json:"reason"` // optional, audit-only (not bound into the list)
}

// handleRevoke marks a grant_id revoked for a project (M5). Idempotent. The revocation takes effect in the NEXT
// export's signed revocation_list — the verifier blocks any use of the revoked grant once that list is fresh.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if s.revocationKey == nil {
		writeErr(w, http.StatusNotImplemented, "revocation not enabled (set FEIR_REVOCATION_SEED)")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var rr revokeRequest
	if err := decode(body, &rr); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid revoke request: "+err.Error())
		return
	}
	if qp := r.URL.Query().Get("project"); qp != "" && rr.ProjectID != qp {
		writeErr(w, http.StatusForbidden, "project_id does not match the authorized ?project=")
		return
	}
	if rr.ProjectID == "" || rr.GrantID == "" {
		writeErr(w, http.StatusBadRequest, "project_id and grant_id are required")
		return
	}
	s.revokedMu.Lock()
	set := s.revoked[rr.ProjectID]
	if set == nil {
		set = map[string]struct{}{}
		s.revoked[rr.ProjectID] = set
	}
	set[rr.GrantID] = struct{}{}
	n := len(set)
	s.revokedMu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]any{
		"revoked":       rr.GrantID,
		"project_id":    rr.ProjectID,
		"revoked_total": n,
		"note":          "takes effect in the next /v2/export's signed revocation_list",
	})
}

// buildRevocationListForExport produces the signed revocation_list for a project's revoked set, with a freshness
// window anchored to the latest checkpoint's created_ts (the same basis the deployment_attestation uses), so the
// verifier reads it `fresh` for THIS bundle and `stale` for a much-later one. Returns nil when nothing is revoked.
func (s *Server) buildRevocationListForExport(projectID string, checks []store.Checkpoint) (map[string]any, error) {
	s.revokedMu.Lock()
	set := s.revoked[projectID]
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	s.revokedMu.Unlock()
	if len(ids) == 0 {
		return nil, nil
	}
	sort.Strings(ids) // deterministic order (the list is canonicalized + signed)

	createdTS := ""
	if len(checks) > 0 {
		var cp struct {
			CreatedTS string `json:"created_ts"`
		}
		if err := json.Unmarshal([]byte(checks[len(checks)-1].JSON), &cp); err == nil {
			createdTS = cp.CreatedTS
		}
	}
	issuedAt, notAfter := attestationWindow(createdTS, s.now(), time.Hour, s.revocationValidity)
	return BuildRevocationList(s.core, s.revocationKey, issuedAt, notAfter, ids)
}
