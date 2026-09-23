package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/feirai/averin/server/internal/store"
)

// WithRevocation enables M5 revocation (ADR 0005): POST /v2/revoke records a grant_id as revoked, and every
// /v2/export carries a signed, time-bounded `revocation_list` over the project's revoked set (the offline
// verifier then blocks any use — brokered OR native — of a revoked grant). `revKey` is the revocation authority
// key; it MUST be role-separated from the broker (issuing + recording), resource, and attestation keys — the
// verifier rejects an overlap as a FATAL config error, so we fail-fast here (a key collision is a programming
// error → panic). The in-memory revoked set is a diagnostic cache. Request admission and export read
// the project Store's committed state, including revocations made on other replicas.
func (s *Server) WithRevocation(revKey ed25519.PrivateKey) *Server {
	// Ordering guard (prevents a future fail-open): WithDurable rehydrates the revoked set from Postgres only
	// `if s.revocationKey != nil` (see durable.go), so it must run AFTER this method. If a durable store is
	// ALREADY attached here (s.durable != nil), WithDurable ran first — either revocation was never going to be
	// enabled (fine, nothing to clobber) or, as here, it's being wired now, in which case the `s.revoked = ...`
	// reset two lines below would silently DISCARD whatever WithDurable already rehydrated, leaving an operator
	// believing a durably-revoked grant is enforced when the in-memory set has quietly gone back to empty. That
	// is a programming/wiring error, so fail fast rather than silently mis-wire — same posture as the R2
	// role-separation panics below.
	if s.durable != nil {
		panic("WithRevocation: must be called BEFORE WithDurable — a durable store is already attached, so resetting the revoked set here would silently discard whatever WithDurable already rehydrated from Postgres")
	}
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

// maxRevokedPerProject bounds the in-memory revoked set per project. A revocation_list is signed + exported in
// full each time, so an unbounded set is both a memory and an export-size amplification vector. 100k revoked
// grants per project is far past any realistic operational need while still capping abuse.
const maxRevokedPerProject = 100_000

// revokeRequest is the POST /v2/revoke wire shape.
type revokeRequest struct {
	ProjectID string `json:"project_id"`
	GrantID   string `json:"grant_id"`
	Reason    string `json:"reason"` // optional, audit-only (not bound into the list)
}

// handleRevoke marks a grant_id revoked for a project (M5). Idempotent. The resource gateway rejects any later
// /v2/use[-intent] of the grant immediately (isRevoked, before consuming), and the NEXT export carries it in the
// signed revocation_list — the verifier blocks any use of the revoked grant once that list is fresh.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if s.revocationKey == nil {
		writeErr(w, http.StatusNotImplemented, "revocation not enabled (set AVERIN_REVOCATION_SEED)")
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
	if err := rejectNUL("project_id", rr.ProjectID, "grant_id", rr.GrantID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Revocation is intentionally PERMISSIVE by grant_id: we do NOT require the id to already exist in this
	// server's store. The primitive is "block any use of this id," and an operator must be able to revoke a
	// compromised id preemptively (or a federated grant minted by a peer broker) that this instance has not yet
	// observed. Gating on existence would turn a security action into a fail-open ("unknown grant_id" read as
	// "nothing to worry about"). Abuse is bounded by auth (project-scoped) + the per-project size cap below.

	n, code, msg := s.revokeGrantIDTotalCtx(r.Context(), rr.ProjectID, rr.GrantID)
	if msg != "" {
		writeErr(w, code, msg)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"revoked":       rr.GrantID,
		"project_id":    rr.ProjectID,
		"revoked_total": n,
		"note":          "enforced at /v2/use immediately; carried in the next /v2/export's signed revocation_list",
	})
}

// revokeGrantID revokes grantID in projectID (the handleRevoke core, also used by the broker_seq void to retire a
// voided grant's capability). msg == "" on success; otherwise code/msg are the HTTP error to surface.
func (s *Server) revokeGrantID(projectID, grantID string) (code int, msg string) {
	_, code, msg = s.revokeGrantIDTotal(projectID, grantID)
	return code, msg
}

// revokeGrantIDTotal is revokeGrantID that also returns the project's revoked-set size after the call.
func (s *Server) revokeGrantIDTotal(projectID, grantID string) (total, code int, msg string) {
	return s.revokeGrantIDTotalCtx(context.Background(), projectID, grantID)
}

func (s *Server) revokeGrantIDTotalCtx(ctx context.Context, projectID, grantID string) (total, code int, msg string) {
	// The guard serializes the cap check and insert across every replica.
	err := s.withProjectWrite(ctx, projectID, func(st store.Store) error {
		ids, err := st.RevokedGrantIDs(projectID)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if id == grantID {
				total = len(ids)
				return nil
			}
		}
		if len(ids) >= s.revocationCap {
			code = http.StatusTooManyRequests
			return errRevocationCap
		}
		if _, err := st.RevokeGrant(projectID, grantID); err != nil {
			return err
		}
		total = len(ids) + 1
		return nil
	})
	if err != nil {
		if code == http.StatusTooManyRequests {
			return 0, code, "the project's revoked-grant set is at capacity; this revocation did not take effect"
		}
		return 0, http.StatusServiceUnavailable, "revocation could not be durably persisted: " + err.Error()
	}
	// Retain the local cache only for legacy introspection; admission and export
	// consult the transaction-bound durable state instead.
	s.revokedMu.Lock()
	set := s.revoked[projectID]
	next := make(map[string]struct{}, len(set)+1)
	for id := range set {
		next[id] = struct{}{}
	}
	next[grantID] = struct{}{}
	s.revoked[projectID] = next
	s.revokedMu.Unlock()
	return total, 0, ""
}

var errRevocationCap = errors.New("revocation capacity reached")

// isRevoked reads the legacy diagnostic cache. Authorization uses Store.IsRevoked
// inside a project transaction so another replica's committed revoke is visible.
func (s *Server) isRevoked(projectID, grantID string) bool {
	s.revokedMu.Lock()
	set := s.revoked[projectID]
	s.revokedMu.Unlock()
	_, revoked := set[grantID]
	return revoked
}

// buildRevocationListForExport produces the signed revocation_list for a project's revoked set, with a freshness
// window anchored to the latest checkpoint's created_ts (the same basis the deployment_attestation uses), so the
// verifier reads it `fresh` for THIS bundle and `stale` for a much-later one. Never nil: an empty revoked set
// yields a signed list with `revoked_grant_ids: []`.
func (s *Server) buildRevocationListForExport(projectID string, checks []store.Checkpoint) (map[string]any, error) {
	// Read the published immutable snapshot (copy-on-write, see handleRevoke): ranging it needs no lock.
	s.revokedMu.Lock()
	set := s.revoked[projectID]
	s.revokedMu.Unlock()
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	// An EMPTY list is still emitted (and signed): with a revocation key pinned, the verifier reads a bundle with
	// no revocation evidence as `missing` (a stripped list must not read as a clean `absent`), so "nothing is
	// revoked" has to be an affirmative, signed, dated statement — otherwise every export of a deployment with
	// revocation configured and zero revocations would be blocked from the capstone.
	return s.buildRevocationListForExportIDs(ids, checks)
}

func (s *Server) buildRevocationListForExportIDs(ids []string, checks []store.Checkpoint) (map[string]any, error) {
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
