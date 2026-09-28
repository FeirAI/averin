package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/feirai/averin/server/internal/broker"
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

// WithRevocationExportV2 selects the plan 009 export format: every /v2/export carries a signed
// `averin.revocation.list.v2` (per-grant mode and cutoff, plus the database snapshot boundary time
// and authorization high watermark), and POST /v2/revoke accepts mode "prospective". Roll out
// reader-first: a legacy verifier rejects a v2 list instead of misreading it, so enable this only
// after every relying verifier understands v2. Without it no prospective revocation is accepted,
// because a v1 list can only state total revocations.
func (s *Server) WithRevocationExportV2() *Server {
	s.revocationExportV2 = true
	return s
}

// revokeRequest is the POST /v2/revoke wire shape.
type revokeRequest struct {
	ProjectID string `json:"project_id"`
	GrantID   string `json:"grant_id"`
	// Mode is "total" (default: compromise, every use invalid) or "prospective" (cancellation
	// effective at the next authorization ordinal; requires the v2 export).
	Mode   string `json:"mode"`
	Reason string `json:"reason"` // optional, recorded with the immutable event
}

// maxRevocationReasonBytes bounds the stored, unsigned reason text.
const maxRevocationReasonBytes = 512

// handleRevoke records an immutable revocation event (M5, plan 009). Idempotent per (grant, mode):
// a retried prospective revocation returns its original cutoff, never a later one. The resource
// gateway rejects any later /v2/use[-intent] and introspection of the grant immediately (any mode),
// and the NEXT export carries it in the signed revocation_list.
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
	if err := s.rejectOpaqueIdentity("project_id", rr.ProjectID, "grant_id", rr.GrantID); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := rr.Mode
	if mode == "" {
		mode = store.RevocationTotal
	}
	switch mode {
	case store.RevocationTotal:
	case store.RevocationProspective:
		if !s.revocationExportV2 {
			writeErr(w, http.StatusBadRequest, "prospective revocation requires the v2 revocation export (AVERIN_REVOCATION_EXPORT_FORMAT=v2); a v1 revocation_list can only state total revocations")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, `mode must be "total" or "prospective"`)
		return
	}
	if len(rr.Reason) > maxRevocationReasonBytes {
		writeErr(w, http.StatusBadRequest, "reason is too long")
		return
	}
	// Revocation is intentionally PERMISSIVE by grant_id: we do NOT require the id to already exist in this
	// server's store. The primitive is "block any use of this id," and an operator must be able to revoke a
	// compromised id preemptively (or a federated grant minted by a peer broker) that this instance has not yet
	// observed. Gating on existence would turn a security action into a fail-open ("unknown grant_id" read as
	// "nothing to worry about"). Abuse is bounded by auth (project-scoped) + the per-project size cap below.
	reason := rr.Reason
	if reason == "" {
		reason = mode
	}
	res, code, msg := s.revokeGrantEvent(r.Context(), store.RevocationEvent{
		ProjectID: rr.ProjectID, GrantID: rr.GrantID, Mode: mode,
		Issuer: broker.KeyID(s.revocationKey.Public().(ed25519.PublicKey)), Reason: reason,
	})
	if msg != "" {
		writeErr(w, code, msg)
		return
	}
	out := map[string]any{
		"revoked":       rr.GrantID,
		"project_id":    rr.ProjectID,
		"mode":          res.effective.Mode,
		"created":       res.created,
		"revoked_total": res.total,
		"note":          "enforced at /v2/use immediately; carried in the next /v2/export's signed revocation_list",
	}
	if res.effective.Mode == store.RevocationProspective {
		out["cutoff_order"] = res.effective.CutoffOrder
	}
	writeJSON(w, http.StatusCreated, out)
}

type revokeResult struct {
	effective store.RevocationEvent // the grant's combined state: any total wins, else the event's cutoff
	created   bool
	total     int
}

// revokeGrantID records a total revocation (used by legacy callers and tests). msg == "" on success;
// otherwise code/msg are the HTTP error to surface.
func (s *Server) revokeGrantID(projectID, grantID string) (code int, msg string) {
	_, code, msg = s.revokeGrantIDTotal(projectID, grantID)
	return code, msg
}

// revokeGrantIDTotal is revokeGrantID that also returns the project's revoked-set size after the call.
func (s *Server) revokeGrantIDTotal(projectID, grantID string) (total, code int, msg string) {
	res, code, msg := s.revokeGrantEvent(context.Background(), store.RevocationEvent{
		ProjectID: projectID, GrantID: grantID, Mode: store.RevocationTotal, Issuer: "averin", Reason: store.RevocationTotal,
	})
	return res.total, code, msg
}

func (s *Server) revokeGrantEvent(ctx context.Context, ev store.RevocationEvent) (res revokeResult, code int, msg string) {
	// The guard serializes the cap check, the cutoff allocation and the insert across every replica.
	err := s.withProjectWrite(ctx, ev.ProjectID, func(st store.Store) error {
		ids, err := st.RevokedGrantIDs(ev.ProjectID)
		if err != nil {
			return err
		}
		known := false
		for _, id := range ids {
			if id == ev.GrantID {
				known = true
				break
			}
		}
		if !known && len(ids) >= s.revocationCap {
			code = http.StatusTooManyRequests
			return errRevocationCap
		}
		stored, created, err := st.PutRevocationEvent(ev)
		if err != nil {
			return err
		}
		res.created, res.effective = created, stored
		// Report the combined state: a total event for the grant overrides any cutoff.
		events, err := st.RevocationEvents(ev.ProjectID)
		if err != nil {
			return err
		}
		for _, e := range events {
			if e.GrantID == ev.GrantID && e.Mode == store.RevocationTotal {
				res.effective = e
			}
		}
		res.total = len(ids)
		if !known {
			res.total++
		}
		return nil
	})
	if err != nil {
		if code == http.StatusTooManyRequests {
			return revokeResult{}, code, "the project's revoked-grant set is at capacity; this revocation did not take effect"
		}
		return revokeResult{}, http.StatusServiceUnavailable, "revocation could not be durably persisted: " + err.Error()
	}
	// Retain the local cache only for legacy introspection; admission and export
	// consult the transaction-bound durable state instead.
	s.revokedMu.Lock()
	set := s.revoked[ev.ProjectID]
	next := make(map[string]struct{}, len(set)+1)
	for id := range set {
		next[id] = struct{}{}
	}
	next[ev.GrantID] = struct{}{}
	s.revoked[ev.ProjectID] = next
	s.revokedMu.Unlock()
	return res, 0, ""
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

// revocationWindow is the legacy freshness window both list formats carry, anchored to the latest
// checkpoint's created_ts (the same basis the deployment_attestation uses), so the verifier reads it
// `fresh` for THIS bundle and `stale` for a much-later one.
func (s *Server) revocationWindow(checks []store.Checkpoint) (issuedAt, notAfter string) {
	createdTS := ""
	if len(checks) > 0 {
		var cp struct {
			CreatedTS string `json:"created_ts"`
		}
		if err := json.Unmarshal([]byte(checks[len(checks)-1].JSON), &cp); err == nil {
			createdTS = cp.CreatedTS
		}
	}
	return attestationWindow(createdTS, s.now(), time.Hour, s.revocationValidity)
}

// buildRevocationListForExportEvents produces the signed revocation_list from the events, boundary
// time and watermark read in ONE repeatable-read project snapshot. It signs exactly those captured
// values; no later wall-clock time replaces the boundary. Never nil: an empty set is still a signed,
// dated statement (a verifier pinning the key reads a missing list as `missing`).
func (s *Server) buildRevocationListForExportEvents(projectID string, events []store.RevocationEvent, boundary time.Time, watermark int64, checks []store.Checkpoint) (map[string]any, error) {
	issuedAt, notAfter := s.revocationWindow(checks)
	entries := CombineRevocationEvents(events)
	if s.revocationExportV2 {
		return BuildRevocationListV2(s.core, s.revocationKey, issuedAt, notAfter,
			RevocationSnapshot{ProjectID: projectID, BoundaryTime: boundary, Watermark: watermark}, entries)
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		// Any v1 membership is total, even for a temporal verifier. A prospective revocation must
		// never be emitted as a v1 id, and silently omitting it would un-revoke it: refuse.
		if e.Mode != store.RevocationTotal {
			return nil, fmt.Errorf("revocation_list: grant %q has a prospective revocation, which the v1 export cannot represent; enable the v2 revocation export", e.GrantID)
		}
		ids = append(ids, e.GrantID)
	}
	return s.buildRevocationListForExportIDs(ids, checks)
}

func (s *Server) buildRevocationListForExportIDs(ids []string, checks []store.Checkpoint) (map[string]any, error) {
	sort.Strings(ids) // deterministic order (the list is canonicalized + signed)
	issuedAt, notAfter := s.revocationWindow(checks)
	return BuildRevocationList(s.core, s.revocationKey, issuedAt, notAfter, ids)
}
