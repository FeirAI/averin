package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"log"
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
// error → panic). The revoked set is the in-memory READ cache; it starts empty here and, when a durable store
// is configured (AVERIN_DATABASE_URL), is rehydrated from Postgres by a subsequent WithDurable call — see there.
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
	// Revocation is intentionally PERMISSIVE by grant_id: we do NOT require the id to already exist in this
	// server's store. The primitive is "block any use of this id," and an operator must be able to revoke a
	// compromised id preemptively (or a federated grant minted by a peer broker) that this instance has not yet
	// observed. Gating on existence would turn a security action into a fail-open ("unknown grant_id" read as
	// "nothing to worry about"). Abuse is bounded by auth (project-scoped) + the per-project size cap below.

	// Serialize per-project across the cap-check-then-persist-then-publish critical section below (finding C):
	// a slow/degraded Postgres round-trip inside Revoke then only blocks another revoke racing for THIS SAME
	// project, not every /v2/revoke on the process. Different projects run fully concurrently under this lock.
	// Readers (isRevoked, buildRevocationListForExport) never take it: they read the published immutable set.
	unlock := s.revokeLocks.Lock(rr.ProjectID)
	defer unlock()

	// Snapshot this project's CURRENT published set (immutable — never written after publication). Only
	// revokedMu is taken, and only for the pointer read.
	s.revokedMu.Lock()
	set := s.revoked[rr.ProjectID]
	s.revokedMu.Unlock()

	// Bound the in-memory set so a caller cannot flood it with fabricated grant_ids (unbounded memory + export
	// bloat). A NEW id past the cap is rejected; re-revoking an existing id is always allowed (idempotent). The
	// rejection is EXPLICIT (429, never a silent drop) so the operator attempting a legitimate revocation knows it
	// did not take effect and can act (raise the cap / restart / investigate a flood) — eviction or expiry is NOT
	// an option here: dropping an id would silently UN-revoke that grant (a fail-open), since revocation is
	// monotone-add. A throttled server-side WARNING also surfaces exhaustion to monitoring.
	_, exists := set[rr.GrantID]
	if !exists && len(set) >= maxRevokedPerProject {
		// revokeCapWarnAt throttles this WARNING across ALL projects (not just this one), so its read+update
		// must stay synchronized independent of the per-project revokeLocks above — revokedMu (brief, global)
		// does that.
		now := s.now()
		s.revokedMu.Lock()
		shouldWarn := now.Sub(s.revokeCapWarnAt) > time.Minute
		if shouldWarn {
			s.revokeCapWarnAt = now
		}
		s.revokedMu.Unlock()
		if shouldWarn {
			log.Printf("WARNING: project %q revoked-grant set is at capacity (%d) — NEW revocations are being REJECTED until the cap is raised or the set is persisted/pruned; this log is throttled to ~1/min", rr.ProjectID, maxRevokedPerProject)
		}
		writeErr(w, http.StatusTooManyRequests, "the project's revoked-grant set is at capacity — raise the cap or persist/prune the set; this revocation did NOT take effect")
		return
	}
	// Persist-then-serve, fail-closed: when a durable store is configured, a NEW revocation must be durable
	// BEFORE it is added to the in-memory set (and thus before it can appear in a signed export) — otherwise a
	// restart right after this response would silently un-revoke it while the caller believes it took effect.
	// Skipped for an already-revoked id: it was durably persisted the first time (or the durable store was not
	// yet configured then, in which case there is nothing to reconcile here — an operator adding
	// AVERIN_DATABASE_URL to an already-running deployment should re-issue any revokes made before that point).
	if !exists && s.durable != nil {
		if err := s.durable.Revoke(rr.ProjectID, rr.GrantID); err != nil {
			log.Printf("ERROR: durable revocation persist failed for project %q grant %q: %v", rr.ProjectID, rr.GrantID, err)
			writeErr(w, http.StatusServiceUnavailable, "revocation could not be durably persisted — NOT applied (fail-closed): "+err.Error())
			return
		}
	}
	// Copy-on-write publish: build old ∪ {id} and swap it in under revokedMu, so a concurrent reader sees either
	// the old or the new set, never a map being written. The publish happens BEFORE the 201, so a revoke that has
	// returned is always observed by the next /v2/use. (An idempotent re-revoke publishes nothing.)
	n := len(set)
	if !exists {
		next := make(map[string]struct{}, len(set)+1)
		for id := range set {
			next[id] = struct{}{}
		}
		next[rr.GrantID] = struct{}{}
		s.revokedMu.Lock()
		s.revoked[rr.ProjectID] = next
		s.revokedMu.Unlock()
		n = len(next)
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"revoked":       rr.GrantID,
		"project_id":    rr.ProjectID,
		"revoked_total": n,
		"note":          "enforced at /v2/use immediately; carried in the next /v2/export's signed revocation_list",
	})
}

// isRevoked reports whether grantID is in the project's revoked set. It reads the published IMMUTABLE snapshot
// under revokedMu only — never revokeLocks, which handleRevoke holds across the durable Postgres write. It is
// called from the use path under the process-wide ingestMu, so waiting on a slow revoke here would stall every
// record/grant/use/checkpoint on the process. A revoke that has returned 201 has already published its set.
func (s *Server) isRevoked(projectID, grantID string) bool {
	s.revokedMu.Lock()
	set := s.revoked[projectID]
	s.revokedMu.Unlock()
	_, revoked := set[grantID]
	return revoked
}

// buildRevocationListForExport produces the signed revocation_list for a project's revoked set, with a freshness
// window anchored to the latest checkpoint's created_ts (the same basis the deployment_attestation uses), so the
// verifier reads it `fresh` for THIS bundle and `stale` for a much-later one. Returns nil when nothing is revoked.
func (s *Server) buildRevocationListForExport(projectID string, checks []store.Checkpoint) (map[string]any, error) {
	// Read the published immutable snapshot (copy-on-write, see handleRevoke): ranging it needs no lock.
	s.revokedMu.Lock()
	set := s.revoked[projectID]
	s.revokedMu.Unlock()
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
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
