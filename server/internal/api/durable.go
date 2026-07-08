package api

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/averin-dev/averin/server/internal/broker"
	"github.com/averin-dev/averin/server/internal/pgdurable"
)

// WithDurable backs the M5 revoked-grant set and the M6/M2 pending two-phase grant state with Postgres
// (server/cmd/averin-server/main.go wires this in only when AVERIN_DATABASE_URL is set). It rehydrates
// both in-memory caches from pd IMMEDIATELY, so it must be called AFTER WithRevocation (which resets
// `revoked` to a fresh, empty map) — calling it before WithRevocation would have the rehydrated set
// silently discarded. Revocation is itself optional (nil s.revocationKey is a legitimate, documented,
// tested standalone configuration — durable two-phase grants with revocation never enabled at all — so
// this method cannot fail-fast on that by itself); the ordering IS enforced, defensively, on the other
// side: WithRevocation panics if s.durable is already non-nil, so a future refactor that reorders the two
// calls (with revocation actually intended) fails loudly at boot instead of silently discarding a
// rehydrated revoked set — see the guard at the top of WithRevocation in revocation_server.go. `pending`
// is always initialized by New(), so ordering relative to WithBroker / WithCosigPolicy does not matter for
// it. A rehydrate failure here is FATAL (log.Fatalf): starting with a silently-empty revoked set or
// pending map would be a fail-open, not a degraded-but-safe start.
func (s *Server) WithDurable(pd *pgdurable.Store) *Server {
	s.durable = pd
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if s.revocationKey != nil {
		revoked, err := pd.LoadRevocations(ctx)
		if err != nil {
			log.Fatalf("durable revocation: rehydrate: %v", err)
		}
		if revoked == nil {
			revoked = map[string]map[string]struct{}{}
		}
		s.revokedMu.Lock()
		s.revoked = revoked
		n := len(s.revoked)
		s.revokedMu.Unlock()
		log.Printf("revocation: rehydrated %d project(s) worth of revoked-grant set(s) from Postgres", n)
	}

	rows, err := pd.LoadPending(ctx)
	if err != nil {
		log.Fatalf("durable two-phase grants: rehydrate: %v", err)
	}
	now := s.now()
	loaded := 0
	s.pendingMu.Lock()
	for _, row := range rows {
		if now.Sub(row.Created) > pendingTTL {
			// Expired — best-effort prune from Postgres too so it does not linger forever; harmless if this
			// fails (LoadPending would just re-see it and re-skip it next boot).
			if derr := pd.DeletePending(row.ProjectID, row.IdemKey); derr != nil {
				log.Printf("WARNING: durable two-phase grants: prune expired pending row (project=%q idem=%q): %v", row.ProjectID, row.IdemKey, derr)
			}
			continue
		}
		var dto pendingGrantDTO
		if uerr := json.Unmarshal(row.Payload, &dto); uerr != nil {
			// A row we cannot parse is not safe to serve (a caller relying on the fields would misbehave), but
			// it is also not a reason to refuse to boot — log it loudly and skip; a re-prepare from the client
			// mints a fresh one. This should not happen outside a schema/format mismatch.
			log.Printf("WARNING: durable two-phase grants: skipping unparseable pending row (project=%q idem=%q): %v", row.ProjectID, row.IdemKey, uerr)
			continue
		}
		s.pending[pendingKey(row.ProjectID, row.IdemKey)] = dto.toPendingGrant(row.IdemKey)
		loaded++
	}
	s.pendingMu.Unlock()
	log.Printf("two-phase grants: rehydrated %d pending grant(s) from Postgres", loaded)

	return s
}

// pendingGrantDTO is the JSON-serializable form of pendingGrant, persisted as the `payload` column of
// pending_grants. pendingGrant's fields are unexported (encoding/json only marshals exported fields), so
// this mirrors them with exported names; every field of broker.Prepared/broker.Request/grantRequest is
// already exported, so round-tripping them is a straight copy.
type pendingGrantDTO struct {
	Prepared broker.Prepared `json:"prepared"`
	Req      broker.Request  `json:"req"`
	GR       grantRequest    `json:"gr"`
	Created  time.Time       `json:"created"`
}

// dtoFromPending converts a pendingGrant to its durable JSON form.
func dtoFromPending(p *pendingGrant) pendingGrantDTO {
	return pendingGrantDTO{Prepared: p.prepared, Req: p.req, GR: p.gr, Created: p.created}
}

// toPendingGrant converts a rehydrated DTO back to a pendingGrant. idemKey comes from the row (not the
// payload) since pendingGrant does not itself carry it — the pendingKey(projectID, idemKey) map key does.
//
// evidenceIntKeys repairs a JSON round-trip footgun: broker.Prepared.Evidence is a map[string]any, and
// encoding/json decodes every JSON number in a map[string]any as float64 — never int64 — regardless of
// what was marshaled. broker.AttachCosignatures hard-requires Evidence["exp"].(int64) (server/internal/
// broker/cosig.go) and would otherwise fail a POST-RESTART cosig finalize with a misleading "no int64 exp"
// error. broker_seq is unconditionally OVERWRITTEN at finalize regardless of its rehydrated value (see
// handleGrantFinalize), and issued_at is never type-asserted, but both are repaired too for consistency —
// the only field this MUST fix for correctness is exp. (Compare broker.Claims, which sidesteps this same
// footgun by decoding into a typed struct instead of map[string]any — see its doc comment.)
func (d pendingGrantDTO) toPendingGrant(idemKey string) *pendingGrant {
	repairEvidenceInts(d.Prepared.Evidence, "exp", "issued_at", "broker_seq")
	return &pendingGrant{prepared: d.Prepared, req: d.Req, gr: d.GR, created: d.Created, idemKey: idemKey}
}

// repairEvidenceInts converts ev[key] from float64 back to int64 for each key present, in place. No-op
// for an absent key or one that is not a float64 (e.g. already int64 on a non-round-tripped map).
func repairEvidenceInts(ev map[string]any, keys ...string) {
	for _, k := range keys {
		if f, ok := ev[k].(float64); ok {
			ev[k] = int64(f)
		}
	}
}
