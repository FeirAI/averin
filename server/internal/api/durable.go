package api

import (
	"context"
	"log"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/pgdurable"
)

// durableWriter is the subset of *pgdurable.Store the request paths call (the boot-time rehydrate in WithDurable
// uses the concrete store). An interface so a test can inject a slow/blocking durable store.
type durableWriter interface {
	PutPending(projectID, idemKey, grantID string, payload []byte, created time.Time) ([]byte, time.Time, error)
	DeletePending(projectID, idemKey string) error
}

// WithDurable validates the auxiliary Postgres durable-state connection and
// rehydrates the legacy in-process revocation cache at boot. Authoritative pending
// and revocation checks on request paths use the project Store transaction; the
// cache never grants permission. Pending grants have no process-local copy: expired
// pending_grants rows are pruned by the store's periodic sweep (StartPendingSweeper). Main wires this to the same database as
// the Store and retains its readiness probe. Call after WithRevocation so the
// optional cache is not reset after loading.
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
// payload), which keys the durable pending_grants row.
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

// pendingSweepGrace keeps a pruned row beyond pendingTTL for longer than any project write transaction
// can run (45 s), so the sweep never removes a row that an in-flight prepare/finalize still judges live.
const pendingSweepGrace = time.Minute

// pendingPruner is implemented by stores whose pending grants outlive the process (Postgres).
type pendingPruner interface {
	PruneExpiredPendingGrants(ctx context.Context, ttl, grace time.Duration, maxProjects int) (int64, error)
}

// StartPendingSweeper periodically deletes expired two-phase pending grants (abandoned prepares) from the
// durable store, so pending_grants does not grow without bound. Each project is pruned under its own
// project write transaction by database time; see store.(*Postgres).PruneExpiredPendingGrants. Failures are
// logged and retried next interval: a deferred prune never authorizes anything, since finalize requires a
// live row. A no-op for stores without durable pending state (the dev in-memory store).
func (s *Server) StartPendingSweeper(ctx context.Context, interval time.Duration) bool {
	pr, ok := s.st.(pendingPruner)
	if !ok {
		return false
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				n, err := pr.PruneExpiredPendingGrants(sctx, pendingTTL, pendingSweepGrace, 256)
				cancel()
				if err != nil {
					log.Printf("WARNING: pending grant sweep failed (expired rows retained until the next sweep): %v", err)
				} else if n > 0 {
					log.Printf("pending grant sweep removed %d expired pending grant(s)", n)
				}
			}
		}
	}()
	return true
}
