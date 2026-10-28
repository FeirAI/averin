package api

import (
	"context"
	"errors"
	"time"

	"github.com/feirai/averin/server/internal/store"
)

// CutBodiesForTest returns the incremental and the full checkpoint body for the project as they would be signed
// now (same created_ts), without signing or storing anything. usedInc is false when the incremental cut does not
// apply (no usable base) and inc is then nil.
func (s *Server) CutBodiesForTest(st store.Store, projectID string) (inc, full map[string]any, usedInc bool, err error) {
	created := ts(s.now())
	inc, usedInc, err = s.cutBodyIncremental(st, projectID, created)
	if err != nil {
		return nil, nil, usedInc, err
	}
	full, err = s.cutBodyFull(st, projectID, created)
	return inc, full, usedInc, err
}

// CreateCheckpointTxForTest runs phase 1 of the cut against st, which must already be bound to the project's
// write transaction. When a shadow is due it returns the internal "shadow due" error and stores nothing; use
// CutCheckpointForTest for the whole cut.
func (s *Server) CreateCheckpointTxForTest(st store.Store, projectID string) (store.Checkpoint, error) {
	return s.createCheckpointTx(st, projectID, nil)
}

// CutCheckpointForTest runs the real cut (all phases, the shadow check included) and stores the checkpoint.
func (s *Server) CutCheckpointForTest(ctx context.Context, projectID string) (store.Checkpoint, error) {
	return s.cutCheckpoint(ctx, projectID)
}

// CutGateCountForTest reports how many project cut gates are currently held or awaited (0 when idle).
func (s *Server) CutGateCountForTest() int { return s.cutGateCount() }

// IsShadowDueForTest reports whether err is the phase 1 "shadow due" sentinel.
func IsShadowDueForTest(err error) bool { var d *errShadowDue; return errors.As(err, &d) }

// IsShadowRacedForTest reports whether err is the "base moved during the shadow" refusal.
func IsShadowRacedForTest(err error) bool { return errors.Is(err, errShadowRaced) }

// ShadowRacedForTest reports how many shadowed cuts were abandoned because the base moved.
func (s *Server) ShadowRacedForTest() int64 { return s.mCutShadowRaced.Value() }

// CutStatsForTest reports how many cuts went incremental and full, and the shadow checks and mismatches seen.
func (s *Server) CutStatsForTest() (incremental, full, shadowChecks, shadowMismatches int64) {
	return s.cut.incremental.Load(), s.cut.full.Load(), s.mCutShadowChecks.Value(), s.mCutShadowMismatch.Value()
}

// ShadowFailedForTest reports how many shadow checks could not run.
func (s *Server) ShadowFailedForTest() int64 { return s.mCutShadowFailed.Value() }

// ShadowBudgetForTest reports the effective shadow budget (after clamping and defaulting).
func (s *Server) ShadowBudgetForTest() time.Duration { return s.shadowBudget() }
