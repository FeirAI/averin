package api

import (
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

// CreateCheckpointTxForTest runs the real cut (incremental or full, with the shadow check) and stores the
// checkpoint, against st, which must already be bound to the project's write transaction.
func (s *Server) CreateCheckpointTxForTest(st store.Store, projectID string) (store.Checkpoint, error) {
	return s.createCheckpointTx(st, projectID)
}

// CutStatsForTest reports how many cuts went incremental and full, and the shadow checks and mismatches seen.
func (s *Server) CutStatsForTest() (incremental, full, shadowChecks, shadowMismatches int64) {
	return s.cut.incremental.Load(), s.cut.full.Load(), s.mCutShadowChecks.Value(), s.mCutShadowMismatch.Value()
}

// ShadowFailedForTest reports how many shadow checks could not run.
func (s *Server) ShadowFailedForTest() int64 { return s.mCutShadowFailed.Value() }
