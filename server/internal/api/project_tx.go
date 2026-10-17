package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/feirai/averin/server/internal/store"
)

// countedStore enforces the per-project record quota inside the evidence transaction.
type countedStore struct {
	store.Store
	max       int // 0 = no quota
	mark      *quotaMark
	created   int
	base      int // records stored before this transaction's first insert
	baseKnown bool
}

func (s *countedStore) PutRecord(projectID, idemKey string, rec store.Record) (store.Record, bool, error) {
	stored, created, err := s.Store.PutRecord(projectID, idemKey, rec)
	if err != nil || !created {
		return stored, created, err
	}
	s.created++
	if s.max <= 0 {
		return stored, created, nil
	}
	if !s.baseKnown {
		// The count is read in the same transaction after the insert, so it includes this record.
		n, cerr := s.Store.RecordCount(projectID)
		if cerr != nil {
			return store.Record{}, false, fmt.Errorf("quota: read record count: %w", cerr) // fail closed
		}
		s.base = n - 1
		s.baseKnown = true
	}
	if s.base+s.created > s.max {
		s.mark.hit()
		return store.Record{}, false, errProjectQuota
	}
	return stored, created, nil
}

func (s *Server) withProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return s.st.WithProjectWrite(ctx, projectID, func(bound store.Store) error {
		return fn(&countedStore{Store: bound, max: s.projectQuota, mark: quotaMarkFrom(ctx)})
	})
}

// errRollbackDecided rolls back a project transaction whose HTTP outcome the callback has
// already decided (a conflict, or an idempotent answer from another committed row). Plan 009:
// an authorization ordinal allocated in that transaction must not persist without its receipt.
var errRollbackDecided = errors.New("project transaction rolled back after a decided non-success outcome")

// decidedRollback maps errRollbackDecided back to "no store error"; the caller then answers from
// the outcome its callback recorded.
func decidedRollback(err error) error {
	if errors.Is(err, errRollbackDecided) {
		return nil
	}
	return err
}
