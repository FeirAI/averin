package api

import (
	"context"
	"errors"

	"github.com/feirai/averin/server/internal/store"
)

// countedStore defers external metering until the evidence transaction commits.
type countedStore struct {
	store.Store
	created int
}

func (s *countedStore) PutRecord(projectID, idemKey string, rec store.Record) (store.Record, bool, error) {
	stored, created, err := s.Store.PutRecord(projectID, idemKey, rec)
	if err == nil && created {
		s.created++
	}
	return stored, created, err
}

func (s *Server) withProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	var count int
	err := s.st.WithProjectWrite(ctx, projectID, func(bound store.Store) error {
		c := &countedStore{Store: bound}
		if err := fn(c); err != nil {
			return err
		}
		count = c.created
		return nil
	})
	if err == nil && count != 0 {
		s.meter.RecordsIngested(projectID, count)
	}
	return err
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
