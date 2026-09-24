package api

import (
	"context"

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
