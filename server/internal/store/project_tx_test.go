package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMemProjectWriteRollbackAndIsolation(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	wantErr := errors.New("abort")
	if err := m.WithProjectWrite(ctx, "p", func(st Store) error {
		if _, err := st.NextDisplaySeq("p", "s"); err != nil {
			return err
		}
		if _, _, err := st.PutRecord("p", "k", rec("h", "s")); err != nil {
			return err
		}
		if _, _, err := st.RecordByIdem("other", "k"); err == nil {
			t.Fatal("bound store accepted another project")
		}
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("rollback = %v", err)
	}
	if n, _ := m.RecordCount("p"); n != 0 {
		t.Fatalf("aborted record persisted: %d", n)
	}
	if err := m.WithProjectRead(ctx, "p", func(st Store) error {
		if _, err := st.NextDisplaySeq("p", "s"); err == nil {
			t.Fatal("read snapshot accepted a write")
		}
		if err := st.WithProjectWrite(ctx, "p", func(Store) error { return nil }); err == nil {
			t.Fatal("nested transaction accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seq, _ := m.NextDisplaySeq("p", "s"); seq != 0 {
		t.Fatalf("aborted display seq persisted: %d", seq)
	}
}

func TestPostgresProjectWriteTwoPools(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	otherPool, err := pgxpool.NewWithConfig(ctx, p.pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer otherPool.Close()
	other := &Postgres{pool: otherPool}
	locked := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- p.WithProjectWrite(ctx, "p", func(st Store) error {
			if _, err := st.Heads("p", "s"); err != nil {
				return err
			}
			close(locked)
			<-release
			_, _, err := st.PutRecord("p", "k1", rec("h1", "s"))
			return err
		})
	}()
	<-locked
	second := make(chan error, 1)
	go func() {
		second <- other.WithProjectWrite(ctx, "p", func(st Store) error {
			heads, err := st.Heads("p", "s")
			if err != nil {
				return err
			}
			if len(heads) != 1 || heads[0] != "h1" {
				return errors.New("second writer missed committed head")
			}
			_, _, err = st.PutRecord("p", "k2", rec("h2", "s", heads...))
			return err
		})
	}()
	independent := make(chan error, 1)
	go func() {
		independent <- other.WithProjectWrite(ctx, "q", func(st Store) error { _, _, err := st.PutRecord("q", "q1", rec("qh", "s")); return err })
	}()
	select {
	case err := <-independent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("project q stalled behind project p")
	}
	select {
	case err := <-second:
		t.Fatalf("second writer escaped project guard: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if heads, err := p.Heads("p", "s"); err != nil || len(heads) != 1 || heads[0] != "h2" {
		t.Fatalf("heads=%v err=%v", heads, err)
	}
}

func TestPostgresProjectWriteRejectsWrongIndex(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx := context.Background()
	if _, err := p.pool.Exec(ctx, `DROP INDEX records_project_record_id_uniq`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `CREATE UNIQUE INDEX records_project_record_id_uniq ON records(project_id, content_hash)`); err != nil {
		t.Fatal(err)
	}
	err := p.WithProjectWrite(ctx, "p", func(Store) error { t.Fatal("unsafe callback ran"); return nil })
	if err == nil {
		t.Fatal("wrong index accepted")
	}
	if _, err := p.AllRecords("p"); err != nil {
		t.Fatalf("damaged history must remain readable: %v", err)
	}
}
