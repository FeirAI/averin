package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

func TestProjectCommitClassification(t *testing.T) {
	if err := classifyProjectCommit(pgx.ErrTxCommitRollback); !errors.Is(err, ErrTransactionAborted) || errors.Is(err, ErrCommitAmbiguous) {
		t.Fatalf("known rollback classified as ambiguous: %v", err)
	}
	if err := classifyProjectCommit(&pgconn.PgError{Code: "40001", Message: "serialization failure"}); !errors.Is(err, ErrTransactionAborted) || errors.Is(err, ErrCommitAmbiguous) {
		t.Fatalf("server-rejected commit classified as ambiguous: %v", err)
	}
	for _, code := range []string{"40003", "08007", "57P01", "XX999"} {
		if err := classifyProjectCommit(&pgconn.PgError{Code: code}); !errors.Is(err, ErrCommitAmbiguous) || errors.Is(err, ErrTransactionAborted) {
			t.Fatalf("commit SQLSTATE %s classified as definite abort: %v", code, err)
		}
	}
	for _, code := range []string{"40P01", "25P02", "23503"} {
		if err := classifyProjectCommit(&pgconn.PgError{Code: code}); !errors.Is(err, ErrTransactionAborted) || errors.Is(err, ErrCommitAmbiguous) {
			t.Fatalf("commit SQLSTATE %s classified as unknown: %v", code, err)
		}
	}
	if err := classifyProjectCommit(context.DeadlineExceeded); !errors.Is(err, ErrCommitAmbiguous) || errors.Is(err, ErrTransactionAborted) {
		t.Fatalf("unknown commit result classified as abort: %v", err)
	}
}

func TestMemProjectSessionCancellationAndClosedHandle(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- m.WithProjectWrite(ctx, "p", func(Store) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not enter")
	}
	defer func() { close(release); <-done }()
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := m.WithProjectWrite(waitCtx, "p", func(Store) error { t.Fatal("canceled callback ran"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked writer = %v", err)
	}
	var escaped Store
	if err := m.WithProjectRead(ctx, "q", func(st Store) error { escaped = st; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := escaped.AllRecords("q"); err == nil {
		t.Fatal("escaped read handle remained live")
	}
	if _, _, err := escaped.PutRecord("q", "k", rec("h", "s")); err == nil {
		t.Fatal("escaped handle wrote after close")
	}
}

func TestMemLedgerClaimsRemainGlobalAcrossProjects(t *testing.T) {
	m := NewMem()
	ctx := context.Background()
	entered := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- m.WithProjectWrite(ctx, "p1", func(st Store) error {
			if err := st.ConsumeJTI("same-jti"); err != nil {
				return err
			}
			close(entered)
			<-release
			return errors.New("abort")
		})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("claim did not start")
	}
	if err := m.WithProjectWrite(ctx, "p2", func(st Store) error { return st.ConsumeJTI("same-jti") }); !errors.Is(err, resourceshim.ErrConsumed) {
		t.Fatalf("cross-project in-flight JTI claim = %v", err)
	}
	close(release)
	if err := <-first; err == nil {
		t.Fatal("first claim did not abort")
	}
	if err := m.WithProjectWrite(ctx, "p2", func(st Store) error { return st.ConsumeJTI("same-jti") }); err != nil {
		t.Fatalf("aborted claim was not released: %v", err)
	}
	if err := m.WithProjectWrite(ctx, "p1", func(st Store) error { return st.ConsumeJTI("same-jti") }); !errors.Is(err, resourceshim.ErrConsumed) {
		t.Fatalf("committed cross-project JTI claim = %v", err)
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
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
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
	select {
	case <-locked:
	case err := <-first:
		t.Fatalf("first writer failed before lock: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
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
	released = true
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

func TestPostgresProjectWriteDeadlineBoundaries(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx := context.Background()
	// Pool acquisition must observe the caller's deadline.
	cfg := p.pool.Config().Copy()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	err = (&Postgres{pool: pool}).WithProjectWrite(deadline, "p", func(Store) error { t.Fatal("callback ran without connection"); return nil })
	cancel()
	conn.Release()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool wait = %v", err)
	}

	// The same deadline also bounds a blocked guard and a statement after it.
	entered := make(chan struct{})
	release := make(chan struct{})
	holder := make(chan error, 1)
	go func() {
		holder <- p.WithProjectWrite(ctx, "p", func(Store) error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("holder did not enter")
	}
	defer func() { close(release); <-holder }()
	deadline, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
	err = p.WithProjectWrite(deadline, "p", func(Store) error { t.Fatal("callback escaped guard"); return nil })
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("guard wait = %v", err)
	}
	deadline, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
	err = p.WithProjectRead(deadline, "q", func(st Store) error {
		_, e := st.(*Postgres).tx.Exec(st.(*Postgres).callContext(), `SELECT pg_sleep(5)`)
		return e
	})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("statement = %v", err)
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
	if _, _, err := p.PutRecord("p", "k", rec("h", "s")); err == nil {
		t.Fatal("standalone write bypassed project transaction index check")
	}
	if _, err := p.AllRecords("p"); err != nil {
		t.Fatalf("damaged history must remain readable: %v", err)
	}
}

func TestPostgresProjectGuardWorksForNonOwnerRuntime(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	schema := p.pool.Config().ConnConfig.RuntimeParams["search_path"]
	role := fmt.Sprintf("averin_tx_runtime_%d", time.Now().UnixNano())
	for _, sql := range []string{
		"CREATE ROLE " + role + " LOGIN PASSWORD 'test_only_password'",
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA " + schema + " TO " + role,
		"GRANT UPDATE ON " + schema + ".project_write_guard TO " + role,
	} {
		if _, err := p.pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = p.pool.Exec(context.Background(), "REVOKE ALL ON ALL TABLES IN SCHEMA "+schema+" FROM "+role)
		_, _ = p.pool.Exec(context.Background(), "REVOKE USAGE ON SCHEMA "+schema+" FROM "+role)
		_, _ = p.pool.Exec(context.Background(), "DROP ROLE "+role)
	}()
	cfg := p.pool.Config().Copy()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = "test_only_password"
	runtimePool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimePool.Close()
	runtime := &Postgres{pool: runtimePool}
	if err := runtime.WithProjectWrite(ctx, "p", func(st Store) error {
		_, _, err := st.PutRecord("p", "k", rec("h", "s"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimePool.Exec(ctx, `UPDATE records SET json='{}' WHERE project_id='p'`); err == nil {
		t.Fatal("non-owner runtime mutated signed evidence")
	}
	if _, err := runtimePool.Exec(ctx, `DELETE FROM records WHERE project_id='p'`); err == nil {
		t.Fatal("non-owner runtime deleted signed evidence")
	}
}

func TestPostgresLedgerClaimsGlobalAndAtomic(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	otherPool, err := pgxpool.NewWithConfig(ctx, p.pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer otherPool.Close()
	other := &Postgres{pool: otherPool}
	entered := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- p.WithProjectWrite(ctx, "p1", func(st Store) error {
			if err := st.ConsumeJTI("shared"); err != nil {
				return err
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	second := make(chan error, 1)
	go func() {
		second <- other.WithProjectWrite(ctx, "p2", func(st Store) error { return st.ConsumeJTI("shared") })
	}()
	select {
	case err := <-second:
		t.Fatalf("cross-project claim escaped in-flight uniqueness: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, resourceshim.ErrConsumed) {
		t.Fatalf("second claim = %v", err)
	}
	if err := p.WithProjectWrite(ctx, "p3", func(st Store) error { return st.ConsumeJTI("rollback") }); err != nil {
		t.Fatal(err)
	}
	if err := p.WithProjectWrite(ctx, "p4", func(st Store) error { return st.ConsumeJTI("rollback") }); !errors.Is(err, resourceshim.ErrConsumed) {
		t.Fatalf("committed claim = %v", err)
	}
	if err := p.WithProjectWrite(ctx, "p3", func(st Store) error {
		if err := st.ConsumeJTI("aborted"); err != nil {
			return err
		}
		return errors.New("abort")
	}); err == nil {
		t.Fatal("abort was lost")
	}
	if err := other.WithProjectWrite(ctx, "p4", func(st Store) error { return st.ConsumeJTI("aborted") }); err != nil {
		t.Fatalf("aborted claim remained consumed: %v", err)
	}
}
