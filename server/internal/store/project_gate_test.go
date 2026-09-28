package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPostgresHotProjectDoesNotStarvePool: more concurrent writers to one project than the pool has
// connections must queue in-process, holding no connection, so another project's write and a read still
// complete promptly. Without the per-project gate every queued writer holds a pool connection while it
// blocks on the project guard, and project B cannot even acquire a connection.
func TestPostgresHotProjectDoesNotStarvePool(t *testing.T) {
	base, done := newTestStore(t)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := base.pool.Config().Copy()
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	p := &Postgres{pool: pool}

	const hot = 6 // three times MaxConns
	holding := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	errs := make(chan error, hot)
	for i := 0; i < hot; i++ {
		i := i
		go func() {
			errs <- p.WithProjectWrite(ctx, "hot", func(st Store) error {
				if i == 0 {
					close(holding)
					<-release
				}
				_, _, err := st.PutRecord("hot", fmt.Sprintf("k%d", i), rec(fmt.Sprintf("hot-%d", i), "s"))
				return err
			})
		}()
		if i == 0 {
			select {
			case <-holding:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	// Give the queued hot writers time to reach the gate (or, without it, the pool).
	time.Sleep(200 * time.Millisecond)
	if n := pool.Stat().AcquiredConns(); n > 1 {
		t.Fatalf("queued same-project writers hold %d pool connections, want at most the one guard holder", n)
	}

	quick, qcancel := context.WithTimeout(ctx, 3*time.Second)
	defer qcancel()
	if err := p.WithProjectWrite(quick, "cold", func(st Store) error {
		_, _, err := st.PutRecord("cold", "c1", rec("cold-1", "s"))
		return err
	}); err != nil {
		t.Fatalf("project cold write starved by hot project: %v", err)
	}
	if err := p.WithProjectRead(quick, "hot", func(st Store) error {
		_, err := st.Heads("hot", "s")
		return err
	}); err != nil {
		t.Fatalf("read starved by hot project: %v", err)
	}

	once.Do(func() { close(release) })
	for i := 0; i < hot; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("hot writer: %v", err)
		}
	}
	if n := p.projectGateCount(); n != 0 {
		t.Fatalf("project gates leaked: %d entries", n)
	}
}

// TestPostgresProjectGateCancellation: a writer queued behind the same project's holder observes its
// context, returns without touching the database, and leaves no gate entry behind.
func TestPostgresProjectGateCancellation(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	holding := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- p.WithProjectWrite(ctx, "p", func(Store) error {
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding
	waitCtx, waitCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer waitCancel()
	called := false
	err := p.WithProjectWrite(waitCtx, "p", func(Store) error { called = true; return nil })
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("queued writer: err=%v called=%v, want deadline before callback", err, called)
	}
	if n := p.projectGateCount(); n != 1 {
		t.Fatalf("gate entries while holder active = %d, want 1", n)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	failing := errors.New("callback failure")
	if err := p.WithProjectWrite(ctx, "p", func(Store) error { return failing }); !errors.Is(err, failing) {
		t.Fatalf("callback error = %v", err)
	}
	if n := p.projectGateCount(); n != 0 {
		t.Fatalf("project gates leaked after error paths: %d entries", n)
	}
}

// TestPostgresPendingSweepPrunesOnlyUnusableRows: the sweep removes pending grants older than ttl+grace by
// database time, keeps rows a finalize could still judge live (inside ttl, or inside the grace margin), and
// waits for the project's guard instead of deleting under an in-flight project transaction.
func TestPostgresPendingSweepPrunesOnlyUnusableRows(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const ttl, grace = 15 * time.Minute, time.Minute
	for _, row := range []struct {
		project, idem string
		age           string
	}{
		{"a", "expired", "20 minutes"},
		{"a", "in-grace", "15 minutes 30 seconds"},
		{"a", "live", "1 minute"},
		{"b", "expired", "2 hours"},
	} {
		if _, err := p.pool.Exec(ctx, `INSERT INTO pending_grants(project_id,idem_key,grant_id,payload,created_at)
			VALUES ($1,$2,$1||':'||$2,'{}',clock_timestamp() - $3::interval)`, row.project, row.idem, row.age); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.PruneExpiredPendingGrants(ctx, ttl, 50*time.Second, 10); err == nil {
		t.Fatal("sweep accepted a grace shorter than the transaction lifetime (45 s session + 10 s commit)")
	}

	// While project a's guard is held, the sweep must not delete a's rows.
	holding := make(chan struct{})
	release := make(chan struct{})
	holder := make(chan error, 1)
	go func() {
		holder <- p.WithProjectWrite(ctx, "a", func(Store) error {
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding
	blocked, bcancel := context.WithTimeout(ctx, 300*time.Millisecond)
	nBlocked, err := p.PruneExpiredPendingGrants(blocked, ttl, grace, 10)
	if err == nil {
		bcancel()
		t.Fatal("sweep completed while project a's guard was held")
	}
	bcancel()
	var aRows int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM pending_grants WHERE project_id='a'`).Scan(&aRows); err != nil || aRows != 3 {
		t.Fatalf("rows of a guarded project changed: %d %v", aRows, err)
	}
	close(release)
	if err := <-holder; err != nil {
		t.Fatal(err)
	}

	n, err := p.PruneExpiredPendingGrants(ctx, ttl, grace, 10)
	if err != nil || nBlocked+n != 2 {
		t.Fatalf("sweeps removed %d+%d rows, err=%v; want the two expired rows", nBlocked, n, err)
	}
	var left []string
	rows, err := p.pool.Query(ctx, `SELECT project_id||'/'||idem_key FROM pending_grants ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		left = append(left, k)
	}
	rows.Close()
	if fmt.Sprint(left) != "[a/in-grace a/live]" {
		t.Fatalf("remaining pending rows = %v", left)
	}
	live, err := p.PendingGrantLive("a", "a:live", time.Now(), ttl)
	if err != nil || !live {
		t.Fatalf("live row no longer live: %v %v", live, err)
	}
	if n, err := p.PruneExpiredPendingGrants(ctx, ttl, grace, 10); err != nil || n != 0 {
		t.Fatalf("second sweep removed %d, err=%v", n, err)
	}
}

// TestPostgresPendingSweepContinuesPastAFailingProject: a project whose guard cannot be taken (held by
// another store's transaction until lock_timeout) fails alone; the sweep still prunes the other
// projects and reports the failure, and a later sweep prunes the blocked project.
func TestPostgresPendingSweepContinuesPastAFailingProject(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const ttl, grace = 15 * time.Minute, time.Minute
	for _, project := range []string{"a", "b", "c"} {
		if _, err := p.pool.Exec(ctx, `INSERT INTO pending_grants(project_id,idem_key,grant_id,payload,created_at)
			VALUES ($1,'expired',$1||':expired','{}',clock_timestamp() - interval '2 hours')`, project); err != nil {
			t.Fatal(err)
		}
	}
	other := &Postgres{pool: p.pool} // a separate store: its in-process gates do not queue the sweep
	holding := make(chan struct{})
	release := make(chan struct{})
	holder := make(chan error, 1)
	go func() {
		holder <- other.WithProjectWrite(ctx, "a", func(Store) error {
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding
	n, err := p.PruneExpiredPendingGrants(ctx, ttl, grace, 10)
	if err == nil || !strings.Contains(err.Error(), `project "a"`) {
		t.Fatalf("sweep with a's guard held elsewhere: err=%v", err)
	}
	if n != 2 {
		t.Fatalf("sweep removed %d rows past the failing project; want b and c", n)
	}
	close(release)
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if n, err := p.PruneExpiredPendingGrants(ctx, ttl, grace, 10); err != nil || n != 1 {
		t.Fatalf("later sweep removed %d, err=%v; want a's row", n, err)
	}
}
