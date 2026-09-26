package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/feirai/averin/server/internal/store"
)

// Plan 009 real-Postgres tests. Two api.Server instances with independent pools model two
// replicas; child-process kills model crashes on each side of COMMIT.

func temporalReplicas(t *testing.T) (*store.Postgres, *pgxpool.Pool, http.Handler, http.Handler) {
	t.Helper()
	pg, admin := newVoidTestPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	second, err := store.NewPostgres(ctx, admin.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	return pg, admin, temporalServer(t, pg, true), temporalServer(t, second, true)
}

// noReceiptAtOrAfterCutoff checks the database invariant behind `proven_before`: no committed
// receipt of a prospectively revoked grant carries an ordinal at or after its cutoff.
func noReceiptAtOrAfterCutoff(t *testing.T, admin *pgxpool.Pool) {
	t.Helper()
	var bad int
	err := admin.QueryRow(context.Background(), `SELECT count(*) FROM authorization_receipts r JOIN revocation_events e
		ON e.project_id=r.project_id AND e.grant_id=r.grant_id AND e.mode='prospective' WHERE r.ordinal >= e.cutoff_order`).Scan(&bad)
	if err != nil || bad != 0 {
		t.Fatalf("%d receipts at/after their grant's cutoff (err %v)", bad, err)
	}
}

func TestTemporalRevokeRacesUseAcrossPoolsPostgres(t *testing.T) {
	_, admin, replicaA, replicaB := temporalReplicas(t)
	ak := grantAgentKey()
	var useFirst, revokeFirst int
	for i := 0; i < 16; i++ {
		grantID, capability := mkGrant(t, replicaA, ak, fmt.Sprintf("race-grant-%d", i))
		var wg sync.WaitGroup
		var useCode int
		var useResp, revokeResp string
		var revokeCode int
		wg.Add(2)
		go func() {
			defer wg.Done()
			useCode, useResp = do(t, replicaA, "POST", "/v2/use", useBody(t, fmt.Sprintf("race-use-%d", i), capability, grantID, ak, "SELECT 1", fmt.Sprintf("race-nonce-%d", i)))
		}()
		go func() {
			defer wg.Done()
			// Stagger the revoke so both commit orders occur; the causal schedules below force each.
			time.Sleep(time.Duration(i%4) * 4 * time.Millisecond)
			revokeCode, revokeResp = do(t, replicaB, "POST", "/v2/revoke?project=p1", revokeBody(grantID, "prospective"))
		}()
		wg.Wait()
		if revokeCode != http.StatusCreated {
			t.Fatalf("revoke %d: %d %s", i, revokeCode, revokeResp)
		}
		var rev revokeReply
		json.Unmarshal([]byte(revokeResp), &rev)
		switch useCode {
		case http.StatusCreated:
			ordinal, _, ok := receiptOrder(t, responseRecord(t, useResp))
			if !ok || ordinal >= rev.CutoffOrder {
				t.Fatalf("race %d: admitted use ordinal %d is not before cutoff %d", i, ordinal, rev.CutoffOrder)
			}
			useFirst++
		default:
			if !strings.Contains(useResp, "revoked") {
				t.Fatalf("race %d: use failed for a reason other than revocation: %d %s", i, useCode, useResp)
			}
			revokeFirst++
		}
		// Once the revoke is acknowledged, every replica rejects a later use of the grant.
		if code, body := do(t, replicaA, "POST", "/v2/use", useBody(t, fmt.Sprintf("race-late-%d", i), capability, grantID, ak, "SELECT 2", fmt.Sprintf("race-late-nonce-%d", i))); code == http.StatusCreated || !strings.Contains(body, "revoked") {
			t.Fatalf("race %d: replica A did not reject a use after replica B's acknowledged revoke as revoked: %d %s", i, code, body)
		}
	}
	t.Logf("use committed first in %d races, revoke first in %d", useFirst, revokeFirst)
	noReceiptAtOrAfterCutoff(t, admin)
}

func TestTemporalRepeatedRevokeAcrossPoolsPostgres(t *testing.T) {
	_, admin, replicaA, replicaB := temporalReplicas(t)
	ak := grantAgentKey()
	grantID, capability := mkGrant(t, replicaA, ak, "repeat-grant")
	if code, body := do(t, replicaA, "POST", "/v2/use", useBody(t, "repeat-use", capability, grantID, ak, "SELECT 1", "repeat-nonce")); code != http.StatusCreated {
		t.Fatalf("use: %d %s", code, body)
	}
	replies := make(chan revokeReply, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(h http.Handler) {
			defer wg.Done()
			code, body := do(t, h, "POST", "/v2/revoke?project=p1", revokeBody(grantID, "prospective"))
			if code != http.StatusCreated {
				t.Errorf("revoke: %d %s", code, body)
				return
			}
			var r revokeReply
			json.Unmarshal([]byte(body), &r)
			replies <- r
		}([]http.Handler{replicaA, replicaB}[i%2])
	}
	wg.Wait()
	close(replies)
	created, cutoff := 0, int64(0)
	for r := range replies {
		if r.Created {
			created++
		}
		if cutoff == 0 {
			cutoff = r.CutoffOrder
		}
		if r.CutoffOrder != cutoff || r.Mode != "prospective" {
			t.Fatalf("concurrent revokes disagree on the cutoff: %+v vs %d", r, cutoff)
		}
	}
	if created != 1 || cutoff != 2 {
		t.Fatalf("created=%d cutoff=%d, want exactly one event with cutoff 2", created, cutoff)
	}
	// Later receipts advance the order; a retry still never moves the cutoff later.
	g2, cap2 := mkGrant(t, replicaB, ak, "repeat-grant-2")
	if code, body := do(t, replicaB, "POST", "/v2/use", useBody(t, "repeat-use-2", cap2, g2, ak, "SELECT 2", "repeat-nonce-2")); code != http.StatusCreated {
		t.Fatalf("use 2: %d %s", code, body)
	}
	if r := mustRevoke(t, replicaA, grantID, "prospective"); r.CutoffOrder != cutoff || r.Created {
		t.Fatalf("retry after later receipts moved the cutoff: %+v", r)
	}
	var rows int
	if err := admin.QueryRow(context.Background(), `SELECT count(*) FROM revocation_events WHERE grant_id=$1`, grantID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("revocation events for the grant: %d %v", rows, err)
	}
	if r := mustRevoke(t, replicaB, grantID, "total"); r.Mode != "total" || !r.Created {
		t.Fatalf("total upgrade across replicas: %+v", r)
	}
}

// TestTemporalSnapshotExportConsistencyPostgres exports on one replica while another commits
// receipts and prospective revocations. Every export's signed watermark must match exactly the
// receipts and cutoffs it carries: nothing at or below it missing, nothing above it present.
func TestTemporalSnapshotExportConsistencyPostgres(t *testing.T) {
	_, admin, writer, exporter := temporalReplicas(t)
	ak := grantAgentKey()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			grantID, capability := mkGrant(t, writer, ak, fmt.Sprintf("snap-grant-%d", i))
			if code, body := do(t, writer, "POST", "/v2/use", useBody(t, fmt.Sprintf("snap-use-%d", i), capability, grantID, ak, "SELECT 1", fmt.Sprintf("snap-nonce-%d", i))); code != http.StatusCreated {
				t.Errorf("writer use: %d %s", code, body)
				return
			}
			if i%3 == 0 {
				do(t, writer, "POST", "/v2/revoke?project=p1", revokeBody(grantID, "prospective"))
			}
		}
	}()
	type exported struct {
		watermark int64
		receipts  map[int64]bool
		cutoffs   map[int64]bool
	}
	var exports []exported
	for i := 0; i < 12; i++ {
		code, body := do(t, exporter, "GET", "/v2/export?project=p1", "")
		if code != http.StatusOK {
			t.Fatalf("export: %d %s", code, body)
		}
		var b struct {
			Records        []json.RawMessage `json:"records"`
			RevocationList struct {
				Snapshot struct {
					Watermark int64 `json:"authorization_high_watermark"`
				} `json:"snapshot"`
				Revocations []struct {
					CutoffOrder *int64 `json:"cutoff_order"`
				} `json:"revocations"`
			} `json:"revocation_list"`
		}
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			t.Fatal(err)
		}
		e := exported{watermark: b.RevocationList.Snapshot.Watermark, receipts: map[int64]bool{}, cutoffs: map[int64]bool{}}
		for _, r := range b.Records {
			if !strings.Contains(string(r), "authorization_order") {
				continue
			}
			if o, _, ok := receiptOrder(t, string(r)); ok {
				e.receipts[o] = true
			}
		}
		for _, r := range b.RevocationList.Revocations {
			if r.CutoffOrder != nil {
				e.cutoffs[*r.CutoffOrder] = true
			}
		}
		exports = append(exports, e)
		time.Sleep(15 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	// Final committed state: every ordinal is either a receipt or a cutoff (no gaps in this test).
	final := map[int64]string{}
	rows, err := admin.Query(context.Background(), `SELECT ordinal, 'receipt' FROM authorization_receipts UNION ALL SELECT cutoff_order, 'cutoff' FROM revocation_events WHERE mode='prospective'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var o int64
		var kind string
		if err := rows.Scan(&o, &kind); err != nil {
			t.Fatal(err)
		}
		final[o] = kind
	}
	rows.Close()
	nonEmpty := 0
	for n, e := range exports {
		if e.watermark > 0 {
			nonEmpty++
		}
		for o := int64(1); o <= e.watermark; o++ {
			switch final[o] {
			case "receipt":
				if !e.receipts[o] {
					t.Fatalf("export %d (watermark %d) omits committed receipt %d", n, e.watermark, o)
				}
			case "cutoff":
				if !e.cutoffs[o] {
					t.Fatalf("export %d (watermark %d) omits committed cutoff %d", n, e.watermark, o)
				}
			default:
				t.Fatalf("ordinal %d at or below watermark %d has no committed receipt or cutoff", o, e.watermark)
			}
		}
		for o := range e.receipts {
			if o > e.watermark {
				t.Fatalf("export %d carries receipt %d above its watermark %d", n, o, e.watermark)
			}
		}
		for o := range e.cutoffs {
			if o > e.watermark {
				t.Fatalf("export %d carries cutoff %d above its watermark %d", n, o, e.watermark)
			}
		}
	}
	if nonEmpty < 2 {
		t.Fatalf("only %d exports observed concurrent writes; the check was vacuous", nonEmpty)
	}
	noReceiptAtOrAfterCutoff(t, admin)
}

func guardOrder(t *testing.T, admin *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	if err := admin.QueryRow(context.Background(), `SELECT COALESCE((SELECT authorization_order FROM project_write_guard WHERE project_id='p1'),0)`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTemporalRevocationProcessCrashCutsPostgres(t *testing.T) {
	t.Setenv("AVERIN_PROJECT_TX_REVOCATION_V2", "1")
	pg, admin := newVoidTestPostgres(t)
	dsn, dir := admin.Config().ConnConfig.ConnString(), t.TempDir()
	peer := startProjectTxProcess(t, dsn, dir)
	ak := grantAgentKey()
	finalize, _ := preparedProcessGrant(t, peer, "crash-grant", ak)
	code, body := callProjectTxProcess(t, peer, "POST", "/v2/grants/finalize", finalize)
	if code != http.StatusCreated {
		t.Fatalf("finalize: %d %s", code, body)
	}
	grantID, capability := processGrantResult(t, body)

	// A use killed after its receipt INSERT, before COMMIT: the ordinal allocation rolls back with it.
	use := useBody(t, "crash-use", capability, grantID, ak, "SELECT 1", "crash-nonce")
	marker := filepath.Join(t.TempDir(), "after-put-use")
	child := startProjectTxPausedProcess(t, dsn, dir, "after_put", "crash-use", marker)
	inFlight := sendProjectTxAsync(child, "/v2/use", use)
	waitProjectTxPause(t, child, marker)
	child.stop()
	<-inFlight
	if n := guardOrder(t, admin); n != 0 {
		t.Fatalf("killed uncommitted use left authorization order %d", n)
	}
	code, body = callProjectTxProcess(t, peer, "POST", "/v2/use", use)
	if code != http.StatusCreated {
		t.Fatalf("exact retry after kill: %d %s", code, body)
	}
	if o, _, _ := receiptOrder(t, responseRecord(t, body)); o != 1 {
		t.Fatalf("retried use ordinal %d, want 1 (the killed allocation must not persist)", o)
	}

	// A revoke killed after its event INSERT, before COMMIT: no event and no cutoff survive.
	revoke := revokeBody(grantID, "prospective")
	marker = filepath.Join(t.TempDir(), "after-revocation-event")
	child = startProjectTxPausedProcess(t, dsn, dir, "after_revocation_event", "", marker)
	inFlight = sendProjectTxAsync(child, "/v2/revoke?project=p1", revoke)
	waitProjectTxPause(t, child, marker)
	child.stop()
	<-inFlight
	if events, err := pg.RevocationEvents("p1"); err != nil || len(events) != 0 {
		t.Fatalf("uncommitted revocation survived kill: %+v %v", events, err)
	}
	if revoked, err := pg.IsRevoked("p1", grantID); err != nil || revoked {
		t.Fatalf("grant revoked by an uncommitted event: %v %v", revoked, err)
	}
	if n := guardOrder(t, admin); n != 1 {
		t.Fatalf("killed uncommitted revoke left authorization order %d, want 1", n)
	}

	// A revoke killed after COMMIT, before its response: the peer's retry returns the committed
	// cutoff (never a later one) and every process rejects later uses.
	marker = filepath.Join(t.TempDir(), "after-revocation-commit")
	child = startProjectTxPausedProcess(t, dsn, dir, "after_revocation_commit", "", marker)
	inFlight = sendProjectTxAsync(child, "/v2/revoke?project=p1", revoke)
	waitProjectTxPause(t, child, marker)
	child.stop()
	<-inFlight
	events, err := pg.RevocationEvents("p1")
	if err != nil || len(events) != 1 || events[0].Mode != "prospective" || events[0].CutoffOrder != 2 {
		t.Fatalf("committed revocation lost or wrong after kill: %+v %v", events, err)
	}
	code, body = callProjectTxProcess(t, peer, "POST", "/v2/revoke?project=p1", revoke)
	var r revokeReply
	json.Unmarshal([]byte(body), &r)
	if code != http.StatusCreated || r.Created || r.CutoffOrder != 2 {
		t.Fatalf("retry after post-commit kill: %d %s", code, body)
	}
	restarted := startProjectTxProcess(t, dsn, dir)
	late := useBody(t, "crash-late-use", capability, grantID, ak, "SELECT 2", "crash-late-nonce")
	if code, body := callProjectTxProcess(t, restarted, "POST", "/v2/use", late); code == http.StatusCreated || !strings.Contains(body, "revoked") {
		t.Fatalf("restarted process did not reject a use after the committed revoke as revoked: %d %s", code, body)
	}
	noReceiptAtOrAfterCutoff(t, admin)
}

// holdTxStore blocks inside the replica's open project transaction, after its receipt or
// revocation event INSERT and before COMMIT, until released. The guard row stays locked meanwhile.
type holdTxStore struct {
	store.Store
	recordIdem   string
	onRevocation bool
	reached      chan struct{}
	release      chan struct{}
	once         sync.Once
}
type holdTxBound struct {
	store.Store
	root *holdTxStore
}

func (h *holdTxStore) hold() {
	h.once.Do(func() {
		close(h.reached)
		<-h.release
	})
}
func (h *holdTxStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return h.Store.WithProjectWrite(ctx, projectID, func(bound store.Store) error { return fn(&holdTxBound{Store: bound, root: h}) })
}
func (b *holdTxBound) PutRecord(projectID, idem string, rec store.Record) (store.Record, bool, error) {
	stored, created, err := b.Store.PutRecord(projectID, idem, rec)
	if err == nil && created && idem == b.root.recordIdem {
		b.root.hold()
	}
	return stored, created, err
}
func (b *holdTxBound) PutRevocationEvent(ev store.RevocationEvent) (store.RevocationEvent, bool, error) {
	stored, created, err := b.Store.PutRevocationEvent(ev)
	if err == nil && created && b.root.onRevocation {
		b.root.hold()
	}
	return stored, created, err
}

// namedReplica opens an independent pool whose backends carry appName, so the test can observe that
// replica's transaction actually waiting on the project guard.
func namedReplica(t *testing.T, admin *pgxpool.Pool, appName string) *store.Postgres {
	t.Helper()
	u, err := url.Parse(admin.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("application_name", appName)
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pg, err := store.NewPostgres(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pg.Close)
	return pg
}

func waitGuardWait(t *testing.T, admin *pgxpool.Pool, appName string, early <-chan [2]string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case r := <-early:
			t.Fatalf("second transaction returned before the first released the guard: %v", r)
		default:
		}
		var waiting bool
		if err := admin.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE application_name=$1 AND state='active' AND wait_event_type='Lock' AND query LIKE '%project_write_guard%')`, appName).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("second transaction never waited on the project guard")
}

// TestTemporalCausalRevokeUseSchedulesPostgres forces both orders across two replicas: each time the
// first transaction holds the project guard with its uncommitted INSERT while the other replica's
// transaction is observed waiting on that guard. A use admitted first gets an ordinal below the
// cutoff; a revoke committed first makes the waiting use fail as revoked without an ordinal.
func TestTemporalCausalRevokeUseSchedulesPostgres(t *testing.T) {
	for _, useFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("use_first=%v", useFirst), func(t *testing.T) {
			_, admin := newVoidTestPostgres(t)
			suffix := time.Now().UnixNano()
			appA, appB := fmt.Sprintf("averin_temporal_a_%d", suffix), fmt.Sprintf("averin_temporal_b_%d", suffix)
			holdA := &holdTxStore{Store: namedReplica(t, admin, appA), reached: make(chan struct{}), release: make(chan struct{})}
			holdB := &holdTxStore{Store: namedReplica(t, admin, appB), reached: make(chan struct{}), release: make(chan struct{})}
			defer func() {
				for _, h := range []*holdTxStore{holdA, holdB} {
					select {
					case <-h.release:
					default:
						close(h.release)
					}
				}
			}()
			replicaA, replicaB := temporalServer(t, holdA, true), temporalServer(t, holdB, true)
			ak := grantAgentKey()
			grantID, capability := mkGrant(t, replicaA, ak, "causal-grant")
			useDone, revokeDone := make(chan [2]string, 1), make(chan [2]string, 1)
			runUse := func() {
				code, body := do(t, replicaA, "POST", "/v2/use", useBody(t, "causal-use", capability, grantID, ak, "SELECT 1", "causal-nonce"))
				useDone <- [2]string{fmt.Sprint(code), body}
			}
			runRevoke := func() {
				code, body := do(t, replicaB, "POST", "/v2/revoke?project=p1", revokeBody(grantID, "prospective"))
				revokeDone <- [2]string{fmt.Sprint(code), body}
			}
			if useFirst {
				holdA.recordIdem = "causal-use"
				go runUse()
				<-holdA.reached
				go runRevoke()
				waitGuardWait(t, admin, appB, revokeDone)
				close(holdA.release)
			} else {
				holdB.onRevocation = true
				go runRevoke()
				<-holdB.reached
				go runUse()
				waitGuardWait(t, admin, appA, useDone)
				close(holdB.release)
			}
			use, rev := <-useDone, <-revokeDone
			if rev[0] != "201" {
				t.Fatalf("revoke: %v", rev)
			}
			var r revokeReply
			json.Unmarshal([]byte(rev[1]), &r)
			if useFirst {
				ordinal, _, ok := receiptOrder(t, responseRecord(t, use[1]))
				if use[0] != "201" || !ok || ordinal != 1 || r.CutoffOrder != 2 {
					t.Fatalf("use-first schedule: use %v ordinal %d, cutoff %d", use[0], ordinal, r.CutoffOrder)
				}
			} else {
				if use[0] == "201" || !strings.Contains(use[1], "revoked") || r.CutoffOrder != 1 {
					t.Fatalf("revoke-first schedule: use %v, cutoff %d", use, r.CutoffOrder)
				}
				if n := guardOrder(t, admin); n != 1 {
					t.Fatalf("a rejected use allocated an ordinal: order %d", n)
				}
			}
			noReceiptAtOrAfterCutoff(t, admin)
		})
	}
}
