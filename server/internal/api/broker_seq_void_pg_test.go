package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/pgschema"
	"github.com/feirai/averin/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// holdGrantAfterInsertStore pauses a real grant after its INSERT, while its
// project transaction still owns the database guard. Only the bound Store is
// wrapped; the handler cannot accidentally fall back to a second connection.
type holdGrantAfterInsertStore struct {
	store.Store
	idem     string
	inserted chan struct{}
	release  chan struct{}
	once     sync.Once
	abort    bool
}

type holdGrantAfterInsertBound struct {
	store.Store
	root *holdGrantAfterInsertStore
}

func (h *holdGrantAfterInsertStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return h.Store.WithProjectWrite(ctx, projectID, func(bound store.Store) error {
		return fn(&holdGrantAfterInsertBound{Store: bound, root: h})
	})
}

func (h *holdGrantAfterInsertBound) PutRecord(projectID, idem string, rec store.Record) (store.Record, bool, error) {
	stored, created, err := h.Store.PutRecord(projectID, idem, rec)
	if err == nil && created && idem == h.root.idem {
		h.root.once.Do(func() { close(h.root.inserted) })
		<-h.root.release
		if h.root.abort {
			return store.Record{}, false, errors.New("injected grant failure after uncommitted INSERT")
		}
	}
	return stored, created, err
}

// newVoidTestPostgres migrates a private schema (exactly as main() does on boot) and returns a Postgres store
// scoped to it plus an admin pool pinned to the same schema. Skips when AVERIN_TEST_DATABASE_URL is unset (the gate
// every Postgres-backed test in this repo uses).
func newVoidTestPostgres(t *testing.T) (*store.Postgres, *pgxpool.Pool) {
	t.Helper()
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run the Postgres-backed broker_seq void tests")
	}
	schema := fmt.Sprintf("averin_void_test_%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	scoped := base + sep + "search_path=" + schema
	admin, err := pgxpool.New(ctx, scoped)
	if err != nil {
		t.Fatalf("connect (admin): %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		_, _ = admin.Exec(dctx, "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	if err := pgschema.Migrate(ctx, scoped); err != nil {
		t.Fatalf("pgschema.Migrate: %v", err)
	}
	pg, err := store.NewPostgres(ctx, scoped)
	if err != nil {
		t.Fatalf("store.NewPostgres: %v", err)
	}
	t.Cleanup(pg.Close)
	return pg, admin
}

// A committed reservation is either voided with its tombstone or left untouched.
func TestBrokerSeqVoidPostgres(t *testing.T) {
	ak := grantAgentKey()
	t.Run("unique index present", func(t *testing.T) {
		pg, _ := newVoidTestPostgres(t)
		h := api.New(mustCore(t), pg, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
		reserveGrantSeq(t, pg, "idem-pg1")
		mkGrant(t, h, ak, "idem-pg2")
		if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
			t.Fatalf("void (%d): %s", code, resp)
		}
		if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Fatalf("checkpoint (%d): %s", code, resp)
		}
		if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-pg1", "read:orders", ak, ak)); code != http.StatusConflict {
			t.Fatalf("late grant (%d): %s", code, resp)
		}
	})
	t.Run("non-unique fallback refuses writes", func(t *testing.T) {
		pg, admin := newVoidTestPostgres(t)
		reserveGrantSeq(t, pg, "idem-pgf")
		ctx := context.Background()
		if _, err := admin.Exec(ctx, `DROP INDEX records_project_record_id_uniq`); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `CREATE INDEX records_project_record_id_idx ON records (project_id, md5(json::jsonb ->> 'record_id'))`); err != nil {
			t.Fatal(err)
		}
		h := api.New(mustCore(t), pg, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
		if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusServiceUnavailable || !strings.Contains(resp, "UNIQUE") {
			t.Fatalf("unsafe void (%d): %s", code, resp)
		}
		if res := reservation(t, pg, 1); res.Voided {
			t.Fatalf("unsafe write changed reservation: %+v", res)
		}
		if _, ok, err := pg.RecordByIdem("p1", "grant-void:1"); err != nil || ok {
			t.Fatalf("unsafe write left tombstone: %v %v", ok, err)
		}
		if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-pgf", "read:orders", ak, ak)); code != http.StatusInternalServerError {
			t.Fatalf("unsafe grant (%d): %s", code, resp)
		}
	})
}

func TestBrokerSeqVoidGrantLandsFirstPostgres(t *testing.T) {
	exerciseBrokerSeqVoidConcurrentGrantPostgres(t, false)
}

func TestBrokerSeqVoidGrantRollsBackPostgres(t *testing.T) {
	exerciseBrokerSeqVoidConcurrentGrantPostgres(t, true)
}

func exerciseBrokerSeqVoidConcurrentGrantPostgres(t *testing.T, abort bool) {
	t.Helper()
	pg, admin := newVoidTestPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Give the void its own pool and a distinct application name so the test
	// observes its actual backend waiting on project_write_guard.
	otherDSN, err := url.Parse(admin.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	appName := fmt.Sprintf("averin_void_guard_wait_%d", time.Now().UnixNano())
	q := otherDSN.Query()
	q.Set("application_name", appName)
	otherDSN.RawQuery = q.Encode()
	other, err := store.NewPostgres(ctx, otherDSN.String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	const idem = "idem-land"
	if seq := reserveGrantSeq(t, pg, idem); seq != 1 {
		t.Fatalf("reserved seq = %d, want 1", seq)
	}
	hold := &holdGrantAfterInsertStore{Store: pg, idem: idem, inserted: make(chan struct{}), release: make(chan struct{}), abort: abort}
	released := false
	defer func() {
		if !released {
			close(hold.release)
		}
	}()
	grantHandler := api.New(mustCore(t), hold, "k0").WithBroker(brokerIssuingKey()).WithRevocation(revocationKey()).Routes()
	voidHandler := api.New(mustCore(t), other, "k0").WithBroker(brokerIssuingKey()).WithRevocation(revocationKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
	ak := grantAgentKey()
	type result struct {
		code int
		body string
	}
	grantDone := make(chan result, 1)
	go func() {
		code, body := do(t, grantHandler, "POST", "/v2/grants", grantBody(idem, "read:orders", ak, ak))
		grantDone <- result{code, body}
	}()
	select {
	case <-hold.inserted:
	case early := <-grantDone:
		t.Fatalf("grant returned before its uncommitted INSERT was held: %d %s", early.code, early.body)
	case <-ctx.Done():
		t.Fatalf("grant did not reach its uncommitted INSERT: %v", ctx.Err())
	}
	// A different project remains writable while p1's grant owns its guard.
	if err := other.WithProjectWrite(ctx, "p2", func(st store.Store) error {
		_, _, err := st.AllocateBrokerSeq("p2", "unrelated-grant")
		return err
	}); err != nil {
		t.Fatalf("independent project stalled: %v", err)
	}
	voidDone := make(chan result, 1)
	go func() {
		code, body := doRecovery(t, voidHandler, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
		voidDone <- result{code, body}
	}()
	for {
		select {
		case early := <-voidDone:
			t.Fatalf("void returned before grant released the project guard: %d %s", early.code, early.body)
		case <-ctx.Done():
			t.Fatalf("void did not reach the project guard: %v", ctx.Err())
		default:
		}
		var waiting bool
		err := admin.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE application_name=$1 AND state='active' AND wait_event_type='Lock'
			  AND query LIKE '%project_write_guard%'
		)`, appName).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect project guard wait: %v", err)
		}
		if waiting {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(hold.release)
	released = true
	select {
	case grant := <-grantDone:
		if abort {
			if grant.code != http.StatusInternalServerError {
				t.Fatalf("injected grant failure did not abort transaction: %d %s", grant.code, grant.body)
			}
		} else if grant.code != http.StatusCreated || grantSeqOf(t, grant.body) != 1 {
			t.Fatalf("held grant did not commit at seq 1: %d %s", grant.code, grant.body)
		}
	case <-ctx.Done():
		t.Fatalf("held grant did not finish: %v", ctx.Err())
	}
	select {
	case void := <-voidDone:
		if abort {
			if void.code != http.StatusCreated || !strings.Contains(void.body, `"created":true`) {
				t.Fatalf("void did not fill the rolled-back grant reservation: %d %s", void.code, void.body)
			}
		} else if void.code != http.StatusConflict || !strings.Contains(void.body, "grant landed; nothing to void") {
			t.Fatalf("void did not lose to the committed grant: %d %s", void.code, void.body)
		}
	case <-ctx.Done():
		t.Fatalf("void did not finish after grant commit: %v", ctx.Err())
	}
	if res := reservation(t, pg, 1); res.Voided != abort {
		t.Fatalf("wrong void marker after grant race: %+v (aborted=%v)", res, abort)
	}
	if _, found, err := pg.RecordByIdem("p1", "grant-void:1"); err != nil || found != abort {
		t.Fatalf("wrong tombstone after grant race: found=%v err=%v aborted=%v", found, err, abort)
	}
	if revoked, err := pg.RevokedGrantIDs("p1"); err != nil || len(revoked) != btoi(abort) {
		t.Fatalf("wrong revocations after grant race: %v %v (aborted=%v)", revoked, err, abort)
	}
	if abort {
		if _, found, err := pg.RecordByIdem("p1", idem); err != nil || found {
			t.Fatalf("aborted grant persisted record: found=%v err=%v", found, err)
		}
		if code, body := do(t, voidHandler, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Fatalf("checkpoint over winning void: %d %s", code, body)
		}
		return
	}
	if code, body := do(t, voidHandler, "POST", "/v2/grants", grantBody(idem, "read:orders", ak, ak)); code != http.StatusCreated || !strings.Contains(body, `"created":false`) || grantSeqOf(t, body) != 1 {
		t.Fatalf("landed grant retry: %d %s", code, body)
	}
	if code, body := do(t, voidHandler, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint over winning grant: %d %s", code, body)
	}
}

func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestBrokerSeqVoidMarkerFailsPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	exerciseVoidMarkerFails(t, pg)
}
