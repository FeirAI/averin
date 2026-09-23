package api_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/pgschema"
	"github.com/feirai/averin/server/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

// TestBrokerSeqVoidPostgres: on Postgres the void relies on the UNIQUE record_id index as its DB backstop (the
// tombstone's record_id IS the voided grant_id). With the index present a wedged seq voids and unwedges the log; on
// a DB where migration 0002 took the WARNING fallback (a NON-unique index over historical duplicates) the void is
// REFUSED — a still-in-flight commit of the grant (possibly on another instance) and the tombstone could both land.
func TestBrokerSeqVoidPostgres(t *testing.T) {
	ak := grantAgentKey()

	t.Run("unique index present: void unwedges", func(t *testing.T) {
		pg, _ := newVoidTestPostgres(t)
		fs := &flakyGrantStore{Store: pg}
		h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
		fs.ambiguousPut = true
		do(t, h, "POST", "/v2/grants", grantBody("idem-pg1", "read:orders", ak, ak))
		mkGrant(t, h, ak, "idem-pg2")
		if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
			t.Fatalf("void on Postgres with the UNIQUE index (%d): %s", code, resp)
		}
		if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Fatalf("checkpoint after the void (%d): %s", code, resp)
		}
		if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-pg1", "read:orders", ak, ak)); code != http.StatusConflict {
			t.Fatalf("a retry of the voided grant must 409 on Postgres too (got %d): %s", code, resp)
		}
	})

	t.Run("non-unique fallback index: void refused", func(t *testing.T) {
		pg, admin := newVoidTestPostgres(t)
		ctx := context.Background()
		// reproduce 0002's WARNING fallback: the same expression as a plain index.
		if _, err := admin.Exec(ctx, `DROP INDEX records_project_record_id_uniq`); err != nil {
			t.Fatalf("drop unique index: %v", err)
		}
		if _, err := admin.Exec(ctx, `CREATE INDEX records_project_record_id_idx ON records (project_id, md5(json::jsonb ->> 'record_id'))`); err != nil {
			t.Fatalf("create fallback index: %v", err)
		}
		fs := &flakyGrantStore{Store: pg}
		h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
		fs.ambiguousPut = true
		do(t, h, "POST", "/v2/grants", grantBody("idem-pgf", "read:orders", ak, ak))
		code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
		if code != http.StatusConflict || !strings.Contains(resp, "does not enforce record_id uniqueness") {
			t.Fatalf("a void without the UNIQUE record_id index must be refused (got %d): %s", code, resp)
		}
		// nothing was voided: the grant's retry still reclaims seq 1.
		if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-pgf", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 1 {
			t.Fatalf("a refused void must leave the reservation for the retry (%d): %s", code, resp)
		}
	})
}

// heldTxStore holds the next PutRecord's transaction OPEN on Postgres: the row (and its disclosures) is inserted but
// not committed, and the call reports a commit-ambiguous error — a grant whose COMMIT is still in flight. commit()
// lets it land. While it is open its record_id sits uncommitted in the UNIQUE index, so a tombstone INSERT for the
// same record_id blocks on it.
type heldTxStore struct {
	store.Store
	admin    *pgxpool.Pool
	holdNext bool
	tx       pgx.Tx
}

func (h *heldTxStore) PutRecord(p, k string, rec store.Record) (store.Record, bool, error) {
	if !h.holdNext {
		return h.Store.PutRecord(p, k, rec)
	}
	h.holdNext = false
	ctx := context.Background()
	tx, err := h.admin.Begin(ctx)
	if err != nil {
		return store.Record{}, false, err
	}
	parents := rec.Parents
	if parents == nil {
		parents = []string{}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO records (project_id, idempotency_key, content_hash, session_id, parents, json) VALUES ($1, $2, $3, $4, $5, $6)`,
		p, k, rec.ContentHash, rec.SessionID, parents, rec.JSON); err != nil {
		_ = tx.Rollback(ctx)
		return store.Record{}, false, err
	}
	for _, d := range rec.Disclosures {
		if _, err := tx.Exec(ctx, `INSERT INTO disclosures (project_id, record_id, field, value_digest, nonce_hex) VALUES ($1, $2, $3, $4, $5)`,
			p, d.RecordID, d.Field, d.ValueDigest, d.NonceHex); err != nil {
			_ = tx.Rollback(ctx)
			return store.Record{}, false, err
		}
	}
	h.tx = tx
	return store.Record{}, false, fmt.Errorf("%w: injected (commit held in flight)", store.ErrCommitAmbiguous)
}

// TestBrokerSeqVoidGrantLandsFirstPostgres (review finding: the database backstop winning for the grant used to
// leave an inert void marker and a 500 retry loop): the grant's transaction is held open, the void's tombstone INSERT
// blocks on its uncommitted record_id index entry, then the grant COMMITS. The void must answer 409 "grant landed;
// nothing to void" with NO marker written, and the grant's retry must idempotently return its record.
func TestBrokerSeqVoidGrantLandsFirstPostgres(t *testing.T) {
	pg, admin := newVoidTestPostgres(t)
	hs := &heldTxStore{Store: pg, admin: admin}
	h := api.New(mustCore(t), hs, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
	ak := grantAgentKey()
	hs.holdNext = true
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-land", "read:orders", ak, ak)); code != http.StatusInternalServerError {
		t.Fatalf("the grant's in-flight commit must 500 (got %d): %s", code, resp)
	}
	if hs.tx == nil {
		t.Fatal("the grant's transaction was not held")
	}
	exerciseVoidGrantLandsFirst(t, pg, h, func() (int, string) {
		type result struct {
			code int
			resp string
		}
		done := make(chan result, 1)
		go func() {
			c, r := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
			done <- result{c, r}
		}()
		// wait until the void's tombstone INSERT is blocked on the grant's uncommitted index entry.
		ctx := context.Background()
		deadline := time.Now().Add(20 * time.Second)
		for {
			var waiting bool
			if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND wait_event_type = 'Lock' AND query ILIKE '%INSERT INTO records%')`).Scan(&waiting); err != nil {
				t.Fatalf("pg_stat_activity: %v", err)
			}
			if waiting {
				break
			}
			select {
			case r := <-done:
				t.Fatalf("the void returned before the grant committed (%d): %s", r.code, r.resp)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("the void's tombstone insert never blocked on the in-flight grant")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err := hs.tx.Commit(ctx); err != nil { // the grant's commit lands
			t.Fatalf("commit held grant: %v", err)
		}
		r := <-done
		return r.code, r.resp
	})
}

// TestBrokerSeqVoidMarkerFailsPostgres: tombstone sealed, marker write failed → a repeat completes (see
// exerciseVoidMarkerFails), on Postgres.
func TestBrokerSeqVoidMarkerFailsPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	exerciseVoidMarkerFails(t, pg)
}
