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
		h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
		fs.ambiguousPut = true
		do(t, h, "POST", "/v2/grants", grantBody("idem-pg1", "read:orders", ak, ak))
		mkGrant(t, h, ak, "idem-pg2")
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
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
		h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
		fs.ambiguousPut = true
		do(t, h, "POST", "/v2/grants", grantBody("idem-pgf", "read:orders", ak, ak))
		code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
		if code != http.StatusConflict || !strings.Contains(resp, "does not enforce record_id uniqueness") {
			t.Fatalf("a void without the UNIQUE record_id index must be refused (got %d): %s", code, resp)
		}
		// nothing was voided: the grant's retry still reclaims seq 1.
		if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-pgf", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 1 {
			t.Fatalf("a refused void must leave the reservation for the retry (%d): %s", code, resp)
		}
	})
}
