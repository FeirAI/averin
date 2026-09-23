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

// A committed reservation is either voided with its tombstone or left untouched.
func TestBrokerSeqVoidPostgres(t *testing.T) {
	ak := grantAgentKey()
	t.Run("unique index present", func(t *testing.T) {
		pg, _ := newVoidTestPostgres(t)
		h := api.New(mustCore(t), pg, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
		reserveGrantSeq(t, pg, "idem-pg1")
		mkGrant(t, h, ak, "idem-pg2")
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
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
		h := api.New(mustCore(t), pg, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusServiceUnavailable || !strings.Contains(resp, "UNIQUE") {
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
	pg, _ := newVoidTestPostgres(t)
	h := api.New(mustCore(t), pg, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
	exerciseVoidGrantLandsFirst(t, pg, h)
}

func TestBrokerSeqVoidMarkerFailsPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	exerciseVoidMarkerFails(t, pg)
}
