package pgdurable

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestStore connects to AVERIN_TEST_DATABASE_URL (skipping if unset, matching the store/pgledger
// packages' Postgres test gate), creates a private schema, and returns a Store scoped to it via
// search_path. The returned cleanup drops the schema and closes both pools.
func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run Postgres-backed pgdurable tests")
	}
	schema := fmt.Sprintf("averin_pgdurable_test_%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect (admin): %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}

	// Append search_path as a query param, choosing the separator by whether the DSN already carries
	// a query string. The CI-style DSN (postgres://user:pw@host:5432/db) has NO '?', so a blind '&'
	// produced an INVALID connstring (search_path swallowed into the path/dbname) and every
	// Postgres-backed pgdurable test errored out — the exact break this test never ran against in CI.
	// pgxpool.New -> ParseConfig turns an unrecognized query param into a startup RuntimeParam, so a
	// well-formed '?search_path=<schema>' pins the schema for both the setup pool and the store's own
	// New(dsn) pool (same mechanism the store tests use via cfg.ConnConfig.RuntimeParams).
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	scoped := base + sep + "search_path=" + schema
	// New no longer applies DDL (the versioned runner internal/pgschema owns it now), so create the
	// package's tables in the private schema for this unit test, via a pool scoped to that schema.
	setup, err := pgxpool.New(ctx, scoped)
	if err != nil {
		admin.Close()
		t.Fatalf("connect (setup): %v", err)
	}
	if _, err := setup.Exec(ctx, SchemaSQL); err != nil {
		setup.Close()
		admin.Close()
		t.Fatalf("apply schema: %v", err)
	}
	setup.Close()

	s, err := New(ctx, scoped)
	if err != nil {
		admin.Close()
		t.Fatalf("New: %v", err)
	}
	return s, func() {
		s.Close()
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		if _, err := admin.Exec(dctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Logf("cleanup: drop schema %s: %v", schema, err)
		}
		admin.Close()
	}
}

// TestPutPendingConflictReturnsWinningRow (review finding B): pending_grants carries a MUTABLE payload
// (unlike revocations, a monotone-add fact) — two mints of the SAME idem key (e.g. two averin replicas
// racing on a shared AVERIN_DATABASE_URL) produce DIFFERENT challenges. The loser of the race must not go
// on serving its own local mint once a DIFFERENT row is durable: PutPending must detect the conflict and
// return the WINNING writer's payload/created_at so the caller caches/serves that instead, and the durable
// row itself must never be overwritten by the loser.
func TestPutPendingConflictReturnsWinningRow(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	created := time.Now()
	firstPayload := []byte(`{"who":"first"}`)
	secondPayload := []byte(`{"who":"second"}`)

	gotFirst, firstCreated, err := s.PutPending("p1", "idem-1", "grant-1", firstPayload, created)
	if err != nil {
		t.Fatalf("first (winning) PutPending: %v", err)
	}
	if string(gotFirst) != string(firstPayload) {
		t.Fatalf("first (winning) PutPending should return its own payload, got %s", gotFirst)
	}

	// A second writer for the SAME idem key with a DIFFERENT payload (as if it minted concurrently, baking
	// in a different call-time now) — must lose the race and get back the FIRST writer's durable payload,
	// not silently succeed with its own.
	gotSecond, secondCreated, err := s.PutPending("p1", "idem-1", "grant-1-other", secondPayload, created.Add(time.Second))
	if err != nil {
		t.Fatalf("second (losing) PutPending: %v", err)
	}
	if string(gotSecond) != string(firstPayload) {
		t.Fatalf("second (losing) PutPending must return the FIRST writer's durable payload, got %s want %s", gotSecond, firstPayload)
	}
	if !secondCreated.Equal(firstCreated) {
		t.Fatalf("second (losing) PutPending must return the FIRST writer's created_at, got %v want %v", secondCreated, firstCreated)
	}

	// The durable row itself must still hold the FIRST writer's payload — never overwritten by the loser.
	rows, err := s.LoadPending(context.Background())
	if err != nil {
		t.Fatalf("LoadPending: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 durable pending row, got %d", len(rows))
	}
	if string(rows[0].Payload) != string(firstPayload) {
		t.Fatalf("durable row was overwritten by the losing writer: %s", rows[0].Payload)
	}
}
