package pgledger_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/feir-dev/feir/server/internal/pgledger"
	"github.com/feir-dev/feir/server/internal/resourceshim"
)

// Set FEIR_TEST_DATABASE_URL (e.g. postgres://postgres:postgres@localhost:5432/postgres) to enable.
func TestPostgresLedger(t *testing.T) {
	dsn := os.Getenv("FEIR_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set FEIR_TEST_DATABASE_URL to run the Postgres ledger test")
	}
	ctx := context.Background()
	l, err := pgledger.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// unique keys so the shared test DB has no cross-run collisions
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nonce, jti := "n-"+suffix, "j-"+suffix

	// first consume succeeds; a second is a replay / double-spend.
	if err := l.ConsumeNonce(nonce); err != nil {
		t.Fatalf("first ConsumeNonce: %v", err)
	}
	if err := l.ConsumeNonce(nonce); !errors.Is(err, resourceshim.ErrConsumed) {
		t.Fatalf("a nonce replay must be ErrConsumed, got %v", err)
	}
	if err := l.ConsumeJTI(jti); err != nil {
		t.Fatalf("first ConsumeJTI: %v", err)
	}
	if err := l.ConsumeJTI(jti); !errors.Is(err, resourceshim.ErrConsumed) {
		t.Fatalf("a jti double-spend must be ErrConsumed, got %v", err)
	}

	// Release un-burns -> the nonce is re-consumable (the pre-persistence rollback).
	l.ReleaseNonce(nonce)
	if err := l.ConsumeNonce(nonce); err != nil {
		t.Fatalf("after Release, re-consume must succeed: %v", err)
	}

	// DURABILITY: a FRESH Ledger (simulating a process restart) still sees the consumption — the whole
	// point of the durable ledger vs the volatile MemLedger.
	l2, err := pgledger.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if err := l2.ConsumeNonce(nonce); !errors.Is(err, resourceshim.ErrConsumed) {
		t.Fatalf("durability: a restart must still see the nonce consumed, got %v", err)
	}

	// CONCURRENCY: many racers consume the SAME key -> exactly one wins (atomic INSERT, no read-then-write).
	raceKey := "race-" + suffix
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.ConsumeJTI(raceKey) == nil {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one racer must win the consume, got %d", wins)
	}

	// cleanup the keys this run created (best-effort; the table is operational state, not evidence).
	l.ReleaseNonce(nonce)
	l.ReleaseJTI(jti)
	l.ReleaseJTI(raceKey)
}
