package api

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/averin-dev/averin/server/internal/store"
)

// These tests exercise the finding-C fix directly: handleGrantPrepare/handleRevoke used to hold a SINGLE
// process-wide mutex across the durable Postgres round-trip (up to opTimeout=10s), so a slow/degraded DB
// serialized ALL prepares/revokes, not just ones racing for the same idem-key/project (a self-inflicted
// DoS). They now serialize per-idem-key (pendingKeyLocks) / per-project (revokeLocks) instead. No real
// Postgres is needed here: both handlers take their keyed lock UNCONDITIONALLY (even with s.durable == nil,
// which skips the DB round-trip entirely), so grabbing the SAME keyedMutex directly from the test — as if
// another goroutine's in-flight request were mid-round-trip — is a faithful, hermetic way to simulate
// contention without a fake/slow durable double.

// TestHandleGrantPrepareDifferentIdemKeysDoNotBlock: a prepare for idem key "B" must complete promptly even
// while idem key "A"'s lock is held (simulating a same-key prepare stuck in a slow PutPending) — different
// keys must run fully concurrently.
func TestHandleGrantPrepareDifferentIdemKeysDoNotBlock(t *testing.T) {
	brokerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	s := New(testCore(t), store.NewMem(), "k0").WithBroker(brokerKey)

	unlockA := s.pendingKeyLocks.Lock(pendingKey("p1", "idem-A"))
	defer unlockA()

	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequest("POST", "/v2/grants/prepare", bytes.NewReader([]byte(grantChallengeBody("idem-B", "read:orders", agentKey))))
		w := httptest.NewRecorder()
		s.handleGrantPrepare(w, req)
		done <- w.Code
	}()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("prepare for a DIFFERENT idem key failed: %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prepare for a DIFFERENT idem key blocked on another key's lock — per-key serialization is too coarse")
	}
}

// TestHandleGrantPrepareSameIdemKeyBlocks: a prepare for idem key "same" must stay blocked while ANOTHER
// holder of that SAME key's lock has not released it, and complete promptly once it does — the
// mint/persist/cache critical section must stay atomic per key (correctness preserved, not weakened).
func TestHandleGrantPrepareSameIdemKeyBlocks(t *testing.T) {
	brokerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	s := New(testCore(t), store.NewMem(), "k0").WithBroker(brokerKey)

	unlockSame := s.pendingKeyLocks.Lock(pendingKey("p1", "idem-same"))

	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequest("POST", "/v2/grants/prepare", bytes.NewReader([]byte(grantChallengeBody("idem-same", "read:orders", agentKey))))
		w := httptest.NewRecorder()
		s.handleGrantPrepare(w, req)
		done <- w.Code
	}()
	select {
	case <-done:
		t.Fatal("prepare for the SAME idem key completed while another holder still held that key's lock")
	case <-time.After(200 * time.Millisecond):
		// expected: still blocked
	}
	unlockSame()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("prepare after the same-key lock was released failed: %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prepare never completed after the same-key lock was released")
	}
}

// TestHandleRevokeDifferentProjectsDoNotBlock: mirrors the prepare test above for handleRevoke — a revoke
// for project "p2" must complete promptly even while project "p1"'s lock is held.
func TestHandleRevokeDifferentProjectsDoNotBlock(t *testing.T) {
	_, revKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(testCore(t), store.NewMem(), "k0").WithRevocation(revKey)

	unlockP1 := s.revokeLocks.Lock("p1")
	defer unlockP1()

	done := make(chan int, 1)
	go func() {
		body := `{"project_id":"p2","grant_id":"g-1"}`
		req := httptest.NewRequest("POST", "/v2/revoke?project=p2", bytes.NewReader([]byte(body)))
		w := httptest.NewRecorder()
		s.handleRevoke(w, req)
		done <- w.Code
	}()
	select {
	case code := <-done:
		if code != http.StatusCreated {
			t.Fatalf("revoke for a DIFFERENT project failed: %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoke for a DIFFERENT project blocked on another project's lock — per-project serialization is too coarse")
	}
}

// TestHandleRevokeSameProjectBlocks: a revoke for project "p1" must stay blocked while another holder of
// that SAME project's lock has not released it — the cap-check-then-persist-then-write critical section
// must stay atomic per project (correctness preserved, not weakened — see handleRevoke's doc comment).
func TestHandleRevokeSameProjectBlocks(t *testing.T) {
	_, revKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(testCore(t), store.NewMem(), "k0").WithRevocation(revKey)

	unlockP1 := s.revokeLocks.Lock("p1")

	done := make(chan int, 1)
	go func() {
		body := `{"project_id":"p1","grant_id":"g-1"}`
		req := httptest.NewRequest("POST", "/v2/revoke?project=p1", bytes.NewReader([]byte(body)))
		w := httptest.NewRecorder()
		s.handleRevoke(w, req)
		done <- w.Code
	}()
	select {
	case <-done:
		t.Fatal("revoke for the SAME project completed while another holder still held that project's lock")
	case <-time.After(200 * time.Millisecond):
		// expected: still blocked
	}
	unlockP1()
	select {
	case code := <-done:
		if code != http.StatusCreated {
			t.Fatalf("revoke after the same-project lock was released failed: %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoke never completed after the same-project lock was released")
	}
}
