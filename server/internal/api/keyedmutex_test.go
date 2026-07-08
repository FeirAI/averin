package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestKeyedMutexSameKeySerializes: two goroutines locking the SAME key must never run their critical
// sections concurrently (mirrors what a single sync.Mutex would guarantee).
func TestKeyedMutexSameKeySerializes(t *testing.T) {
	var km keyedMutex
	var inCritical int32
	var sawOverlap int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := km.Lock("same-key")
			defer unlock()
			if atomic.AddInt32(&inCritical, 1) > 1 {
				atomic.StoreInt32(&sawOverlap, 1)
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&inCritical, -1)
		}()
	}
	wg.Wait()
	if atomic.LoadInt32(&sawOverlap) != 0 {
		t.Fatal("two holders of the SAME key ran concurrently — keyedMutex failed to serialize")
	}
}

// TestKeyedMutexDifferentKeysConcurrent: locking DIFFERENT keys must NOT block on each other — this is the
// whole point of the keyed lock (finding C: a slow Postgres round-trip for one idem-key/project must not
// stall every other one).
func TestKeyedMutexDifferentKeysConcurrent(t *testing.T) {
	var km keyedMutex
	const n = 10
	release := make(chan struct{})
	entered := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			unlock := km.Lock(string(rune('a' + i)))
			defer unlock()
			entered <- struct{}{}
			<-release
		}(i)
	}
	// All n holders (distinct keys) must be able to enter their critical section WITHOUT any of them
	// releasing first — if they were serialized on one lock, this would deadlock and time out.
	for i := 0; i < n; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d/%d distinct-key holders entered concurrently — keys are blocking each other", i, n)
		}
	}
	close(release)
	wg.Wait()
}

// TestKeyedMutexNoLeak: once every holder/waiter has unlocked, the internal map must not retain the key —
// otherwise a long-running process (an idem key or project id per request) would leak memory forever.
func TestKeyedMutexNoLeak(t *testing.T) {
	var km keyedMutex
	for i := 0; i < 100; i++ {
		unlock := km.Lock("k")
		unlock()
	}
	km.mu.Lock()
	n := len(km.locks)
	km.mu.Unlock()
	if n != 0 {
		t.Fatalf("keyedMutex leaked %d entries after all unlocks", n)
	}
}
