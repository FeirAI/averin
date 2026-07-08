package api

import "sync"

// keyedMutex serializes operations that share a key while letting operations on DIFFERENT keys run fully
// concurrently. It exists so a slow/degraded Postgres round-trip (PutPending, Revoke — up to opTimeout=10s)
// held inside a critical section only blocks OTHER callers contending for the SAME idem-key / project-id,
// not every /v2/grants/prepare or /v2/revoke on the whole process (see handleGrantPrepare and handleRevoke).
//
// Per-key locks are created lazily and reference-counted, so the backing map never retains an entry once
// nothing holds or is waiting on that key — safe for an unbounded key space (idem keys, project ids) under
// long-running process uptime.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedMutexEntry
}

type keyedMutexEntry struct {
	mu   sync.Mutex
	refs int
}

// Lock blocks until the caller holds the lock for key, then returns an unlock func the caller MUST call
// exactly once (typically via `defer`) to release it. Locking two DIFFERENT keys never blocks on each
// other; locking the SAME key from two goroutines serializes them, matching a single sync.Mutex per key.
func (k *keyedMutex) Lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedMutexEntry{}
	}
	e, ok := k.locks[key]
	if !ok {
		e = &keyedMutexEntry{}
		k.locks[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.locks, key) // last holder/waiter gone — nothing left to reference this entry
		}
		k.mu.Unlock()
	}
}
