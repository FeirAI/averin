package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// rssBytes returns this process's resident set size from /proc/self/statm.
func rssBytes(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		t.Fatal(err)
	}
	var size, resident int64
	if _, err := fmt.Sscan(string(b), &size, &resident); err != nil {
		t.Fatal(err)
	}
	return resident * int64(os.Getpagesize())
}

// TestWholeBundleVerifyDoesNotRetainArenaMemory: glibc keeps one malloc arena per OS thread and never
// returns freed pages, so a whole-history verification on N distinct cgo threads used to leave N peaks
// resident (soak: RSS doubling per hour). The fix trims the C heap after each full-bundle verification.
func TestWholeBundleVerifyDoesNotRetainArenaMemory(t *testing.T) {
	if runtime.GOOS != "linux" || !core.HeapTrimSupported() {
		t.Skip("malloc_trim exists only on linux/glibc; nothing to assert on this platform")
	}
	s := New(testCore(t), store.NewMem(), "k0").WithAuth(auth.NewOpenStore())
	h := s.Routes()
	// 1000 generic records over 12 sessions, a checkpoint every 100 records.
	for batch := 0; batch < 10; batch++ {
		var parts []string
		for i := 0; i < 100; i++ {
			n := batch*100 + i
			parts = append(parts, fmt.Sprintf(`{"idempotency_key":"k%d","project_id":"p","session_id":"s%d","action":"tool.call"}`, n, n%12))
		}
		if code, resp := arenaDo(h, "POST", "/v2/records", "["+strings.Join(parts, ",")+"]"); code != http.StatusCreated {
			t.Fatalf("ingest (%d): %s", code, resp)
		}
		if code, resp := arenaDo(h, "POST", "/v2/checkpoints?project=p", ""); code != http.StatusCreated {
			t.Fatalf("checkpoint (%d): %s", code, resp)
		}
	}
	bundle, err := s.buildBundle("p", false)
	if err != nil {
		t.Fatal(err)
	}
	opts := s.selfVerifyOptsFor("p")

	// 8 distinct, parked OS threads so each verification can land in its own glibc arena.
	const threads = 8
	jobs := make([]chan func(), threads)
	var wg sync.WaitGroup
	for i := range jobs {
		jobs[i] = make(chan func())
		wg.Add(1)
		go func(c chan func()) {
			defer wg.Done()
			runtime.LockOSThread()
			for f := range c {
				f()
			}
		}(jobs[i])
	}
	defer func() {
		for _, c := range jobs {
			close(c)
		}
		wg.Wait()
	}()

	settle := func() { runtime.GC(); debug.FreeOSMemory() }
	settle()
	before := rssBytes(t)
	for i, c := range jobs {
		done := make(chan string)
		c <- func() { done <- s.core.VerifyBundleWith(bundle, opts) }
		if rep := <-done; !strings.Contains(rep, `"ok":true`) && !strings.Contains(rep, `"ok": true`) {
			t.Fatalf("thread %d: bundle did not verify: %.300s", i, rep)
		}
	}
	settle()
	growth := rssBytes(t) - before
	t.Logf("bundle %d bytes, RSS growth after %d whole-bundle verifications on %d threads: %d MB", len(bundle), threads, threads, growth>>20)
	if growth > 32<<20 {
		t.Fatalf("RSS grew %d MB (limit 32 MB): freed C-heap arenas are being retained after whole-bundle verification", growth>>20)
	}
}

// arenaDo serves one request on h and returns the status and body.
func arenaDo(h http.Handler, method, path, body string) (int, string) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec.Code, rec.Body.String()
}
