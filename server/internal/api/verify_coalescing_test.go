package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/averin-dev/averin/server/internal/core"
	"github.com/averin-dev/averin/server/internal/store"
)

func TestVerifyFlightGroupCoalescesConcurrentWork(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	work := func() (string, error) {
		if calls.Add(1) != 1 {
			t.Fatal("verification work ran more than once")
		}
		close(started)
		<-release
		return `{"ok":true}`, nil
	}

	var group verifyFlightGroup
	first := make(chan struct{})
	go func() {
		defer close(first)
		if report, err := group.run(context.Background(), "tenant-a\x00opts", work); err != nil || report != `{"ok":true}` {
			t.Errorf("first result = %q, %v", report, err)
		}
	}()
	<-started

	second := make(chan struct{})
	go func() {
		defer close(second)
		if report, err := group.run(context.Background(), "tenant-a\x00opts", work); err != nil || report != `{"ok":true}` {
			t.Errorf("second result = %q, %v", report, err)
		}
	}()
	waitForVerifyWaiters(t, &group, "tenant-a\x00opts", 2)
	select {
	case <-second:
		t.Fatal("second request returned before the shared verification completed")
	case <-time.After(25 * time.Millisecond):
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("verification calls = %d, want 1", got)
	}

	close(release)
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("first request did not finish")
	}
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("second request did not finish")
	}
}

func TestVerifyFlightGroupDoesNotCacheErrors(t *testing.T) {
	var calls atomic.Int32
	work := func() (string, error) {
		if calls.Add(1) == 1 {
			return "", errors.New("temporary verification failure")
		}
		return `{"ok":true}`, nil
	}
	var group verifyFlightGroup

	if _, err := group.run(context.Background(), "tenant-a\x00opts", work); err == nil {
		t.Fatal("first verification unexpectedly succeeded")
	}
	report, err := group.run(context.Background(), "tenant-a\x00opts", work)
	if err != nil || report != `{"ok":true}` {
		t.Fatalf("second verification = %q, %v; failure was cached", report, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("verification calls = %d, want 2 after an error", got)
	}
}

func TestVerifyFlightGroupCancellationDoesNotCancelSharedWork(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	work := func() (string, error) {
		close(started)
		<-release
		return `{"ok":true}`, nil
	}
	var group verifyFlightGroup

	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := group.run(ctx, "tenant-a\x00opts", work)
		first <- err
	}()
	<-started

	second := make(chan struct{})
	go func() {
		defer close(second)
		report, err := group.run(context.Background(), "tenant-a\x00opts", work)
		if err != nil || report != `{"ok":true}` {
			t.Errorf("remaining waiter = %q, %v", report, err)
		}
	}()
	waitForVerifyWaiters(t, &group, "tenant-a\x00opts", 2)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
	}
	close(release)
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("remaining waiter did not receive the shared result")
	}
}

func TestVerifyFlightGroupRejectsUniqueProjectsWhenCapacityIsFull(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	work := func() (string, error) {
		close(started)
		<-release
		return `{"ok":true}`, nil
	}
	group := verifyFlightGroup{maxFlights: 1}
	first := make(chan error, 1)
	go func() {
		_, err := group.run(context.Background(), "tenant-a", work)
		first <- err
	}()
	<-started

	if _, err := group.run(context.Background(), "tenant-b", work); !errors.Is(err, errVerifyOverloaded) {
		t.Fatalf("second unique project error = %v, want overload", err)
	}
	group.mu.Lock()
	if got := len(group.flights); got != 1 {
		group.mu.Unlock()
		t.Fatalf("flight map size = %d, want 1", got)
	}
	group.mu.Unlock()

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first project error = %v", err)
	}
}

func waitForVerifyWaiters(t *testing.T, group *verifyFlightGroup, key string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		group.mu.Lock()
		flight := group.flights[key]
		got := 0
		if flight != nil {
			got = flight.waiters
		}
		group.mu.Unlock()
		if got >= want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("verification waiters for %q did not reach %d", key, want)
}

type gatedVerifySealer struct {
	Sealer
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *gatedVerifySealer) VerifyBundleWith(bundleJSON, optsJSON string) string {
	s.calls.Add(1)
	s.once.Do(func() { close(s.started) })
	<-s.release
	return s.Sealer.VerifyBundleWith(bundleJSON, optsJSON)
}

func TestHandleVerifyCoalescesConcurrentCoreCalls(t *testing.T) {
	base, err := core.New("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	sealer := &gatedVerifySealer{
		Sealer:  base,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	srv := New(sealer, store.NewMem(), "k0")
	h := srv.Routes()

	first := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/v2/verify?project=tenant-a", nil))
		first <- rec.Code
	}()
	<-sealer.started

	second := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/v2/verify?project=tenant-a", strings.NewReader("")))
		second <- rec.Code
	}()
	waitForVerifyWaiters(t, &srv.verifyFlights, verificationKey("tenant-a", srv.selfVerifyOpts()), 2)
	select {
	case <-second:
		t.Fatal("concurrent verify returned before the shared core call completed")
	case <-time.After(25 * time.Millisecond):
	}
	if got := sealer.calls.Load(); got != 1 {
		t.Fatalf("core verification calls = %d, want 1", got)
	}

	close(sealer.release)
	if code := <-first; code != 200 {
		t.Fatalf("first verify status = %d, want 200", code)
	}
	if code := <-second; code != 200 {
		t.Fatalf("second verify status = %d, want 200", code)
	}
}

func TestHandleVerifyReturns503WhenUniqueFlightCapacityIsFull(t *testing.T) {
	base, err := core.New("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	sealer := &gatedVerifySealer{
		Sealer:  base,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	srv := New(sealer, store.NewMem(), "k0")
	srv.verifyFlights.maxFlights = 1
	h := srv.Routes()

	first := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/v2/verify?project=tenant-a", nil))
		first <- rec.Code
	}()
	<-sealer.started

	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest("GET", "/v2/verify?project=tenant-b", nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second unique project status = %d, want 503", second.Code)
	}

	close(sealer.release)
	if code := <-first; code != http.StatusOK {
		t.Fatalf("first verify status = %d, want 200", code)
	}
}

type panicVerifySealer struct {
	Sealer
}

func (s panicVerifySealer) VerifyBundleWith(string, string) string {
	panic("sensitive verification internals")
}

func TestHandleVerifyDoesNotExposeRecoveredPanic(t *testing.T) {
	base, err := core.New("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	srv := New(panicVerifySealer{Sealer: base}, store.NewMem(), "k0")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/v2/verify?project=tenant-a", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic verify status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sensitive verification internals") {
		t.Fatalf("panic details leaked to client: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "verification failed") {
		t.Fatalf("sanitized verification error missing: %s", rec.Body.String())
	}
}
