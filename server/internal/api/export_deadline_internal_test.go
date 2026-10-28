package api

import (
	"context"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

func TestParseExportTimeout(t *testing.T) {
	good := map[string]time.Duration{"": 10 * time.Minute, "15m": 15 * time.Minute, "1m": time.Minute, "60m": time.Hour, "1h": time.Hour, " 20m ": 20 * time.Minute}
	for in, want := range good {
		got, err := ParseExportTimeout(in)
		if err != nil || got != want {
			t.Errorf("ParseExportTimeout(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"30s", "2h", "-1m", "0", "abc", "61m", "59s", "10"} {
		if got, err := ParseExportTimeout(in); err == nil {
			t.Errorf("ParseExportTimeout(%q) = %v, want an error", in, got)
		}
	}
}

// slowLoadStore delays the whole-history record load, standing in for a build that runs past its deadline.
type slowLoadStore struct {
	store.Store
	delay *atomic.Int64 // nanoseconds
}

func (c *slowLoadStore) bind(st store.Store) *slowLoadStore {
	return &slowLoadStore{Store: st, delay: c.delay}
}
func (c *slowLoadStore) WithProjectRead(ctx context.Context, p string, fn func(store.Store) error) error {
	return c.Store.WithProjectRead(ctx, p, func(st store.Store) error { return fn(c.bind(st)) })
}
func (c *slowLoadStore) AllRecords(p string) ([]store.Record, error) {
	time.Sleep(time.Duration(c.delay.Load()))
	return c.Store.AllRecords(p)
}

func deadlineServer(t *testing.T, d time.Duration) (*Server, *slowLoadStore, http.Handler) {
	t.Helper()
	now := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	cs := &slowLoadStore{Store: store.NewMem().WithClock(clock), delay: &atomic.Int64{}}
	s := New(testCore(t), cs, "k0").WithAuth(auth.NewOpenStore()).WithClock(clock).WithBundleDeadline(d)
	h := s.Routes()
	seedHistory(t, h, "acme", 6, rand.New(rand.NewSource(1)), 3)
	return s, cs, h
}

func TestExportPastDeadlineAnswers504BeforeAnyByteAndKeepsTheSlot(t *testing.T) {
	s, cs, h := deadlineServer(t, 200*time.Millisecond)
	// three other builds are in flight: the abandoned export's worker holds the fourth slot.
	for i := 0; i < maxConcurrentBundleReads-1; i++ {
		s.bundleSem <- struct{}{}
	}
	cs.delay.Store(int64(700 * time.Millisecond))
	start := time.Now()
	code, body := precheckDo(h, "GET", "/v2/export?project=acme", "")
	if code != http.StatusGatewayTimeout {
		t.Fatalf("slow export: %d %s, want 504", code, body)
	}
	if el := time.Since(start); el > 600*time.Millisecond {
		t.Fatalf("504 took %s, want about the 200ms deadline", el)
	}
	for _, want := range []string{"AVERIN_EXPORT_TIMEOUT", "GET /v2/segments", "month=YYYY-MM"} {
		if !strings.Contains(body, want) {
			t.Errorf("504 body %q lacks %q", body, want)
		}
	}
	if v := s.mBundleDeadline.WithLabelValue("export").Value(); v != 1 {
		t.Errorf("deadline counter = %d, want 1", v)
	}
	// I6: the worker still owns its slot, so the cap holds while the abandoned build runs.
	if code, _ := precheckDo(h, "GET", "/v2/export?project=acme", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("export while the abandoned build runs: %d, want 503", code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(s.bundleSem) > maxConcurrentBundleReads-1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(s.bundleSem) != maxConcurrentBundleReads-1 {
		t.Fatalf("slot not released after the abandoned build ended: %d held", len(s.bundleSem))
	}
	cs.delay.Store(0)
	if code, body := precheckDo(h, "GET", "/v2/export?project=acme", ""); code != http.StatusOK {
		t.Fatalf("export after the slot freed: %d %s", code, body)
	}
}

func TestExportWithinDeadlineIsUnchanged(t *testing.T) {
	s, _, h := deadlineServer(t, 5*time.Second)
	code, body := precheckDo(h, "GET", "/v2/export?project=acme", "")
	if code != http.StatusOK || !strings.Contains(body, `"gap_report"`) {
		t.Fatalf("export: %d %s", code, body)
	}
	if len(s.bundleSem) != 0 {
		t.Fatalf("slot leaked after a normal export: %d held", len(s.bundleSem))
	}
}

func TestVerifyPastDeadlineAnswers504(t *testing.T) {
	s, cs, h := deadlineServer(t, 200*time.Millisecond)
	cs.delay.Store(int64(700 * time.Millisecond))
	code, body := precheckDo(h, "GET", "/v2/verify?project=acme", "")
	if code != http.StatusGatewayTimeout || !strings.Contains(body, "AVERIN_EXPORT_TIMEOUT") {
		t.Fatalf("slow verify: %d %s, want 504", code, body)
	}
	if v := s.mBundleDeadline.WithLabelValue("verify").Value(); v != 1 {
		t.Errorf("deadline counter = %d, want 1", v)
	}
	// the shared flight finishes on its own and leaves no slot held.
	deadline := time.Now().Add(5 * time.Second)
	for len(s.bundleSem) > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(s.bundleSem) != 0 {
		t.Fatalf("verify flight leaked a slot: %d held", len(s.bundleSem))
	}
	cs.delay.Store(0)
	if code, body := precheckDo(h, "GET", "/v2/verify?project=acme", ""); code != http.StatusOK {
		t.Fatalf("verify after: %d %s", code, body)
	}
}
