package metrics_test

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/averin-dev/averin/server/internal/metrics"
)

func TestCounterIncAndValue(t *testing.T) {
	r := metrics.NewRegistry()
	c := r.Counter("test_total", "a test counter")
	if c.Value() != 0 {
		t.Fatalf("expected 0, got %d", c.Value())
	}
	c.Inc()
	c.Add(4)
	if c.Value() != 5 {
		t.Fatalf("expected 5, got %d", c.Value())
	}
	var sb strings.Builder
	r.WriteText(&sb)
	out := sb.String()
	if !strings.Contains(out, "# HELP test_total a test counter\n# TYPE test_total counter\ntest_total 5\n") {
		t.Fatalf("unexpected exposition text: %s", out)
	}
}

// TestCounterRegistrationIsIdempotent: calling Counter/CounterVec twice with the same name must
// return the SAME underlying counter (not silently create a second, orphaned one) — a caller that
// re-derives the same metric name (e.g. across two WithX option calls) must not lose increments.
func TestCounterRegistrationIsIdempotent(t *testing.T) {
	r := metrics.NewRegistry()
	a := r.Counter("dup_total", "help")
	b := r.Counter("dup_total", "different help text — must not matter, same counter wins")
	a.Inc()
	b.Inc()
	if a.Value() != 2 {
		t.Fatalf("expected the two Counter() calls to share one counter (value 2), got %d", a.Value())
	}
}

func TestCounterVecLabels(t *testing.T) {
	r := metrics.NewRegistry()
	cv := r.CounterVec("use_total", "use outcomes", "outcome")
	cv.WithLabelValue("allow").Inc()
	cv.WithLabelValue("allow").Inc()
	cv.WithLabelValue("deny").Inc()

	var sb strings.Builder
	r.WriteText(&sb)
	out := sb.String()
	if !strings.Contains(out, `use_total{outcome="allow"} 2`) {
		t.Fatalf("missing allow=2: %s", out)
	}
	if !strings.Contains(out, `use_total{outcome="deny"} 1`) {
		t.Fatalf("missing deny=1: %s", out)
	}
}

func TestGaugeFuncReadsFreshOnEveryRender(t *testing.T) {
	r := metrics.NewRegistry()
	n := 0
	r.GaugeFunc("live_total", "a live gauge", func() float64 { n++; return float64(n) })

	var first strings.Builder
	r.WriteText(&first)
	var second strings.Builder
	r.WriteText(&second)
	if !strings.Contains(first.String(), "live_total 1") {
		t.Fatalf("expected first render to read 1, got: %s", first.String())
	}
	if !strings.Contains(second.String(), "live_total 2") {
		t.Fatalf("expected second render to re-read the callback (2), got: %s", second.String())
	}
}

func TestCounterFuncRendersAsCounterType(t *testing.T) {
	r := metrics.NewRegistry()
	r.CounterFunc("dropped_total", "a monotonic external counter", func() int64 { return 7 })
	var sb strings.Builder
	r.WriteText(&sb)
	out := sb.String()
	if !strings.Contains(out, "# TYPE dropped_total counter\ndropped_total 7") {
		t.Fatalf("unexpected exposition text: %s", out)
	}
}

func TestHandlerServesPrometheusText(t *testing.T) {
	r := metrics.NewRegistry()
	r.Counter("served_total", "served").Inc()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	r.Handler()(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("unexpected content-type: %s", ct)
	}
	if !strings.Contains(rec.Body.String(), "served_total 1") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

// TestConcurrentIncrementsAreRace-safe: Counter.Inc/Add must be safe under concurrent callers (the
// real usage pattern — many request goroutines incrementing the same counter). Run with -race.
func TestConcurrentIncrements(t *testing.T) {
	r := metrics.NewRegistry()
	c := r.Counter("concurrent_total", "help")
	var wg sync.WaitGroup
	const n = 200
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Inc()
		}()
	}
	wg.Wait()
	if c.Value() != n {
		t.Fatalf("expected %d, got %d", n, c.Value())
	}
}
