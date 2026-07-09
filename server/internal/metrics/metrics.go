// Package metrics is a minimal, hand-rolled Prometheus text-exposition registry: sync/atomic
// counters plus gauge/counter callbacks, rendered as Prometheus exposition-format text. This
// deliberately does NOT import github.com/prometheus/client_golang (or any other third-party metrics
// library) — averin's go.mod carries only pgx (+ its transitive deps); a /metrics surface must not
// add a new dependency. Everything here is stdlib (sync, sync/atomic, net/http, fmt, io).
//
// Usage is register-once (typically at server construction / option-application time, single-
// threaded startup) then read-many (one atomic increment per request, one render per scrape) — the
// registry's own bookkeeping lock is only ever contended at registration, never on the request hot
// path (Counter.Inc is a single atomic add).
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically increasing value, safe for concurrent use.
type Counter struct {
	v int64
}

// Inc increments the counter by 1.
func (c *Counter) Inc() { atomic.AddInt64(&c.v, 1) }

// Add increments the counter by delta (delta must be >= 0 — a counter never decreases).
func (c *Counter) Add(delta int64) { atomic.AddInt64(&c.v, delta) }

// Value returns the counter's current value.
func (c *Counter) Value() int64 { return atomic.LoadInt64(&c.v) }

// renderable is anything the registry can emit as one Prometheus exposition-format block.
type renderable interface {
	render(w io.Writer)
}

type simpleCounter struct {
	name, help string
	c          *Counter
}

func (s *simpleCounter) render(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", s.name, s.help, s.name, s.name, s.c.Value())
}

// CounterVec is a fixed-cardinality set of counters distinguished by ONE label. Only ever key it by
// label VALUES the server itself controls (a fixed small enum like "allow"/"deny") — never by raw
// caller input, which would make label cardinality (and thus memory) unbounded.
type CounterVec struct {
	name, help, label string
	mu                sync.Mutex
	values            map[string]*Counter
	order             []string
}

// WithLabelValue returns the counter for the given label value, creating it on first use.
func (cv *CounterVec) WithLabelValue(value string) *Counter {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	c, ok := cv.values[value]
	if !ok {
		c = &Counter{}
		cv.values[value] = c
		cv.order = append(cv.order, value)
	}
	return c
}

func (cv *CounterVec) render(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", cv.name, cv.help, cv.name)
	cv.mu.Lock()
	order := append([]string(nil), cv.order...)
	cv.mu.Unlock()
	for _, v := range order {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", cv.name, cv.label, v, cv.WithLabelValue(v).Value())
	}
}

type gaugeFunc struct {
	name, help string
	fn         func() float64
}

func (g *gaugeFunc) render(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", g.name, g.help, g.name, g.name, g.fn())
}

type counterFunc struct {
	name, help string
	fn         func() int64
}

func (c *counterFunc) render(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", c.name, c.help, c.name, c.name, c.fn())
}

// Registry is a small hand-rolled Prometheus-text metrics registry (counters, labeled counters, and
// gauge/counter callbacks). Safe for concurrent registration and rendering. It is not a general-
// purpose metrics library — just enough to expose averin's countable signals without a new
// third-party dependency.
type Registry struct {
	mu    sync.Mutex
	order []string
	items map[string]renderable
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{items: map[string]renderable{}}
}

func (r *Registry) register(name string, item renderable) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[name]; !exists {
		r.order = append(r.order, name)
	}
	r.items[name] = item
}

// Counter registers (or returns the already-registered) unlabeled counter named name.
func (r *Registry) Counter(name, help string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.items[name]; ok {
		return existing.(*simpleCounter).c
	}
	c := &Counter{}
	r.items[name] = &simpleCounter{name: name, help: help, c: c}
	r.order = append(r.order, name)
	return c
}

// CounterVec registers (or returns the already-registered) label-valued counter set named name,
// distinguished by ONE label named labelName.
func (r *Registry) CounterVec(name, help, labelName string) *CounterVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.items[name]; ok {
		return existing.(*CounterVec)
	}
	cv := &CounterVec{name: name, help: help, label: labelName, values: map[string]*Counter{}}
	r.items[name] = cv
	r.order = append(r.order, name)
	return cv
}

// GaugeFunc registers a gauge named name whose value is fn(), called fresh on every scrape (e.g. a
// live pgx pool connection count). Overwrites any previously registered metric of the same name.
func (r *Registry) GaugeFunc(name, help string, fn func() float64) {
	r.register(name, &gaugeFunc{name: name, help: help, fn: fn})
}

// CounterFunc registers a monotonic counter named name whose value is fn() (a running total already
// tracked elsewhere, e.g. another package's own atomic drop counter). Overwrites any previously
// registered metric of the same name.
func (r *Registry) CounterFunc(name, help string, fn func() int64) {
	r.register(name, &counterFunc{name: name, help: help, fn: fn})
}

// WriteText renders the whole registry as Prometheus text exposition format, in registration order.
func (r *Registry) WriteText(w io.Writer) {
	r.mu.Lock()
	order := append([]string(nil), r.order...)
	items := make([]renderable, len(order))
	for i, name := range order {
		items[i] = r.items[name]
	}
	r.mu.Unlock()
	for _, item := range items {
		item.render(w)
	}
}

// Handler serves the registry as Prometheus exposition-format text (unauthenticated; the caller wires
// it onto whichever mux(es) should expose it).
func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var b strings.Builder
		r.WriteText(&b)
		w.Write([]byte(b.String()))
	}
}
