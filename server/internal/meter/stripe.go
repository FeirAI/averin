package meter

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StripeReporter forwards billable events to Stripe's meter-events API as they happen. It wraps a
// base Meter (so counting still works locally) and is best-effort: a reporting failure never affects
// ingestion or the integrity guarantees. With no API key it is a no-op counter.
type StripeReporter struct {
	Meter
	apiKey      string
	recordMeter string // Stripe meter event_name for sealed records
	exportMeter string // Stripe meter event_name for exports
	endpoint    string
	client      *http.Client
	events      chan event    // bounded async queue (one worker) — no unbounded goroutine fan-out
	done        chan struct{} // closed when the worker drains + exits (for graceful Close)
	closeOnce   sync.Once
	dropped     int64 // atomic: events dropped because the bounded queue was full (see send). Read via Dropped().
	postFailed  int64 // atomic: events whose Stripe delivery failed (transport error or non-2xx). Read via PostFailures().
}

type event struct {
	name, project string
	value         int64
}

type StripeConfig struct {
	APIKey          string
	RecordEventName string
	ExportEventName string
	Endpoint        string // override for tests; defaults to Stripe
	Client          *http.Client
}

func NewStripeReporter(base Meter, cfg StripeConfig) *StripeReporter {
	ep := cfg.Endpoint
	if ep == "" {
		ep = "https://api.stripe.com/v1/billing/meter_events"
	}
	cl := cfg.Client
	if cl == nil {
		cl = &http.Client{Timeout: 5 * time.Second}
	}
	r := &StripeReporter{
		Meter:       base,
		apiKey:      cfg.APIKey,
		recordMeter: orDefault(cfg.RecordEventName, "averin_record"),
		exportMeter: orDefault(cfg.ExportEventName, "averin_export"),
		endpoint:    ep,
		client:      cl,
	}
	if r.apiKey != "" {
		r.events = make(chan event, 1024)
		r.done = make(chan struct{})
		go r.worker()
	}
	return r
}

func (s *StripeReporter) RecordsIngested(project string, n int) {
	// bill only the change in billable count (records above the free tier), so a batch that
	// straddles the free-tier boundary is not over-billed.
	before, _ := Billable(s.Usage(project))
	s.Meter.RecordsIngested(project, n)
	after, _ := Billable(s.Usage(project))
	if delta := after - before; delta > 0 {
		s.send(s.recordMeter, project, delta)
	}
}

func (s *StripeReporter) ExportIssued(project string) {
	s.Meter.ExportIssued(project)
	s.send(s.exportMeter, project, 1)
}

// send enqueues a Stripe meter event. Best-effort and non-blocking: if the bounded queue is full
// (Stripe outage / overload) the event is dropped rather than blocking or spawning goroutines.
func (s *StripeReporter) send(eventName, project string, value int64) {
	if s.events == nil {
		return
	}
	select {
	case s.events <- event{eventName, project, value}:
	default: // drop under back-pressure — metering must never block recording
		atomic.AddInt64(&s.dropped, 1)
	}
}

// Dropped returns the total number of billable events dropped because the bounded async queue was
// full (a Stripe outage / overload). Exposed for /metrics (a nonzero, growing rate means metering
// events — and thus revenue — are being silently lost).
func (s *StripeReporter) Dropped() int64 { return atomic.LoadInt64(&s.dropped) }

// PostFailures returns the total number of billable events whose Stripe delivery FAILED — a transport
// error or a non-2xx response (most often an unmapped project→stripe_customer_id, since post() maps
// project verbatim onto stripe_customer_id). These events are NOT retried (durable retried delivery is a
// DEFERRED item — see docs/dev/CONFIGURATION.md §Metering), so a nonzero, growing count is silent
// under-billing. Exposed on /metrics as averin_meter_post_failures_total.
func (s *StripeReporter) PostFailures() int64 { return atomic.LoadInt64(&s.postFailed) }

func (s *StripeReporter) worker() {
	defer close(s.done)
	for e := range s.events {
		s.post(e)
	}
}

// Close drains the queued billable events (so a graceful shutdown does not silently drop revenue
// metering) and waits for the worker to finish, bounded by ctx. It MUST be called only AFTER the
// HTTP server has drained (no handler can still call send) — sending on the closed channel would
// panic; the caller orders this after httpSrv.Shutdown. A no-op when no API key is configured.
func (s *StripeReporter) Close(ctx context.Context) {
	if s.events == nil {
		return
	}
	s.closeOnce.Do(func() { close(s.events) })
	select {
	case <-s.done: // worker drained the buffer + exited
	case <-ctx.Done(): // deadline hit — remaining events are best-effort lost (logged by the caller)
	}
}

// post sends one meter event (https://docs.stripe.com/billing/usage-based). Delivery is best-effort and
// NOT retried; a transport error or a non-2xx response is counted (PostFailures, surfaced on /metrics) and
// logged rather than swallowed, so silent under-billing is observable. A non-2xx is most often an unmapped
// project→stripe_customer_id (this maps project verbatim onto stripe_customer_id).
func (s *StripeReporter) post(e event) {
	form := url.Values{}
	form.Set("event_name", e.name)
	form.Set("payload[stripe_customer_id]", e.project) // map project -> customer out of band in prod
	form.Set("payload[value]", strconv.FormatInt(e.value, 10))
	req, err := http.NewRequest("POST", s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		atomic.AddInt64(&s.postFailed, 1)
		log.Printf("WARNING: build Stripe meter-event %q for project %q failed: %v (billable event LOST, not retried)", e.name, e.project, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		atomic.AddInt64(&s.postFailed, 1)
		log.Printf("WARNING: POST Stripe meter-event %q for project %q failed: %v (billable event LOST, not retried)", e.name, e.project, err)
		return
	}
	// Drain then close so the keep-alive connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		atomic.AddInt64(&s.postFailed, 1)
		log.Printf("WARNING: Stripe meter-event %q for project %q returned HTTP %d (billable event LOST, not retried; check the project→stripe_customer_id mapping)", e.name, e.project, resp.StatusCode)
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
