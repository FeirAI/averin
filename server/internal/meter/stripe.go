package meter

import (
	"context"
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

// post sends one meter event (https://docs.stripe.com/billing/usage-based). Errors are swallowed.
func (s *StripeReporter) post(e event) {
	form := url.Values{}
	form.Set("event_name", e.name)
	form.Set("payload[stripe_customer_id]", e.project) // map project -> customer out of band in prod
	form.Set("payload[value]", strconv.FormatInt(e.value, 10))
	req, err := http.NewRequest("POST", s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := s.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
