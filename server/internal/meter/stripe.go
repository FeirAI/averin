package meter

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	events      chan event // bounded async queue (one worker) — no unbounded goroutine fan-out
}

type event struct {
	name, project string
	value         int64
}

type StripeConfig struct {
	APIKey            string
	RecordEventName   string
	ExportEventName   string
	Endpoint          string // override for tests; defaults to Stripe
	Client            *http.Client
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
		recordMeter: orDefault(cfg.RecordEventName, "feir_record"),
		exportMeter: orDefault(cfg.ExportEventName, "feir_export"),
		endpoint:    ep,
		client:      cl,
	}
	if r.apiKey != "" {
		r.events = make(chan event, 1024)
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
	}
}

func (s *StripeReporter) worker() {
	for e := range s.events {
		s.post(e)
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
