package meter

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestMemCountingAndBillable(t *testing.T) {
	m := NewMem()
	m.RecordsIngested("p1", 3)
	m.RecordsIngested("p1", 2)
	m.ExportIssued("p1")
	u := m.Usage("p1")
	if u.Records != 5 || u.Exports != 1 {
		t.Fatalf("bad usage: %+v", u)
	}
	// under the free tier -> 0 billable records
	if r, e := Billable(u); r != 0 || e != 1 {
		t.Fatalf("billable under free tier wrong: r=%d e=%d", r, e)
	}
	m.RecordsIngested("p1", FreeTierRecords)
	if r, _ := Billable(m.Usage("p1")); r != 5 {
		t.Fatalf("billable above free tier wrong: %d", r)
	}
}

func TestStripeReporterPostsMeterEvents(t *testing.T) {
	got := make(chan url.Values, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk_test_x" {
			t.Errorf("missing/wrong auth header")
		}
		r.ParseForm()
		got <- r.PostForm
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rep := NewStripeReporter(NewMem(), StripeConfig{APIKey: "sk_test_x", Endpoint: srv.URL})

	// export always bills
	rep.ExportIssued("cust-1")
	select {
	case f := <-got:
		if f.Get("event_name") != "averin_export" || f.Get("payload[stripe_customer_id]") != "cust-1" {
			t.Fatalf("bad export event: %v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no export meter event")
	}

	// records above the free tier bill
	rep.RecordsIngested("cust-1", FreeTierRecords+10)
	select {
	case f := <-got:
		if f.Get("event_name") != "averin_record" {
			t.Fatalf("bad record event: %v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no record meter event")
	}
}

func TestStripeBillsOnlyTheDeltaAcrossFreeTier(t *testing.T) {
	got := make(chan url.Values, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got <- r.PostForm
		w.WriteHeader(200)
	}))
	defer srv.Close()
	rep := NewStripeReporter(NewMem(), StripeConfig{APIKey: "k", Endpoint: srv.URL})

	rep.RecordsIngested("c", FreeTierRecords) // entirely within free tier -> no event
	select {
	case f := <-got:
		t.Fatalf("free-tier records must not bill: %v", f)
	case <-time.After(300 * time.Millisecond):
	}
	rep.RecordsIngested("c", 5) // crosses the boundary -> bills exactly 5
	select {
	case f := <-got:
		if f.Get("payload[value]") != "5" {
			t.Fatalf("expected delta 5, got %s", f.Get("payload[value]"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event for the 5 billable records")
	}
}

func TestStripeNoKeyIsNoOp(t *testing.T) {
	// with no API key, it just counts locally and never calls out.
	rep := NewStripeReporter(NewMem(), StripeConfig{})
	rep.RecordsIngested("p", 5)
	rep.ExportIssued("p")
	if u := rep.Usage("p"); u.Records != 5 || u.Exports != 1 {
		t.Fatalf("no-op reporter should still count: %+v", u)
	}
}
