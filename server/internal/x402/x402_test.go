package x402

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// devSettle parses a dev proof "agent=<a>;nonce=<n>;amount=<micros>;req=<key>".
func devSettle(proof string) (Payment, error) {
	p := Payment{}
	for _, kv := range strings.Split(proof, ";") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "agent":
			p.Agent = parts[1]
		case "nonce":
			p.Nonce = parts[1]
		case "amount":
			fmt.Sscanf(parts[1], "%d", &p.AmountMicros)
		case "req":
			p.RequestKey = parts[1]
		}
	}
	if p.Agent == "" {
		return p, fmt.Errorf("missing agent")
	}
	return p, nil
}

func guarded() http.Handler {
	g := New(1000, 5000, devSettle) // price 1000 micros, max 5000/agent
	return g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("served"))
	}))
}

func call(h http.Handler, proof string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/paid", nil)
	if proof != "" {
		req.Header.Set("X-PAYMENT", proof)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUnpaidReturns402WithPrice(t *testing.T) {
	rec := call(guarded(), "")
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"amount_micros":1000`) {
		t.Fatalf("402 missing price: %s", rec.Body.String())
	}
}

func TestValidPaymentIsServed(t *testing.T) {
	rec := call(guarded(), "agent=a1;nonce=n1;amount=1000;req=r1")
	if rec.Code != 200 || rec.Body.String() != "served" {
		t.Fatalf("valid payment should be served, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestReplayedNonceRejected(t *testing.T) {
	h := guarded()
	if call(h, "agent=a1;nonce=dup;amount=1000;req=r1").Code != 200 {
		t.Fatal("first should pass")
	}
	if call(h, "agent=a1;nonce=dup;amount=1000;req=r2").Code != http.StatusPaymentRequired {
		t.Fatal("replayed nonce must be rejected")
	}
}

func TestSpendLimitEnforced(t *testing.T) {
	h := guarded()
	// 5 payments of 1000 = 5000 (the cap); the 6th exceeds it
	for i := 0; i < 5; i++ {
		if call(h, fmt.Sprintf("agent=a1;nonce=n%d;amount=1000;req=r%d", i, i)).Code != 200 {
			t.Fatalf("payment %d under cap should pass", i)
		}
	}
	if call(h, "agent=a1;nonce=n6;amount=1000;req=r6").Code != http.StatusPaymentRequired {
		t.Fatal("over the per-agent spend cap must be rejected")
	}
}

func TestUnderpaymentRejected(t *testing.T) {
	if call(guarded(), "agent=a1;nonce=n1;amount=500;req=r1").Code != http.StatusPaymentRequired {
		t.Fatal("underpayment must be rejected")
	}
}

func TestOverflowAndNonPositiveRejected(t *testing.T) {
	h := guarded()
	// i64-max amount must be rejected by the (overflow-safe) cap check, not wrap negative
	if call(h, "agent=a1;nonce=n1;amount=9223372036854775807;req=r1").Code != http.StatusPaymentRequired {
		t.Fatal("absurd amount must be rejected, not overflow the cap")
	}
	if call(h, "agent=a1;nonce=n2;amount=0;req=r2").Code != http.StatusPaymentRequired {
		t.Fatal("zero payment must be rejected")
	}
}
