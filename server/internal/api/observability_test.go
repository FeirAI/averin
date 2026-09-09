package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
)

// fakePinger is a stub api.Pinger for /readyz tests — it never touches a real database, it just
// returns whatever err was configured (nil = healthy, non-nil = "the pool is unreachable").
type fakePinger struct{ err error }

func (f fakePinger) Ping(ctx context.Context) error { return f.err }

// TestReadyzReadyWithNoRegisteredDependency (in-memory store, dev posture): with nothing registered
// via WithReadiness, /readyz has no dependency to be unready about and must report 200.
func TestReadyzReadyWithNoRegisteredDependency(t *testing.T) {
	h := newSrv(t)
	code, body := do(t, h, "GET", "/readyz", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 ready with no registered dependency, got %d: %s", code, body)
	}
	if !strings.Contains(body, `"status":"ready"`) {
		t.Fatalf("expected a ready status body, got: %s", body)
	}
}

// TestReadyzFailingPoolReturns503 (fail-closed, not fail-open): a registered dependency whose Ping
// errors must flip /readyz to 503 and name the failing component — never silently report ready.
func TestReadyzFailingPoolReturns503(t *testing.T) {
	s := newServer(t)
	s.WithReadiness("fake_db", fakePinger{err: errors.New("connection refused")})
	h := s.Routes()
	code, body := do(t, h, "GET", "/readyz", "")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when a registered dependency's Ping fails, got %d: %s", code, body)
	}
	if !strings.Contains(body, `"status":"not-ready"`) || !strings.Contains(body, `"fake_db"`) {
		t.Fatalf("expected a not-ready body naming the failing component fake_db, got: %s", body)
	}
}

// TestReadyzHealthyPoolReturns200 covers the mirror case: a registered dependency whose Ping succeeds
// must not itself make /readyz unready.
func TestReadyzHealthyPoolReturns200(t *testing.T) {
	s := newServer(t)
	s.WithReadiness("fake_db", fakePinger{err: nil})
	h := s.Routes()
	code, body := do(t, h, "GET", "/readyz", "")
	if code != http.StatusOK {
		t.Fatalf("expected 200 when the registered dependency's Ping succeeds, got %d: %s", code, body)
	}
}

// TestReadyzAndMetricsStayOpenUnderAuth (CRITICAL): /v2/* gated behind project auth must NOT hide
// /readyz or /metrics — both are unauthenticated health/observability surfaces, exactly like /healthz.
func TestReadyzAndMetricsStayOpenUnderAuth(t *testing.T) {
	s := newServer(t).WithAuth(auth.NewMapStore(map[string][]string{"p1": {"s3cret"}}))
	s.WithReadiness("fake_db", fakePinger{err: nil})
	h := s.Routes()
	if code, body := do(t, h, "GET", "/readyz", ""); code != http.StatusOK {
		t.Fatalf("/readyz must stay open with auth enabled, got %d: %s", code, body)
	}
	if code, body := do(t, h, "GET", "/metrics", ""); code != http.StatusOK {
		t.Fatalf("/metrics must stay open with auth enabled, got %d: %s", code, body)
	}
	if code, _ := do(t, h, "GET", "/healthz", ""); code != http.StatusOK {
		t.Fatalf("/healthz must stay open with auth enabled, got %d", code)
	}
	// but /v2/* is still gated
	if code, _ := do(t, h, "GET", "/v2/sessions?project=p1", ""); code != http.StatusUnauthorized {
		t.Fatalf("expected /v2/* to remain gated behind auth, got %d", code)
	}
}

// TestMetricsEmitsCountersAfterSealAndDenial drives one ordinary record ingest (a seal) and one
// forbidden-scope grant request (a B11 denial, itself sealed as a grant_denied record), then asserts
// GET /metrics reflects both: the hand-rolled Prometheus-text exposition carries the sealed-records
// counter at >= 2 (the ordinary record + the denial record) with valid HELP/TYPE lines.
func TestMetricsEmitsCountersAfterSealAndDenial(t *testing.T) {
	h := denyLogServer(t) // WithBroker + WithDeniedGrantLog (see server_denial_test.go)

	// a seal: ordinary record ingest.
	postRecord(t, h, `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"db.read"}`)

	// a denial: forbidden single_operation scope -> 400, sealed as a grant_denied record (B11).
	ak := grantAgentKey()
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-deny", "iam:reset", ak, ak))
	if code != http.StatusBadRequest {
		t.Fatalf("expected the forbidden scope to be denied 400, got %d: %s", code, resp)
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics: %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("unexpected /metrics content-type: %s", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# HELP averin_records_sealed_total") ||
		!strings.Contains(body, "# TYPE averin_records_sealed_total counter") {
		t.Fatalf("missing averin_records_sealed_total HELP/TYPE lines: %s", body)
	}
	// Both the ordinary record and the denial record go through the same seal choke point
	// (sealAndStore -> s.core.SealRecord), so the counter must reflect at least 2 seals.
	if !strings.Contains(body, "averin_records_sealed_total 2") {
		t.Fatalf("expected averin_records_sealed_total to count both seals (record + denial), got: %s", body)
	}
	if !strings.Contains(body, "# HELP averin_use_requests_total") {
		t.Fatalf("expected the /v2/use outcome counter vec's HELP/TYPE header even with no label values emitted yet (no /v2/use request in this test): %s", body)
	}
}

// TestMetricsUseAllowDenyCounters drives one successful /v2/use (allow) and one rejected /v2/use
// against a well-formed-but-unminted capability (deny — broker.VerifyCapability fails), then asserts
// GET /metrics shows exactly one of each labeled outcome.
func TestMetricsUseAllowDenyCounters(t *testing.T) {
	h := newBrokerResourceServer(t)
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")

	code, resp := do(t, h, "POST", "/v2/use", useBody(t, "idem-use-ok", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("valid use should succeed, got %d: %s", code, resp)
	}
	// A well-formed ("<payload>.<sig>") but never-minted capability: useBody can still derive a
	// credential binding + PoP challenge from it, but broker.VerifyCapability rejects it at ValidateUse
	// step 1 (not signed by the broker issuing key) — a clean, deterministic deny.
	code, resp = do(t, h, "POST", "/v2/use", useBody(t, "idem-use-bad", "Zm9yZ2Vk.Zm9yZ2Vk", grantID, ak, "SELECT 1", "nonce-2"))
	if code != http.StatusBadRequest {
		t.Fatalf("an unminted capability should be denied 400, got %d: %s", code, resp)
	}

	code, body := do(t, h, "GET", "/metrics", "")
	if code != http.StatusOK {
		t.Fatalf("GET /metrics: %d", code)
	}
	if !strings.Contains(body, `averin_use_requests_total{outcome="allow"} 1`) {
		t.Fatalf("expected exactly 1 allow, got: %s", body)
	}
	if !strings.Contains(body, `averin_use_requests_total{outcome="deny"} 1`) {
		t.Fatalf("expected exactly 1 deny, got: %s", body)
	}
}

// TestMetricsDenialBudgetDropCounter exercises the denial-budget-drop counter directly (mirrors
// TestDenialBudgetBoundsVaryingScopeSweep in server_denial_budget_test.go): with a per-project budget
// of burst 1, only the FIRST of two distinct forbidden-scope probes (distinct session_id, so neither
// collapses onto the other via deterministic-id dedup) gets sealed — the second is dropped by the
// budget, and /metrics must show exactly one drop.
func TestMetricsDenialBudgetDropCounter(t *testing.T) {
	s := newServer(t).
		WithBroker(brokerIssuingKey()).
		WithDeniedGrantLog().
		WithDeniedGrantBudget(api.DenialBudget{PerProjectPerSec: 0.001, PerProjectBurst: 1, GlobalPerSec: 0.001, GlobalBurst: 1000, MaxProjects: 100})
	h := s.Routes()
	ak := grantAgentKey()
	customGrant(t, h, ak, "idem-s1", "s1", "iam:reset", 60) // sealed (within budget)
	customGrant(t, h, ak, "idem-s2", "s2", "iam:reset", 60) // dropped (budget exhausted)

	code, body := do(t, h, "GET", "/metrics", "")
	if code != http.StatusOK {
		t.Fatalf("GET /metrics: %d", code)
	}
	if !strings.Contains(body, "averin_denial_budget_drops_total 1") {
		t.Fatalf("expected exactly 1 denial-budget drop (burst 1, 2 distinct probes), got: %s", body)
	}
}
