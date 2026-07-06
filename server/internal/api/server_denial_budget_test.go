package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/averin-dev/averin/server/internal/api"
	"github.com/averin-dev/averin/server/internal/core"
	"github.com/averin-dev/averin/server/internal/store"
)

// TestDenialBudgetBoundsVaryingScopeSweep (#47): with the denied-grant log on AND a per-project budget of
// burst 2, a sweep of 5 DISTINCT forbidden probes (varying session_id, which escapes deterministic-id dedup)
// still returns 400 on every request (the budget never changes what the caller sees) but seals only 2 denial
// records — the rest are dropped once the budget is exhausted. The control below shows the SAME sweep seals
// all 5 without a budget, proving the budget is what bounds the sweep.
func TestDenialBudgetBoundsVaryingScopeSweep(t *testing.T) {
	build := func(withBudget bool) http.Handler {
		c, err := core.New(seed)
		if err != nil {
			t.Fatalf("core: %v", err)
		}
		s := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithDeniedGrantLog()
		if withBudget {
			// burst 2, ~zero refill over the test's sub-second runtime; global generous so the per-project
			// bucket is the binding limit.
			s = s.WithDeniedGrantBudget(api.DenialBudget{PerProjectPerSec: 0.001, PerProjectBurst: 2, GlobalPerSec: 0.001, GlobalBurst: 1000, MaxProjects: 100})
		}
		return s.Routes()
	}

	sweep := func(h http.Handler) string {
		ak := grantAgentKey()
		// 5 distinct probes (distinct session_id under a fixed forbidden scope) — each a separate denial.
		for _, sess := range []string{"s1", "s2", "s3", "s4", "s5"} {
			customGrant(t, h, ak, "idem-sweep", sess, "iam:reset", 60) // asserts 400 on every probe
		}
		if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Fatalf("checkpoint: %d %s", code, r)
		}
		_, report := do(t, h, "GET", "/v2/verify?project=p1", "")
		return report
	}

	// With the budget: every probe still 400 (asserted inside customGrant), but only burst=2 seals survive.
	if report := sweep(build(true)); !strings.Contains(report, `"denied_grants":2`) {
		t.Fatalf("a per-project budget of burst 2 must bound a 5-probe sweep to 2 sealed denials: %s", report)
	}
	// Control: same sweep, no budget -> all 5 distinct probes seal (the prior unbounded behavior).
	if report := sweep(build(false)); !strings.Contains(report, `"denied_grants":5`) {
		t.Fatalf("without a budget the 5-probe sweep should seal all 5 denials: %s", report)
	}
}
