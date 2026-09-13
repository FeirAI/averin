package api

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

// White-box tests for the denial-seal rate limiter (#47). They drive allow() directly with a controllable
// clock so the token-bucket math is exercised deterministically (no wall-clock dependence).

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *fakeClock               { return &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()} }

func allow(b *denialBudget, p string) bool { ok, _ := b.allow(p); return ok }

func TestDenialBudgetPerProjectBurstAndRefill(t *testing.T) {
	clk := newClock()
	// per-project: 1 tok/s, burst 3; global effectively unlimited.
	b := newDenialBudget(1, 3, 1000, 1_000_000, 16, clk.now)

	// Fresh bucket starts full at burst=3 -> first three seals pass, the fourth is dropped (no time elapsed).
	for i := 0; i < 3; i++ {
		if !allow(b, "p1") {
			t.Fatalf("seal %d within burst must be allowed", i)
		}
	}
	if allow(b, "p1") {
		t.Fatal("the 4th seal in one instant must be dropped (per-project burst exhausted)")
	}
	// After 2s, 2 tokens refill (capped at burst) -> exactly two more pass, then drop again.
	clk.add(2 * time.Second)
	if !allow(b, "p1") || !allow(b, "p1") {
		t.Fatal("two tokens should have refilled after 2s")
	}
	if allow(b, "p1") {
		t.Fatal("only 2 tokens refilled in 2s; the 3rd must be dropped")
	}
}

func TestDenialBudgetGlobalCeilingSpansProjects(t *testing.T) {
	clk := newClock()
	// global: burst 2, ~no refill; per-project generous. The global ceiling must bound TOTAL seals across
	// DISTINCT projects, so an attacker varying project_id cannot exceed it.
	b := newDenialBudget(1000, 1_000_000, 0.0001, 2, 16, clk.now)
	if !allow(b, "pA") {
		t.Fatal("first global token")
	}
	if !allow(b, "pB") {
		t.Fatal("second global token (different project)")
	}
	if allow(b, "pC") {
		t.Fatal("global ceiling (burst 2) must drop the 3rd seal even across distinct projects")
	}
}

func TestDenialBudgetRefusalDoesNotLeakGlobalToken(t *testing.T) {
	clk := newClock()
	// per-project burst 1, global burst 10. A per-project DROP must not consume a global token.
	b := newDenialBudget(0.0001, 1, 0.0001, 10, 16, clk.now)
	if !allow(b, "p1") { // pp 1->0, global 10->9
		t.Fatal("first p1 seal allowed")
	}
	if allow(b, "p1") { // pp exhausted -> drop, global MUST stay 9
		t.Fatal("second p1 seal must be dropped (per-project burst 1)")
	}
	if got := b.global.tokens; got != 9 {
		t.Fatalf("a per-project drop leaked a global token: global=%v, want 9", got)
	}
	if !allow(b, "p2") { // global 9->8
		t.Fatal("p2 seal allowed (its own fresh per-project bucket)")
	}
	if got := b.global.tokens; got != 8 {
		t.Fatalf("global token accounting off: global=%v, want 8", got)
	}
}

func TestDenialBudgetMapIsBounded(t *testing.T) {
	clk := newClock()
	// maxProjects 2, per-project burst 1, global generous. The 3rd distinct project cannot be tracked, so it
	// is governed by the global ceiling alone and the map never grows past the cap.
	b := newDenialBudget(0.0001, 1, 1000, 1_000_000, 2, clk.now)
	if !allow(b, "p1") || !allow(b, "p2") {
		t.Fatal("p1, p2 seals allowed (map now full)")
	}
	if !allow(b, "p3") {
		t.Fatal("p3 (untracked, at cap) must still be allowed via the global ceiling")
	}
	if !allow(b, "p4") {
		t.Fatal("p4 (untracked, at cap) must still be allowed via the global ceiling")
	}
	if len(b.perProject) != 2 {
		t.Fatalf("the per-project map must stay bounded at maxProjects=2, got %d entries", len(b.perProject))
	}
	if _, tracked := b.perProject[sha256.Sum256([]byte("p3"))]; tracked {
		t.Fatal("an over-cap project must not be inserted into the map (memory-DoS bound)")
	}
	// A tracked project's bucket is retained, so p1's per-project limit still applies (burst 1, no refill).
	if allow(b, "p1") {
		t.Fatal("p1's retained per-project bucket must still rate-limit it")
	}
}

func TestDenialBudgetHashesOversizedProjectKeys(t *testing.T) {
	clk := newClock()
	// per-project burst 1, global generous, cap 4. project_id is caller-supplied and the ingest body cap allows
	// multi-MB values; the map must store a FIXED-SIZE sha256 key, not the raw string (adversarial review: else the
	// entry-bounded map is still a byte-unbounded memory DoS).
	b := newDenialBudget(0.0001, 1, 1000, 1_000_000, 4, clk.now)
	huge := strings.Repeat("A", 1<<20) // 1 MiB caller-supplied project_id
	if !allow(b, huge+"-1") {
		t.Fatal("first huge-project seal should be allowed")
	}
	if allow(b, huge+"-1") {
		t.Fatal("the SAME huge project must be rate-limited (its hash keys a retained bucket, burst 1)")
	}
	// a DIFFERENT huge project hashes to a distinct key -> its own fresh bucket (collision-resistant).
	if !allow(b, huge+"-2") {
		t.Fatal("a distinct huge project must get its own bucket")
	}
	// the map key type is [32]byte (compile-time fixed), so each retained entry costs 32 bytes regardless of
	// the project_id length; two distinct huge projects -> exactly 2 fixed-size keys.
	if len(b.perProject) != 2 {
		t.Fatalf("two distinct huge projects -> 2 fixed-size keys, got %d", len(b.perProject))
	}
}

func TestDenialBudgetDropLogThrottled(t *testing.T) {
	clk := newClock()
	b := newDenialBudget(0.0001, 1, 0.0001, 1, 16, clk.now) // burst 1 everywhere -> 2nd+ seals drop
	if _, logDrop := b.allow("p1"); logDrop {
		t.Fatal("a successful seal must not emit a drop log")
	}
	if _, logDrop := b.allow("p1"); !logDrop {
		t.Fatal("the first drop should log")
	}
	if _, logDrop := b.allow("p1"); logDrop {
		t.Fatal("a second drop within logInterval must be throttled (no log)")
	}
	clk.add(2 * time.Second) // past logInterval (1s)
	if _, logDrop := b.allow("p1"); !logDrop {
		t.Fatal("a drop after logInterval should log again")
	}
}
