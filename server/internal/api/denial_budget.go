package api

import (
	"crypto/sha256"
	"sync"
	"time"
)

// denial_budget.go (#47, T5/B11 follow-up): bound the volume of best-effort grant-DENIAL seals so a
// metadata-oracle probe — a sweep that varies the scope (or brute-forces PoP), each variation a DISTINCT
// denial that escapes deterministic-id dedup — cannot inflate stored (billable) records without limit. This
// is the safeguard the WithDeniedGrantLog doc names as the prerequisite "before default-on".
//
// Design. A denial seal proceeds only if BOTH a GLOBAL and a PER-PROJECT token bucket permit it:
//   - The GLOBAL bucket is the hard DoS ceiling. It is O(1) state and INDEPENDENT of project_id cardinality,
//     so an attacker who varies project_id (a caller-supplied field) can never exceed the global seal rate.
//     It is checked FIRST, which also throttles per-project map growth: under a sustained sweep the global
//     bucket empties and `allow` early-returns before the map even grows.
//   - The PER-PROJECT bucket adds fairness (one project's sweep cannot starve another project's denial log).
//     It lives in a map BOUNDED to maxProjects entries; once the map is full, a new/untracked project is
//     governed by the global ceiling alone — the map never grows past the cap, so it is not itself a
//     memory-DoS vector keyed on attacker input.
//
// A refusal consumes NO tokens (the global token is taken only when the per-project bucket also permits), so
// a denied seal never leaks budget. Dropping a seal is safe: the denial log is best-effort defense-in-depth,
// and the caller's 4xx is unaffected (sealGrantDenial runs after the response is determined).

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// refill adds rate*elapsed tokens (capped at burst). A zero `last` (fresh bucket) starts full at burst.
func (b *tokenBucket) refill(rate, burst float64, now time.Time) {
	if b.last.IsZero() {
		b.tokens = burst
		b.last = now
		return
	}
	b.tokens += rate * now.Sub(b.last).Seconds()
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
}

type denialBudget struct {
	mu          sync.Mutex
	now         func() time.Time
	ppRate      float64 // per-project refill, tokens/sec
	ppBurst     float64 // per-project max tokens
	gRate       float64 // global refill, tokens/sec
	gBurst      float64 // global max tokens
	maxProjects int
	logInterval time.Duration
	global      tokenBucket
	// keyed by sha256(project_id), NOT the raw project_id: project_id is caller-supplied and the ingest body
	// cap allows multi-megabyte values, so storing raw keys would make this DoS-control a memory-DoS itself
	// (entry-bounded but not byte-bounded). A 32-byte collision-resistant hash bounds each key (adversarial review).
	perProject  map[[32]byte]*tokenBucket
	lastDropLog time.Time
}

func newDenialBudget(ppRate float64, ppBurst int, gRate float64, gBurst, maxProjects int, now func() time.Time) *denialBudget {
	return &denialBudget{
		now: now, ppRate: ppRate, ppBurst: float64(ppBurst), gRate: gRate, gBurst: float64(gBurst),
		maxProjects: maxProjects, logInterval: time.Second, perProject: make(map[[32]byte]*tokenBucket),
	}
}

// allow reports whether a denial seal for `project` may proceed, consuming one token from BOTH the global and
// the per-project bucket — but consuming NEITHER unless both permit (so a refusal never leaks budget). The
// second return is true at most once per logInterval when a drop occurs, to bound drop-logging under a sweep
// (so the log itself is not a per-request amplification vector).
func (d *denialBudget) allow(project string) (ok bool, logDrop bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.global.refill(d.gRate, d.gBurst, now)
	if d.global.tokens < 1 {
		// Global ceiling hit — bounds total seal rate regardless of how many distinct project_ids a sweep
		// uses. This early return also keeps the per-project map from growing under a sustained sweep.
		return false, d.noteDrop(now)
	}
	key := sha256.Sum256([]byte(project)) // fixed-size key: never store the raw (caller-sized) project_id
	pb := d.perProject[key]
	if pb == nil {
		if len(d.perProject) >= d.maxProjects {
			// Map at cap: govern this untracked project by the GLOBAL ceiling alone. O(1), no eviction scan —
			// the global check above already gates new entries to <= gRate/sec, so the map barely grows under
			// attack. Memory is hard-bounded at maxProjects * 32 bytes (fixed-size keys).
			d.global.tokens--
			return true, false
		}
		pb = &tokenBucket{}
		d.perProject[key] = pb
	}
	pb.refill(d.ppRate, d.ppBurst, now)
	if pb.tokens < 1 {
		// Per-project limit hit. Do NOT consume the global token (no leak); the global bucket is unchanged.
		return false, d.noteDrop(now)
	}
	pb.tokens--
	d.global.tokens--
	return true, false
}

// noteDrop returns true at most once per logInterval, throttling drop logs so a high-volume sweep cannot turn
// each dropped seal into a log-write (which would defeat the budget). Caller holds d.mu.
func (d *denialBudget) noteDrop(now time.Time) bool {
	if d.lastDropLog.IsZero() || now.Sub(d.lastDropLog) >= d.logInterval {
		d.lastDropLog = now
		return true
	}
	return false
}

// DenialBudget configures the per-project + global rate limit on best-effort B11 denial seals (#47). Any
// non-positive field takes a generous default. The GLOBAL bucket is the hard, project_id-cardinality-
// independent DoS ceiling; the PER-PROJECT bucket (in a maxProjects-bounded map) adds cross-project fairness.
type DenialBudget struct {
	PerProjectPerSec float64 // sustained per-project denial-seal rate (default 5)
	PerProjectBurst  int     // per-project burst allowance (default 50)
	GlobalPerSec     float64 // sustained server-wide denial-seal rate (default 50)
	GlobalBurst      int     // server-wide burst allowance (default 500)
	MaxProjects      int     // bound on tracked per-project buckets (default 4096)
}

// WithDeniedGrantBudget caps the volume of best-effort B11 denial seals so a varying-scope (or PoP brute-force)
// sweep cannot inflate stored records without limit — the documented prerequisite for turning the denied-grant
// log on by default. Opt-in: with no budget set, denial seals are unbounded (the prior behavior). Only takes
// effect alongside WithDeniedGrantLog (nothing seals denials otherwise).
func (s *Server) WithDeniedGrantBudget(cfg DenialBudget) *Server {
	ppRate := cfg.PerProjectPerSec
	if ppRate <= 0 {
		ppRate = 5
	}
	ppBurst := cfg.PerProjectBurst
	if ppBurst <= 0 {
		ppBurst = 50
	}
	gRate := cfg.GlobalPerSec
	if gRate <= 0 {
		gRate = 50
	}
	gBurst := cfg.GlobalBurst
	if gBurst <= 0 {
		gBurst = 500
	}
	maxProjects := cfg.MaxProjects
	if maxProjects <= 0 {
		maxProjects = 4096
	}
	// Capture the server clock by closure so the budget always reads the current s.now (robust to option
	// ordering and to tests that swap the clock after construction).
	s.denialBudget = newDenialBudget(ppRate, ppBurst, gRate, gBurst, maxProjects, func() time.Time { return s.now() })
	return s
}

// IngestBudget configures the coarse per-project + global rate limit on state-mutating POST /v2/* ingest
// (averin#20). Any non-positive field takes a GENEROUS default (so an enabled-but-unsized budget throttles
// only a runaway, not a busy legitimate agent). Like DenialBudget, the GLOBAL bucket is the hard, project_id-
// cardinality-independent ceiling and the PER-PROJECT bucket (in a maxProjects-bounded map) adds fairness.
type IngestBudget struct {
	PerProjectPerSec float64 // sustained per-project ingest rate (default 50)
	PerProjectBurst  int     // per-project burst allowance (default 200)
	GlobalPerSec     float64 // sustained server-wide ingest rate (default 500)
	GlobalBurst      int     // server-wide burst allowance (default 2000)
	MaxProjects      int     // bound on tracked per-project buckets (default 4096)
}

// WithIngestBudget installs a coarse per-project + global token bucket on the state-mutating POST /v2/* ingest
// routes, so a leaked token (or an unauthenticated default deploy) cannot drive unbounded billable, append-only
// DB growth — a saturated bucket answers 429. OPT-IN: with no ingest budget set the routes are unlimited (the
// prior behavior), so no existing deployment is throttled and no boot is bricked. This is defense-in-depth; a
// reverse-proxy / API-gateway rate limit remains the PRIMARY, HARD deploy control (see CONFIGURATION.md).
func (s *Server) WithIngestBudget(cfg IngestBudget) *Server {
	ppRate := cfg.PerProjectPerSec
	if ppRate <= 0 {
		ppRate = 50
	}
	ppBurst := cfg.PerProjectBurst
	if ppBurst <= 0 {
		ppBurst = 200
	}
	gRate := cfg.GlobalPerSec
	if gRate <= 0 {
		gRate = 500
	}
	gBurst := cfg.GlobalBurst
	if gBurst <= 0 {
		gBurst = 2000
	}
	maxProjects := cfg.MaxProjects
	if maxProjects <= 0 {
		maxProjects = 4096
	}
	s.ingestBudget = newDenialBudget(ppRate, ppBurst, gRate, gBurst, maxProjects, func() time.Time { return s.now() })
	return s
}
