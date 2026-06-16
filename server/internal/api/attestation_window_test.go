package api

import (
	"testing"
	"time"
)

// TestAttestationWindow (D7.2 round-2) exercises the freshness-window helper directly: the window must
// bracket the checkpoint's created_ts (NOT export time), tolerate an anchor genTime landing days after the
// seal (the widened not_after), and — when created_ts is missing/unparseable — widen the LOWER bound rather
// than fail an honest attestation closed.
func TestAttestationWindow(t *testing.T) {
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	issuedSkew, validity := time.Hour, 7*24*time.Hour
	cpTime := "2026-06-10T00:00:00.000Z" // sealed 6 days before this export

	// Valid created_ts: the window brackets the checkpoint time, independent of export `now`.
	iss, na := attestationWindow(cpTime, now, issuedSkew, validity)
	if !(iss < cpTime && cpTime < na) {
		t.Fatalf("window [%s,%s] must bracket the checkpoint created_ts %s", iss, na, cpTime)
	}
	// not_after must be EXACTLY created_ts + validity (anchored to the checkpoint, NOT export now()): this
	// pins both the created_ts anchoring of the upper bound and the widened validity, so a half-revert that
	// re-anchors not_after to now() (which is > created_ts here) cannot survive.
	if na != ts(time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)) { // created_ts (06-10) + 7d
		t.Fatalf("not_after %s must be created_ts + validity (7d), not anchored to export time", na)
	}
	// ...and it must cover an anchor genTime that lands well after the seal (the >24h-latency residual).
	lateAnchor := ts(time.Date(2026, 6, 11, 1, 0, 0, 0, time.UTC)) // created_ts + 25h
	if !(lateAnchor <= na) {
		t.Fatalf("not_after %s must cover an anchor genTime %s that lands >24h after the seal", na, lateAnchor)
	}
	// issued_at must sit just below the checkpoint time (the small jitter skew), NOT near export `now`.
	if iss != ts(time.Date(2026, 6, 9, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("issued_at %s should be created_ts - 1h, not anchored to export time", iss)
	}

	// Empty created_ts: cannot bracket the real anchor time, so the LOWER bound widens around export time
	// (fail-safe, not the old now()-1h that fail-closed an honest legacy-checkpoint attestation).
	issEmpty, _ := attestationWindow("", now, issuedSkew, validity)
	wideBoundary := ts(now.Add(-29 * 24 * time.Hour))
	if !(issEmpty < wideBoundary) {
		t.Fatalf("empty created_ts must widen issued_at to ~now-30d (got %s, want < %s)", issEmpty, wideBoundary)
	}
	// Garbage created_ts widens identically.
	issGarbage, _ := attestationWindow("not-a-timestamp", now, issuedSkew, validity)
	if issGarbage != issEmpty {
		t.Fatalf("unparseable created_ts must widen like an empty one (got %s vs %s)", issGarbage, issEmpty)
	}
}
