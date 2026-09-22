package store

import (
	"errors"
	"testing"
)

// exerciseDisclosures runs the disclosure-store contract against any Store implementation, so Mem
// (TestMemDisclosures) and Postgres (TestPostgresDisclosures) are proven to behave identically.
// Disclosure secrets are written atomically with their record via PutRecord(Record.Disclosures);
// there is no separate write path.
func exerciseDisclosures(t *testing.T, s Store) {
	t.Helper()

	// Empty project returns a non-nil empty slice (the export layer marshals it directly).
	if d, err := s.Disclosures("p"); err != nil || d == nil || len(d) != 0 {
		t.Fatalf("empty disclosures = %v (nil=%v) err=%v; want non-nil empty", d, d == nil, err)
	}

	// r1 (inserted first) commits output+input in NON-canonical order; r0 commits input and must
	// still sort FIRST in the output — so a store returning insertion order would fail below.
	r1 := Record{
		JSON: `{"r":1}`, ContentHash: "sha256:c1", SessionID: "s",
		Disclosures: []DisclosureSecret{
			{RecordID: "r1", Field: "output", ValueDigest: "sha256:v2", NonceHex: "bb"},
			{RecordID: "r1", Field: "input", ValueDigest: "sha256:v1", NonceHex: "aa"},
		},
	}
	if _, created, err := s.PutRecord("p", "k1", r1); err != nil || !created {
		t.Fatalf("put r1: created=%v err=%v", created, err)
	}
	r0 := Record{
		JSON: `{"r":0}`, ContentHash: "sha256:c0", SessionID: "s",
		Disclosures: []DisclosureSecret{
			{RecordID: "r0", Field: "input", ValueDigest: "sha256:v0", NonceHex: "00"},
		},
	}
	if _, created, err := s.PutRecord("p", "k0", r0); err != nil || !created {
		t.Fatalf("put r0: created=%v err=%v", created, err)
	}

	// Idempotent re-put of r1 (same idem key) with DIFFERENT disclosure secrets: created=false, and
	// the disclosures must NOT be overwritten or duplicated — the commitment for a field is immutable.
	r1b := r1
	r1b.Disclosures = []DisclosureSecret{{RecordID: "r1", Field: "input", ValueDigest: "sha256:CHANGED", NonceHex: "cc"}}
	if _, created, err := s.PutRecord("p", "k1", r1b); err != nil || created {
		t.Fatalf("re-put r1: created=%v err=%v; want created=false", created, err)
	}

	got, err := s.Disclosures("p")
	if err != nil {
		t.Fatalf("disclosures: %v", err)
	}
	// Canonical (record_id, field) order, identical for Mem and Postgres, regardless of insert order,
	// with the ORIGINAL secrets kept (the idempotent re-put was ignored).
	want := []DisclosureSecret{
		{RecordID: "r0", Field: "input", ValueDigest: "sha256:v0", NonceHex: "00"},
		{RecordID: "r1", Field: "input", ValueDigest: "sha256:v1", NonceHex: "aa"},
		{RecordID: "r1", Field: "output", ValueDigest: "sha256:v2", NonceHex: "bb"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d disclosures, want %d (idempotent re-put must not duplicate)", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("disclosure[%d] = %+v, want %+v (canonical order, original secret kept)", i, got[i], want[i])
		}
	}

	// Project isolation: another project sees none of these.
	if d, err := s.Disclosures("other"); err != nil || len(d) != 0 {
		t.Fatalf("project isolation: other = %v err=%v; want empty", d, err)
	}
}

func TestMemDisclosures(t *testing.T) {
	exerciseDisclosures(t, NewMem())
}

// exerciseAnchors runs the anchor-store contract against any Store implementation.
func exerciseAnchors(t *testing.T, s Store) {
	t.Helper()

	if a, err := s.Anchors("p"); err != nil || a == nil || len(a) != 0 {
		t.Fatalf("empty anchors = %v (nil=%v) err=%v; want non-nil empty", a, a == nil, err)
	}
	if err := s.PutAnchor("p", 0, "tok0"); err != nil {
		t.Fatalf("put anchor 0: %v", err)
	}
	if err := s.PutAnchor("p", 1, "tok1"); err != nil {
		t.Fatalf("put anchor 1: %v", err)
	}
	// Idempotent per seq: a second PutAnchor for the same seq with a different token keeps the first.
	if err := s.PutAnchor("p", 0, "DIFFERENT"); err != nil {
		t.Fatalf("re-put anchor 0: %v", err)
	}
	got, err := s.Anchors("p")
	if err != nil {
		t.Fatalf("anchors: %v", err)
	}
	if len(got) != 2 || got[0] != "tok0" || got[1] != "tok1" {
		t.Fatalf("anchors = %v; want {0:tok0, 1:tok1} (idempotent, original kept)", got)
	}
	if a, err := s.Anchors("other"); err != nil || len(a) != 0 {
		t.Fatalf("project isolation: other anchors = %v err=%v; want empty", a, err)
	}
}

func TestMemAnchors(t *testing.T) {
	exerciseAnchors(t, NewMem())
}

// exerciseBrokerSeq runs the D6 grant-transparency sequence contract against any Store: gapless and
// strictly increasing per project [1..N], idempotent on grant_id (a retry returns the original seq and
// does NOT advance the counter), and isolated per project.
func exerciseBrokerSeq(t *testing.T, s Store) {
	t.Helper()
	for i, gid := range []string{"g1", "g2", "g3"} {
		seq, err := s.AllocateBrokerSeq("p", gid)
		if err != nil {
			t.Fatalf("alloc %s: %v", gid, err)
		}
		if want := int64(i + 1); seq != want {
			t.Fatalf("alloc %s = %d; want %d (gapless [1..N])", gid, seq, want)
		}
	}
	// idempotent on grant_id: re-allocating an existing grant returns its original seq, no advance.
	if seq, err := s.AllocateBrokerSeq("p", "g2"); err != nil || seq != 2 {
		t.Fatalf("re-alloc g2 = %d err=%v; want idempotent 2", seq, err)
	}
	// the next NEW grant continues gapless (the idempotent retry above did not consume a number).
	if seq, err := s.AllocateBrokerSeq("p", "g4"); err != nil || seq != 4 {
		t.Fatalf("alloc g4 = %d err=%v; want 4 (gapless after idempotent retry)", seq, err)
	}
	// per-project isolation: a different project starts its own sequence at 1.
	if seq, err := s.AllocateBrokerSeq("other", "g1"); err != nil || seq != 1 {
		t.Fatalf("alloc other/g1 = %d err=%v; want 1 (per-project)", seq, err)
	}
	// ReleaseBrokerSeq frees a not-yet-recorded allocation; the freed (highest) seq is REUSED gaplessly.
	if seq, err := s.AllocateBrokerSeq("p", "g5"); err != nil || seq != 5 {
		t.Fatalf("alloc g5 = %d err=%v; want 5", seq, err)
	}
	if err := s.ReleaseBrokerSeq("p", "g5"); err != nil {
		t.Fatalf("release g5: %v", err)
	}
	if seq, err := s.AllocateBrokerSeq("p", "g6"); err != nil || seq != 5 {
		t.Fatalf("after releasing g5, alloc g6 = %d err=%v; want reused 5 (gapless rollback)", seq, err)
	}
	// releasing an unallocated grant is a safe no-op.
	if err := s.ReleaseBrokerSeq("p", "never-allocated"); err != nil {
		t.Fatalf("release of unallocated grant must be a no-op: %v", err)
	}
	// MaxBrokerSeq reports the highest ALLOCATED seq per project (0 when none) — what checkpoint creation
	// compares against the recorded grant count to refuse anchoring a gap.
	if max, err := s.MaxBrokerSeq("p"); err != nil || max != 5 {
		t.Fatalf("MaxBrokerSeq(p) = %d err=%v; want 5", max, err)
	}
	if max, err := s.MaxBrokerSeq("other"); err != nil || max != 1 {
		t.Fatalf("MaxBrokerSeq(other) = %d err=%v; want 1", max, err)
	}
	if max, err := s.MaxBrokerSeq("empty"); err != nil || max != 0 {
		t.Fatalf("MaxBrokerSeq(empty) = %d err=%v; want 0", max, err)
	}
}

func TestMemBrokerSeq(t *testing.T) {
	exerciseBrokerSeq(t, NewMem())
}

// exerciseIdemBinding pins the converged idempotency-key-binding contract shared by Mem and Postgres
// (append-only): when a record collapses on content_hash under a NEW idempotency key, that new key is NOT
// bound to the collapsed row — RecordByIdem(newKey) is found=false on BOTH stores. Mem used to bind it
// (RecordByIdem(newKey)=found=true), diverging from Postgres (which physically cannot, REVOKE UPDATE +
// content_hash unique index) and risking a foreign row surfacing through the broker/use idempotency probes.
func exerciseIdemBinding(t *testing.T, s Store) {
	t.Helper()
	r := rec("sha256:dup", "s1")

	// K1 creates the row.
	if _, created, err := s.PutRecord("p", "K1", r); err != nil || !created {
		t.Fatalf("put K1: created=%v err=%v; want created", created, err)
	}
	// Same content under a NEW key K2 collapses (created=false) and returns the canonical row...
	if got, created, err := s.PutRecord("p", "K2", r); err != nil || created || got.ContentHash != r.ContentHash {
		t.Fatalf("put K2: created=%v hash=%q err=%v; want collapse to the existing row", created, got.ContentHash, err)
	}
	// ...but K2 must NOT be bound: RecordByIdem(K2) is found=false (the converged append-only contract).
	if _, found, err := s.RecordByIdem("p", "K2"); err != nil || found {
		t.Fatalf("RecordByIdem(K2) found=%v err=%v; want found=false (no cross-key binding on content collapse)", found, err)
	}
	// K1 — the key that actually created the row — IS bound.
	if _, found, err := s.RecordByIdem("p", "K1"); err != nil || !found {
		t.Fatalf("RecordByIdem(K1) found=%v err=%v; want found=true", found, err)
	}
	// A retry under K2 still collapses on content_hash to the same row (idempotent), and stays unbound.
	if got, created, err := s.PutRecord("p", "K2", r); err != nil || created || got.ContentHash != r.ContentHash {
		t.Fatalf("retry K2: created=%v err=%v; want stable collapse", created, err)
	}
	if _, found, _ := s.RecordByIdem("p", "K2"); found {
		t.Fatalf("RecordByIdem(K2) after retry: want still found=false")
	}
}

func TestMemIdemBinding(t *testing.T) {
	exerciseIdemBinding(t, NewMem())
}

// exerciseRecordIDUnique pins the per-project record_id uniqueness contract shared by Mem and Postgres: a
// DIFFERENT record under an already-held record_id is rejected with ErrRecordIDConflict and persists nothing
// (no row, no idem binding, no disclosure secret), while an exact replay — same idempotency key, or
// byte-identical content under a new key — still collapses onto the stored row, and another project is
// unaffected.
func exerciseRecordIDUnique(t *testing.T, s Store) {
	t.Helper()
	a := Record{JSON: `{"record_id":"r1","v":1}`, ContentHash: "sha256:ra", SessionID: "s",
		Disclosures: []DisclosureSecret{{RecordID: "r1", Field: "input", ValueDigest: "sha256:va", NonceHex: "aa"}}}
	b := Record{JSON: `{"record_id":"r1","v":2}`, ContentHash: "sha256:rb", SessionID: "s",
		Disclosures: []DisclosureSecret{{RecordID: "r1", Field: "input", ValueDigest: "sha256:vb", NonceHex: "bb"}}}
	if _, created, err := s.PutRecord("p", "k1", a); err != nil || !created {
		t.Fatalf("put a: created=%v err=%v", created, err)
	}
	if got, created, err := s.PutRecord("p", "k1", a); err != nil || created || got.ContentHash != a.ContentHash {
		t.Fatalf("exact replay (same idem) must collapse: created=%v err=%v got=%s", created, err, got.ContentHash)
	}
	if got, created, err := s.PutRecord("p", "k3", a); err != nil || created || got.ContentHash != a.ContentHash {
		t.Fatalf("byte-identical content under a new key must collapse: created=%v err=%v", created, err)
	}
	if _, _, err := s.PutRecord("p", "k2", b); !errors.Is(err, ErrRecordIDConflict) {
		t.Fatalf("a different record under record_id r1 must fail with ErrRecordIDConflict, got %v", err)
	}
	if n, _ := s.RecordCount("p"); n != 1 {
		t.Fatalf("record count after the rejected duplicate = %d, want 1", n)
	}
	if _, found, _ := s.RecordByIdem("p", "k2"); found {
		t.Fatalf("the rejected record's idempotency key must not be bound")
	}
	if has, err := s.HasRecordID("p", "r1"); err != nil || !has {
		t.Fatalf("HasRecordID(p, r1) = %v err=%v; want true", has, err)
	}
	if has, err := s.HasRecordID("p", "nope"); err != nil || has {
		t.Fatalf("HasRecordID(p, nope) = %v err=%v; want false", has, err)
	}
	if d, _ := s.Disclosures("p"); len(d) != 1 || d[0].ValueDigest != "sha256:va" {
		t.Fatalf("disclosures = %+v; want only the FIRST record's secret", d)
	}
	if _, created, err := s.PutRecord("other", "k2", b); err != nil || !created {
		t.Fatalf("the same record_id in ANOTHER project must be accepted: created=%v err=%v", created, err)
	}
}

func TestMemRecordIDUnique(t *testing.T) {
	exerciseRecordIDUnique(t, NewMem())
}
