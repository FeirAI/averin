package store

import "testing"

// exerciseDisclosures runs the disclosure-store contract against any Store implementation, so Mem
// (TestMemDisclosures) and Postgres (TestPostgresDisclosures) are proven to behave identically.
func exerciseDisclosures(t *testing.T, s Store) {
	t.Helper()

	// Empty project returns a non-nil empty slice (the export layer marshals it directly).
	if d, err := s.Disclosures("p"); err != nil || d == nil || len(d) != 0 {
		t.Fatalf("empty disclosures = %v (nil=%v) err=%v; want non-nil empty", d, d == nil, err)
	}

	// Insert in NON-canonical order: r1/output, r1/input, then r0/input (which must sort FIRST).
	// This exercises the (record_id, field) ordering — insertion order is deliberately not the
	// expected output order, so a store that returned insertion order would fail the assertion below.
	ins := []DisclosureSecret{
		{RecordID: "r1", Field: "output", ValueDigest: "sha256:v2", NonceHex: "bb"},
		{RecordID: "r1", Field: "input", ValueDigest: "sha256:v1", NonceHex: "aa"},
		{RecordID: "r0", Field: "input", ValueDigest: "sha256:v0", NonceHex: "00"},
	}
	for _, d := range ins {
		if err := s.PutDisclosure("p", d); err != nil {
			t.Fatalf("put %+v: %v", d, err)
		}
	}

	// Idempotent on (record_id, field): re-recording the same slot with DIFFERENT secrets must NOT
	// overwrite or duplicate — the commitment for a field is immutable once sealed.
	if err := s.PutDisclosure("p", DisclosureSecret{
		RecordID: "r1", Field: "input", ValueDigest: "sha256:CHANGED", NonceHex: "cc",
	}); err != nil {
		t.Fatalf("re-put: %v", err)
	}

	got, err := s.Disclosures("p")
	if err != nil {
		t.Fatalf("disclosures: %v", err)
	}
	// Canonical (record_id, field) order, identical for Mem and Postgres, regardless of insert order.
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
