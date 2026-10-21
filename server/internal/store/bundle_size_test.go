package store

import "testing"

// BundleSizeParts sums stored JSON in octets (multibyte text counts its bytes, not its characters) and agrees
// between the in-memory and Postgres stores; an empty project is all zeros.
func bundleSizeScenario(t *testing.T, s Store) {
	t.Helper()
	empty, err := s.BundleSizeParts("none")
	if err != nil || empty != (BundleSizeParts{}) {
		t.Fatalf("empty project: %+v %v", empty, err)
	}
	recs := []string{`{"a":"x"}`, `{"a":"héllo ✓"}`, `{"a":"日本語"}`}
	var want BundleSizeParts
	for i, j := range recs {
		hash := []string{"sha256:aa", "sha256:bb", "sha256:cc"}[i]
		if _, _, err := s.PutRecord("p", "k"+hash, Record{JSON: j, ContentHash: hash, SessionID: "s"}); err != nil {
			t.Fatal(err)
		}
		want.RecordBytes += int64(len(j))
		want.Records++
	}
	for i, j := range []string{`{"seq":1}`, `{"seq":2,"n":"é"}`} {
		if err := s.PutCheckpoint("p", Checkpoint{JSON: j, CheckpointHash: []string{"h1", "h2"}[i], Seq: int64(i + 1)}); err != nil {
			t.Fatal(err)
		}
		want.CheckpointBytes += int64(len(j))
		want.Checkpoints++
	}
	got, err := s.BundleSizeParts("p")
	if err != nil || got != want {
		t.Fatalf("got %+v want %+v (%v)", got, want, err)
	}
}

func TestBundleSizePartsMem(t *testing.T) { bundleSizeScenario(t, NewMem()) }

func TestBundleSizePartsPostgres(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	bundleSizeScenario(t, p)
}
