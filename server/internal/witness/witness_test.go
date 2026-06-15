package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// cp builds a checkpoint JSON document with the given seq and an arbitrary distinguishing field so
// two checkpoints at the same seq can differ in bytes (a fork).
func cp(t *testing.T, seq int64, hash string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"domain":          "flightrecorder.checkpoint.v2",
		"project_id":      "p1",
		"checkpoint_seq":  seq,
		"checkpoint_hash": hash,
	})
	if err != nil {
		t.Fatalf("marshal checkpoint: %v", err)
	}
	return b
}

// witnesses returns the implementations under test so each behavioral test runs against both.
func witnesses(t *testing.T) map[string]Witness {
	t.Helper()
	fs, err := NewFSWitness(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSWitness: %v", err)
	}
	return map[string]Witness{
		"mem": NewMemWitness(),
		"fs":  fs,
	}
}

func TestAppendAndList(t *testing.T) {
	ctx := context.Background()
	for name, w := range witnesses(t) {
		t.Run(name, func(t *testing.T) {
			c0 := cp(t, 0, "h0")
			c1 := cp(t, 1, "h1")
			c2 := cp(t, 2, "h2")
			// append out of order; List must return seq-ordered
			for _, c := range [][]byte{c2, c0, c1} {
				if err := w.Append(ctx, "p1", c); err != nil {
					t.Fatalf("append: %v", err)
				}
			}
			got, err := w.List(ctx, "p1")
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(got) != 3 {
				t.Fatalf("want 3 entries, got %d", len(got))
			}
			for i, want := range [][]byte{c0, c1, c2} {
				if s, _ := seqOf(got[i]); s != int64(i) {
					t.Fatalf("entry %d has seq %d", i, s)
				}
				if !bytes.Equal(got[i], want) {
					t.Fatalf("entry %d bytes differ from appended", i)
				}
			}
			// a different project is isolated
			if other, _ := w.List(ctx, "p2"); len(other) != 0 {
				t.Fatalf("project isolation broken: got %d entries for p2", len(other))
			}
		})
	}
}

func TestAppendIdempotent(t *testing.T) {
	ctx := context.Background()
	for name, w := range witnesses(t) {
		t.Run(name, func(t *testing.T) {
			c := cp(t, 0, "h0")
			for i := 0; i < 3; i++ {
				if err := w.Append(ctx, "p1", c); err != nil {
					t.Fatalf("append %d: %v", i, err)
				}
			}
			got, _ := w.List(ctx, "p1")
			if len(got) != 1 {
				t.Fatalf("idempotent append should yield 1 entry, got %d", len(got))
			}
		})
	}
}

func TestForkRejected(t *testing.T) {
	ctx := context.Background()
	for name, w := range witnesses(t) {
		t.Run(name, func(t *testing.T) {
			orig := cp(t, 0, "h0")
			if err := w.Append(ctx, "p1", orig); err != nil {
				t.Fatalf("append original: %v", err)
			}
			// a DIFFERENT checkpoint claiming seq 0 -> fork
			fork := cp(t, 0, "h0-EVIL")
			err := w.Append(ctx, "p1", fork)
			if !errors.Is(err, ErrFork) {
				t.Fatalf("want ErrFork, got %v", err)
			}
			// the original entry must be untouched (append-only, no overwrite)
			got, _ := w.List(ctx, "p1")
			if len(got) != 1 {
				t.Fatalf("want 1 entry after rejected fork, got %d", len(got))
			}
			if !bytes.Equal(got[0], orig) {
				t.Fatalf("original entry was mutated by a fork attempt")
			}
		})
	}
}

// TestFSAppendOnlyNoMutation verifies the on-disk entry file is never rewritten: re-appending
// identical bytes is a no-op (idempotent) and a conflicting append leaves the file's content and
// modtime unchanged.
func TestFSAppendOnlyNoMutation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	w, err := NewFSWitness(root)
	if err != nil {
		t.Fatalf("NewFSWitness: %v", err)
	}
	orig := cp(t, 0, "h0")
	if err := w.Append(ctx, "p1", orig); err != nil {
		t.Fatalf("append: %v", err)
	}
	file := filepath.Join(root, "p1", entryName(0))
	st0, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// idempotent re-append: no error, file unchanged
	if err := w.Append(ctx, "p1", orig); err != nil {
		t.Fatalf("idempotent re-append: %v", err)
	}
	// fork attempt: ErrFork, file unchanged
	if err := w.Append(ctx, "p1", cp(t, 0, "evil")); !errors.Is(err, ErrFork) {
		t.Fatalf("want ErrFork, got %v", err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read after attempts: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("witness file content changed; append-only violated")
	}
	st1, _ := os.Stat(file)
	if st0.Size() != st1.Size() {
		t.Fatalf("witness file size changed: %d -> %d", st0.Size(), st1.Size())
	}
}

func TestAppendRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		proj string
		json []byte
	}{
		{"empty project", "", cp(t, 0, "h")},
		{"missing seq", "p1", []byte(`{"checkpoint_hash":"h"}`)},
		{"invalid json", "p1", []byte(`{not json`)},
		{"negative seq", "p1", []byte(`{"checkpoint_seq":-1}`)},
	}
	for name, w := range witnesses(t) {
		for _, tc := range tests {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				if err := w.Append(ctx, tc.proj, tc.json); err == nil {
					t.Fatalf("expected error for %q, got nil", tc.name)
				}
			})
		}
	}
}

// TestFSWitnessRejectsTraversalProjectID ensures a crafted project id cannot escape the witness root.
func TestFSWitnessRejectsTraversalProjectID(t *testing.T) {
	ctx := context.Background()
	w, err := NewFSWitness(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSWitness: %v", err)
	}
	for _, bad := range []string{"../escape", "a/b", "..", ".", "x\x00y", "a/../../etc"} {
		if err := w.Append(ctx, bad, cp(t, 0, "h")); err == nil {
			t.Fatalf("project id %q should be rejected", bad)
		}
		if _, err := w.List(ctx, bad); err == nil {
			t.Fatalf("List should reject project id %q", bad)
		}
	}
}

// TestMemAppendDefensiveCopy proves mutating the caller's slice after Append does not corrupt the
// stored witness entry.
func TestMemAppendDefensiveCopy(t *testing.T) {
	ctx := context.Background()
	w := NewMemWitness()
	c := cp(t, 0, "h0")
	if err := w.Append(ctx, "p1", c); err != nil {
		t.Fatalf("append: %v", err)
	}
	for i := range c {
		c[i] = 'X' // scribble over the caller's buffer
	}
	got, _ := w.List(ctx, "p1")
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if s, err := seqOf(got[0]); err != nil || s != 0 {
		t.Fatalf("stored entry corrupted by caller mutation: seq=%d err=%v", s, err)
	}
}

func TestAppendContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, w := range witnesses(t) {
		t.Run(name, func(t *testing.T) {
			if err := w.Append(ctx, "p1", cp(t, 0, "h")); !errors.Is(err, context.Canceled) {
				t.Fatalf("want context.Canceled, got %v", err)
			}
			if _, err := w.List(ctx, "p1"); !errors.Is(err, context.Canceled) {
				t.Fatalf("List want context.Canceled, got %v", err)
			}
		})
	}
}

// ---- TSA ----

func imprint(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func TestStubTSADeterministic(t *testing.T) {
	ctx := context.Background()
	s := StubTSA{}
	a, err := s.Stamp(ctx, imprint("hash-A"))
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	b, _ := s.Stamp(ctx, imprint("hash-A"))
	if !bytes.Equal(a, b) {
		t.Fatalf("StubTSA not deterministic for identical imprint")
	}
	c, _ := s.Stamp(ctx, imprint("hash-B"))
	if bytes.Equal(a, c) {
		t.Fatalf("StubTSA returned same token for different imprints")
	}
	if !bytes.HasPrefix(a, []byte("STUBTSAv1")) {
		t.Fatalf("StubTSA token missing default prefix")
	}
	// wrong imprint length is rejected
	if _, err := s.Stamp(ctx, []byte("short")); err == nil {
		t.Fatalf("StubTSA should reject non-32-byte imprint")
	}
}

func TestBuildTimeStampReqShape(t *testing.T) {
	der, err := BuildTimeStampReq(imprint("checkpoint-hash"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// outer SEQUENCE
	if len(der) < 2 || der[0] != 0x30 {
		t.Fatalf("TSQ does not start with SEQUENCE tag: %x", der)
	}
	// version INTEGER 1 immediately follows the SEQUENCE header (length is short-form here)
	if der[2] != 0x02 || der[3] != 0x01 || der[4] != 0x01 {
		t.Fatalf("TSQ version is not INTEGER 1: %x", der[2:5])
	}
	// the SHA-256 OID and the 32-byte imprint must both appear
	if !bytes.Contains(der, sha256OID) {
		t.Fatalf("TSQ missing SHA-256 OID")
	}
	if !bytes.Contains(der, imprint("checkpoint-hash")) {
		t.Fatalf("TSQ missing the imprint bytes")
	}
	// certReq BOOLEAN TRUE present
	if !bytes.Contains(der, []byte{0x01, 0x01, 0xFF}) {
		t.Fatalf("TSQ missing certReq BOOLEAN TRUE")
	}
	// wrong imprint length rejected
	if _, err := BuildTimeStampReq([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for short imprint")
	}
}

func TestHTTPTSAPostsTSQAndReturnsToken(t *testing.T) {
	ctx := context.Background()
	imp := imprint("anchor-me")
	wantToken := []byte("DER-TIMESTAMP-TOKEN")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("want POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != tsqContentType {
			t.Errorf("want content-type %q, got %q", tsqContentType, ct)
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		// the server received a DER TSQ that contains the imprint we asked to stamp
		if !bytes.Contains(body, imp) {
			t.Errorf("posted TSQ does not contain the imprint")
		}
		if len(body) == 0 || body[0] != 0x30 {
			t.Errorf("posted body is not a DER SEQUENCE")
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(wantToken)
	}))
	defer srv.Close()

	tsa := &HTTPTSA{URL: srv.URL}
	tok, err := tsa.Stamp(ctx, imp)
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if !bytes.Equal(tok, wantToken) {
		t.Fatalf("token mismatch: got %q", tok)
	}
}

func TestHTTPTSAErrorPaths(t *testing.T) {
	ctx := context.Background()

	// non-200 -> error, status surfaced, no body leaked
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("secret-error-detail"))
	}))
	defer bad.Close()
	if _, err := (&HTTPTSA{URL: bad.URL}).Stamp(ctx, imprint("x")); err == nil {
		t.Fatal("expected error on non-200")
	} else if bytes.Contains([]byte(err.Error()), []byte("secret-error-detail")) {
		t.Fatalf("error leaked response body: %v", err)
	}

	// empty token -> error
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer empty.Close()
	if _, err := (&HTTPTSA{URL: empty.URL}).Stamp(ctx, imprint("x")); err == nil {
		t.Fatal("expected error on empty token")
	}

	// missing URL -> error
	if _, err := (&HTTPTSA{}).Stamp(ctx, imprint("x")); err == nil {
		t.Fatal("expected error on empty URL")
	}

	// custom TSQBuilder is honored
	called := false
	custom := &HTTPTSA{
		URL: empty.URL,
		Build: func(_ []byte) ([]byte, error) {
			called = true
			return []byte{0x30, 0x00}, nil
		},
	}
	_, _ = custom.Stamp(ctx, imprint("x"))
	if !called {
		t.Fatal("custom TSQBuilder was not invoked")
	}
}
