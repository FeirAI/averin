package content

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stores returns each Store implementation under test, so every behavioral test runs against both
// MemStore and FSStore without duplication.
func stores(t *testing.T) map[string]Store {
	t.Helper()
	fs, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	return map[string]Store{
		"mem": NewMemStore(),
		"fs":  fs,
	}
}

func TestDigestFormat(t *testing.T) {
	d := Digest([]byte("hello"))
	// known SHA-256 of "hello"
	want := "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if d != want {
		t.Fatalf("Digest = %q, want %q", d, want)
	}
}

func TestRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("the quick brown fox"),
		{},                               // empty blob
		[]byte("\x00\x01\x02binary"),     // binary / NUL bytes
		bytes.Repeat([]byte("x"), 1<<16), // larger blob
	}
	for name, st := range stores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			for _, data := range cases {
				addr, err := st.Put(context.Background(), data)
				if err != nil {
					t.Fatalf("Put: %v", err)
				}
				if addr.Digest != Digest(data) {
					t.Errorf("addr.Digest = %q, want %q", addr.Digest, Digest(data))
				}
				if addr.Length != len(data) {
					t.Errorf("addr.Length = %d, want %d", addr.Length, len(data))
				}
				// ObjectVersion is the digest because content-addressed storage is immutable.
				if addr.ObjectVersion != addr.Digest {
					t.Errorf("ObjectVersion = %q, want == Digest %q", addr.ObjectVersion, addr.Digest)
				}
				got, err := st.Get(context.Background(), addr.Digest)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				if !bytes.Equal(got, data) {
					t.Errorf("Get returned %q, want %q", got, data)
				}
			}
		})
	}
}

func TestPutIdempotent(t *testing.T) {
	for name, st := range stores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			data := []byte("idempotent payload")
			a1, err := st.Put(context.Background(), data)
			if err != nil {
				t.Fatalf("Put #1: %v", err)
			}
			a2, err := st.Put(context.Background(), data)
			if err != nil {
				t.Fatalf("Put #2: %v", err)
			}
			if a1 != a2 {
				t.Errorf("idempotent Put gave different addresses: %+v vs %+v", a1, a2)
			}
			got, err := st.Get(context.Background(), a1.Digest)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("Get = %q, want %q", got, data)
			}
		})
	}
}

// TestPutDoesNotAliasInput proves Put copies the caller's slice: mutating it afterwards must not
// change what was stored (otherwise the content-address invariant could be broken after the fact).
func TestPutDoesNotAliasInput(t *testing.T) {
	for name, st := range stores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			data := []byte("mutable input")
			addr, err := st.Put(context.Background(), data)
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			orig := append([]byte(nil), data...)
			for i := range data {
				data[i] = 'Z' // clobber the caller's buffer
			}
			got, err := st.Get(context.Background(), addr.Digest)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got, orig) {
				t.Errorf("stored content changed after caller mutated its slice: got %q, want %q", got, orig)
			}
		})
	}
}

func TestGetAbsentDigest(t *testing.T) {
	// a well-formed but never-stored digest
	absent := Digest([]byte("never stored"))
	for name, st := range stores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			_, err := st.Get(context.Background(), absent)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get(absent) err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestGetInvalidDigest(t *testing.T) {
	bad := []struct {
		name   string
		digest string
	}{
		{"no prefix", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"wrong prefix", "md5:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"too short", "sha256:abcd"},
		{"too long", "sha256:" + strings.Repeat("a", 65)},
		{"non-hex", "sha256:" + strings.Repeat("z", 64)},
		{"uppercase", "sha256:2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824"},
		{"path traversal", "sha256:../../../../etc/passwd"},
		{"empty", ""},
	}
	for name, st := range stores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			for _, tc := range bad {
				_, err := st.Get(context.Background(), tc.digest)
				if !errors.Is(err, ErrInvalidDigest) {
					t.Errorf("Get(%s=%q) err = %v, want ErrInvalidDigest", tc.name, tc.digest, err)
				}
			}
		})
	}
}

// TestFSGetDetectsCorruption corrupts the on-disk blob and confirms Get returns ErrIntegrity rather
// than the substituted bytes — the core threat-#5 detection guarantee.
func TestFSGetDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := []byte("authentic content")
	addr, err := st.Put(context.Background(), data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Find the single blob file (named sha256-<hex>) and overwrite its bytes.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var blobPath string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sha256-") {
			blobPath = filepath.Join(dir, e.Name())
		}
	}
	if blobPath == "" {
		t.Fatalf("no blob file found in %s", dir)
	}
	if err := os.WriteFile(blobPath, []byte("substituted content!"), 0o600); err != nil {
		t.Fatalf("corrupt write: %v", err)
	}
	got, err := st.Get(context.Background(), addr.Digest)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Get(corrupted) err = %v (data=%q), want ErrIntegrity", err, got)
	}
}

// TestMemGetDetectsCorruption tampers with the in-memory blob map directly to prove the verify step
// runs for MemStore too (not just FSStore).
func TestMemGetDetectsCorruption(t *testing.T) {
	st := NewMemStore()
	data := []byte("authentic content")
	addr, err := st.Put(context.Background(), data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	st.blobs[addr.Digest] = []byte("tampered") // simulate at-rest substitution
	if _, err := st.Get(context.Background(), addr.Digest); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Get(tampered) err = %v, want ErrIntegrity", err)
	}
}

// TestFSPutAtomicReExisting confirms re-Putting identical bytes when the file already exists takes
// the idempotent fast path and leaves content intact.
func TestFSPutReExisting(t *testing.T) {
	dir := t.TempDir()
	st, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := []byte("existing")
	if _, err := st.Put(context.Background(), data); err != nil {
		t.Fatalf("Put #1: %v", err)
	}
	if _, err := st.Put(context.Background(), data); err != nil {
		t.Fatalf("Put #2: %v", err)
	}
	// Exactly one blob file should exist (no temp leftovers, no duplicates).
	entries, _ := os.ReadDir(dir)
	blobs := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sha256-") {
			blobs++
		}
		if strings.HasPrefix(e.Name(), "tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
	if blobs != 1 {
		t.Errorf("expected 1 blob file, found %d", blobs)
	}
}

func TestNewFSStoreEmptyDir(t *testing.T) {
	if _, err := NewFSStore(""); err == nil {
		t.Fatal("NewFSStore(\"\") = nil err, want error")
	}
}

func TestEncryptedFSStoreTenantIsolationAndCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	st, err := NewEncryptedFSStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	ctxA := WithTenant(context.Background(), "tenant-a")
	ctxB := WithTenant(context.Background(), "tenant-b")
	plain := []byte("visible model output")
	addr, err := st.Put(ctxA, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctxA, addr.Digest)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if _, err := st.Get(ctxB, addr.Digest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read = %v", err)
	}
	_ = filepath.WalkDir(st.root, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasPrefix(d.Name(), "sha256-") {
			raw, _ := os.ReadFile(path)
			if bytes.Contains(raw, plain) {
				t.Error("plaintext is present in encrypted blob")
			}
		}
		return nil
	})
	if _, err := st.Put(context.Background(), plain); err == nil {
		t.Fatal("missing tenant context accepted")
	}
}

// TestFSStorePermissions checks the root and blob files are not world/group readable (raw blobs may
// hold sensitive input/output).
func TestFSStorePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	st, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	if info, err := os.Stat(dir); err != nil {
		t.Fatalf("stat root: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("root perm = %o, want 700", perm)
	}
	addr, err := st.Put(context.Background(), []byte("secret"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "sha256-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatalf("info: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("blob perm = %o, want 600", perm)
		}
	}
	_ = addr
}

// PurgeOlderThan keys retention on file mtime, and Put dedups on an existing blob — a
// re-committed blob must have its retention window RESTARTED (mtime touched), or content
// still in active use is purged as if it were only as old as the first Put.
func TestPutRefreshesMtimeSoRecommitRestartsRetention(t *testing.T) {
	st, err := NewEncryptedFSStore(t.TempDir(), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithTenant(context.Background(), "tenant-a")
	plain := []byte("re-committed payload")
	addr, err := st.Put(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	// Backdate the blob past the cutoff, then re-commit the same content.
	old := time.Now().Add(-48 * time.Hour)
	if err := filepath.WalkDir(st.root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasPrefix(d.Name(), "sha256-") {
			return err
		}
		return os.Chtimes(path, old, old)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(ctx, plain); err != nil {
		t.Fatal(err)
	}
	removed, err := st.PurgeOlderThan(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 0 {
		t.Fatalf("re-committed blob purged early: removed=%d", removed)
	}
	if got, err := st.Get(ctx, addr.Digest); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("blob must survive purge after re-commit: %q %v", got, err)
	}
}
