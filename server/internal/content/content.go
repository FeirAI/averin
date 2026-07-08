// Package content is a content-addressed blob store for raw input/output/rationale payloads. Blobs
// are pinned by their SHA-256 digest, which is the address: the same bytes always produce the same
// address, and the address can never refer to different bytes. This closes threat #5 (mutable keys):
// because the key IS the hash of the content, there is no way to swap the bytes behind an address
// without changing the address, and every read re-hashes the bytes and rejects any mismatch.
//
// IMPORTANT: this package does NOT compute the averin hiding commitments (Pedersen/blinded digests for
// selective disclosure) — that lives in the Rust core. Here we only store and fetch raw bytes by a
// plain SHA-256 digest and hand back an immutable address. The address returned here is therefore
// the *content* address, not a hiding commitment.
package content

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Address is the immutable, content-derived handle for a stored blob. Because content-addressed
// storage is immutable by construction, ObjectVersion is the digest itself: there is exactly one
// version of any given content, and it never changes.
type Address struct {
	Digest        string `json:"digest"`         // "sha256:<lowercase-hex>"
	Length        int    `json:"length"`         // byte length of the stored blob
	ObjectVersion string `json:"object_version"` // == Digest (content-addressed == immutable)
}

// Errors returned by the store. Callers can compare with errors.Is.
var (
	// ErrNotFound is returned by Get when no blob exists for the requested digest.
	ErrNotFound = errors.New("content: not found")
	// ErrInvalidDigest is returned when a digest string is malformed (wrong prefix, bad hex,
	// or wrong length). Validating the digest before touching the filesystem also blocks path
	// traversal: a digest like "../../etc/passwd" never reaches a file open.
	ErrInvalidDigest = errors.New("content: invalid digest")
	// ErrIntegrity is returned by Get when the stored bytes do not hash back to the requested
	// digest — i.e. the blob was substituted or corrupted at rest (threat #5 / detection).
	ErrIntegrity = errors.New("content: integrity check failed: stored bytes do not match digest")
)

const digestPrefix = "sha256:"

// Store stores and retrieves opaque blobs by their SHA-256 content address.
type Store interface {
	// Put stores data and returns its content address. Put is idempotent: storing the same bytes
	// again yields the same digest/address and does not duplicate or mutate anything.
	Put(ctx context.Context, data []byte) (Address, error)
	// Get returns the bytes previously stored under digest. It re-hashes the returned bytes and
	// fails with ErrIntegrity if they do not match the requested digest (substitution detection),
	// ErrNotFound if the digest is absent, and ErrInvalidDigest if the digest is malformed.
	Get(ctx context.Context, digest string) ([]byte, error)
}

type tenantContextKey struct{}

// WithTenant binds durable content encryption to a tenant/project identity.
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, strings.TrimSpace(tenant))
}

func tenantFrom(ctx context.Context) (string, error) {
	tenant, _ := ctx.Value(tenantContextKey{}).(string)
	if tenant == "" {
		return "", errors.New("content: tenant context is required")
	}
	return tenant, nil
}

// Digest computes the content address ("sha256:<hex>") of data.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return digestPrefix + hex.EncodeToString(sum[:])
}

// addressFor builds the immutable Address for a digest/length pair.
func addressFor(digest string, length int) Address {
	return Address{Digest: digest, Length: length, ObjectVersion: digest}
}

// parseDigest validates "sha256:<64-lowercase-hex>" and returns the raw hex (no prefix). It rejects
// anything else, which is what keeps a digest from ever being usable as a filesystem path component.
func parseDigest(digest string) (hexPart string, err error) {
	if !strings.HasPrefix(digest, digestPrefix) {
		return "", fmt.Errorf("%w: missing %q prefix", ErrInvalidDigest, digestPrefix)
	}
	h := strings.TrimPrefix(digest, digestPrefix)
	if len(h) != sha256.Size*2 { // 32 bytes -> 64 hex chars
		return "", fmt.Errorf("%w: expected %d hex chars, got %d", ErrInvalidDigest, sha256.Size*2, len(h))
	}
	// Require lowercase hex specifically so the digest has a single canonical form (a blob stored
	// as the lowercase digest cannot be re-addressed under a differently-cased string).
	if h != strings.ToLower(h) {
		return "", fmt.Errorf("%w: digest hex must be lowercase", ErrInvalidDigest)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("%w: not valid hex: %v", ErrInvalidDigest, err)
	}
	return h, nil
}

// verify re-hashes data and confirms it matches digest in constant time. It returns ErrIntegrity on
// mismatch. Constant-time comparison avoids leaking, via timing, how much of a substituted blob's
// digest happened to match — cheap defense for a security-critical check.
func verify(digest string, data []byte) error {
	got := Digest(data)
	if subtle.ConstantTimeCompare([]byte(got), []byte(digest)) != 1 {
		return ErrIntegrity
	}
	return nil
}

// ---- in-memory implementation ----

// MemStore is an in-memory content store for tests and single-node dev. It is safe for concurrent
// use.
type MemStore struct {
	mu    sync.RWMutex
	blobs map[string][]byte // digest -> bytes
}

// NewMemStore returns an empty in-memory content store.
func NewMemStore() *MemStore {
	return &MemStore{blobs: map[string][]byte{}}
}

// Put stores data and returns its address. Idempotent: re-storing identical bytes is a no-op that
// returns the same address.
func (m *MemStore) Put(_ context.Context, data []byte) (Address, error) {
	digest := Digest(data)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blobs[digest]; !ok {
		// Copy so a caller mutating its slice after Put cannot mutate stored content (which would
		// silently break the content-address invariant).
		cp := make([]byte, len(data))
		copy(cp, data)
		m.blobs[digest] = cp
	}
	return addressFor(digest, len(data)), nil
}

// Get returns the bytes for digest, verifying integrity before handing them back.
func (m *MemStore) Get(_ context.Context, digest string) ([]byte, error) {
	if _, err := parseDigest(digest); err != nil {
		return nil, err
	}
	m.mu.RLock()
	stored, ok := m.blobs[digest]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if err := verify(digest, stored); err != nil {
		return nil, err
	}
	// Return a copy so callers cannot mutate the canonical stored blob.
	out := make([]byte, len(stored))
	copy(out, stored)
	return out, nil
}

// ---- filesystem implementation ----

// FSStore persists blobs as files named by their digest under a root directory. Because the filename
// is the content digest, the filesystem layout is itself content-addressed and immutable.
type FSStore struct {
	root string
}

// NewFSStore returns a content store rooted at dir, creating it if necessary. The root is created
// with 0o700 so blobs (which may contain sensitive raw input/output) are not world-readable.
func NewFSStore(dir string) (*FSStore, error) {
	if dir == "" {
		return nil, errors.New("content: empty root dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("content: create root: %w", err)
	}
	return &FSStore{root: dir}, nil
}

// path maps a validated digest to its on-disk file. parseDigest has already rejected any non-hex
// content, so hexPart can never contain a path separator or "..".
func (f *FSStore) path(digest string) (string, error) {
	hexPart, err := parseDigest(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(f.root, "sha256-"+hexPart), nil
}

// Put writes data to its content-addressed file and returns the address. Idempotent: if the file
// already exists it is left untouched (same bytes -> same file). The write is atomic (temp file +
// rename) so a crash mid-write never leaves a truncated blob under a digest that would then fail
// verification on read.
func (f *FSStore) Put(_ context.Context, data []byte) (Address, error) {
	digest := Digest(data)
	dst, err := f.path(digest)
	if err != nil {
		return Address{}, err
	}
	if _, err := os.Stat(dst); err == nil {
		return addressFor(digest, len(data)), nil // already present; idempotent
	} else if !errors.Is(err, os.ErrNotExist) {
		return Address{}, fmt.Errorf("content: stat: %w", err)
	}

	tmp, err := os.CreateTemp(f.root, "tmp-*")
	if err != nil {
		return Address{}, fmt.Errorf("content: temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if anything below fails before the rename succeeds.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return Address{}, fmt.Errorf("content: write: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return Address{}, fmt.Errorf("content: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Address{}, fmt.Errorf("content: close: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return Address{}, fmt.Errorf("content: rename: %w", err)
	}
	return addressFor(digest, len(data)), nil
}

// Get reads the file for digest and verifies it hashes back to that digest before returning it. A
// corrupted or substituted file on disk therefore surfaces as ErrIntegrity rather than silently
// returning the wrong bytes.
func (f *FSStore) Get(_ context.Context, digest string) ([]byte, error) {
	p, err := f.path(digest)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("content: read: %w", err)
	}
	if err := verify(digest, data); err != nil {
		return nil, err
	}
	return data, nil
}

// EncryptedFSStore stores tenant-encrypted AES-256-GCM envelopes while the
// public Address remains bound to the plaintext digest sealed in proof records.
type EncryptedFSStore struct {
	root   string
	master [32]byte
}

func NewEncryptedFSStore(dir string, masterKey []byte) (*EncryptedFSStore, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("content: encryption master key must be exactly 32 bytes")
	}
	if dir == "" {
		return nil, errors.New("content: empty root dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("content: create encrypted root: %w", err)
	}
	s := &EncryptedFSStore{root: dir}
	copy(s.master[:], masterKey)
	return s, nil
}

func (s *EncryptedFSStore) tenantKey(tenant string) []byte {
	h := hmac.New(sha256.New, s.master[:])
	_, _ = h.Write([]byte("averin-content-v1\x00" + tenant))
	return h.Sum(nil)
}

func (s *EncryptedFSStore) path(tenant, digest string) (string, error) {
	hexPart, err := parseDigest(digest)
	if err != nil {
		return "", err
	}
	tenantHash := sha256.Sum256([]byte(tenant))
	dir := filepath.Join(s.root, "tenant-"+hex.EncodeToString(tenantHash[:16]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "sha256-"+hexPart), nil
}

func (s *EncryptedFSStore) Put(ctx context.Context, data []byte) (Address, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return Address{}, err
	}
	digest := Digest(data)
	dst, err := s.path(tenant, digest)
	if err != nil {
		return Address{}, err
	}
	if _, err := os.Stat(dst); err == nil {
		// Refresh mtime on the dedup hit: PurgeOlderThan keys retention on mtime, so a
		// re-committed blob must restart its retention window instead of inheriting the
		// first Put's age and being purged early. Best-effort — a failed touch only
		// shortens retention, never breaks proof integrity.
		now := time.Now()
		_ = os.Chtimes(dst, now, now)
		return addressFor(digest, len(data)), nil
	}
	block, err := aes.NewCipher(s.tenantKey(tenant))
	if err != nil {
		return Address{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Address{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Address{}, err
	}
	envelope := append([]byte("AVENC1"), nonce...)
	envelope = gcm.Seal(envelope, nonce, data, []byte(tenant+"\x00"+digest))
	tmp, err := os.CreateTemp(filepath.Dir(dst), "tmp-*")
	if err != nil {
		return Address{}, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(envelope); err != nil {
		_ = tmp.Close()
		return Address{}, err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return Address{}, err
	}
	if err := tmp.Close(); err != nil {
		return Address{}, err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return Address{}, err
	}
	return addressFor(digest, len(data)), nil
}

func (s *EncryptedFSStore) Get(ctx context.Context, digest string) ([]byte, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	p, err := s.path(tenant, digest)
	if err != nil {
		return nil, err
	}
	envelope, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.tenantKey(tenant))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(envelope) < 6+gcm.NonceSize() || string(envelope[:6]) != "AVENC1" {
		return nil, ErrIntegrity
	}
	nonce := envelope[6 : 6+gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce, envelope[6+gcm.NonceSize():], []byte(tenant+"\x00"+digest))
	if err != nil || verify(digest, plain) != nil {
		return nil, ErrIntegrity
	}
	return plain, nil
}

// PurgeOlderThan deletes raw encrypted payloads after retention. Proof metadata
// keeps its sealed digest and remains verifiable after this deletion.
func (s *EncryptedFSStore) PurgeOlderThan(cutoff time.Time) (int, error) {
	removed := 0
	err := filepath.WalkDir(s.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "sha256-") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}
