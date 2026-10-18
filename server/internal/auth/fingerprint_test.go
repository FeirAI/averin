package auth

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/secretfp"
)

// The store keeps digests only, so the posture fingerprints are computed when a plaintext token is
// added; a digest-configured key has none, and re-adding it by digest must not erase a known one.
func TestMapStore_Fingerprints(t *testing.T) {
	ks := NewMapStore(map[string][]string{"p1": {"tok-a"}, "p2": {"tok-a", "tok-b"}})
	want := []string{secretfp.Fingerprint("tok-a", FingerprintRelationship), secretfp.Fingerprint("tok-b", FingerprintRelationship)}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0]
	}
	got := ks.Fingerprints()
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Fingerprints() = %v, want %v", got, want)
	}
	ks.AddDigest("p3", sha256.Sum256([]byte("tok-c")), RoleAdmin, time.Time{})
	if len(ks.Fingerprints()) != 2 {
		t.Fatalf("a digest-only key must have no fingerprint, got %v", ks.Fingerprints())
	}
	ks.AddDigest("p1", sha256.Sum256([]byte("tok-a")), RoleRead, time.Time{})
	if len(ks.Fingerprints()) != 2 {
		t.Fatalf("re-adding by digest erased a known fingerprint: %v", ks.Fingerprints())
	}
}
