package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/store"
)

// A repeatable-read export may see the previous committed cutoff while a
// revocation transaction is in flight. Once it commits, subsequent snapshots
// and use transactions must see the new revocation.
func TestInFlightRevokeSnapshotAndCommitVisibility(t *testing.T) {
	_, rev, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMem()
	s := New(testCore(t), st, "k0").WithRevocation(rev)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		done <- st.WithProjectWrite(ctx, "p1", func(bound store.Store) error {
			if _, err := bound.RevokeGrant("p1", "g-slow"); err != nil {
				return err
			}
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	finished := false
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		if !finished {
			<-done
		}
	}()
	if yes, err := st.IsRevoked("p1", "g-slow"); err != nil || yes {
		t.Fatalf("uncommitted revoke visible: %v, %v", yes, err)
	}
	exported := make(chan error, 1)
	go func() { _, err := s.buildBundle("p1", false); exported <- err }()
	select {
	case err := <-exported:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read snapshot blocked behind writer")
	}
	close(release)
	err = <-done
	finished = true
	if err != nil {
		t.Fatal(err)
	}
	if yes, err := st.IsRevoked("p1", "g-slow"); err != nil || !yes {
		t.Fatalf("committed revoke invisible: %v, %v", yes, err)
	}
	bundle, err := s.buildBundle("p1", false)
	if err != nil || !strings.Contains(bundle, `"g-slow"`) {
		t.Fatalf("later export missing revoke: %v, %s", err, bundle)
	}
}
