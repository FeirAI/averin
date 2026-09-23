package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// blockingDurable is a durable store whose Revoke blocks until released — a slow/degraded Postgres round-trip.
type blockingDurable struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingDurable) Revoke(string, string) error {
	close(b.entered)
	<-b.release
	return nil
}

func (b *blockingDurable) PutPending(_, _, _ string, payload []byte, created time.Time) ([]byte, time.Time, error) {
	return payload, created, nil
}

func (b *blockingDurable) DeletePending(string, string) error { return nil }

// TestSlowRevokeDoesNotStallUseCheck (review finding 3): handleRevoke holds the per-project revoke lock across the
// durable Postgres write, and isRevoked runs on the /v2/use path under the process-wide ingestMu. If isRevoked took
// that same lock, ONE slow revoke would stall every ingest on the process. It must read the published snapshot
// instead: return immediately while the revoke is in flight (not yet revoked — persist-then-publish), and observe
// the revocation once the revoke has returned.
func TestSlowRevokeDoesNotStallUseCheck(t *testing.T) {
	c, err := core.New("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	_, rev, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := New(c, store.NewMem(), "k0").WithRevocation(rev)
	bd := &blockingDurable{entered: make(chan struct{}), release: make(chan struct{})}
	s.durable = bd

	done := make(chan int, 1)
	go func() {
		body, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": "g-slow"})
		w := httptest.NewRecorder()
		s.handleRevoke(w, httptest.NewRequest("POST", "/v2/revoke?project=p1", bytes.NewReader(body)))
		done <- w.Code
	}()
	<-bd.entered // the revoke now holds revokeLocks(p1) inside the durable write

	checked := make(chan bool, 1)
	go func() { checked <- s.isRevoked("p1", "g-slow") }()
	select {
	case revoked := <-checked:
		if revoked {
			t.Fatal("a revocation must not be visible before it is durably persisted")
		}
	case <-time.After(2 * time.Second):
		close(bd.release)
		t.Fatal("isRevoked blocked behind an in-flight durable revoke — a slow revoke stalls /v2/use (and ingestMu)")
	}
	exported := make(chan error, 1)
	go func() { _, err := s.buildRevocationListForExport("p1", nil); exported <- err }()
	select {
	case err := <-exported:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(bd.release)
		t.Fatal("the export blocked behind an in-flight durable revoke")
	}

	close(bd.release)
	if code := <-done; code != http.StatusCreated {
		t.Fatalf("revoke = %d, want 201", code)
	}
	if !s.isRevoked("p1", "g-slow") {
		t.Fatal("a revoke that returned 201 must be observed by the next use check")
	}
}
