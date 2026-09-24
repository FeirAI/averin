package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/store"
)

func holdProject(t *testing.T, st store.Store, projectID string) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- st.WithProjectWrite(ctx, projectID, func(store.Store) error {
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
	case err := <-done:
		t.Fatalf("holder failed: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
		cancel()
	}
}

func TestGrantPrepareProjectSerialization(t *testing.T) {
	brokerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	st := store.NewMem()
	s := New(testCore(t), st, "k0").WithBroker(brokerKey)
	release := holdProject(t, st, "p1")
	defer func() {
		if release != nil {
			release()
		}
	}()
	request := func(project, idem string) int {
		body := grantChallengeBodyForProject(project, idem, "read:orders", agentKey)
		w := httptest.NewRecorder()
		s.handleGrantPrepare(w, httptest.NewRequest("POST", "/v2/grants/prepare", bytes.NewReader([]byte(body))))
		return w.Code
	}
	blocked := make(chan int, 1)
	go func() { blocked <- request("p1", "same") }()
	select {
	case code := <-blocked:
		t.Fatalf("same project escaped guard: %d", code)
	case <-time.After(100 * time.Millisecond):
	}
	other := make(chan int, 1)
	go func() { other <- request("p2", "independent") }()
	select {
	case code := <-other:
		if code != http.StatusOK {
			t.Fatalf("other project prepare = %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("other project stalled")
	}
	release()
	release = nil
	select {
	case code := <-blocked:
		if code != http.StatusOK {
			t.Fatalf("same project prepare = %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("same project never resumed")
	}
}

func TestRevokeProjectSerialization(t *testing.T) {
	_, revKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMem()
	s := New(testCore(t), st, "k0").WithRevocation(revKey)
	release := holdProject(t, st, "p1")
	defer func() {
		if release != nil {
			release()
		}
	}()
	request := func(project string) int {
		body := `{"project_id":"` + project + `","grant_id":"g-1"}`
		w := httptest.NewRecorder()
		s.handleRevoke(w, httptest.NewRequest("POST", "/v2/revoke?project="+project, bytes.NewReader([]byte(body))))
		return w.Code
	}
	blocked := make(chan int, 1)
	go func() { blocked <- request("p1") }()
	select {
	case code := <-blocked:
		t.Fatalf("same project escaped guard: %d", code)
	case <-time.After(100 * time.Millisecond):
	}
	other := make(chan int, 1)
	go func() { other <- request("p2") }()
	select {
	case code := <-other:
		if code != http.StatusCreated {
			t.Fatalf("other project revoke = %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("other project stalled")
	}
	release()
	release = nil
	select {
	case code := <-blocked:
		if code != http.StatusCreated {
			t.Fatalf("same project revoke = %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("same project never resumed")
	}
}
