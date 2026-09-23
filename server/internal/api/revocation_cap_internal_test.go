package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// TestRevokeSetSizeCap (white-box): the in-memory revoked set is bounded per project so a caller cannot flood it
// with fabricated grant_ids (unbounded memory + signed-export amplification). A NEW id past the cap is rejected
// 429, but re-revoking an id ALREADY in the set is always allowed (idempotent) even at capacity.
func TestRevokeSetSizeCap(t *testing.T) {
	const serverSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	c, err := core.New(serverSeed)
	if err != nil {
		t.Fatal(err)
	}
	_, rev, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := New(c, store.NewMem(), "k0").WithRevocation(rev)

	s.revocationCap = 3
	for _, id := range []string{"g0", "g1", "g2"} {
		if _, code, msg := s.revokeGrantIDTotal("p1", id); code != 0 || msg != "" {
			t.Fatalf("seed revoke %s: %d %s", id, code, msg)
		}
	}

	post := func(grantID string) int {
		body, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": grantID})
		req := httptest.NewRequest("POST", "/v2/revoke?project=p1", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.handleRevoke(w, req)
		return w.Code
	}

	// A brand-new id at capacity is rejected.
	if code := post("a-brand-new-id-not-in-the-set"); code != http.StatusTooManyRequests {
		t.Fatalf("a new id past the cap must be 429, got %d", code)
	}
	// Re-revoking an id already present is idempotent and allowed even at capacity.
	if code := post("g0"); code != http.StatusCreated {
		t.Fatalf("re-revoking an existing id at capacity must be 201 (idempotent), got %d", code)
	}
	// The set never grew past the cap.
	ids, err := s.st.RevokedGrantIDs("p1")
	if err != nil || len(ids) != s.revocationCap {
		t.Fatalf("durable set grew past the cap: %v, %v", ids, err)
	}
}
