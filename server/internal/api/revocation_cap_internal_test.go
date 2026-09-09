package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

	// Fill p1's set exactly to the cap, directly (the white-box reason this is an internal test).
	set := make(map[string]struct{}, maxRevokedPerProject)
	for i := 0; i < maxRevokedPerProject; i++ {
		set["g"+strconv.Itoa(i)] = struct{}{}
	}
	s.revoked["p1"] = set

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
	if len(s.revoked["p1"]) != maxRevokedPerProject {
		t.Fatalf("set grew past the cap: %d", len(s.revoked["p1"]))
	}
}
