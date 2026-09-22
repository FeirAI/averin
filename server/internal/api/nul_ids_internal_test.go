package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// TestNULInIDsRejected: project_id / idempotency_key feed NUL-delimited derivations (uuidV5Shaped, pendingKey, the
// batch dedup keys, the verify cache key), so a U+0000 inside one (the RCP parser accepts an escaped \u0000) lets
// (project "a", idem "b\0c") and (project "a\0b", idem "c") derive the SAME grant/use/outcome/introspection id and
// pending key across projects. Every entry point must refuse a NUL in project_id, idempotency_key and record_id
// (body, ?project= and the Idempotency-Key header) with a 400 before deriving anything.
func TestNULInIDsRejected(t *testing.T) {
	// The collision this guards against is real: both pairs derive one id.
	if deterministicGrantID("a", "b\x00c") != deterministicGrantID("a\x00b", "c") {
		t.Fatal("expected the NUL-delimited derivation to collide (the premise of this test)")
	}
	if pendingKey("a", "b\x00c") != pendingKey("a\x00b", "c") {
		t.Fatal("expected the NUL-delimited pending key to collide (the premise of this test)")
	}

	c, err := core.New("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	resSeed := bytes.Repeat([]byte{0x77}, 32)
	rc, err := core.New(hex.EncodeToString(resSeed))
	if err != nil {
		t.Fatal(err)
	}
	rev := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, 32))
	brk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	h := New(c, store.NewMem(), "k0").WithBroker(brk).WithResource(rc, "orders-db").
		WithIntrospection(ed25519.NewKeyFromSeed(resSeed)).WithRevocation(rev).Routes()

	do := func(method, target, body string, hdr map[string]string) (int, string) {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	// The colliding pair, on every body-carrying route that derives an id from (project_id, idempotency_key).
	pairs := []struct{ project, idem string }{{`a`, `b\u0000c`}, {`a\u0000b`, `c`}}
	for _, p := range pairs {
		ids := `"project_id":"` + p.project + `","idempotency_key":"` + p.idem + `","session_id":"s1"`
		for _, tc := range []struct{ path, body string }{
			{"/v2/records", `{` + ids + `}`},
			{"/v2/records", `[{` + ids + `}]`},
			{"/v2/grants", `{` + ids + `,"agent_id":"x","action":"a","resource":"r","scope":"s"}`},
			{"/v2/grants/prepare", `{` + ids + `,"agent_id":"x","action":"a","resource":"r","scope":"s"}`},
			{"/v2/grants/finalize", `{` + ids + `}`},
			{"/v2/use", `{` + ids + `,"capability":"c"}`},
			{"/v2/use-intent", `{` + ids + `,"capability":"c"}`},
			{"/v2/use-outcome", `{` + ids + `,"intent_record_id":"i","status":"ok"}`},
			{"/v2/introspection", `{` + ids + `,"grant_id":"g","credential_ref":"cr","effective_scope":"s","effective_exp":1}`},
		} {
			code, resp := do("POST", tc.path, tc.body, nil)
			if code != http.StatusBadRequest || !strings.Contains(resp, "NUL") {
				t.Errorf("POST %s with project_id=%q idempotency_key=%q: got %d %s, want 400 (NUL)", tc.path, p.project, p.idem, code, resp)
			}
		}
	}
	for _, tc := range []struct{ method, target, body string }{
		{"POST", "/v2/records", `{"project_id":"p1","session_id":"s1","idempotency_key":"k","record_id":"r\u0000x"}`},
		{"POST", "/v2/revoke", `{"project_id":"p1","grant_id":"g\u0000x"}`},
		{"POST", "/v2/revoke", `{"project_id":"p\u0000x","grant_id":"g"}`},
		{"POST", "/v2/checkpoints?project=a%00b", ``},
		{"GET", "/v2/verify?project=a%00b", ``},
		{"GET", "/v2/export?project=a%00b", ``},
		{"POST", "/v2/otel/traces?project=a%00b", `{}`},
	} {
		if code, resp := do(tc.method, tc.target, tc.body, nil); code != http.StatusBadRequest || !strings.Contains(resp, "NUL") {
			t.Errorf("%s %s %s: got %d %s, want 400 (NUL)", tc.method, tc.target, tc.body, code, resp)
		}
	}
	if code, resp := do("POST", "/v2/records", `{"project_id":"p1","session_id":"s1"}`, map[string]string{"Idempotency-Key": "b\x00c"}); code != http.StatusBadRequest || !strings.Contains(resp, "NUL") {
		t.Errorf("Idempotency-Key header with a NUL: got %d %s, want 400 (NUL)", code, resp)
	}
	// A NUL-free request on the same routes is unaffected.
	if code, resp := do("POST", "/v2/records", `{"project_id":"p1","session_id":"s1","idempotency_key":"k"}`, nil); code != http.StatusCreated {
		t.Fatalf("a NUL-free record must still ingest: %d %s", code, resp)
	}
}
