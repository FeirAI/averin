package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// feir-ops#16, parent-order rule on the producer side. No soak record has more than one parent, so this
// closes that gap: a record sealed with a FORCED parent (the use_outcome producer) that sorts AFTER the
// session head must still carry byte-ascending parents, and the export must verify with every record proven.
func TestForcedParentIsSealedInAscendingOrderAndVerifies(t *testing.T) {
	c, err := core.New("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	s := New(c, store.NewMem(), "k0").WithAuth(auth.NewOpenStore())
	seal := func(session, idem string, forced []string) map[string]any {
		rec := map[string]any{"project_id": "p1", "session_id": session, "agent_id": "a", "action": "act"}
		if forced != nil {
			rec["causal_prev_hashes"] = forced
		}
		var sealed string
		if err := s.withProjectWrite(t.Context(), "p1", func(st store.Store) error {
			var e error
			sealed, _, e = s.sealAndStore(st, "p1", session, idem, rec, nil)
			return e
		}); err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(sealed), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	head := seal("sess-A", "a-0", nil)["content_hash"].(string)
	// A record in another session whose hash sorts after A's head (random hashes: a few tries suffice).
	var forced string
	for i := 0; i < 64 && forced == ""; i++ {
		if h := seal("sess-B", fmt.Sprintf("b-%d", i), nil)["content_hash"].(string); h > head {
			forced = h
		}
	}
	if forced == "" {
		t.Fatal("no record sorted after the session head in 64 tries")
	}
	out := seal("sess-A", "a-1", []string{forced})
	var parents []string
	for _, p := range out["causal_prev_hashes"].([]any) {
		parents = append(parents, p.(string))
	}
	if len(parents) != 2 || !sort.StringsAreSorted(parents) || parents[0] != head || parents[1] != forced {
		t.Fatalf("parents = %v, want [%s %s] (byte-ascending, no duplicates)", parents, head, forced)
	}
	h := s.Routes()
	req := httptest.NewRequest("POST", "/v2/checkpoints?project=p1", strings.NewReader(""))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("checkpoint: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v2/verify?project=p1", nil))
	rep := w.Body.String()
	if !strings.Contains(rep, `"ok":true`) || strings.Contains(rep, "not a canonical set") {
		t.Fatalf("export with a multi-parent record must verify: %s", rep)
	}
}

// In shadow mode (the documented rollback switch) the ingest check is skipped, like the top-level one; in
// enforce mode it refuses. validateGenericRecordItem is called directly so nothing is sealed (the api suite
// fails if any body is sealed in shadow mode).
func TestIngestNestedMemberCheckIsSkippedOnlyInShadowMode(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	rec := func() map[string]any {
		return map[string]any{"project_id": "p1", "session_id": "s1", "tokens": map[string]any{"in": 1.0, "total": 3.0}}
	}
	enforce, err := core.New(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	se := New(enforce, store.NewMem(), "k0").WithAuth(auth.NewOpenStore())
	if err := se.validateGenericRecordItem(rec()); err == nil || !strings.Contains(err.Error(), "tokens.total") {
		t.Fatalf("enforce mode must refuse and name tokens.total, got %v", err)
	}
	shadow, err := core.New(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	shadow.SetSealShapeMode(core.SealShapeShadow)
	ss := New(shadow, store.NewMem(), "k0").WithAuth(auth.NewOpenStore())
	if err := ss.validateGenericRecordItem(rec()); err != nil {
		t.Fatalf("shadow mode must skip the nested check, got %v", err)
	}
}
