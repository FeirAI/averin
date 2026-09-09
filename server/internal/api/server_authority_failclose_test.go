package api_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// forgedHumanSignedBody builds a human_signed (kill/approval-shaped) record whose evidence_sig is signed by
// `signer` — the toggle tests pin a DIFFERENT key so verification fails, modeling a govder/averin authority-key
// MISALIGNMENT. signAuthorityEvidence + peSeed are defined in server_authority_test.go (same test package).
func forgedHumanSignedBody(idem, project, recordID string, signer ed25519.PrivateKey) string {
	sum := sha256.Sum256([]byte("kill-authority-claim"))
	eh := "sha256:" + hex.EncodeToString(sum[:])
	body, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": project, "session_id": "s1", "record_id": recordID,
		"event_type": "decision", "status": "ok", "action": "kill",
		"authority": map[string]any{
			"source": "human_signed", "evidence_hash": eh,
			"evidence_sig": signAuthorityEvidence("human_signed", project, recordID, eh, signer),
		},
	})
	return string(body)
}

// TestRequirePinnedAuthorityRejectsMisalignedElevation (averin#6, fail-closed): with a human_signed key pinned
// AND AVERIN_REQUIRE_PINNED_AUTHORITY on, a human_signed record whose evidence_sig was signed by the WRONG key
// (a key misalignment) is REJECTED with 500 — and seals NOTHING — instead of being silently downgraded to the
// forgeable caller_declared and permanently recorded. This is the whole point of the toggle: a kill/audit is
// never recorded at forgeable authority when the operator asked for fail-closed.
func TestRequirePinnedAuthorityRejectsMisalignedElevation(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	pinned := ed25519.NewKeyFromSeed(peSeed(0x51)) // key the server pins for human_signed
	wrong := ed25519.NewKeyFromSeed(peSeed(0x52))  // MISALIGNMENT: records are signed by this other key
	h := api.New(c, store.NewMem(), "k0").
		WithPolicyEngineKey("human_signed", pinned.Public().(ed25519.PublicKey)).
		WithRequirePinnedAuthority(true).Routes()

	body := forgedHumanSignedBody("k1", "p1", "kill-1", wrong)
	if code, r := do(t, h, "POST", "/v2/records", body); code != http.StatusInternalServerError {
		t.Fatalf("with AVERIN_REQUIRE_PINNED_AUTHORITY on, a misaligned human_signed elevation must be REJECTED 500, got %d: %s", code, r)
	}
	// nothing entered the append-only store at forgeable authority.
	code, list := do(t, h, "GET", "/v2/records?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, list)
	}
	var out struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal([]byte(list), &out)
	if out.Total != 0 {
		t.Fatalf("a rejected elevation must seal NOTHING, got total=%d: %s", out.Total, list)
	}
}

// TestFailedElevationUnderFailOpenOptOutDowngradesToCallerDeclared (averin#6, back-compat): the SAME
// misalignment with the fail-OPEN opt-out EXPLICITLY selected (AVERIN_REQUIRE_PINNED_AUTHORITY=0) preserves
// the Phase-1 behavior — the record seals (201) downgraded to caller_declared.
//
// F3: this test was named ...DefaultsToCallerDeclared and asserted the downgrade *as the default*. That is
// precisely the assertion that made the fail-open default read as intended behavior instead of a defect, so
// the default flip had to be renamed here, not just reconfigured. The default posture is now pinned by
// TestDefaultPostureIsFailClosed below.
func TestFailedElevationUnderFailOpenOptOutDowngradesToCallerDeclared(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	pinned := ed25519.NewKeyFromSeed(peSeed(0x51))
	wrong := ed25519.NewKeyFromSeed(peSeed(0x52))
	h := api.New(c, store.NewMem(), "k0").
		WithPolicyEngineKey("human_signed", pinned.Public().(ed25519.PublicKey)).
		WithRequirePinnedAuthority(false).Routes() // EXPLICIT fail-open opt-out

	body := forgedHumanSignedBody("k1", "p1", "kill-1", wrong)
	code, r := do(t, h, "POST", "/v2/records", body)
	if code != http.StatusCreated {
		t.Fatalf("with the fail-open opt-out, a failed elevation must still seal (back-compat), got %d: %s", code, r)
	}
	if !strings.Contains(r, `"source":"caller_declared"`) {
		t.Fatalf("a failed elevation must downgrade to caller_declared: %s", r)
	}
}

// TestDefaultPostureIsFailClosed (F3) is the regression test for the fail-OPEN default itself: a server built
// with NO authority options at all — exactly what api.New gives an embedder, and what averin-server produces
// when AVERIN_REQUIRE_PINNED_AUTHORITY is unset — must REJECT a record claiming an elevated source it cannot
// verify, and seal nothing. It also pins the misalignment case (a pinned key, wrong signer).
//
// Before F3 the guard existed but defaulted OFF and was set in no shipped config, so the whole product ran
// fail-open: this test asserts the DEFAULT, which is the only thing production actually uses.
func TestDefaultPostureIsFailClosed(t *testing.T) {
	newDefault := func(t *testing.T, opts ...func(*api.Server) *api.Server) http.Handler {
		t.Helper()
		c, err := core.New(seed)
		if err != nil {
			t.Fatalf("core: %v", err)
		}
		srv := api.New(c, store.NewMem(), "k0") // NO WithRequirePinnedAuthority call at all
		for _, o := range opts {
			srv = o(srv)
		}
		return srv.Routes()
	}
	assertRejectedAndEmpty := func(t *testing.T, h http.Handler, body, what string) {
		t.Helper()
		if code, r := do(t, h, "POST", "/v2/records", body); code != http.StatusInternalServerError {
			t.Fatalf("%s: default posture must REJECT with 500, got %d: %s", what, code, r)
		}
		code, list := do(t, h, "GET", "/v2/records?project=p1", "")
		if code != http.StatusOK {
			t.Fatalf("list: %d %s", code, list)
		}
		var out struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal([]byte(list), &out)
		if out.Total != 0 {
			t.Fatalf("%s: a rejected elevation must seal NOTHING, got total=%d: %s", what, out.Total, list)
		}
	}

	// (a) UNPINNED source (no authority key configured at all) — the shipped-config case (F2/F3).
	unsigned := ed25519.NewKeyFromSeed(peSeed(0x53))
	assertRejectedAndEmpty(t, newDefault(t),
		forgedHumanSignedBody("k1", "p1", "kill-1", unsigned), "unpinned human_signed")

	// (b) PINNED but misaligned key (govder/averin key drift) — must also reject by default.
	pinned := ed25519.NewKeyFromSeed(peSeed(0x51))
	wrong := ed25519.NewKeyFromSeed(peSeed(0x52))
	assertRejectedAndEmpty(t,
		newDefault(t, func(s *api.Server) *api.Server {
			return s.WithPolicyEngineKey("human_signed", pinned.Public().(ed25519.PublicKey))
		}),
		forgedHumanSignedBody("k2", "p1", "kill-2", wrong), "misaligned human_signed")

	// (c) an honest caller_declared record is untouched by the default posture.
	h := newDefault(t)
	if code, r := do(t, h, "POST", "/v2/records", `{"idempotency_key":"ok","project_id":"p1","session_id":"s1","action":"db.read"}`); code != http.StatusCreated {
		t.Fatalf("ordinary caller_declared traffic must still seal under the default posture, got %d: %s", code, r)
	}
}

// TestRequirePinnedAuthorityElevatesValidEvidence: the toggle must NOT break a LEGITIMATE elevation — a
// human_signed record signed by the PINNED key still verifies, seals (201), and retains its elevated source.
func TestRequirePinnedAuthorityElevatesValidEvidence(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	pinned := ed25519.NewKeyFromSeed(peSeed(0x51))
	h := api.New(c, store.NewMem(), "k0").
		WithPolicyEngineKey("human_signed", pinned.Public().(ed25519.PublicKey)).
		WithRequirePinnedAuthority(true).Routes()

	body := forgedHumanSignedBody("k1", "p1", "kill-1", pinned) // signed by the PINNED key -> valid
	code, r := do(t, h, "POST", "/v2/records", body)
	if code != http.StatusCreated {
		t.Fatalf("a VALID elevation must still seal under the toggle, got %d: %s", code, r)
	}
	if !strings.Contains(r, `"source":"human_signed"`) {
		t.Fatalf("a valid human_signed elevation must be retained: %s", r)
	}
}

// TestRequirePinnedAuthorityIgnoresCallerDeclared: ordinary Phase-1 traffic (no elevated authority claim) is
// never rejected by the toggle — it has nothing to fail.
func TestRequirePinnedAuthorityIgnoresCallerDeclared(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	h := api.New(c, store.NewMem(), "k0").WithRequirePinnedAuthority(true).Routes()
	code, r := do(t, h, "POST", "/v2/records", `{"idempotency_key":"k1","project_id":"p1","session_id":"s1","action":"db.read"}`)
	if code != http.StatusCreated {
		t.Fatalf("the toggle must not affect ordinary caller_declared traffic, got %d: %s", code, r)
	}
}
