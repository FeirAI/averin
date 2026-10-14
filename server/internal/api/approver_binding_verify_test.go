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
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// TestVerifyFailsUnboundApprovalUnderPinnedKey (AVE-10): with the approver-binding policy on and the
// authority key pinned, an approval whose signed evidence leaves out who approved fails the server's OWN
// /v2/verify and says why (export reuses the verdict only for its completeness wording and does not refuse). Without the pinned authority key the record would be
// Unverifiable and the policy could never fire, which is what this test guards against.
func TestVerifyFailsUnboundApprovalUnderPinnedKey(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	pe := ed25519.NewKeyFromSeed(peSeed(0x51))
	build := func(bound bool) http.Handler {
		s := api.New(c, store.NewMem(), "k0").WithAuth(auth.NewOpenStore()).
			WithPolicyEngineKey("human_signed", pe.Public().(ed25519.PublicKey)).
			WithRequireApproverBinding(bound, "")
		return s.Routes()
	}
	legacy := `{"agent_id":"agent-7","event_id":"ev-appr-1-approved","event_type":"approval","occurred_at":"2026-10-10T12:00:00.000Z","outcome":"ok","tenant_id":"acme"}`
	sum := sha256.Sum256([]byte(legacy))
	eh := "sha256:" + hex.EncodeToString(sum[:])
	rid := "govder-v3-ev-appr-1-approved"
	rec := map[string]any{
		"project_id": "acme", "record_id": rid, "session_id": "tenant:acme",
		"span_id": "sp1", "parent_span_id": nil, "agent_ts": "2026-10-10T12:00:00.000Z",
		"schema_version": "2", "canon_version": "rcp-1", "domain": "flightrecorder.record.v2",
		"agent_id": "agent-7", "agent_version": "unknown", "event_type": "approval_gate", "action": "approval",
		"observed_via": "sdk", "status": "ok",
		"authority": map[string]any{
			"source": "human_signed", "enforcement_point": "sdk", "evidence_hash": eh,
			"proof_version": "v3", "subject_projection": "averin.authority.subject.v1",
		},
		"extensions": map[string]any{"govder": map[string]any{
			"v": "1.0.0", "type": "approval", "event_id": "ev-appr-1-approved", "outcome": "ok",
			"occurred_at": "2026-10-10T12:00:00.000Z",
			"body":        map[string]any{"approval_id": "appr-1", "status": "approved", "decided_by": "alice@acme.test"},
		}},
	}
	signer, err := core.New(hex.EncodeToString(peSeed(0x51)))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rec)
	proof, err := signer.SignAuthorityRecordV3(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	au := rec["authority"].(map[string]any)
	au["subject_digest"], au["evidence_sig"] = proof.SubjectDigest, proof.EvidenceSig
	rec["idempotency_key"] = "appr-1"
	rb, _ := json.Marshal(rec)
	body := string(rb)
	for _, tc := range []struct {
		name  string
		bound bool
		fail  bool
	}{{"policy on", true, true}, {"policy off", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := build(tc.bound)
			if code, resp := do(t, h, "POST", "/v2/records", body); code != http.StatusCreated {
				t.Fatalf("ingest (%d): %s", code, resp)
			}
			for _, path := range []string{"/v2/verify?project=acme"} {
				code, resp := do(t, h, "GET", path, "")
				if code != http.StatusOK {
					t.Fatalf("%s (%d): %s", path, code, resp)
				}
				if got := strings.Contains(resp, "approver binding is required"); got != tc.fail {
					t.Fatalf("%s: binding issue present=%v want %v: %s", path, got, tc.fail, resp)
				}
			}
		})
	}
}
