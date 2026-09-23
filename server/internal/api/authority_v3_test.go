package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

func TestV3AuthorityBindsFinalSemanticRecordAcrossRecorderReseal(t *testing.T) {
	recorder, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	externalSeed := peSeed(0x67)
	approver, err := core.New(hex.EncodeToString(externalSeed))
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(externalSeed).Public().(ed25519.PublicKey)
	st := store.NewMem()
	h := api.New(recorder, st, "k0").WithPolicyEngineKey("human_signed", pub).Routes()
	rec := map[string]any{
		"schema_version": "2", "canon_version": "rcp-1", "domain": "flightrecorder.record.v2",
		"project_id": "p1", "record_id": "r1", "session_id": "s1", "agent_id": "a1",
		"agent_version": "1", "span_id": "sp1", "parent_span_id": nil,
		"agent_ts": "2026-01-01T00:00:00.000Z", "event_type": "decision",
		"action": "approve", "status": "ok", "observed_via": "sdk",
		"input_commit": map[string]any{"alg": "sha256", "commitment": "sha256:" + strings.Repeat("2", 64), "low_entropy": true},
		"extensions":   map[string]any{"new_vendor": map[string]any{"meaning": "approved"}},
		"authority": map[string]any{
			"source": "human_signed", "enforcement_point": "sdk",
			"evidence_hash": "sha256:" + strings.Repeat("1", 64),
			"proof_version": "v3", "subject_projection": "averin.authority.subject.v1",
		},
	}
	raw, _ := json.Marshal(rec)
	proof, err := approver.SignAuthorityRecordV3(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	a := rec["authority"].(map[string]any)
	a["subject_digest"], a["evidence_sig"] = proof.SubjectDigest, proof.EvidenceSig
	rec["idempotency_key"] = "v3-good"
	raw, _ = json.Marshal(rec)
	if code, body := do(t, h, "POST", "/v2/records", string(raw)); code != http.StatusCreated {
		t.Fatalf("valid v3 authority did not seal (%d): %s", code, body)
	}
	stored, err := st.AllRecords("p1")
	if err != nil || len(stored) != 1 {
		t.Fatalf("valid v3 storage: %d, %v", len(stored), err)
	}
	if got, err := recorder.VerifyAuthorityRecord(stored[0].JSON, approver.PubKey()); err != nil || got != "verified" {
		t.Fatalf("sealed authority = %q, %v", got, err)
	}
	var sealed map[string]any
	if err := json.Unmarshal([]byte(stored[0].JSON), &sealed); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"project_id":        func(r map[string]any) { r["project_id"] = "p2" },
		"record_id":         func(r map[string]any) { r["record_id"] = "r2" },
		"session_id":        func(r map[string]any) { r["session_id"] = "s2" },
		"agent_id":          func(r map[string]any) { r["agent_id"] = "a2" },
		"agent_version":     func(r map[string]any) { r["agent_version"] = "2" },
		"span_id":           func(r map[string]any) { r["span_id"] = "sp2" },
		"parent_span_id":    func(r map[string]any) { r["parent_span_id"] = "parent" },
		"agent_ts":          func(r map[string]any) { r["agent_ts"] = "2026-01-01T00:00:01.000Z" },
		"event_type":        func(r map[string]any) { r["event_type"] = "tool_call" },
		"action":            func(r map[string]any) { r["action"] = "deny" },
		"status":            func(r map[string]any) { r["status"] = "blocked" },
		"observed_via":      func(r map[string]any) { r["observed_via"] = "broker" },
		"enforcement_point": func(r map[string]any) { r["authority"].(map[string]any)["enforcement_point"] = "tool_gateway" },
		"commitment": func(r map[string]any) {
			r["input_commit"].(map[string]any)["commitment"] = "sha256:" + strings.Repeat("3", 64)
		},
		"known_extension": func(r map[string]any) {
			r["extensions"].(map[string]any)["new_vendor"].(map[string]any)["meaning"] = "denied"
		},
		"unknown_extension": func(r map[string]any) { r["extensions"].(map[string]any)["future_vendor"] = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copyJSON, _ := json.Marshal(sealed)
			var changed map[string]any
			if err := json.Unmarshal(copyJSON, &changed); err != nil {
				t.Fatal(err)
			}
			delete(changed, "content_hash")
			delete(changed, "sig")
			mutate(changed)
			copyJSON, _ = json.Marshal(changed)
			resealed, err := recorder.SealRecord(string(copyJSON))
			if err != nil {
				t.Fatalf("legitimate recorder re-seal failed: %v", err)
			}
			if got, err := recorder.VerifyAuthorityRecord(resealed, approver.PubKey()); err != nil || got != "failed" {
				t.Fatalf("re-sealed %s retained v3 authority: %q, %v", name, got, err)
			}
		})
	}
}
