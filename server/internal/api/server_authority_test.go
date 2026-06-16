package api_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/store"
)

// signAuthorityEvidence signs an authority statement the way the core does (authority.rs sign_evidence):
// ed25519 over LP4("feir.authority.v1") ‖ LP4(source) ‖ LP4(record_id) ‖ utf8(evidence_hash).
func signAuthorityEvidence(source, recordID, evidenceHash string, pe ed25519.PrivateKey) string {
	var pre []byte
	lp := func(s string) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(s)))
		pre = append(pre, b[:]...)
		pre = append(pre, s...)
	}
	lp("feir.authority.v1")
	lp(source)
	lp(recordID)
	pre = append(pre, evidenceHash...)
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(pe, pre))
}

func peSeed(b byte) []byte { s := make([]byte, ed25519.SeedSize); s[0] = b; return s }

// TestPolicyEngineSignedAuthorityElevates (T7): with an external policy-engine key pinned, a generic record
// carrying a policy_engine_signed evidence_sig that verifies under it is elevated from the forgeable
// caller_declared to policy_engine_signed — and an offline verifier pinning the SAME key as authority_keys
// reads it as `verified`. A forged sig (wrong key) falls back to caller_declared.
func TestPolicyEngineSignedAuthorityElevates(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	pe := ed25519.NewKeyFromSeed(peSeed(0x44)) // the external policy engine (distinct from the server key)
	h := api.New(c, store.NewMem(), "k0").WithPolicyEngineKey("policy_engine_signed", pe.Public().(ed25519.PublicKey)).Routes()

	sum := sha256.Sum256([]byte("authority-claim"))
	eh := "sha256:" + hex.EncodeToString(sum[:])

	post := func(idem, recordID, evSig string) string {
		body, _ := json.Marshal(map[string]any{
			"idempotency_key": idem, "project_id": "p1", "session_id": "s1", "record_id": recordID,
			"event_type": "decision", "status": "ok", "action": "x",
			"authority": map[string]any{"source": "policy_engine_signed", "evidence_hash": eh, "evidence_sig": evSig},
		})
		code, resp := do(t, h, "POST", "/v2/records", string(body))
		if code != http.StatusCreated {
			t.Fatalf("ingest %s (%d): %s", recordID, code, resp)
		}
		return resp
	}

	// valid policy-engine evidence -> elevated source retained.
	resp := post("i1", "policy-rec-1", signAuthorityEvidence("policy_engine_signed", "policy-rec-1", eh, pe))
	if !strings.Contains(resp, `"source":"policy_engine_signed"`) {
		t.Fatalf("a valid policy-engine evidence_sig should elevate the source: %s", resp)
	}
	// forged evidence (signed by a DIFFERENT key) -> falls back to caller_declared.
	wrong := ed25519.NewKeyFromSeed(peSeed(0x45))
	resp2 := post("i2", "policy-rec-2", signAuthorityEvidence("policy_engine_signed", "policy-rec-2", eh, wrong))
	if !strings.Contains(resp2, `"source":"caller_declared"`) {
		t.Fatalf("a forged policy-engine evidence_sig must fall back to caller_declared: %s", resp2)
	}
	// a non-canonical (uppercase-hex) evidence_hash the verifier would reject must NOT be stamped — even with
	// a valid sig over it — so the server never stamps a record the auditor reads as `failed` (cross-language parity).
	ehUpper := "sha256:" + strings.ToUpper(hex.EncodeToString(sum[:]))
	respUp := post("i3", "policy-rec-3", signAuthorityEvidence("policy_engine_signed", "policy-rec-3", ehUpper, pe))
	if !strings.Contains(respUp, `"source":"caller_declared"`) {
		t.Fatalf("a non-canonical (uppercase-hex) evidence_hash must NOT elevate (verifier requires lowercase): %s", respUp)
	}

	// offline verify: pinning the policy-engine key as authority_keys reads policy-rec-1 as VERIFIED, and the
	// forged policy-rec-2 (now caller_declared) as declared.
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	pePub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(pe.Public().(ed25519.PublicKey))
	rep := c.VerifyBundleWith(exp, fmt.Sprintf(`{"authority_keys":[%q]}`, pePub))
	var report struct {
		RecordTrust []struct {
			RecordID  string `json:"record_id"`
			Authority string `json:"authority"`
		} `json:"record_trust"`
	}
	if err := json.Unmarshal([]byte(rep), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, rep)
	}
	got := map[string]string{}
	for _, rt := range report.RecordTrust {
		got[rt.RecordID] = rt.Authority
	}
	if got["policy-rec-1"] != "verified" {
		t.Fatalf("policy-rec-1 authority = %q, want verified: %s", got["policy-rec-1"], rep)
	}
	if got["policy-rec-2"] == "verified" {
		t.Fatalf("the forged-evidence record must NOT verify: %s", rep)
	}
}
