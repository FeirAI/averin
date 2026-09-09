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

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// signAuthorityEvidence signs an authority statement the way the core does (authority.rs sign_evidence):
// ed25519 over LP4("averin.authority.v2") ‖ LP4(source) ‖ LP4(project_id) ‖ LP4(record_id) ‖ utf8(evidence_hash).
func signAuthorityEvidence(source, projectID, recordID, evidenceHash string, pe ed25519.PrivateKey) string {
	var pre []byte
	lp := func(s string) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(s)))
		pre = append(pre, b[:]...)
		pre = append(pre, s...)
	}
	lp("averin.authority.v2")
	lp(source)
	lp(projectID)
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
	// F3: this test drives the DOWNGRADE path (forged sig / cross-project replay / non-canonical hash must
	// seal as caller_declared), which is the explicit fail-OPEN opt-out. Under the default fail-closed
	// posture those same records are REJECTED — covered by TestDefaultPostureIsFailClosed.
	h := api.New(c, store.NewMem(), "k0").
		WithPolicyEngineKey("policy_engine_signed", pe.Public().(ed25519.PublicKey)).
		WithRequirePinnedAuthority(false).Routes()

	sum := sha256.Sum256([]byte("authority-claim"))
	eh := "sha256:" + hex.EncodeToString(sum[:])

	post := func(proj, idem, recordID, evSig string) string {
		body, _ := json.Marshal(map[string]any{
			"idempotency_key": idem, "project_id": proj, "session_id": "s1", "record_id": recordID,
			"event_type": "decision", "status": "ok", "action": "x",
			"authority": map[string]any{"source": "policy_engine_signed", "evidence_hash": eh, "evidence_sig": evSig},
		})
		code, resp := do(t, h, "POST", "/v2/records", string(body))
		if code != http.StatusCreated {
			t.Fatalf("ingest %s (%d): %s", recordID, code, resp)
		}
		return resp
	}

	// valid policy-engine evidence (signed over project p1) -> elevated source retained.
	resp := post("p1", "i1", "policy-rec-1", signAuthorityEvidence("policy_engine_signed", "p1", "policy-rec-1", eh, pe))
	if !strings.Contains(resp, `"source":"policy_engine_signed"`) {
		t.Fatalf("a valid policy-engine evidence_sig should elevate the source: %s", resp)
	}
	// forged evidence (signed by a DIFFERENT key) -> falls back to caller_declared.
	wrong := ed25519.NewKeyFromSeed(peSeed(0x45))
	resp2 := post("p1", "i2", "policy-rec-2", signAuthorityEvidence("policy_engine_signed", "p1", "policy-rec-2", eh, wrong))
	if !strings.Contains(resp2, `"source":"caller_declared"`) {
		t.Fatalf("a forged policy-engine evidence_sig must fall back to caller_declared: %s", resp2)
	}
	// CROSS-PROJECT REPLAY (Codex): a block validly signed for project p1 (same record_id/evidence_hash/sig),
	// replayed into project p2, must NOT elevate — project_id is bound into the authority preimage.
	respX := post("p2", "i4", "policy-rec-1", signAuthorityEvidence("policy_engine_signed", "p1", "policy-rec-1", eh, pe))
	if !strings.Contains(respX, `"source":"caller_declared"`) {
		t.Fatalf("a p1-signed authority block replayed into p2 must fall back to caller_declared: %s", respX)
	}
	// a non-canonical (uppercase-hex) evidence_hash the verifier would reject must NOT be stamped — even with
	// a valid sig over it — so the server never stamps a record the auditor reads as `failed` (cross-language parity).
	ehUpper := "sha256:" + strings.ToUpper(hex.EncodeToString(sum[:]))
	respUp := post("p1", "i3", "policy-rec-3", signAuthorityEvidence("policy_engine_signed", "p1", "policy-rec-3", ehUpper, pe))
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

// TestMultipleAuthorityKeysElevatePerSource (residual fix): the server can pin DISTINCT keys for
// policy_engine_signed AND human_signed at the same time. A human_signed record signed by the pinned human
// key elevates to human_signed (so govder's kill/approval records read as human_signed, not caller_declared);
// a policy_engine_signed record signed by the pinned policy key still elevates to policy_engine_signed; and a
// record signed by an UNPINNED key (or claiming a source whose key cross-signs the other source's evidence)
// stays caller_declared. The offline verifier pinning BOTH keys as authority_keys reads each as `verified`.
func TestMultipleAuthorityKeysElevatePerSource(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	pe := ed25519.NewKeyFromSeed(peSeed(0x44))    // policy engine (signs policy_engine_signed)
	human := ed25519.NewKeyFromSeed(peSeed(0x46)) // human-approval service (signs human_signed) — a DIFFERENT key
	rogue := ed25519.NewKeyFromSeed(peSeed(0x47)) // unpinned key
	h := api.New(c, store.NewMem(), "k0").
		WithPolicyEngineKey("policy_engine_signed", pe.Public().(ed25519.PublicKey)).
		WithPolicyEngineKey("human_signed", human.Public().(ed25519.PublicKey)).
		WithRequirePinnedAuthority(false). // F3: this test asserts the DOWNGRADE path (fail-open opt-out)
		Routes()

	sum := sha256.Sum256([]byte("authority-claim"))
	eh := "sha256:" + hex.EncodeToString(sum[:])

	post := func(idem, recordID, source, evSig string) string {
		body, _ := json.Marshal(map[string]any{
			"idempotency_key": idem, "project_id": "p1", "session_id": "s1", "record_id": recordID,
			"event_type": "decision", "status": "ok", "action": "x",
			"authority": map[string]any{"source": source, "evidence_hash": eh, "evidence_sig": evSig},
		})
		code, resp := do(t, h, "POST", "/v2/records", string(body))
		if code != http.StatusCreated {
			t.Fatalf("ingest %s (%d): %s", recordID, code, resp)
		}
		return resp
	}

	// human_signed signed by the pinned human key -> elevates to human_signed (the residual fix).
	respH := post("ih", "human-rec-1", "human_signed", signAuthorityEvidence("human_signed", "p1", "human-rec-1", eh, human))
	if !strings.Contains(respH, `"source":"human_signed"`) {
		t.Fatalf("a valid human-key evidence_sig should elevate to human_signed: %s", respH)
	}
	// policy_engine_signed signed by the pinned policy key -> still elevates (back-compat).
	respP := post("ip", "policy-rec-1", "policy_engine_signed", signAuthorityEvidence("policy_engine_signed", "p1", "policy-rec-1", eh, pe))
	if !strings.Contains(respP, `"source":"policy_engine_signed"`) {
		t.Fatalf("a valid policy-key evidence_sig should still elevate to policy_engine_signed: %s", respP)
	}
	// human_signed signed by an UNPINNED key -> caller_declared.
	respR := post("ir", "rogue-rec-1", "human_signed", signAuthorityEvidence("human_signed", "p1", "rogue-rec-1", eh, rogue))
	if !strings.Contains(respR, `"source":"caller_declared"`) {
		t.Fatalf("an unpinned key must fall back to caller_declared: %s", respR)
	}
	// CROSS-SOURCE: a human_signed claim whose evidence is signed by the POLICY key (the wrong source's key)
	// must NOT elevate — the human source's pinned key is the human key, and the verifier binds source into
	// the preimage anyway. Stays caller_declared.
	respX := post("ix", "cross-rec-1", "human_signed", signAuthorityEvidence("human_signed", "p1", "cross-rec-1", eh, pe))
	if !strings.Contains(respX, `"source":"caller_declared"`) {
		t.Fatalf("a human_signed claim signed by the policy key must stay caller_declared: %s", respX)
	}

	// offline verify: pinning BOTH keys as authority_keys reads the human and policy records as VERIFIED.
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	pePub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(pe.Public().(ed25519.PublicKey))
	humanPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(human.Public().(ed25519.PublicKey))
	rep := c.VerifyBundleWith(exp, fmt.Sprintf(`{"authority_keys":[%q,%q]}`, pePub, humanPub))
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
	if got["human-rec-1"] != "verified" {
		t.Fatalf("human-rec-1 authority = %q, want verified: %s", got["human-rec-1"], rep)
	}
	if got["policy-rec-1"] != "verified" {
		t.Fatalf("policy-rec-1 authority = %q, want verified: %s", got["policy-rec-1"], rep)
	}
	if got["rogue-rec-1"] == "verified" {
		t.Fatalf("the unpinned-key record must NOT verify: %s", rep)
	}
}

// TestAuthorityKeyRejectsDuplicateSourceAndReusedKey (residual fix, role separation): pinning the same source
// twice, or re-using ONE key for two different sources, must panic — keeping the pinned set as cleanly
// role-separated as the verifier's per-source authority_keys model expects.
func TestAuthorityKeyRejectsDuplicateSourceAndReusedKey(t *testing.T) {
	pe := ed25519.NewKeyFromSeed(peSeed(0x44)).Public().(ed25519.PublicKey)
	human := ed25519.NewKeyFromSeed(peSeed(0x46)).Public().(ed25519.PublicKey)

	mustPanic := func(name string, fn func()) {
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: expected panic", name)
			}
		}()
		fn()
	}
	mustPanic("duplicate source", func() {
		c, _ := core.New(seed)
		api.New(c, store.NewMem(), "k0").
			WithPolicyEngineKey("policy_engine_signed", pe).
			WithPolicyEngineKey("policy_engine_signed", human)
	})
	mustPanic("one key reused across two sources", func() {
		c, _ := core.New(seed)
		api.New(c, store.NewMem(), "k0").
			WithPolicyEngineKey("policy_engine_signed", pe).
			WithPolicyEngineKey("human_signed", pe)
	})
}

// TestDelegateSignedAuthorityElevates (plan 031 D8): with an external delegate-agent key pinned for the
// "delegate_signed" source, a generic record carrying a delegate_signed evidence_sig that verifies under it is
// elevated from the forgeable caller_declared to delegate_signed; an offline verifier pinning the SAME key as
// authority_keys reads it as `verified`. A forged sig (wrong key), a sig signed for a DIFFERENT source
// (cross-source re-label), or a cross-project replay all fall back to caller_declared.
func TestDelegateSignedAuthorityElevates(t *testing.T) {
	c, err := core.New(seed)
	if err != nil {
		t.Fatalf("core: %v", err)
	}
	delegate := ed25519.NewKeyFromSeed(peSeed(0x48)) // role-separated delegate-agent authority
	wrong := ed25519.NewKeyFromSeed(peSeed(0x49))    // an unpinned key
	policy := ed25519.NewKeyFromSeed(peSeed(0x44))   // the policy-engine key (cross-source test)
	h := api.New(c, store.NewMem(), "k0").
		WithPolicyEngineKey("delegate_signed", delegate.Public().(ed25519.PublicKey)).
		WithRequirePinnedAuthority(false). // F3: this test asserts the DOWNGRADE path (fail-open opt-out)
		Routes()

	sum := sha256.Sum256([]byte("delegate-decision"))
	eh := "sha256:" + hex.EncodeToString(sum[:])

	post := func(proj, idem, recordID, source, evSig string) string {
		body, _ := json.Marshal(map[string]any{
			"idempotency_key": idem, "project_id": proj, "session_id": "s1", "record_id": recordID,
			"event_type": "decision", "status": "ok", "action": "x",
			"authority": map[string]any{"source": source, "evidence_hash": eh, "evidence_sig": evSig},
		})
		code, resp := do(t, h, "POST", "/v2/records", string(body))
		if code != http.StatusCreated {
			t.Fatalf("ingest %s (%d): %s", recordID, code, resp)
		}
		return resp
	}

	// valid delegate_signed evidence (signed over p1) -> elevated source retained.
	resp := post("p1", "d1", "delegate-rec-1", "delegate_signed", signAuthorityEvidence("delegate_signed", "p1", "delegate-rec-1", eh, delegate))
	if !strings.Contains(resp, `"source":"delegate_signed"`) {
		t.Fatalf("a valid delegate-key evidence_sig should elevate the source: %s", resp)
	}
	// forged evidence (signed by an UNPINNED key) -> falls back to caller_declared.
	resp2 := post("p1", "d2", "delegate-rec-2", "delegate_signed", signAuthorityEvidence("delegate_signed", "p1", "delegate-rec-2", eh, wrong))
	if !strings.Contains(resp2, `"source":"caller_declared"`) {
		t.Fatalf("a forged delegate_signed evidence_sig must fall back to caller_declared: %s", resp2)
	}
	// cross-source re-label: a delegate_signed claim whose evidence is signed by the POLICY key (wrong source's
	// key) must NOT elevate — the source is bound into the preimage and the pinned key is the delegate key.
	resp3 := post("p1", "d3", "delegate-rec-3", "delegate_signed", signAuthorityEvidence("delegate_signed", "p1", "delegate-rec-3", eh, policy))
	if !strings.Contains(resp3, `"source":"caller_declared"`) {
		t.Fatalf("a delegate_signed claim signed by the policy key must stay caller_declared: %s", resp3)
	}
	// CROSS-PROJECT REPLAY (Codex): a block validly signed for project p1, replayed into project p2, must NOT elevate.
	respX := post("p2", "d4", "delegate-rec-1", "delegate_signed", signAuthorityEvidence("delegate_signed", "p1", "delegate-rec-1", eh, delegate))
	if !strings.Contains(respX, `"source":"caller_declared"`) {
		t.Fatalf("a p1-signed delegate_signed block replayed into p2 must fall back to caller_declared: %s", respX)
	}

	// offline verify: pinning the delegate key as authority_keys reads delegate-rec-1 as VERIFIED.
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	dsPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(delegate.Public().(ed25519.PublicKey))
	rep := c.VerifyBundleWith(exp, fmt.Sprintf(`{"authority_keys":[%q]}`, dsPub))
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
	if got["delegate-rec-1"] != "verified" {
		t.Fatalf("delegate-rec-1 authority = %q, want verified: %s", got["delegate-rec-1"], rep)
	}
	if got["delegate-rec-2"] == "verified" {
		t.Fatalf("the forged-evidence record must NOT verify: %s", rep)
	}
}

// TestAuthorityRejectsUnknownPinnedSource proves WithPolicyEngineKey still fail-closes on a source outside
// the recognized set (only policy_engine_signed, human_signed, and delegate_signed are pinnable).
func TestAuthorityRejectsUnknownPinnedSource(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		defer func() {
			if recover() == nil {
				t.Fatalf("expected panic")
			}
		}()
		fn()
	}
	mustPanic("unknown source", func() {
		c, _ := core.New(seed)
		k := ed25519.NewKeyFromSeed(peSeed(0x50)).Public().(ed25519.PublicKey)
		api.New(c, store.NewMem(), "k0").WithPolicyEngineKey("unknown_source", k)
	})
}

// TestPolicyEngineKeyMustBeDisjointFromResource (T7, Codex convergence): pinning a policy-engine key that
// equals the RESOURCE key must fail fast at Routes() — in BOTH option orders (the guard cannot live only in
// WithPolicyEngineKey, since WithResource may run after it). Else a resource key could elevate generic
// authority, which the offline verifier's authority_keys disjointness check now also fatals on.
func TestPolicyEngineKeyMustBeDisjointFromResource(t *testing.T) {
	rcForKey, err := core.New(resourceSeed)
	if err != nil {
		t.Fatalf("resource core: %v", err)
	}
	rpubBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(rcForKey.PubKey(), "ed25519pub:"))
	if err != nil {
		t.Fatalf("decode resource pubkey: %v", err)
	}
	rpub := ed25519.PublicKey(rpubBytes)
	for _, order := range []string{"resource-first", "policy-first"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s: Routes() must panic when the policy-engine key == the resource key", order)
				}
			}()
			c, _ := core.New(seed)
			rc, _ := core.New(resourceSeed)
			s := api.New(c, store.NewMem(), "k0")
			if order == "resource-first" {
				s.WithResource(rc, "orders-db").WithPolicyEngineKey("policy_engine_signed", rpub)
			} else {
				s.WithPolicyEngineKey("policy_engine_signed", rpub).WithResource(rc, "orders-db")
			}
			s.Routes()
		}()
	}
}
