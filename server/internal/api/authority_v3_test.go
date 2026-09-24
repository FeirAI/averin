package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// Govder emits this exact signed budget-safe-mode wire record in its fixture
// test. The generic endpoint must accept its v3 ID and body-bound proof, while
// continuing to reserve bare UUIDv5 IDs for broker/introspection records.
func TestGovderBudgetSafeModeV3FixtureSealsAtGenericIngest(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../../spec/fixtures/govder-budget-safe-mode-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicKey string         `json:"public_key"`
		Record    map[string]any `json:"record"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimPrefix(fixture.PublicKey, "ed25519pub:")
	if encoded == fixture.PublicKey {
		t.Fatal("Govder fixture has no ed25519pub key prefix")
	}
	pub, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("invalid Govder fixture public key: %v", err)
	}
	id, _ := fixture.Record["record_id"].(string)
	if !strings.HasPrefix(id, "govder-v3-") {
		t.Fatalf("Govder fixture record ID is outside its event namespace: %q", id)
	}
	recorder, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMem()
	h := api.New(recorder, st, "k0").WithPolicyEngineKey("policy_engine_signed", ed25519.PublicKey(pub)).Routes()
	raw, err := json.Marshal(fixture.Record)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := do(t, h, "POST", "/v2/records", string(raw)); code != http.StatusCreated {
		t.Fatalf("Govder v3 budget event did not seal (%d): %s", code, body)
	}
	stored, err := st.AllRecords("acme")
	if err != nil || len(stored) != 1 {
		t.Fatalf("Govder budget event storage: %d, %v", len(stored), err)
	}
	if got, err := recorder.VerifyAuthorityRecord(stored[0].JSON, string(fixture.PublicKey)); err != nil || got != "verified" {
		t.Fatalf("Govder budget event v3 authority = %q, %v", got, err)
	}
	// The guard remains effective for the same producer's historical bare
	// UUIDv5-shaped ID, even if accompanied by an otherwise valid v3 proof.
	bare := strings.TrimPrefix(id, "govder-v3-")
	fixture.Record["record_id"] = bare
	fixture.Record["idempotency_key"] = "govder:bare-uuid-v5-rejected"
	raw, err = json.Marshal(fixture.Record)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := do(t, h, "POST", "/v2/records", string(raw)); code != http.StatusBadRequest || !strings.Contains(body, "reserved") {
		t.Fatalf("bare UUIDv5 namespace was not rejected before seal (%d): %s", code, body)
	}
	stored, err = st.AllRecords("acme")
	if err != nil || len(stored) != 1 {
		t.Fatalf("rejected bare UUIDv5 caused durable effect: %d, %v", len(stored), err)
	}
}

func TestV3SDKPreparedFixtureSealsWithoutSemanticRewrite(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../../spec/golden-vectors/authority-sdk-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Prepared map[string]any `json:"prepared_record"`
		Digest   string         `json:"subject_digest"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
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
	raw, err := json.Marshal(fixture.Prepared)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := approver.SignAuthorityRecordV3(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if proof.SubjectDigest != fixture.Digest {
		t.Fatalf("SDK fixture digest = %s, want %s", proof.SubjectDigest, fixture.Digest)
	}
	authority := fixture.Prepared["authority"].(map[string]any)
	authority["subject_digest"] = proof.SubjectDigest
	authority["evidence_sig"] = proof.EvidenceSig
	expected := map[string]any{}
	raw, _ = json.Marshal(fixture.Prepared)
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	fixture.Prepared["idempotency_key"] = "sdk-v3-fixture"
	raw, _ = json.Marshal(fixture.Prepared)
	if code, body := do(t, h, "POST", "/v2/records", string(raw)); code != http.StatusCreated {
		t.Fatalf("prepared SDK v3 record did not seal (%d): %s", code, body)
	}
	stored, err := st.AllRecords("p1")
	if err != nil || len(stored) != 1 {
		t.Fatalf("prepared SDK record storage: %d, %v", len(stored), err)
	}
	if got, err := recorder.VerifyAuthorityRecord(stored[0].JSON, approver.PubKey()); err != nil || got != "verified" {
		t.Fatalf("prepared SDK authority = %q, %v", got, err)
	}
	var sealed map[string]any
	if err := json.Unmarshal([]byte(stored[0].JSON), &sealed); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"received_ts", "display_seq", "causal_prev_hashes", "key", "content_hash", "sig"} {
		delete(sealed, field)
	}
	if !reflect.DeepEqual(sealed, expected) {
		t.Fatalf("server rewrote externally approved semantic record\nsealed: %#v\napproved: %#v", sealed, expected)
	}
}

func TestV3NonNFCIdentityRejectedBeforeAuthorityLookup(t *testing.T) {
	fixtureBytes, err := os.ReadFile("../../../spec/golden-vectors/authority-sdk-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Prepared map[string]any `json:"prepared_record"`
	}
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	approver, err := core.New(hex.EncodeToString(peSeed(0x67)))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(fixture.Prepared)
	proof, err := approver.SignAuthorityRecordV3(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	authority := fixture.Prepared["authority"].(map[string]any)
	authority["subject_digest"], authority["evidence_sig"] = proof.SubjectDigest, proof.EvidenceSig
	recorder, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMem()
	// No external key is configured: an authority lookup would fail if it ran.
	h := api.New(recorder, st, "k0").Routes()
	for _, field := range []string{"project_id", "record_id"} {
		t.Run(field, func(t *testing.T) {
			original, _ := json.Marshal(fixture.Prepared)
			var rec map[string]any
			if err := json.Unmarshal(original, &rec); err != nil {
				t.Fatal(err)
			}
			rec[field] = "e\u0301"
			rec["idempotency_key"] = "non-nfc-" + field
			raw, _ := json.Marshal(rec)
			code, body := do(t, h, "POST", "/v2/records", string(raw))
			if code != http.StatusBadRequest || !strings.Contains(body, "NFC") {
				t.Fatalf("non-NFC %s should fail identity validation first (%d): %s", field, code, body)
			}
			for _, project := range []string{"p1", "e\u0301", "é"} {
				persisted, err := st.AllRecords(project)
				if err != nil || len(persisted) != 0 {
					t.Fatalf("non-NFC %s left %d records for %q: %v", field, len(persisted), project, err)
				}
			}
		})
	}
}

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
		"extensions": map[string]any{
			"new_vendor": map[string]any{"meaning": "approved"},
			"feir_evidence": map[string]any{
				"capture_authority": "sdk",
				"lineage":           map[string]any{"session_id": "s1", "span_id": "sp1", "parent_span_id": nil},
			},
		},
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
		"project_id":      func(r map[string]any) { r["project_id"] = "p2" },
		"record_id":       func(r map[string]any) { r["record_id"] = "r2" },
		"session_id":      func(r map[string]any) { r["session_id"] = "s2" },
		"agent_id":        func(r map[string]any) { r["agent_id"] = "a2" },
		"agent_version":   func(r map[string]any) { r["agent_version"] = "2" },
		"span_id":         func(r map[string]any) { r["span_id"] = "sp2" },
		"parent_span_id":  func(r map[string]any) { r["parent_span_id"] = "parent" },
		"agent_ts":        func(r map[string]any) { r["agent_ts"] = "2026-01-01T00:00:01.000Z" },
		"event_type":      func(r map[string]any) { r["event_type"] = "tool_call" },
		"record_kind":     func(r map[string]any) { r["record_kind"] = "budget-exhausted" },
		"action":          func(r map[string]any) { r["action"] = "deny" },
		"status":          func(r map[string]any) { r["status"] = "blocked" },
		"observed_via":    func(r map[string]any) { r["observed_via"] = "broker" },
		"anchored_ts":     func(r map[string]any) { r["anchored_ts"] = "2026-01-01T00:00:02.000Z" },
		"framework":       func(r map[string]any) { r["framework"] = "test-runtime" },
		"tokens":          func(r map[string]any) { r["tokens"] = map[string]any{"in": 1, "out": 2} },
		"cost_micros_usd": func(r map[string]any) { r["cost_micros_usd"] = 12 },
		"content": func(r map[string]any) {
			r["content"] = map[string]any{"uri": "object://1", "digest": "sha256:" + strings.Repeat("4", 64), "length": 1, "object_version": "v1"}
		},
		"enforcement_point": func(r map[string]any) { r["authority"].(map[string]any)["enforcement_point"] = "tool_gateway" },
		"authority_source":  func(r map[string]any) { r["authority"].(map[string]any)["source"] = "policy_engine_signed" },
		"evidence_hash": func(r map[string]any) {
			r["authority"].(map[string]any)["evidence_hash"] = "sha256:" + strings.Repeat("7", 64)
		},
		"proof_version":      func(r map[string]any) { r["authority"].(map[string]any)["proof_version"] = "v4" },
		"drop_proof_version": func(r map[string]any) { delete(r["authority"].(map[string]any), "proof_version") },
		"subject_projection": func(r map[string]any) { r["authority"].(map[string]any)["subject_projection"] = "other" },
		"decision_basis":     func(r map[string]any) { r["authority"].(map[string]any)["decision_basis"] = "human_approved" },
		"policy_hash": func(r map[string]any) {
			r["authority"].(map[string]any)["policy_hash"] = "sha256:" + strings.Repeat("5", 64)
		},
		"policy_snapshot_ref": func(r map[string]any) {
			r["authority"].(map[string]any)["policy_snapshot_ref"] = map[string]any{"uri": "object://policy", "digest": "sha256:" + strings.Repeat("6", 64), "object_version": "v1"}
		},
		"grant_id":              func(r map[string]any) { r["authority"].(map[string]any)["grant_id"] = "grant-1" },
		"grant_type":            func(r map[string]any) { r["authority"].(map[string]any)["grant_type"] = "id-jag" },
		"authorizing_principal": func(r map[string]any) { r["authority"].(map[string]any)["authorizing_principal"] = "principal-1" },
		"delegation_chain":      func(r map[string]any) { r["authority"].(map[string]any)["delegation_chain"] = []string{"delegate-1"} },
		"evaluated_at":          func(r map[string]any) { r["authority"].(map[string]any)["evaluated_at"] = "2026-01-01T00:00:01.000Z" },
		"expires_at":            func(r map[string]any) { r["authority"].(map[string]any)["expires_at"] = "2026-01-02T00:00:00.000Z" },
		"nonce":                 func(r map[string]any) { r["authority"].(map[string]any)["nonce"] = "nonce-1" },
		"commitment": func(r map[string]any) {
			r["input_commit"].(map[string]any)["commitment"] = "sha256:" + strings.Repeat("3", 64)
		},
		"commit_low_entropy": func(r map[string]any) { r["input_commit"].(map[string]any)["low_entropy"] = false },
		"output_commit":      func(r map[string]any) { r["output_commit"] = r["input_commit"] },
		"rationale_commit":   func(r map[string]any) { r["rationale_commit"] = r["input_commit"] },
		"credential_commit":  func(r map[string]any) { r["credential_commit"] = r["input_commit"] },
		"known_extension": func(r map[string]any) {
			r["extensions"].(map[string]any)["new_vendor"].(map[string]any)["meaning"] = "denied"
		},
		"unknown_extension": func(r map[string]any) { r["extensions"].(map[string]any)["future_vendor"] = true },
		"feir_lineage": func(r map[string]any) {
			r["extensions"].(map[string]any)["feir_evidence"].(map[string]any)["lineage"].(map[string]any)["span_id"] = "other-span"
		},
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
	// A later invalid v3 proof must reject the whole batch before the first
	// independently valid item is sealed.
	batchRecord := func(recordID, idem string) map[string]any {
		raw, _ := json.Marshal(rec)
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatal(err)
		}
		item["record_id"] = recordID
		delete(item, "idempotency_key")
		block := item["authority"].(map[string]any)
		delete(block, "subject_digest")
		delete(block, "evidence_sig")
		raw, _ = json.Marshal(item)
		proof, err := approver.SignAuthorityRecordV3(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		block["subject_digest"], block["evidence_sig"] = proof.SubjectDigest, proof.EvidenceSig
		item["idempotency_key"] = idem
		return item
	}
	good := batchRecord("batch-good", "idem-good")
	bad := batchRecord("batch-bad", "idem-bad")
	bad["action"] = "not approved"
	batchStore := store.NewMem()
	batchHandler := api.New(recorder, batchStore, "k0").WithPolicyEngineKey("human_signed", pub).Routes()
	batch, _ := json.Marshal([]any{good, bad})
	if code, body := do(t, batchHandler, "POST", "/v2/records", string(batch)); code < 400 {
		t.Fatalf("invalid later v3 proof did not reject batch (%d): %s", code, body)
	}
	if persisted, err := batchStore.AllRecords("p1"); err != nil || len(persisted) != 0 {
		t.Fatalf("partial v3 batch persisted %d records: %v", len(persisted), err)
	}
	for _, field := range []string{"input", "output", "rationale"} {
		t.Run("raw_"+field, func(t *testing.T) {
			item := batchRecord("raw-"+field, "idem-"+field)
			item[field] = "private value"
			delete(item, "idempotency_key")
			block := item["authority"].(map[string]any)
			delete(block, "subject_digest")
			delete(block, "evidence_sig")
			raw, _ := json.Marshal(item)
			proof, err := approver.SignAuthorityRecordV3(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			block["subject_digest"], block["evidence_sig"] = proof.SubjectDigest, proof.EvidenceSig
			item["idempotency_key"] = "idem-" + field
			raw, _ = json.Marshal(item)
			if code, body := do(t, batchHandler, "POST", "/v2/records", string(raw)); code != http.StatusBadRequest {
				t.Fatalf("v3 raw %s should fail before commitment (%d): %s", field, code, body)
			}
			if persisted, err := batchStore.AllRecords("p1"); err != nil || len(persisted) != 0 {
				t.Fatalf("raw %s created %d records: %v", field, len(persisted), err)
			}
		})
	}
}
