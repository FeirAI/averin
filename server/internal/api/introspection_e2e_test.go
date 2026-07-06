package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/averin-dev/averin/server/internal/broker"
	"github.com/averin-dev/averin/server/internal/core"
)

// resourceKeyFromSeed derives the raw ed25519 key the resource signs the M3 introspection challenge with — the
// SAME key core.New(resourceSeed) holds (so rc.PubKey() pins it), since core exposes only SignEvidence (a tagged
// evidence-hash sig) and the structured averin.resource.introspection.v1 sig is over raw challenge bytes.
func resourceKeyFromSeed(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	b, err := hex.DecodeString(resourceSeed)
	if err != nil {
		t.Fatalf("decode resourceSeed: %v", err)
	}
	return ed25519.NewKeyFromSeed(b)
}

// nativeGrantRecord seals a native (token_exchange) broker grant record carrying the given grant_evidence,
// returning the sealed JSON + its content_hash. Broker-signed (evidence_sig by c, outer seal by c/k0).
func nativeGrantRecord(t *testing.T, c *core.Core, grantID string, ge map[string]any) (string, string) {
	t.Helper()
	geJSON, _ := json.Marshal(ge)
	evidenceHash, err := c.RcpEvidenceHash(string(geJSON))
	if err != nil {
		t.Fatalf("RcpEvidenceHash(grant): %v", err)
	}
	evidenceSig, err := c.SignEvidence("gateway_enforced", "proj-001", grantID, evidenceHash)
	if err != nil {
		t.Fatalf("SignEvidence(grant): %v", err)
	}
	recBody := map[string]any{
		"schema_version": "2", "canon_version": "rcp-1", "domain": "flightrecorder.record.v2",
		"record_id": grantID, "project_id": "proj-001", "agent_id": "averin-broker", "agent_version": "averin-broker",
		"session_id": "s1", "span_id": "sp-" + grantID, "parent_span_id": nil, "causal_prev_hashes": []string{},
		"display_seq": 0, "agent_ts": "2026-06-15T10:00:00.000Z", "received_ts": "2026-06-15T10:00:00.000Z",
		"event_type": "credential_grant", "action": ge["action"], "observed_via": "broker", "status": "ok",
		"authority": map[string]any{
			"source": "gateway_enforced", "enforcement_point": "credential_broker", "grant_type": broker.GrantTypeIDJAG,
			"grant_id": grantID, "evidence_hash": evidenceHash, "evidence_sig": evidenceSig,
		},
		"extensions": map[string]any{"broker": map[string]any{"kind": "grant", "grant_evidence": ge}},
		"key":        map[string]any{"signing_key_id": "k0", "key_epoch": 0, "key_valid_from": "2026-06-01T00:00:00.000Z", "key_status": "active"},
	}
	recJSON, _ := json.Marshal(recBody)
	sealed, err := c.SealRecord(string(recJSON))
	if err != nil {
		t.Fatalf("SealRecord(grant): %v", err)
	}
	return sealed, fieldOf(t, sealed, "content_hash")
}

// introspectionRecord seals a resource introspection_transcript record carrying the given introspection_evidence
// (outer seal by c/k0; evidence_sig by the RESOURCE core rc, so the record's authority elevates under
// resource_authority_keys). `prev` is the record's DAG parent (the native grant).
func introspectionRecord(t *testing.T, c *core.Core, rc *core.Core, recordID, grantID, resourceID, prev string, ie map[string]any) (string, string) {
	t.Helper()
	ieJSON, _ := json.Marshal(ie)
	evidenceHash, err := c.RcpEvidenceHash(string(ieJSON))
	if err != nil {
		t.Fatalf("RcpEvidenceHash(transcript): %v", err)
	}
	evidenceSig, err := rc.SignEvidence("gateway_enforced", "proj-001", recordID, evidenceHash)
	if err != nil {
		t.Fatalf("SignEvidence(transcript) under resource key: %v", err)
	}
	recBody := map[string]any{
		"schema_version": "2", "canon_version": "rcp-1", "domain": "flightrecorder.record.v2",
		"record_id": recordID, "project_id": "proj-001", "agent_id": "averin-resource", "agent_version": "averin-resource",
		"session_id": "s1", "span_id": "sp-" + recordID, "parent_span_id": nil, "causal_prev_hashes": []string{prev},
		"display_seq": 1, "agent_ts": "2026-06-15T10:00:05.000Z", "received_ts": "2026-06-15T10:00:05.000Z",
		"event_type": "tool_call", "action": ie["effective_scope"], "observed_via": "broker", "status": "ok",
		"authority": map[string]any{
			"source": "gateway_enforced", "enforcement_point": "tool_gateway",
			"grant_id": grantID, "evidence_hash": evidenceHash, "evidence_sig": evidenceSig,
		},
		"extensions": map[string]any{"broker": map[string]any{"kind": "introspection_transcript", "grant_id": grantID, "resource_id": resourceID, "introspection_evidence": ie}},
		"key":        map[string]any{"signing_key_id": "k0", "key_epoch": 0, "key_valid_from": "2026-06-01T00:00:00.000Z", "key_status": "active"},
	}
	recJSON, _ := json.Marshal(recBody)
	sealed, err := c.SealRecord(string(recJSON))
	if err != nil {
		t.Fatalf("SealRecord(transcript): %v", err)
	}
	return sealed, fieldOf(t, sealed, "content_hash")
}

// assembleNativeBundle wraps a native grant + its introspection transcript in an anchored, grant-head checkpoint
// (so the grant is closed AND broker_trust can reach sequence_verified) and returns the bundle JSON.
func assembleNativeBundle(t *testing.T, c *core.Core, tsa ed25519.PrivateKey, sealedGrant, grantHash, sealedTranscript, transcriptHash string) string {
	t.Helper()
	grantHead := broker.BrokerGrantHead([]broker.GrantSeqHash{{Seq: 1, ContentHash: grantHash}}, broker.EmptyGrantHeadRoot())
	cpBody := map[string]any{
		"schema_version": "2", "canon_version": "rcp-1", "domain": "flightrecorder.checkpoint.v2",
		"checkpoint_id": "cp-proj-001-0", "project_id": "proj-001", "checkpoint_seq": 0,
		"prev_checkpoint_hash": nil, "frontier": []string{transcriptHash}, "record_count": 2,
		"broker_grant_head": grantHead, "created_ts": "2026-06-15T10:10:00.000Z",
		"key": map[string]any{"signing_key_id": "k0", "key_epoch": 0, "key_valid_from": "2026-06-01T00:00:00.000Z", "key_status": "active"},
	}
	cpJSON, _ := json.Marshal(cpBody)
	sealedCp, err := c.SealCheckpoint(string(cpJSON))
	if err != nil {
		t.Fatalf("SealCheckpoint: %v", err)
	}
	var cpMap map[string]json.RawMessage
	json.Unmarshal([]byte(sealedCp), &cpMap)
	cpMap["anchor"], _ = json.Marshal(makeTestAnchor(fieldOf(t, sealedCp, "checkpoint_hash"), "2026-06-15T10:10:01.000Z", "test-tsa", tsa))
	anchoredCp, _ := json.Marshal(cpMap)
	bundle := map[string]any{
		"bundle_version": "1", "project_id": "proj-001",
		"keys":        []any{map[string]any{"signing_key_id": "k0", "key_epoch": 0, "public_key": c.PubKey(), "key_status": "active"}},
		"records":     []json.RawMessage{json.RawMessage(sealedGrant), json.RawMessage(sealedTranscript)},
		"checkpoints": []json.RawMessage{json.RawMessage(anchoredCp)},
	}
	bundleJSON, _ := json.Marshal(bundle)
	return string(bundleJSON)
}

// TestIntrospectionTranscriptRoundTripsThroughRustVerifier is the cross-language end-to-end proof for ADR 0005
// M3: a native (token_exchange) grant + a resource-signed introspection_transcript produced ENTIRELY in Go
// (broker.NativeGrantEvidence + broker.IntrospectionEvidence, the structured averin.resource.introspection.v1 sig
// built in Go), sealed + anchored via the Rust core FFI, and verified by the SAME Rust verifier — confirming the
// Go-canonicalized introspection_evidence is bound to the native grant and counted by the M3 pre-pass exactly as
// the native Rust fixtures are (introspection_status:"attested"), with fail-closed negative controls.
func TestIntrospectionTranscriptRoundTripsThroughRustVerifier(t *testing.T) {
	c, _ := core.New(seed)          // broker recording + evidence-signing key (also the record-seal key, k0)
	rc, _ := core.New(resourceSeed) // resource authority key (signs the transcript evidence + structured sig)
	resKey := resourceKeyFromSeed(t)
	tsa := testTSAKey()

	const grantID = "grant-native-1"
	const resourceID = "orders-db"
	const lease = "lease-sts-001"
	const grantScope = "read:orders write:orders"
	const issuedAt = int64(1_718_445_600)
	const exp = int64(1_718_449_200)
	const introspectedAt = int64(1_718_445_700)
	transcriptHash := "sha256:" + strings.Repeat("ab", 32)

	pinned := func(extra string) string {
		return `{"broker_authority_keys":["` + c.PubKey() + `"],"resource_authority_keys":["` + rc.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"]` + extra + `}`
	}

	ge := broker.NativeGrantEvidence(grantID, "db.query:orders-ro", resourceID, grantScope, lease, 1, issuedAt, exp)
	sealedGrant, grantHash := nativeGrantRecord(t, c, grantID, ge)

	// POSITIVE: a valid transcript whose effective_scope is a PROPER subset of the grant scope (a real narrowing)
	// reaches introspection_status:"attested" and is surfaced as narrowed; the surface is purely native (uses_matched:0).
	ie := broker.IntrospectionEvidence(resKey, grantID, lease, "read:orders", resourceID, transcriptHash, introspectedAt, exp)
	sealedT, tHash := introspectionRecord(t, c, rc, "intro-1", grantID, resourceID, grantHash, ie)
	bundle := assembleNativeBundle(t, c, tsa, sealedGrant, grantHash, sealedT, tHash)
	rep := c.VerifyBundleWith(bundle, pinned(""))
	for _, want := range []string{
		`"ok":true`,
		`"native_credential_present":true`,
		`"introspection_transcripts_total":1`,
		`"introspection_transcripts_verified":1`,
		`"introspection_scope_narrowed":1`,
		`"introspection_status":"attested"`,
		`"uses_matched":0`, // a native surface uses NO brokered PoP receipts
		`"broker_trust":"sequence_verified"`,
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("Go-produced native+transcript bundle did not verify as expected (missing %s):\n%s", want, rep)
		}
	}

	// NEGATIVE 1: drop the resource_authority_keys pin -> the transcript's structured sig verifies under no
	// pinned resource issuer -> unattested + fail-closed. (Also leaves the resource record's authority unverified.)
	repNoRes := c.VerifyBundleWith(bundle, `{"broker_authority_keys":["`+c.PubKey()+`"],"tsa_keys":["`+tsaPubEncoded(tsa)+`"]}`)
	if !strings.Contains(repNoRes, `"ok":false`) || strings.Contains(repNoRes, `"introspection_status":"attested"`) {
		t.Fatalf("with no resource_authority_keys pinned the transcript must fail closed:\n%s", repNoRes)
	}

	// NEGATIVE 2: a FORGED structured sig (signed by a non-pinned imposter key, while the record evidence_sig is
	// still the resource's so it routes as a resource record) must not verify -> unattested + !ok.
	imposter := ed25519.NewKeyFromSeed(bytesSeed(0x71))
	ieForged := broker.IntrospectionEvidence(imposter, grantID, lease, "read:orders", resourceID, transcriptHash, introspectedAt, exp)
	sealedF, fHash := introspectionRecord(t, c, rc, "intro-1", grantID, resourceID, grantHash, ieForged)
	repForged := c.VerifyBundleWith(assembleNativeBundle(t, c, tsa, sealedGrant, grantHash, sealedF, fHash), pinned(""))
	if !strings.Contains(repForged, `"ok":false`) || !strings.Contains(repForged, `"introspection_status":"unattested"`) {
		t.Fatalf("a forged introspection sig must fail closed:\n%s", repForged)
	}
	if !strings.Contains(repForged, "does not verify under any pinned resource_authority_keys") {
		t.Fatalf("the forged-sig failure must be surfaced:\n%s", repForged)
	}

	// NEGATIVE 3: a transcript whose effective_scope BROADENS the grant scope (a token not in the grant) -> the
	// resource broadened past the grant -> hard violation -> !ok (the cross-language scope-subset rejection).
	ieBroad := broker.IntrospectionEvidence(resKey, grantID, lease, "read:orders admin:all", resourceID, transcriptHash, introspectedAt, exp)
	sealedB, bHash := introspectionRecord(t, c, rc, "intro-1", grantID, resourceID, grantHash, ieBroad)
	repBroad := c.VerifyBundleWith(assembleNativeBundle(t, c, tsa, sealedGrant, grantHash, sealedB, bHash), pinned(""))
	if !strings.Contains(repBroad, `"ok":false`) || !strings.Contains(repBroad, "broadened past the grant") {
		t.Fatalf("a scope-broadening transcript must fail closed:\n%s", repBroad)
	}

	// NEGATIVE 4: a transcript whose credential_ref != the native grant's lease_id must not cover the grant.
	ieRef := broker.IntrospectionEvidence(resKey, grantID, "lease-OTHER", "read:orders", resourceID, transcriptHash, introspectedAt, exp)
	sealedR, rHash := introspectionRecord(t, c, rc, "intro-1", grantID, resourceID, grantHash, ieRef)
	repRef := c.VerifyBundleWith(assembleNativeBundle(t, c, tsa, sealedGrant, grantHash, sealedR, rHash), pinned(""))
	if !strings.Contains(repRef, `"ok":false`) || !strings.Contains(repRef, "credential_ref") {
		t.Fatalf("a credential_ref-mismatched transcript must fail closed:\n%s", repRef)
	}
}
