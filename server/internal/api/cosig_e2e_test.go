package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/averin-dev/averin/server/internal/broker"
	"github.com/averin-dev/averin/server/internal/core"
)

// pubEncoded renders an ed25519 public key in the "ed25519pub:<b64url>" form the verifier opts expect.
func pubEncoded(pub ed25519.PublicKey) string {
	return "ed25519pub:" + base64.RawURLEncoding.EncodeToString(pub)
}

// TestCosigGrantRoundTripsThroughRustVerifier is the cross-language end-to-end proof for ADR 0005 M6: a
// cosigned grant produced ENTIRELY in Go (broker.Prepare + AttachCosignatures), sealed + anchored via the
// Rust core FFI, and verified by the SAME Rust verifier — confirming the Go-canonicalized cosignatures[]
// structure is read and counted by count_cosig_approvals exactly as the native Rust fixtures are. Closes the
// structural round-trip gap the unit tests (which build the structure natively in each language) leave open.
func TestCosigGrantRoundTripsThroughRustVerifier(t *testing.T) {
	c, _ := core.New(seed) // the broker recording + evidence-signing key (one key, like the Rust fixtures)
	tsa := testTSAKey()

	// 1) Mint a real grant via the broker producer path (fixes credential_binding + exp).
	agentSeed := make([]byte, ed25519.SeedSize)
	agentSeed[0] = 7
	agentPriv := ed25519.NewKeyFromSeed(agentSeed)
	agentPub := agentPriv.Public().(ed25519.PublicKey)
	issSeed := make([]byte, ed25519.SeedSize)
	issSeed[0] = 9
	issuing := ed25519.NewKeyFromSeed(issSeed)
	const grantID = "grant-cosig-1"
	req := broker.Request{
		AgentID:     "agent-x",
		Action:      "db.query:orders-ro",
		Resource:    "orders-db",
		Scope:       "single_operation",
		AgentPubKey: base64.RawURLEncoding.EncodeToString(agentPub),
		TTL:         time.Hour,
	}
	req.AgentSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(agentPriv, req.Challenge()))
	prepared, err := broker.Prepare(req, grantID, func() (int64, error) { return 1, nil }, time.Unix(1_718_445_600, 0), issuing)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// 2) Two approvers (role-separated from the broker/tsa keys) cosign the prepared grant; attach 2-of-2.
	a1 := ed25519.NewKeyFromSeed(bytesSeed(40))
	a2 := ed25519.NewKeyFromSeed(bytesSeed(41))
	exp := prepared.Evidence["exp"].(int64)
	mkCosig := func(ap ed25519.PrivateKey) broker.Cosignature {
		pub := ap.Public().(ed25519.PublicKey)
		kid := broker.KeyID(pub)
		sig := ed25519.Sign(ap, broker.CosigApprovalChallenge(grantID, kid, prepared.CredentialBinding, 2, exp))
		return broker.Cosignature{ApproverKid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	}
	cosigs := []broker.Cosignature{mkCosig(a1), mkCosig(a2)}
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}
	if err := broker.AttachCosignatures(&prepared, 2, cosigs, approvers); err != nil {
		t.Fatalf("AttachCosignatures: %v", err)
	}

	// 3) Build + seal the broker grant record carrying the cosigned evidence (evidence_hash re-derived by the
	//    core via RCP, so the verifier re-derives the same hash from the embedded grant_evidence — R1).
	evidenceJSON, _ := json.Marshal(prepared.Evidence)
	evidenceHash, err := c.RcpEvidenceHash(string(evidenceJSON))
	if err != nil {
		t.Fatalf("RcpEvidenceHash: %v", err)
	}
	evidenceSig, err := c.SignEvidence("gateway_enforced", "proj-001", grantID, evidenceHash)
	if err != nil {
		t.Fatalf("SignEvidence: %v", err)
	}
	recBody := map[string]any{
		"schema_version": "2", "canon_version": "rcp-1", "domain": "flightrecorder.record.v2",
		"record_id": grantID, "project_id": "proj-001", "agent_id": "agent-x", "agent_version": "averin-broker",
		"session_id": "s1", "span_id": "sp-" + grantID, "parent_span_id": nil, "causal_prev_hashes": []string{},
		"display_seq": 0, "agent_ts": "2026-06-15T10:00:00.000Z", "received_ts": "2026-06-15T10:00:00.000Z",
		"event_type": "credential_grant", "action": req.Action, "observed_via": "broker", "status": "ok",
		"authority": map[string]any{
			"source": "gateway_enforced", "enforcement_point": "credential_broker", "grant_type": broker.GrantTypeIDJAG,
			"grant_id": grantID, "evidence_hash": evidenceHash, "evidence_sig": evidenceSig,
		},
		"extensions": map[string]any{"broker": map[string]any{"kind": "grant", "grant_evidence": prepared.Evidence}},
		"key":        map[string]any{"signing_key_id": "k0", "key_epoch": 0, "key_valid_from": "2026-06-01T00:00:00.000Z", "key_status": "active"},
	}
	recJSON, _ := json.Marshal(recBody)
	sealedGrant, err := c.SealRecord(string(recJSON))
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	grantHash := fieldOf(t, sealedGrant, "content_hash")

	// 4) Anchored checkpoint over the grant's content_hash (so the grant is CLOSED — the cosig gate only
	//    runs for closed, verified broker grants).
	// the grant carries broker_seq=1, so D6 grant-transparency is active — the checkpoint must commit a
	// broker_grant_head over the recorded grant log or the verifier flags suppression.
	grantHead := broker.BrokerGrantHead([]broker.GrantSeqHash{{Seq: 1, ContentHash: grantHash}}, broker.EmptyGrantHeadRoot())
	cpBody := map[string]any{
		"schema_version": "2", "canon_version": "rcp-1", "domain": "flightrecorder.checkpoint.v2",
		"checkpoint_id": "cp-proj-001-0", "project_id": "proj-001", "checkpoint_seq": 0,
		"prev_checkpoint_hash": nil, "frontier": []string{grantHash}, "record_count": 1,
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

	// 5) Assemble the bundle and verify through the Rust core, pinning the broker/tsa/cosig-approver keys.
	bundle := map[string]any{
		"bundle_version": "1", "project_id": "proj-001",
		"keys":        []any{map[string]any{"signing_key_id": "k0", "key_epoch": 0, "public_key": c.PubKey(), "key_status": "active"}},
		"records":     []json.RawMessage{json.RawMessage(sealedGrant)},
		"checkpoints": []json.RawMessage{json.RawMessage(anchoredCp)},
	}
	bundleJSON, _ := json.Marshal(bundle)
	opts := map[string]any{
		"broker_authority_keys": []string{c.PubKey()},
		"tsa_keys":              []string{tsaPubEncoded(tsa)},
		"cosig_approver_keys":   []string{pubEncoded(approvers[0]), pubEncoded(approvers[1])},
	}
	optsJSON, _ := json.Marshal(opts)
	rep := c.VerifyBundleWith(string(bundleJSON), string(optsJSON))

	for _, want := range []string{`"ok":true`, `"cosig_status":"satisfied"`, `"cosigned_grants_total":1`, `"cosigned_grants_satisfied":1`, `"cosig_threshold_failures":0`, `"grant_verified":1`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("Go-produced cosigned bundle did not verify as expected (missing %s):\n%s", want, rep)
		}
	}

	// Negative control: drop one pinned approver -> 2-of-2 can no longer be satisfied -> fail-closed.
	optsOne := map[string]any{
		"broker_authority_keys": []string{c.PubKey()},
		"tsa_keys":              []string{tsaPubEncoded(tsa)},
		"cosig_approver_keys":   []string{pubEncoded(approvers[0])},
	}
	oneJSON, _ := json.Marshal(optsOne)
	repOne := c.VerifyBundleWith(string(bundleJSON), string(oneJSON))
	if !strings.Contains(repOne, `"ok":false`) || !strings.Contains(repOne, `"cosig_status":"unsatisfied"`) {
		t.Fatalf("with only 1 of 2 approver keys pinned the bundle must fail closed:\n%s", repOne)
	}
}

func bytesSeed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	return s
}

func fieldOf(t *testing.T, jsonStr, key string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		t.Fatalf("parse json for %s: %v", key, err)
	}
	var v string
	if err := json.Unmarshal(m[key], &v); err != nil {
		t.Fatalf("field %s: %v", key, err)
	}
	return v
}
