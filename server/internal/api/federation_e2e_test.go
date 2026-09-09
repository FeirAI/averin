package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
)

// prepareFedGrantEvidence mints a federated (broker_id-tagged) single_operation grant via the REAL producer
// path (broker.Prepare with Request.BrokerID) at a given per-broker broker_seq, returning its signed
// grant_evidence map (carrying broker_id + broker_seq). One agent key suffices (federation_status is about the
// grant LOG, not uses).
func prepareFedGrantEvidence(t *testing.T, brokerID, grantID string, seq int64) map[string]any {
	t.Helper()
	agentSeed := make([]byte, ed25519.SeedSize)
	agentSeed[0] = 7
	agentPriv := ed25519.NewKeyFromSeed(agentSeed)
	agentPub := agentPriv.Public().(ed25519.PublicKey)
	issuing := ed25519.NewKeyFromSeed(bytesSeed(9))
	req := broker.Request{
		AgentID:     "agent-x",
		Action:      "db.query:orders-ro",
		Resource:    "orders-db",
		Scope:       "single_operation",
		AgentPubKey: base64.RawURLEncoding.EncodeToString(agentPub),
		TTL:         time.Hour,
		BrokerID:    brokerID,
	}
	req.AgentSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(agentPriv, req.Challenge()))
	prepared, err := broker.Prepare(req, grantID, func() (int64, error) { return seq, nil }, time.Unix(1_718_445_600, 0), issuing)
	if err != nil {
		t.Fatalf("Prepare(%s): %v", brokerID, err)
	}
	if prepared.Evidence["broker_id"] != brokerID {
		t.Fatalf("Prepare did not tag broker_id: %v", prepared.Evidence["broker_id"])
	}
	return prepared.Evidence
}

// fedCheckpointBundle wraps two federated grant records in an anchored checkpoint carrying the given
// broker_grant_heads MAP, returning the bundle JSON. (Both grants are outer-sealed by `c`/k0; in the V1
// shared-root model their evidence is also signed by `c` via nativeGrantRecord.)
func fedCheckpointBundle(t *testing.T, c *core.Core, tsa ed25519.PrivateKey, recs []string, hashes []string, recordCount int, heads map[string]any) string {
	t.Helper()
	cpBody := map[string]any{
		"schema_version": "2", "canon_version": "rcp-1", "domain": "flightrecorder.checkpoint.v2",
		"checkpoint_id": "cp-proj-001-0", "project_id": "proj-001", "checkpoint_seq": 0,
		"prev_checkpoint_hash": nil, "frontier": hashes, "record_count": recordCount,
		"broker_grant_heads": heads, "created_ts": "2026-06-15T10:10:00.000Z",
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
	records := make([]json.RawMessage, len(recs))
	for i, r := range recs {
		records[i] = json.RawMessage(r)
	}
	bundle := map[string]any{
		"bundle_version": "1", "project_id": "proj-001",
		"keys":        []any{map[string]any{"signing_key_id": "k0", "key_epoch": 0, "public_key": c.PubKey(), "key_status": "active"}},
		"records":     records,
		"checkpoints": []json.RawMessage{json.RawMessage(anchoredCp)},
	}
	bundleJSON, _ := json.Marshal(bundle)
	return string(bundleJSON)
}

// fedGrantRecord seals a federated grant record whose grant_evidence is signed by a SPECIFIC broker authority
// core `brokerCore` (the V2 per-broker key), while the record is outer-sealed by `c`/k0. Returns the sealed JSON
// + content_hash.
func fedGrantRecord(t *testing.T, c *core.Core, brokerCore *core.Core, grantID string, ge map[string]any) (string, string) {
	t.Helper()
	geJSON, _ := json.Marshal(ge)
	evidenceHash, err := c.RcpEvidenceHash(string(geJSON))
	if err != nil {
		t.Fatalf("RcpEvidenceHash: %v", err)
	}
	evidenceSig, err := brokerCore.SignEvidence("gateway_enforced", "proj-001", grantID, evidenceHash)
	if err != nil {
		t.Fatalf("SignEvidence under broker key: %v", err)
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
		t.Fatalf("SealRecord: %v", err)
	}
	return sealed, fieldOf(t, sealed, "content_hash")
}

// TestFederationPerBrokerKeysRoundTripsThroughRustVerifier is the V2 cross-language proof: two brokers whose
// grants' evidence is signed by SEPARATE per-broker authority keys (pinned via the federated_broker_keys opts
// MAP through the FFI), each grant elevating ONLY under its own broker's key — with a negative control where
// broker A's grant signed by broker B's key fails to be A-accountable.
func TestFederationPerBrokerKeysRoundTripsThroughRustVerifier(t *testing.T) {
	c, _ := core.New(seed)                                                                // the record-seal key (k0)
	ca, _ := core.New("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1") // broker A authority
	cb, _ := core.New("b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2") // broker B authority
	tsa := testTSAKey()

	geA := prepareFedGrantEvidence(t, "broker-A", "grant-a", 1)
	geB := prepareFedGrantEvidence(t, "broker-B", "grant-b", 1)
	recA, hashA := fedGrantRecord(t, c, ca, "grant-a", geA) // A's evidence signed by ca
	recB, hashB := fedGrantRecord(t, c, cb, "grant-b", geB) // B's evidence signed by cb
	heads := broker.BrokerGrantHeads(map[string][]broker.GrantSeqHash{
		"broker-A": {{Seq: 1, ContentHash: hashA}},
		"broker-B": {{Seq: 1, ContentHash: hashB}},
	}, nil)
	bundle := fedCheckpointBundle(t, c, tsa, []string{recA, recB}, []string{hashA, hashB}, 2, heads)

	// pin per-broker authority via the federated_broker_keys opts MAP (the V2 JSON/FFI path).
	pinned := `{"federated_broker_keys":{"broker-A":["` + ca.PubKey() + `"],"broker-B":["` + cb.PubKey() + `"]},"tsa_keys":["` + tsaPubEncoded(tsa) + `"]}`
	rep := c.VerifyBundleWith(bundle, pinned)
	for _, want := range []string{`"ok":true`, `"federation_status":"sequence_verified"`, `"brokers_seq_verified":2`, `"grant_verified":2`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("per-broker-pinned federation did not verify (missing %s):\n%s", want, rep)
		}
	}

	// NEGATIVE: broker A's grant signed by broker B's key (cb) -> does NOT elevate under A's pinned set (ca) ->
	// grant_verified drops (A is not B-forgeable).
	recAforged, hashAf := fedGrantRecord(t, c, cb, "grant-a", geA) // A's evidence signed by cb (wrong broker)
	headsF := broker.BrokerGrantHeads(map[string][]broker.GrantSeqHash{
		"broker-A": {{Seq: 1, ContentHash: hashAf}},
		"broker-B": {{Seq: 1, ContentHash: hashB}},
	}, nil)
	repF := c.VerifyBundleWith(fedCheckpointBundle(t, c, tsa, []string{recAforged, recB}, []string{hashAf, hashB}, 2, headsF), pinned)
	if strings.Contains(repF, `"grant_verified":2`) {
		t.Fatalf("broker A's grant signed by broker B's key must NOT be A-accountable:\n%s", repF)
	}
	if !strings.Contains(repF, `"grant_verified":1`) {
		t.Fatalf("only broker B's grant should remain verified:\n%s", repF)
	}
}

// TestFederationCrossBrokerCertRoundTripsThroughRustVerifier is the cross-language proof for the OPTIONAL M4
// transitive tier: a PINNED issuer broker A signs a cross_broker_cert (via broker.CrossBrokerCert) vouching for
// an UNPINNED subject broker B's authority key; B's grant — signed by B's key, carrying the cert — round-trips
// through the Rust verifier and elevates to transitive_grants:1, grant_verified:1 with ONLY A pinned. Plus a
// negative control: a cert from an unpinned issuer does NOT elevate the subject.
func TestFederationCrossBrokerCertRoundTripsThroughRustVerifier(t *testing.T) {
	c, _ := core.New(seed) // the record-seal key (k0)
	caSeed := "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	cbSeed := "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	ca, _ := core.New(caSeed) // issuer A authority (PINNED)
	cb, _ := core.New(cbSeed) // subject B authority (NOT pinned)
	tsa := testTSAKey()

	caRawSeed, _ := hex.DecodeString(caSeed)
	caRaw := ed25519.NewKeyFromSeed(caRawSeed) // A's raw key, to sign the cert
	cbRawSeed, _ := hex.DecodeString(cbSeed)
	cbPub := ed25519.NewKeyFromSeed(cbRawSeed).Public().(ed25519.PublicKey) // B's authority pubkey

	geB := prepareFedGrantEvidence(t, "broker-B", "grant-b", 1)
	// A vouches for B's KEY over the grant's OWN (scope, resource); not_after >= the grant's issued_at (1718445600).
	cert := broker.CrossBrokerCert("broker-A", "broker-B", cbPub, geB["scope"].(string), geB["resource_id"].(string), 1_718_449_200, caRaw)
	geB["cross_broker_cert"] = cert
	recB, hashB := fedGrantRecord(t, c, cb, "grant-b", geB) // B's evidence (with the cert) signed by cb

	heads := broker.BrokerGrantHeads(map[string][]broker.GrantSeqHash{"broker-B": {{Seq: 1, ContentHash: hashB}}}, nil)
	bundle := fedCheckpointBundle(t, c, tsa, []string{recB}, []string{hashB}, 1, heads)

	// pin ONLY issuer A; broker B is NOT in federated_broker_keys -> B elevates ONLY via A's cert.
	pinned := `{"federated_broker_keys":{"broker-A":["` + ca.PubKey() + `"]},"tsa_keys":["` + tsaPubEncoded(tsa) + `"]}`
	rep := c.VerifyBundleWith(bundle, pinned)
	for _, want := range []string{`"ok":true`, `"grant_verified":1`, `"transitive_grants":1`, `"federation_status":"sequence_verified"`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("Go-produced cross_broker_cert transitive grant did not verify (missing %s):\n%s", want, rep)
		}
	}

	// NEGATIVE: pin a DIFFERENT issuer (not A) -> the cert's issuer A is unpinned -> no transitive elevation.
	other, _ := core.New("c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3")
	pinnedOther := `{"federated_broker_keys":{"broker-OTHER":["` + other.PubKey() + `"]},"tsa_keys":["` + tsaPubEncoded(tsa) + `"]}`
	repN := c.VerifyBundleWith(bundle, pinnedOther)
	if strings.Contains(repN, `"transitive_grants":1`) || strings.Contains(repN, `"grant_verified":1`) {
		t.Fatalf("a cert from an UNPINNED issuer must not elevate the subject:\n%s", repN)
	}
}

// TestFederationTwoBrokersRoundTripsThroughRustVerifier is the cross-language end-to-end proof for ADR 0005 M4:
// two independently-sequenced brokers, each minted via broker.Prepare(Request.BrokerID) with its own broker_seq,
// committed under a Go-built per-broker broker_grant_heads MAP (broker.BrokerGrantHeads), sealed + anchored via
// the Rust core FFI and verified by the SAME Rust verifier — reaching federation_status:"sequence_verified" with
// brokers_total:2 (a flat D6 verifier would read the interleaved seqs as a gap). Plus a per-broker suppression
// negative control proving a dropped broker head fails closed.
func TestFederationTwoBrokersRoundTripsThroughRustVerifier(t *testing.T) {
	c, _ := core.New(seed) // the shared broker recording + evidence-signing key (V1 shared-root federation)
	tsa := testTSAKey()

	geA := prepareFedGrantEvidence(t, "broker-A", "grant-a", 1)
	geB := prepareFedGrantEvidence(t, "broker-B", "grant-b", 1)
	recA, hashA := nativeGrantRecord(t, c, "grant-a", geA)
	recB, hashB := nativeGrantRecord(t, c, "grant-b", geB)

	// the per-broker head MAP (the new M4 producer artifact), each broker's head folding ONLY its own log.
	heads := broker.BrokerGrantHeads(map[string][]broker.GrantSeqHash{
		"broker-A": {{Seq: 1, ContentHash: hashA}},
		"broker-B": {{Seq: 1, ContentHash: hashB}},
	}, nil)

	// no uses in this bundle (federation_status is about the grant LOG) -> no resource_authority_keys pinned
	// (pinning it to the broker key would violate the broker/resource disjointness).
	pinned := `{"broker_authority_keys":["` + c.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"]}`
	bundle := fedCheckpointBundle(t, c, tsa, []string{recA, recB}, []string{hashA, hashB}, 2, heads)
	rep := c.VerifyBundleWith(bundle, pinned)
	for _, want := range []string{
		`"ok":true`,
		`"federation_status":"sequence_verified"`,
		`"brokers_total":2`,
		`"brokers_seq_verified":2`,
		`"cross_broker_suppression":0`,
		`"broker_trust":"sequence_verified"`,
		`"grant_verified":2`,
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("Go-produced two-broker federation did not verify as expected (missing %s):\n%s", want, rep)
		}
	}

	// NEGATIVE CONTROL: drop broker B's head from the map -> B's grant is committed without a transparency head
	// -> suppression -> fail-closed.
	headsDropB := broker.BrokerGrantHeads(map[string][]broker.GrantSeqHash{
		"broker-A": {{Seq: 1, ContentHash: hashA}},
	}, nil)
	repDrop := c.VerifyBundleWith(fedCheckpointBundle(t, c, tsa, []string{recA, recB}, []string{hashA, hashB}, 2, headsDropB), pinned)
	for _, want := range []string{`"ok":false`, `"federation_status":"suppression"`, `"cross_broker_suppression":1`} {
		if !strings.Contains(repDrop, want) {
			t.Fatalf("dropping broker B's head must fail closed (missing %s):\n%s", want, repDrop)
		}
	}
}
