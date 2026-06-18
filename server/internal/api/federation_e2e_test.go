package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/feir-dev/feir/server/internal/broker"
	"github.com/feir-dev/feir/server/internal/core"
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
