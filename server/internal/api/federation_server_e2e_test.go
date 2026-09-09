package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// TestFederationServerEmitsPerBrokerHeadsEndToEnd (M4 server wiring): a server configured WithBrokerID tags its
// grants with grant_evidence.broker_id and emits a per-broker_id `broker_grant_heads` map in each checkpoint, so
// a REAL server-produced bundle (grant + use, checkpointed + anchored) verifies through the Rust core under
// `federated_broker_keys` — reaching federation_status:"sequence_verified" with brokers_total:1. A regression
// guard confirms an UNCONFIGURED server stays single-broker (federation absent), byte-compatible with the legacy path.
func TestFederationServerEmitsPerBrokerHeadsEndToEnd(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithBrokerID("broker-X").
		WithResource(rc, "orders-db").
		Routes()
	ak := grantAgentKey()
	grantID, capb := mkGrant(t, h, ak, "idem-grant")

	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capb, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("use (%d): %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if !strings.Contains(exp, `"broker_grant_heads"`) {
		t.Fatalf("a federated server must emit a broker_grant_heads map in the checkpoint:\n%s", exp)
	}
	anchored := attachTestAnchor(t, exp, tsa)

	// the grant's evidence_sig is signed by the server recording key `c` (gateway_enforced); pin it as broker-X's
	// per-broker authority. Role-disjoint from the resource key (rc) and the TSA.
	pinned := `{"federated_broker_keys":{"broker-X":["` + c.PubKey() + `"]},"resource_authority_keys":["` + rc.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"]}`
	rep := c.VerifyBundleWith(anchored, pinned)
	for _, want := range []string{
		`"ok":true`,
		`"federation_status":"sequence_verified"`,
		`"brokers_total":1`,
		`"brokers_seq_verified":1`,
		`"cross_broker_suppression":0`,
		`"grant_verified":1`,
		`"uses_matched":1`,
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("server-produced federation bundle did not verify (missing %s):\n%s", want, rep)
		}
	}
}

// TestUnconfiguredServerStaysSingleBroker (regression): without WithBrokerID, the server emits NO broker_id and
// NO broker_grant_heads map — the legacy single-broker D6 path, byte-compatible with before.
func TestUnconfiguredServerStaysSingleBroker(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	h := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").Routes()
	ak := grantAgentKey()
	grantID, capb := mkGrant(t, h, ak, "idem-grant")
	if code, r := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", capb, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("use (%d): %s", code, r)
	}
	do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if strings.Contains(exp, `"broker_grant_heads"`) || strings.Contains(exp, `"broker_id"`) {
		t.Fatalf("an unconfigured server must NOT emit broker_id / broker_grant_heads:\n%s", exp)
	}
	pinned := `{"broker_authority_keys":["` + c.PubKey() + `"],"resource_authority_keys":["` + rc.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"]}`
	rep := c.VerifyBundleWith(attachTestAnchor(t, exp, tsa), pinned)
	for _, want := range []string{`"ok":true`, `"federation_status":"absent"`, `"broker_trust":"sequence_verified"`, `"grant_verified":1`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("unconfigured server bundle (missing %s):\n%s", want, rep)
		}
	}
}
