package api_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/feirai/averin/server/internal/store"
)

func TestVoidWithoutRevocationKeyBlocksPreparedCapability(t *testing.T) {
	base := store.NewMem()
	resourceCore, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(mustCore(t), base, "k0").WithBroker(brokerIssuingKey()).WithResource(resourceCore, "orders-db").WithBrokerSeqVoidMinAge(0).Routes()
	ak := grantAgentKey()
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	now := time.Now()
	req := broker.Request{
		PoPVersion: 2, ProjectID: "p1", IdempotencyKey: "idem-prepared-void", SessionID: "s1",
		IssuedAt: now.Unix(), RequestExpiresAt: now.Add(broker.MaxRequestAge).Unix(),
		AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: "read:orders",
		ScopeClass: broker.ScopeSingleOperation, AgentPubKey: pub, TTL: time.Minute,
	}
	req.AgentSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge()))
	grantID := reservedGrantID("idem-prepared-void")
	prepared, err := broker.Prepare(req, grantID, func() (int64, error) { return 1, nil }, time.Now(), brokerIssuingKey())
	if err != nil {
		t.Fatal(err)
	}
	reserveGrantSeq(t, base, "idem-prepared-void")
	use := useBody(t, "idem-use-void", prepared.Capability, grantID, ak, "SELECT 1", "nonce-void")
	var presented struct {
		UseSig string `json:"use_sig"`
	}
	if err := json.Unmarshal([]byte(use), &presented); err != nil {
		t.Fatal(err)
	}
	commitment, err := mustCore(t).Commit("input", []byte("SELECT 1"), strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	// This independently verifies the issuer signature, audience, action, PoP,
	// and freshness before void. The test must not pass merely because the
	// prepared descriptor was malformed or expired.
	shim := resourceshim.New(brokerIssuingKey().Public().(ed25519.PublicKey), "orders-db", resourceshim.NewMemLedger()).WithProject("p1")
	ev, err := shim.ValidateUse(prepared.Capability, presented.UseSig, resourceshim.Op{Action: "db.query:orders-ro", ParamsCommitment: commitment}, "nonce-void", time.Now())
	if err != nil {
		t.Fatalf("prepared capability was not otherwise valid: %v", err)
	}
	shim.RollbackUse(ev)
	if code, response := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
		t.Fatalf("void (%d): %s", code, response)
	}
	if code, response := do(t, h, "POST", "/v2/use", use); code != http.StatusBadRequest || !strings.Contains(response, "revoked") {
		t.Fatalf("prepared capability was not denied specifically by signed void (%d): %s", code, response)
	}
}

func voidBody(seq int64) string {
	return fmt.Sprintf(`{"project_id":"p1","broker_seq":%d,"reason":"orphaned by an ambiguous commit"}`, seq)
}

// pinnedBrokerOpts pins the recording/broker key and the test TSA, so the offline verifier evaluates D6 under trust.
func pinnedBrokerOpts(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`{"trusted_keys":[%q],"broker_authority_keys":[%q],"tsa_keys":[%q]}`,
		mustCore(t).PubKey(), mustCore(t).PubKey(), tsaPubEncoded(testTSAKey()))
}

// TestBrokerSeqVoidUnwedgesCheckpoint (review finding 1): g1's commit is ambiguous at seq 1 and its client never
// retries; g2 records seq 2. Every checkpoint is then refused forever (the allocated max 2 != 1 recorded grant). The
// operator voids seq 1: a signed grant_void tombstone fills it, the checkpoint signs, and the bundle verifies OFFLINE
// under pinned keys with a sequence_verified broker log and exactly ONE grant (the tombstone is never a grant).
// g1's late retry is refused (409) — it must never get the voided seq back — and a repeat void is idempotent.
func TestBrokerSeqVoidUnwedgesCheckpoint(t *testing.T) {
	base := store.NewMem()
	c := mustCore(t)
	h := api.New(c, base, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
	ak := grantAgentKey()
	reserveGrantSeq(t, base, "idem-g1")
	code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g2", "read:orders", ak, ak))
	if code != http.StatusCreated || grantSeqOf(t, resp) != 2 {
		t.Fatalf("g2 must record seq 2 (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusInternalServerError || !strings.Contains(resp, "checkpoint refused") {
		t.Fatalf("the wedge: a checkpoint over the orphaned seq 1 must be refused (got %d): %s", code, resp)
	}

	code, resp = do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
	if code != http.StatusCreated {
		t.Fatalf("void seq 1 (%d): %s", code, resp)
	}
	var voided struct {
		GrantID string `json:"grant_id"`
		Created bool   `json:"created"`
		Record  struct {
			RecordID   string `json:"record_id"`
			EventType  string `json:"event_type"`
			Extensions struct {
				Broker struct {
					Kind         string `json:"kind"`
					VoidEvidence struct {
						BrokerSeq int64  `json:"broker_seq"`
						GrantID   string `json:"grant_id"`
						ProjectID string `json:"project_id"`
					} `json:"void_evidence"`
				} `json:"broker"`
			} `json:"extensions"`
		} `json:"record"`
	}
	if err := json.Unmarshal([]byte(resp), &voided); err != nil {
		t.Fatal(err)
	}
	ve := voided.Record.Extensions.Broker.VoidEvidence
	if !voided.Created || voided.Record.Extensions.Broker.Kind != "grant_void" || voided.Record.EventType != "credential_grant_void" ||
		ve.BrokerSeq != 1 || ve.ProjectID != "p1" || ve.GrantID != voided.GrantID || voided.Record.RecordID != voided.GrantID {
		t.Fatalf("the tombstone must bind (project, broker_seq, reserved grant_id): %s", resp)
	}

	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint after the void (%d): %s", code, resp)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	rep := c.VerifyBundleWith(attachTestAnchor(t, exp, testTSAKey()), pinnedBrokerOpts(t))
	for _, want := range []string{`"ok":true`, `"broker_trust":"sequence_verified"`, `"grant_total":1`, `"grant_verified":1`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("the unwedged bundle must verify offline with %s\nreport: %s", want, rep)
		}
	}

	// a tombstone must be broker-signed to fill its seq: under a pinned broker key that did NOT sign it, it is a hard
	// failure of its own (not a silent gap-filler).
	wrongBroker := fmt.Sprintf(`{"trusted_keys":[%q],"broker_authority_keys":[%q],"tsa_keys":[%q]}`,
		c.PubKey(), tsaPubEncoded(grantAgentKey()), tsaPubEncoded(testTSAKey()))
	if rep := c.VerifyBundleWith(attachTestAnchor(t, exp, testTSAKey()), wrongBroker); !strings.Contains(rep, `"ok":false`) ||
		!strings.Contains(rep, "grant_void tombstone") || !strings.Contains(rep, "does not verify under a pinned broker key") {
		t.Fatalf("a tombstone not signed under the pinned broker key must fail verification:\n%s", rep)
	}

	// g1's client comes back: its grant_id is retired, never handed the voided seq (nor a new one).
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g1", "read:orders", ak, ak)); code != http.StatusConflict || !strings.Contains(resp, "voided") {
		t.Fatalf("a retry of the voided grant must 409 (got %d): %s", code, resp)
	}
	// a repeat void returns the existing tombstone.
	if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusOK || !strings.Contains(resp, `"created":false`) {
		t.Fatalf("a repeat void must return the existing tombstone (got %d): %s", code, resp)
	}
	// new grants continue after the voided number.
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-g3", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 3 {
		t.Fatalf("g3 must take seq 3 (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint over {void 1, 2, 3} (%d): %s", code, resp)
	}
	if code, report := do(t, h, "GET", "/v2/verify?project=p1", ""); code != http.StatusOK || !strings.Contains(report, `"ok":true`) {
		t.Fatalf("self-verify after the void (%d): %s", code, report)
	}
}

// TestBrokerSeqVoidRefusals: only a seq that is allocated, NOT recorded and older than the safety age can be voided.
// A seq whose ambiguous commit actually LANDED is refused however old it is (the store read is the authority).
func TestBrokerSeqVoidRefusals(t *testing.T) {
	ak := grantAgentKey()

	t.Run("not allocated", func(t *testing.T) {
		h := api.New(mustCore(t), store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(7)); code != http.StatusNotFound {
			t.Fatalf("voiding an unallocated seq must 404 (got %d): %s", code, resp)
		}
	})
	t.Run("recorded", func(t *testing.T) {
		h := api.New(mustCore(t), store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
		mkGrant(t, h, ak, "idem-rec")
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "is recorded") {
			t.Fatalf("voiding a recorded seq must 409 (got %d): %s", code, resp)
		}
	})
	t.Run("too young", func(t *testing.T) {
		base := store.NewMem()
		h := api.New(mustCore(t), base, "k0").WithBroker(brokerIssuingKey()).Routes() // default safety age (1h)
		reserveGrantSeq(t, base, "idem-young")
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "AVERIN_BROKER_SEQ_VOID_MIN_AGE") {
			t.Fatalf("voiding a reservation younger than the safety age must 409 (got %d): %s", code, resp)
		}
		// the reservation is untouched: the grant's retry still reclaims seq 1.
		if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-young", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 1 {
			t.Fatalf("a refused void must leave the reservation for the retry (%d): %s", code, resp)
		}
	})
	t.Run("ambiguous commit that landed", func(t *testing.T) {
		base := store.NewMem()
		h := api.New(mustCore(t), base, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
		mkGrant(t, h, ak, "idem-landed")
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "is recorded") {
			t.Fatalf("voiding a seq whose ambiguous commit landed must 409 (got %d): %s", code, resp)
		}
	})
	t.Run("reserved idempotency prefix", func(t *testing.T) {
		h := api.New(mustCore(t), store.NewMem(), "k0").Routes()
		if code, resp := do(t, h, "POST", "/v2/records", `{"idempotency_key":"grant-void:1","project_id":"p1","session_id":"s1"}`); code != http.StatusBadRequest {
			t.Fatalf("a caller must not squat a tombstone's idempotency key (got %d): %s", code, resp)
		}
	})
}

// reissuingStore models the bug a void must make impossible: an allocator that hands a NEW grant a voided number.
type reissuingStore struct {
	store.Store
	forceSeq int64
	parent   *reissuingStore
}

func (r *reissuingStore) AllocateBrokerSeq(projectID, grantID string) (int64, bool, error) {
	if r.parent != nil {
		if r.parent.forceSeq > 0 {
			seq := r.parent.forceSeq
			r.parent.forceSeq = 0
			return seq, true, nil
		}
		return r.Store.AllocateBrokerSeq(projectID, grantID)
	}
	if r.forceSeq > 0 {
		seq := r.forceSeq
		r.forceSeq = 0
		return seq, true, nil
	}
	return r.Store.AllocateBrokerSeq(projectID, grantID)
}

func (r *reissuingStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return r.Store.WithProjectWrite(ctx, projectID, func(st store.Store) error {
		return fn(&reissuingStore{Store: st, parent: r})
	})
}

// TestVerifierRejectsGrantDuplicatingVoidedSeq: once seq 1 is filled by a grant_void tombstone, a real grant that
// ALSO claims seq 1 is a duplicate broker_seq — the producer refuses to checkpoint over it, and the offline verifier
// names the violation (it never lets the tombstone and the grant both fill the one seq).
func TestVerifierRejectsGrantDuplicatingVoidedSeq(t *testing.T) {
	base := store.NewMem()
	rs := &reissuingStore{Store: base}
	c := mustCore(t)
	h := api.New(c, rs, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).Routes()
	ak := grantAgentKey()

	if _, _, err := base.AllocateBrokerSeq("p1", "abandoned-grant"); err != nil {
		t.Fatal(err)
	}
	if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
		t.Fatalf("void (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint over the tombstone (%d): %s", code, resp)
	}
	rs.forceSeq = 1 // a (buggy) allocator re-issues the voided number to a different grant
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-dup", "read:orders", ak, ak)); code != http.StatusCreated || grantSeqOf(t, resp) != 1 {
		t.Fatalf("the injected duplicate grant must record at seq 1 (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusInternalServerError || !strings.Contains(resp, "duplicate seq") {
		t.Fatalf("the producer must refuse to checkpoint over a duplicate seq (got %d): %s", code, resp)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	rep := c.VerifyBundleWith(attachTestAnchor(t, exp, testTSAKey()), pinnedBrokerOpts(t))
	if !strings.Contains(rep, `"ok":false`) || !strings.Contains(rep, "broker_seq 1 is claimed by more than one committed record") {
		t.Fatalf("the verifier must reject a grant duplicating a voided seq:\n%s", rep)
	}
}
