package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/store"
)

// fakeClock is a settable clock shared by the api server and the Mem store.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// A continuously failing client cannot postpone the durable recovery fence.
// The project guard drains earlier attempts and its permanent fence bars later
// attempts, independently of local attempt age or process start time.
func TestBrokerSeqRecoveryPerpetualFailedRetries(t *testing.T) {
	ak := grantAgentKey()

	t.Run("failed retries cannot postpone the permanent fence", func(t *testing.T) {
		clk := newFakeClock()
		ls := &flakyGrantStore{Store: store.NewMem().WithClock(clk.Now)}
		h := api.New(mustCore(t), ls, "k0").WithBroker(brokerIssuingKey()).WithClock(clk.Now).WithRecoveryAuth(testRecoveryStore()).Routes()

		reserveGrantSeq(t, ls.Store, "idem-race") // T0: an orphaned durable reservation
		for i := 0; i < 3; i++ {
			ls.failHeads = true
			if code, resp := do(t, h, "POST", "/v2/grants", grantBodyAt("idem-race", "read:orders", ak, ak, clk.Now())); code != http.StatusInternalServerError {
				t.Fatalf("failed retry %d (%d): %s", i, code, resp)
			}
			clk.Advance(time.Minute)
		}
		if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated || !strings.Contains(resp, `"outcome":"voided"`) {
			t.Fatalf("recovery starved by failed retries (%d): %s", code, resp)
		}
		if code, resp := do(t, h, "POST", "/v2/grants", grantBodyAt("idem-race", "read:orders", ak, ak, clk.Now())); code != http.StatusConflict || !strings.Contains(resp, "fenced") {
			t.Fatalf("late retry bypassed fence (%d): %s", code, resp)
		}
		if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Fatalf("the tombstone fills seq 1, so a checkpoint signs (%d): %s", code, resp)
		}
	})

	t.Run("fresh reservation needs no wall clock delay", func(t *testing.T) {
		clk := newFakeClock()
		fs := &flakyGrantStore{Store: store.NewMem().WithClock(clk.Now)}
		h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithClock(clk.Now).WithRecoveryAuth(testRecoveryStore()).Routes()

		reserveGrantSeq(t, fs.Store, "idem-ctl")
		if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
			t.Fatalf("fresh reservation must fence and void (got %d): %s", code, resp)
		}
	})
}

// TestBrokerSeqVoidRevokesVoidedGrant (design note): with revocation enabled, the void also revokes the voided
// grant_id, so a capability minted for it before the void can no longer be used, and the next export's signed
// revocation_list carries it — while the unwedged bundle still verifies offline (a revoked id with no grant is fine).
func TestBrokerSeqVoidRevokesVoidedGrant(t *testing.T) {
	fs := &flakyGrantStore{Store: store.NewMem()}
	c := mustCore(t)
	rev := revocationKey()
	h := api.New(c, fs, "k0").WithBroker(brokerIssuingKey()).WithRevocation(rev).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
	ak := grantAgentKey()

	reserveGrantSeq(t, fs.Store, "idem-rv1")
	mkGrant(t, h, ak, "idem-rv2")
	code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
	if code != http.StatusCreated || !strings.Contains(resp, `"revoked":true`) {
		t.Fatalf("a void under revocation must revoke the voided grant_id (%d): %s", code, resp)
	}
	var v struct {
		GrantID string `json:"grant_id"`
	}
	if err := json.Unmarshal([]byte(resp), &v); err != nil || v.GrantID == "" {
		t.Fatalf("decode void: %v %s", err, resp)
	}
	// already revoked: an explicit revoke is idempotent (the set still holds exactly that one id).
	rb, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": v.GrantID})
	if code, r := do(t, h, "POST", "/v2/revoke?project=p1", string(rb)); code != http.StatusCreated || !strings.Contains(r, `"revoked_total":1`) {
		t.Fatalf("the voided grant_id must already be in the revoked set (%d): %s", code, r)
	}
	// a repeat void (idempotent) re-applies the revocation harmlessly.
	if code, r := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusOK || !strings.Contains(r, `"revoked":true`) {
		t.Fatalf("a repeat void must return the tombstone and keep the revocation (%d): %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint (%d): %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	if !strings.Contains(exp, `"revocation_list"`) || !strings.Contains(exp, v.GrantID) {
		t.Fatalf("the export's revocation_list must carry the voided grant_id:\n%s", exp)
	}
	revPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(rev.Public().(ed25519.PublicKey))
	opts := `{"trusted_keys":["` + c.PubKey() + `"],"broker_authority_keys":["` + c.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(testTSAKey()) + `"],"revocation_keys":["` + revPub + `"]}`
	rep := c.VerifyBundleWith(attachTestAnchor(t, exp, testTSAKey()), opts)
	for _, want := range []string{`"ok":true`, `"broker_trust":"sequence_verified"`, `"grant_total":1`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("the unwedged, revoked bundle must still verify offline with %s\nreport: %s", want, rep)
		}
	}
}
