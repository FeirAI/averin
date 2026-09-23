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

// TestBrokerSeqVoidAgeCountsLatestAttempt (review finding 1): seq 1 is reserved at T0 by an ambiguous commit that
// never lands. At T0+59m the client retries — AllocateBrokerSeq returns the SAME seq (fresh=false, so the store's
// allocated_at stays T0) and the retry's commit is in flight. At T0+61m the reservation is 61m old by allocated_at
// alone, which would pass the default 1h safety age; the void must still be refused because the grant's LATEST
// attempt was only 2m ago. Once the in-flight commit lands, the store read refuses the void for good.
func TestBrokerSeqVoidAgeCountsLatestAttempt(t *testing.T) {
	ak := grantAgentKey()

	t.Run("a recent retry blocks a void that allocated_at alone would pass", func(t *testing.T) {
		clk := newFakeClock()
		ls := &lateCommitStore{flakyGrantStore: flakyGrantStore{Store: store.NewMem().WithClock(clk.Now)}}
		h := api.New(mustCore(t), ls, "k0").WithBroker(brokerIssuingKey()).WithClock(clk.Now).Routes() // default 1h

		ls.ambiguousPut = true // T0: ambiguous commit that never lands
		if code, resp := do(t, h, "POST", "/v2/grants", grantBodyAt("idem-race", "read:orders", ak, ak, clk.Now())); code != http.StatusInternalServerError {
			t.Fatalf("T0 ambiguous commit must 500 (got %d): %s", code, resp)
		}
		clk.Advance(59 * time.Minute)
		ls.holdNext = true // T0+59m: the retry reuses seq 1; its commit is in flight (invisible to the store reads)
		if code, resp := do(t, h, "POST", "/v2/grants", grantBodyAt("idem-race", "read:orders", ak, ak, clk.Now())); code != http.StatusInternalServerError {
			t.Fatalf("T0+59m retry with an in-flight commit must 500 (got %d): %s", code, resp)
		}
		clk.Advance(2 * time.Minute) // T0+61m: allocated_at is 61m old
		code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
		if code != http.StatusConflict || !strings.Contains(resp, "last attempted by its grant") {
			t.Fatalf("a void within the safety age of the grant's latest attempt must 409 (got %d): %s", code, resp)
		}
		ls.land(t) // the retry's commit lands: the seq is recorded, so no void can ever take it
		clk.Advance(2 * time.Hour)
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "is recorded") {
			t.Fatalf("once the commit landed the void must 409 as recorded (got %d): %s", code, resp)
		}
		if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
			t.Fatalf("the landed grant fills seq 1, so a checkpoint signs (%d): %s", code, resp)
		}
	})

	t.Run("control: without a retry the same void passes at T0+61m", func(t *testing.T) {
		clk := newFakeClock()
		fs := &flakyGrantStore{Store: store.NewMem().WithClock(clk.Now)}
		h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithClock(clk.Now).Routes()

		fs.ambiguousPut = true
		do(t, h, "POST", "/v2/grants", grantBodyAt("idem-ctl", "read:orders", ak, ak, clk.Now()))
		clk.Advance(30 * time.Minute)
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "AVERIN_BROKER_SEQ_VOID_MIN_AGE") {
			t.Fatalf("a 30m-old reservation must be refused (got %d): %s", code, resp)
		}
		clk.Advance(31 * time.Minute)
		if code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
			t.Fatalf("a 61m-old, never-retried reservation must void (got %d): %s", code, resp)
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
	h := api.New(c, fs, "k0").WithBroker(brokerIssuingKey()).WithRevocation(rev).WithBrokerSeqVoidMinAge(0).Routes()
	ak := grantAgentKey()

	fs.ambiguousPut = true
	do(t, h, "POST", "/v2/grants", grantBody("idem-rv1", "read:orders", ak, ak))
	mkGrant(t, h, ak, "idem-rv2")
	code, resp := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1))
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
	if code, r := do(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusOK || !strings.Contains(r, `"revoked":true`) {
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
