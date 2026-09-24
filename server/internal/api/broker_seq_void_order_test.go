package api_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/store"
)

// failMarkStore injects the failure at the transaction-bound marker write.
type failMarkStore struct {
	store.Store
	failMark bool
	parent   *failMarkStore
}

func (f *failMarkStore) WithProjectWrite(ctx context.Context, projectID string, fn func(store.Store) error) error {
	return f.Store.WithProjectWrite(ctx, projectID, func(st store.Store) error {
		return fn(&failMarkStore{Store: st, parent: f})
	})
}
func (f *failMarkStore) VoidBrokerSeq(projectID, grantID string, seq int64) error {
	if f.parent != nil && f.parent.failMark {
		f.parent.failMark = false
		return errors.New("injected void-marker write failure")
	}
	return f.Store.VoidBrokerSeq(projectID, grantID, seq)
}

func reservation(t *testing.T, s store.Store, seq int64) store.BrokerSeqReservation {
	t.Helper()
	res, found, err := s.BrokerSeqAt("p1", seq)
	if err != nil || !found {
		t.Fatalf("BrokerSeqAt(%d): found=%v err=%v", seq, found, err)
	}
	return res
}

func exerciseVoidGrantLandsFirst(t *testing.T, base store.Store, h http.Handler) {
	t.Helper()
	ak := grantAgentKey()
	mkGrant(t, h, ak, "idem-land")
	if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "grant landed; nothing to void") {
		t.Fatalf("landed grant must win over void (%d): %s", code, resp)
	}
	if res := reservation(t, base, 1); res.Voided {
		t.Fatalf("lost void wrote marker: %+v", res)
	}
	if _, ok, err := base.RecordByIdem("p1", "grant-void:1"); err != nil || ok {
		t.Fatalf("lost void wrote tombstone: %v %v", ok, err)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-land", "read:orders", ak, ak)); code != http.StatusCreated || !strings.Contains(resp, `"created":false`) || grantSeqOf(t, resp) != 1 {
		t.Fatalf("landed retry (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("landed grant checkpoint (%d): %s", code, resp)
	}
}

func TestBrokerSeqVoidGrantLandsFirstMem(t *testing.T) {
	base := store.NewMem()
	h := api.New(mustCore(t), base, "k0").WithBroker(brokerIssuingKey()).WithRevocation(revocationKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
	exerciseVoidGrantLandsFirst(t, base, h)
	if code, r := do(t, h, "POST", "/v2/revoke?project=p1", `{"project_id":"p1","grant_id":"unrelated"}`); code != http.StatusCreated || !strings.Contains(r, `"revoked_total":1`) {
		t.Fatalf("lost void revoked landed grant (%d): %s", code, r)
	}
}

// Tombstone, marker and revocation are one transaction. A marker failure must roll back the signed tombstone.
func exerciseVoidMarkerFails(t *testing.T, base store.Store) {
	t.Helper()
	fs := &failMarkStore{Store: base, failMark: true}
	h := api.New(mustCore(t), fs, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
	reserveGrantSeq(t, base, "idem-mf1")
	if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusInternalServerError || !strings.Contains(resp, "void marker") {
		t.Fatalf("marker failure must fail (%d): %s", code, resp)
	}
	if res := reservation(t, base, 1); res.Voided {
		t.Fatalf("failed transaction marked reservation: %+v", res)
	}
	if _, ok, err := base.RecordByIdem("p1", "grant-void:1"); err != nil || ok {
		t.Fatalf("failed transaction persisted tombstone: %v %v", ok, err)
	}
	if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
		t.Fatalf("void retry (%d): %s", code, resp)
	}
	if res := reservation(t, base, 1); !res.Voided {
		t.Fatalf("successful void did not mark: %+v", res)
	}
	if _, ok, err := base.RecordByIdem("p1", "grant-void:1"); err != nil || !ok {
		t.Fatalf("successful void lacks tombstone: %v %v", ok, err)
	}
	if code, resp := do(t, h, "POST", "/v2/grants", grantBody("idem-mf1", "read:orders", ak, ak)); code != http.StatusConflict || !strings.Contains(resp, "voided") {
		t.Fatalf("late grant retry (%d): %s", code, resp)
	}
	if code, resp := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint after void (%d): %s", code, resp)
	}
}
func TestBrokerSeqVoidMarkerFailsMem(t *testing.T) { exerciseVoidMarkerFails(t, store.NewMem()) }

func TestBrokerSeqVoidInertLegacyMarker(t *testing.T) {
	base := store.NewMem()
	h := api.New(mustCore(t), base, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).WithRecoveryAuth(testRecoveryStore()).Routes()
	mkGrant(t, h, grantAgentKey(), "idem-inert")
	res := reservation(t, base, 1)
	if err := base.VoidBrokerSeq("p1", res.GrantID, 1); err != nil {
		t.Fatal(err)
	}
	if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "grant landed; nothing to void") || !strings.Contains(resp, "INERT") {
		t.Fatalf("legacy marker over grant (%d): %s", code, resp)
	}
	if _, ok, _ := base.RecordByIdem("p1", "grant-void:1"); ok {
		t.Fatal("void sealed over landed grant")
	}
}

func TestBrokerSeqVoidBootFloor(t *testing.T) {
	clk := newFakeClock()
	base := store.NewMem().WithClock(clk.Now)
	reserveGrantSeq(t, base, "idem-boot")
	clk.Advance(3 * time.Hour)
	h := api.New(mustCore(t), base, "k0").WithBroker(brokerIssuingKey()).WithClock(clk.Now).WithRecoveryAuth(testRecoveryStore()).Routes()
	clk.Advance(10 * time.Minute)
	if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusConflict || !strings.Contains(resp, "before this process started") {
		t.Fatalf("boot floor (%d): %s", code, resp)
	}
	clk.Advance(51 * time.Minute)
	if code, resp := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated {
		t.Fatalf("after boot floor (%d): %s", code, resp)
	}
}
