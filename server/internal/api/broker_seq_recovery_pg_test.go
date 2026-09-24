package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/store"
)

// A fence committed before a failed reconciliation survives a process change.
// The next replica completes the same operation; another actor cannot claim it.
func TestBrokerSeqRecoveryFencePersistsAcrossReplicasPostgres(t *testing.T) {
	pg, admin := newVoidTestPostgres(t)
	reserveGrantSeq(t, pg, "orphan-replica")
	failing := &failMarkStore{Store: pg, failMark: true}
	first := api.New(mustCore(t), failing, "k0").WithBroker(brokerIssuingKey()).WithRecoveryAuth(testRecoveryStore()).Routes()
	if code, body := doRecovery(t, first, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusServiceUnavailable || !strings.Contains(body, `"fenced":true`) {
		t.Fatalf("first replica must report durable incomplete recovery: %d %s", code, body)
	}
	fence, found, err := pg.RecoveryFenceAt("p1", 1)
	if err != nil || !found || fence.OperationID != "recovery-test-1" {
		t.Fatalf("first replica did not commit fence: %+v %v %v", fence, found, err)
	}
	if _, found, err := pg.RecoveryResultAt("p1", 1); err != nil || found {
		t.Fatalf("failed reconciliation committed result: %v %v", found, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	other, err := store.NewPostgres(ctx, admin.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	second := api.New(mustCore(t), other, "k0").WithBroker(brokerIssuingKey()).WithRecoveryAuth(testRecoveryStore()).Routes()
	if code, body := doRecovery(t, second, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated || !strings.Contains(body, `"outcome":"voided"`) {
		t.Fatalf("second replica failed to complete recovery: %d %s", code, body)
	}
	if code, body := doRecovery(t, second, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusOK || !strings.Contains(body, `"created":false`) {
		t.Fatalf("same operation did not converge: %d %s", code, body)
	}
	replay := httptest.NewRequest(http.MethodPost, "/v2/broker-seq/void?project=p1", strings.NewReader(voidBody(1)))
	replay.Header.Set("Authorization", "Bearer second-recovery-token")
	w := httptest.NewRecorder()
	second.ServeHTTP(w, replay)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"outcome":"action_conflict"`) {
		t.Fatalf("second actor claimed fenced operation: %d %s", w.Code, w.Body.String())
	}
	got, found, err := other.RecoveryFenceAt("p1", 1)
	if err != nil || !found || got.ActorID != fence.ActorID || !got.FencedAt.Equal(fence.FencedAt) {
		t.Fatalf("replica changed immutable fence: %+v vs %+v, %v", got, fence, err)
	}
}

// A held project transaction gives the operator a bounded retryable response.
// It does not stall another project or turn cancellation into proof of rollback.
func TestBrokerSeqRecoveryBlockedGuardDeadlinePostgres(t *testing.T) {
	pg, admin := newVoidTestPostgres(t)
	reserveGrantSeq(t, pg, "orphan-held")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	holding := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- pg.WithProjectWrite(ctx, "p1", func(st store.Store) error {
			close(holding)
			<-release
			return nil
		})
	}()
	select {
	case <-holding:
	case <-ctx.Done():
		t.Fatalf("did not acquire first project guard: %v", ctx.Err())
	}
	defer func() {
		if release != nil {
			close(release)
			<-done
		}
	}()
	other, err := store.NewPostgres(ctx, admin.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	h := api.New(mustCore(t), other, "k0").WithBroker(brokerIssuingKey()).WithRecoveryAuth(testRecoveryStore()).Routes()
	start := time.Now()
	reqCtx, stop := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer stop()
	req := httptest.NewRequest(http.MethodPost, "/v2/broker-seq/void?project=p1", strings.NewReader(voidBody(1))).WithContext(reqCtx)
	req.Header.Set("Authorization", "Bearer test-recovery-token")
	w := httptest.NewRecorder()
	ended := make(chan struct{})
	go func() { h.ServeHTTP(w, req); close(ended) }()
	if err := other.WithProjectWrite(ctx, "p2", func(st store.Store) error {
		_, _, e := st.AllocateBrokerSeq("p2", "other-project")
		return e
	}); err != nil {
		t.Fatalf("other project stalled behind held guard: %v", err)
	}
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled recovery did not return within bounded time")
	}
	if time.Since(start) > 2*time.Second || w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"retryable":true`) {
		t.Fatalf("blocked recovery lacked bounded retryable response: %d %s", w.Code, w.Body.String())
	}
	if _, found, err := other.RecoveryFenceAt("p1", 1); err != nil || found {
		t.Fatalf("held first transaction allowed premature fence: %v %v", found, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("held transaction failed: %v", err)
	}
	// Disable deferred cleanup after explicit release/drain.
	release = nil
	done = nil
	if code, body := doRecovery(t, h, "POST", "/v2/broker-seq/void?project=p1", voidBody(1)); code != http.StatusCreated || !strings.Contains(body, `"outcome":"voided"`) {
		t.Fatalf("same operation did not converge after guard released: %d %s", code, body)
	}
}
