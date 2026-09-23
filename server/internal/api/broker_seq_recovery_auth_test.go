package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/store"
)

func recoveryRequest(h http.Handler, token, body string) (int, string) {
	r := httptest.NewRequest(http.MethodPost, "/v2/broker-seq/void?project=p1", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestBrokerSeqRecoveryDecomposedReasonReplay(t *testing.T) {
	st := store.NewMem()
	if _, _, err := st.AllocateBrokerSeq("p1", "reserved-grant"); err != nil {
		t.Fatal(err)
	}
	h := api.New(mustCore(t), st, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).
		WithRecoveryAuth(testRecoveryStore()).Routes()
	body := fmt.Sprintf(`{"project_id":"p1","broker_seq":1,"operation_id":"incident-1","reason":%q}`, "Cafe\u0301 recovery")
	code, response := recoveryRequest(h, "test-recovery-token", body)
	if code != http.StatusCreated {
		t.Fatalf("initial recovery: %d %s", code, response)
	}
	if !strings.Contains(response, "Café recovery") {
		t.Fatalf("stored reason was not NFC-normalized: %s", response)
	}
	if code, response := recoveryRequest(h, "test-recovery-token", body); code != http.StatusOK || !strings.Contains(response, `"created":false`) {
		t.Fatalf("identical decomposed-Unicode retry: %d %s", code, response)
	}
}

func writerRequest(h http.Handler, method, path, body string) (int, string) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer writer-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestBrokerSeqRecoveryAuthorizationAndEvidence(t *testing.T) {
	st := store.NewMem()
	seq, _, err := st.AllocateBrokerSeq("p1", "reserved-grant")
	if err != nil || seq != 1 {
		t.Fatalf("reserve seq: %d %v", seq, err)
	}
	recovery := testRecoveryStore()
	c := mustCore(t)
	h := api.New(c, st, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).
		WithAuth(auth.NewMapStore(map[string][]string{"p1": {"writer-token"}})).WithRecoveryAuth(recovery).Routes()
	body := voidBody(1)
	for _, tc := range []struct {
		name, token string
	}{
		{"missing", ""}, {"writer", "writer-token"}, {"wrong", "other-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, response := recoveryRequest(h, tc.token, body)
			if code != http.StatusForbidden || (tc.token != "" && strings.Contains(response, tc.token)) {
				t.Fatalf("denial got %d: %s", code, response)
			}
			if _, ok, err := st.RecordByIdem("p1", "grant-void:1"); err != nil || ok {
				t.Fatalf("denied recovery sealed evidence: found=%v err=%v", ok, err)
			}
			res, ok, err := st.BrokerSeqAt("p1", 1)
			if err != nil || !ok || res.Voided {
				t.Fatalf("denied recovery changed reservation: %+v %v %v", res, ok, err)
			}
		})
	}
	ordinary := httptest.NewRequest(http.MethodPost, "/v2/records?project=p1", strings.NewReader(`{}`))
	ordinary.Header.Set("Authorization", "Bearer test-recovery-token")
	ordinaryResponse := httptest.NewRecorder()
	h.ServeHTTP(ordinaryResponse, ordinary)
	if ordinaryResponse.Code != http.StatusUnauthorized {
		t.Fatalf("recovery credential granted ordinary write access: %d", ordinaryResponse.Code)
	}
	for _, bad := range []string{
		`{"project_id":"p2","broker_seq":1,"operation_id":"op","reason":"valid reason"}`,
		`{"project_id":"p1","broker_seq":1,"operation_id":"","reason":"valid reason"}`,
		`{"project_id":"p1","broker_seq":1,"operation_id":"op","reason":" "}`,
		`{"project_id":"p1","broker_seq":1,"operation_id":"op id","reason":"valid reason"}`,
		`{"project_id":"p1","broker_seq":1,"operation_id":"opé","reason":"valid reason"}`,
		`{"project_id":"p1","broker_seq":1,"operation_id":"op\n","reason":"valid reason"}`,
		`{"project_id":"p1","broker_seq":1,"operation_id":"op","reason":"valid reason","actor_id":"spoofed"}`,
	} {
		code, _ := recoveryRequest(h, "test-recovery-token", bad)
		if code != http.StatusBadRequest && code != http.StatusForbidden {
			t.Fatalf("bad request got %d: %s", code, bad)
		}
	}
	if _, ok, err := st.RecordByIdem("p1", "grant-void:1"); err != nil || ok {
		t.Fatalf("invalid recovery inputs sealed evidence: found=%v err=%v", ok, err)
	}
	if res, ok, err := st.BrokerSeqAt("p1", 1); err != nil || !ok || res.Voided {
		t.Fatalf("invalid recovery inputs changed reservation: %+v %v %v", res, ok, err)
	}
	code, response := recoveryRequest(h, "test-recovery-token", body)
	if code != http.StatusCreated {
		t.Fatalf("authorized recovery got %d: %s", code, response)
	}
	var out struct {
		Record struct {
			Extensions struct {
				Broker struct {
					VoidEvidence struct {
						ActorID     string `json:"actor_id"`
						OperationID string `json:"operation_id"`
						Reason      string `json:"reason"`
					} `json:"void_evidence"`
				} `json:"broker"`
			} `json:"extensions"`
		} `json:"record"`
	}
	if err := json.Unmarshal([]byte(response), &out); err != nil {
		t.Fatal(err)
	}
	ev := out.Record.Extensions.Broker.VoidEvidence
	if ev.ActorID != "test-operator" || ev.OperationID != "recovery-test-1" || ev.Reason != "orphaned by an ambiguous commit" {
		t.Fatalf("recovery evidence missed authenticated actor/action/reason: %+v", ev)
	}
	if code, response := recoveryRequest(h, "test-recovery-token", body); code != http.StatusOK || !strings.Contains(response, `"created":false`) {
		t.Fatalf("identical replay got %d: %s", code, response)
	}
	for _, conflict := range []string{
		strings.Replace(body, "recovery-test-1", "other-operation", 1),
		strings.Replace(body, "orphaned by an ambiguous commit", "different reason", 1),
	} {
		if code, response := recoveryRequest(h, "test-recovery-token", conflict); code != http.StatusConflict {
			t.Fatalf("conflicting replay got %d: %s", code, response)
		}
	}
	if code, response := recoveryRequest(h, "second-recovery-token", body); code != http.StatusConflict {
		t.Fatalf("different authenticated actor claimed tombstone: %d %s", code, response)
	}
	if code, response := writerRequest(h, http.MethodPost, "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint after recovery: %d %s", code, response)
	}
	code, exported := writerRequest(h, http.MethodGet, "/v2/export?project=p1", "")
	if code != http.StatusOK {
		t.Fatalf("export after recovery: %d %s", code, exported)
	}
	verified := c.VerifyBundleWith(attachTestAnchor(t, exported, testTSAKey()), pinnedBrokerOpts(t))
	if !strings.Contains(verified, `"ok":true`) {
		t.Fatalf("original recovery evidence did not verify: %s", verified)
	}
	for _, tampered := range []string{
		strings.Replace(exported, `"actor_id":"test-operator"`, `"actor_id":"spoofed"`, 1),
		strings.Replace(exported, `"actor_id":"test-operator",`, ``, 1),
	} {
		if tampered == exported {
			t.Fatal("test did not change the exported actor evidence")
		}
		report := c.VerifyBundleWith(attachTestAnchor(t, tampered, testTSAKey()), pinnedBrokerOpts(t))
		if !strings.Contains(report, `"ok":false`) {
			t.Fatalf("altered actor evidence verified: %s", report)
		}
	}
}

func TestBrokerSeqRecoveryDevOpenStillDenied(t *testing.T) {
	h := api.New(mustCore(t), store.NewMem(), "k0").WithBroker(brokerIssuingKey()).
		WithAuth(auth.NewOpenStore()).Routes()
	for _, token := range []string{"", "ordinary-writer"} {
		if code, response := recoveryRequest(h, token, voidBody(1)); code != http.StatusForbidden {
			t.Fatalf("dev-open ordinary auth granted recovery with %q: %d %s", token, code, response)
		}
	}
}

func TestBrokerSeqRecoveryDeniedPostgres(t *testing.T) {
	pg, _ := newVoidTestPostgres(t)
	seq, _, err := pg.AllocateBrokerSeq("p1", "reserved-grant")
	if err != nil || seq != 1 {
		t.Fatalf("reserve seq: %d %v", seq, err)
	}
	h := api.New(mustCore(t), pg, "k0").WithBroker(brokerIssuingKey()).WithBrokerSeqVoidMinAge(0).
		WithAuth(auth.NewMapStore(map[string][]string{"p1": {"writer-token"}})).WithRecoveryAuth(testRecoveryStore()).Routes()
	if code, response := recoveryRequest(h, "writer-token", voidBody(1)); code != http.StatusForbidden {
		t.Fatalf("writer recovery got %d: %s", code, response)
	}
	if _, ok, err := pg.RecordByIdem("p1", "grant-void:1"); err != nil || ok {
		t.Fatalf("denial committed tombstone: found=%v err=%v", ok, err)
	}
	res, ok, err := pg.BrokerSeqAt("p1", 1)
	if err != nil || !ok || res.Voided {
		t.Fatalf("denial changed reservation: %+v %v %v", res, ok, err)
	}
}
