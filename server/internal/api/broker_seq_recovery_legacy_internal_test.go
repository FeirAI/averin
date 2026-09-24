package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// A pre-006 signed tombstone may have committed before its marker. The new
// operator repairs only operational state; no actor is retroactively signed
// into the original evidence. Partial/new attribution cannot be adopted.
func TestBrokerSeqRecoveryLegacyTombstoneAttribution(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		actor, op             string
		removeActor, removeOp bool
		want                  int
	}{
		{"pre006 absent attribution", "", "", true, true, http.StatusOK},
		{"partial attribution", "original", "", false, true, http.StatusConflict},
		{"different operation", "original", "original-op", false, false, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := core.New(strings.Repeat("11", 32))
			if err != nil {
				t.Fatal(err)
			}
			base := store.NewMem()
			if _, _, err := base.AllocateBrokerSeq("p1", "g1"); err != nil {
				t.Fatal(err)
			}
			rs, _, err := auth.ParseRecoveryKeys(`[{"project_id":"p1","actor_id":"reconciler","token":"recovery-secret"},{"project_id":"p1","actor_id":"second","token":"second-secret"}]`)
			if err != nil {
				t.Fatal(err)
			}
			s := New(c, base, "k0").WithBroker(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))).WithRecoveryAuth(rs)
			old := brokerSeqVoidRequest{ProjectID: "p1", BrokerSeq: 1, SessionID: "broker-seq-void", ActorID: tc.actor, OperationID: tc.op, Reason: "original incident"}
			rec, err := s.buildGrantVoidRecord(old, "g1")
			if err != nil {
				t.Fatal(err)
			}
			ev := rec["extensions"].(map[string]any)["broker"].(map[string]any)["void_evidence"].(map[string]any)
			if tc.removeActor {
				delete(ev, "actor_id")
			}
			if tc.removeOp {
				delete(ev, "operation_id")
			}
			eb, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := c.RcpEvidenceHash(string(eb))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := c.SignEvidence("gateway_enforced", "p1", "g1", hash)
			if err != nil {
				t.Fatal(err)
			}
			authority := rec["authority"].(map[string]any)
			authority["evidence_hash"], authority["evidence_sig"] = hash, sig
			var original string
			if err := s.withProjectWrite(t.Context(), "p1", func(st store.Store) error {
				var e error
				original, _, e = s.sealAndStore(st, "p1", "broker-seq-void", "grant-void:1", rec, nil)
				return e
			}); err != nil {
				t.Fatal(err)
			}
			before, found, err := base.RecordByIdem("p1", "grant-void:1")
			if err != nil || !found {
				t.Fatalf("original: %v %v", found, err)
			}
			h := s.Routes()
			call := func(method, token, path, body string) (int, string) {
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w.Code, w.Body.String()
			}
			if tc.want == http.StatusOK {
				if code, body := call("GET", "recovery-secret", "/v2/broker-seq/void?project=p1&broker_seq=1", ""); code != http.StatusOK || !strings.Contains(body, `"original_void_actor_unattributed":true`) {
					t.Fatalf("legacy preflight (%d): %s", code, body)
				}
			}
			body := `{"project_id":"p1","broker_seq":1,"operation_id":"new-op","reason":"reconcile old tombstone"}`
			code, response := call("POST", "recovery-secret", "/v2/broker-seq/void?project=p1", body)
			if code != tc.want {
				t.Fatalf("repair (%d): %s", code, response)
			}
			after, found, err := base.RecordByIdem("p1", "grant-void:1")
			if err != nil || !found || after.JSON != original || after.ContentHash != before.ContentHash {
				t.Fatalf("original evidence changed: %+v %+v %v", before, after, err)
			}
			if tc.want == http.StatusOK {
				if !strings.Contains(response, `"legacy_tombstone":true`) || !strings.Contains(response, `"reconciliation_actor_id":"reconciler"`) || !strings.Contains(response, `"original_void_actor_unattributed":true`) {
					t.Fatalf("misattributed legacy repair: %s", response)
				}
				if res, found, _ := base.BrokerSeqAt("p1", 1); !found || !res.Voided {
					t.Fatalf("legacy marker unrepaired: %+v", res)
				}
				if result, found, _ := base.RecoveryResultAt("p1", 1); !found || result.Outcome != "voided" || result.WinningRecordHash != before.ContentHash {
					t.Fatalf("legacy terminal: %+v %v", result, found)
				}
				if code, _ := call("POST", "second-secret", "/v2/broker-seq/void?project=p1", body); code != http.StatusConflict {
					t.Fatalf("second actor claimed first fence: %d", code)
				}
			} else if _, found, _ := base.RecoveryFenceAt("p1", 1); found {
				t.Fatal("conflicting original was fenced")
			}
		})
	}
}
