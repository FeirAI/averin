package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/resourceshim"
	"github.com/feirai/averin/server/internal/store"
)

type countRecoveryContent struct {
	content.Store
	puts int
}

func (c *countRecoveryContent) Put(ctx context.Context, b []byte) (content.Address, error) {
	c.puts++
	return c.Store.Put(ctx, b)
}

// A pre-attribution signed tombstone may have committed before its marker. The new
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
			brokerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
			resourceCore, err := core.New(strings.Repeat("22", 32))
			if err != nil {
				t.Fatal(err)
			}
			blobs := &countRecoveryContent{Store: content.NewMemStore()}
			s := New(c, base, "k0").WithContent(blobs).WithBroker(brokerKey).WithResource(resourceCore, "orders-db").WithRecoveryAuth(rs)
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
			// Model the original pre-attribution v2 signature, not the v3 proof
			// produced by the current tombstone builder.
			delete(authority, "proof_version")
			delete(authority, "subject_projection")
			delete(authority, "subject_digest")
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
			if status, err := c.VerifyAuthorityRecord(before.JSON, c.PubKey()); err != nil || status != "legacy_unbound" {
				t.Fatalf("historical tombstone must carry a valid v2 authority signature: %s %v", status, err)
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
				// A pre-006 tombstone can predate its marker, fence and result.
				// It still blocks a valid pre-minted capability at both use entrypoints
				// even though this server has no revocation signing key.
				agent := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
				now := time.Now()
				request := broker.Request{PoPVersion: 2, ProjectID: "p1", IdempotencyKey: "legacy-prepared", SessionID: "s1",
					IssuedAt: now.Unix(), RequestExpiresAt: now.Add(broker.MaxRequestAge).Unix(),
					AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: "read:orders",
					ScopeClass: broker.ScopeSingleOperation, AgentPubKey: base64.RawURLEncoding.EncodeToString(agent.Public().(ed25519.PublicKey)), TTL: time.Minute}
				request.AgentSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(agent, request.Challenge()))
				prepared, err := broker.Prepare(request, "g1", func() (int64, error) { return 1, nil }, now, brokerKey)
				if err != nil {
					t.Fatal(err)
				}
				binding, err := resourceshim.CredentialBinding(prepared.Capability)
				if err != nil {
					t.Fatal(err)
				}
				paramsNonce := strings.Repeat("ab", 32)
				commitment, err := c.Commit("input", []byte("SELECT 1"), paramsNonce)
				if err != nil {
					t.Fatal(err)
				}
				for _, phase := range []string{"use", "use-intent"} {
					nonce := "nonce-legacy-" + phase
					challenge := resourceshim.UsePoPChallenge("g1", "orders-db", "db.query:orders-ro", commitment, binding, nonce)
					useSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(agent, challenge))
					wire, _ := json.Marshal(map[string]any{"idempotency_key": "legacy-" + phase, "project_id": "p1", "session_id": "s1",
						"capability": prepared.Capability, "use_sig": useSig, "action": "db.query:orders-ro", "params": "SELECT 1",
						"nonce": nonce, "params_nonce": paramsNonce})
					if code, body := call("POST", "", "/v2/"+phase, string(wire)); code != http.StatusBadRequest || !strings.Contains(body, "revoked") {
						t.Fatalf("legacy tombstone failed to retire %s capability (%d): %s", phase, code, body)
					}
					if _, found, _ := base.RecordByIdem("p1", "legacy-"+phase); found {
						t.Fatalf("denied legacy %s wrote a receipt", phase)
					}
				}
				if blobs.puts != 0 {
					t.Fatalf("retired capability staged %d params blobs before rejection", blobs.puts)
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
