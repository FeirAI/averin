package api_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
)

// Distinct Server objects and PostgreSQL pools model two live replicas. Each
// route must resolve pending, revocation and checkpoint state from the database.
func TestProjectTransactionsAcrossReplicas(t *testing.T) {
	first, admin := newVoidTestPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	second, err := store.NewPostgres(ctx, admin.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	approver := seedKey(40)
	resourceCore, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	sharedContent := content.NewMemStore()
	newReplica := func(st store.Store) http.Handler {
		return api.New(mustCore(t), st, "k0").WithContent(sharedContent).WithBroker(brokerIssuingKey()).WithCosigPolicy(1, []ed25519.PublicKey{approver.Public().(ed25519.PublicKey)}).WithResource(resourceCore, "orders-db").WithRevocation(revocationKey()).Routes()
	}
	h1, h2 := newReplica(first), newReplica(second)
	ak := grantAgentKey()
	request := grantBody("idem-cross", "read:orders", ak, ak)
	code, body := do(t, h1, "POST", "/v2/grants/prepare", request)
	if code != http.StatusOK {
		t.Fatalf("prepare replica 1 (%d): %s", code, body)
	}
	var prepared prepareResp
	if err := json.Unmarshal([]byte(body), &prepared); err != nil {
		t.Fatal(err)
	}
	kid := broker.KeyID(approver.Public().(ed25519.PublicKey))
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(approver, broker.CosigApprovalChallenge(prepared.GrantID, kid, prepared.CredentialBinding, 1, prepared.Exp)))
	fin := finalizeBody(request, map[string]any{"cosignatures": []broker.Cosignature{{ApproverKid: kid, Sig: signature}}})
	code, body = do(t, h2, "POST", "/v2/grants/finalize", fin)
	if code != http.StatusCreated {
		t.Fatalf("finalize replica 2 (%d): %s", code, body)
	}
	var result struct {
		GrantID    string `json:"grant_id"`
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil || result.GrantID != prepared.GrantID || result.Capability == "" {
		t.Fatalf("finalized capability mismatch: %v %s", err, body)
	}
	if code, response := do(t, h1, "POST", "/v2/grants/finalize", fin); code != http.StatusCreated || !strings.Contains(response, `"created":false`) {
		t.Fatalf("replica 1 exact finalize retry (%d): %s", code, response)
	}
	if row, found, err := first.PendingGrant("p1", "idem-cross"); err != nil || found {
		t.Fatalf("pending row after finalize: %+v found=%v err=%v", row, found, err)
	}
	revoke, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": result.GrantID})
	if code, response := do(t, h1, "POST", "/v2/revoke?project=p1", string(revoke)); code != http.StatusCreated {
		t.Fatalf("revoke replica 1 (%d): %s", code, response)
	}
	if code, response := do(t, h2, "POST", "/v2/use", useBody(t, "idem-cross-use", result.Capability, result.GrantID, ak, "SELECT 1", "nonce-cross")); code == http.StatusCreated {
		t.Fatalf("replica 2 admitted revoked grant: %s", response)
	}

	// Independent writers can checkpoint concurrently without a duplicate seq.
	var wg sync.WaitGroup
	failures := make(chan string, 2)
	for _, handler := range []http.Handler{h1, h2} {
		wg.Add(1)
		go func(h http.Handler) {
			defer wg.Done()
			c, r := do(t, h, "POST", "/v2/checkpoints?project=p1", "")
			if c != http.StatusCreated {
				failures <- r
			}
		}(handler)
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Fatalf("concurrent checkpoint: %s", failure)
	}
	if cps, err := first.Checkpoints("p1"); err != nil || len(cps) != 2 || cps[0].Seq == cps[1].Seq {
		t.Fatalf("checkpoint chain: %+v err=%v", cps, err)
	}
	if code, report := do(t, h2, "GET", "/v2/verify?project=p1", ""); code != http.StatusOK || !strings.Contains(report, `"chain_ok":true`) || !strings.Contains(report, `"dag_ok":true`) || !strings.Contains(report, `"checkpoints_verified":2`) {
		t.Fatalf("cross-replica bundle (%d): %s", code, report)
	}
}
