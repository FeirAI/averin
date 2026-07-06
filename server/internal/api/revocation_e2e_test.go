package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/averin-dev/averin/server/internal/api"
	"github.com/averin-dev/averin/server/internal/core"
)

func revocationKey() ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = 0x5a // role-separated from broker(seed)/resource(resourceSeed)/tsa/agent
	return ed25519.NewKeyFromSeed(s)
}

// attachRevocationList splices a top-level revocation_list into an exported bundle JSON.
func attachRevocationList(t *testing.T, bundleJSON string, rl map[string]any) string {
	t.Helper()
	var b map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bundleJSON), &b); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	rlJSON, _ := json.Marshal(rl)
	b["revocation_list"] = rlJSON
	out, _ := json.Marshal(b)
	return string(out)
}

// TestRevocationListBlocksRevokedUseEndToEnd (M5): a Go-built signed revocation_list, spliced into a REAL
// anchored grant+two-phase-use bundle and verified through the Rust core, blocks the use of the revoked
// grant — proving the producer↔verifier contract end-to-end (the verifier recomputes the same RCP-canonical
// digest the producer signed, honors the role-separated revocation_keys, and gates the use on freshness).
func TestRevocationListBlocksRevokedUseEndToEnd(t *testing.T) {
	h := newBrokerResourceServer(t)
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	ak := grantAgentKey()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")

	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(resp), &intent)
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	if code, r := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, r)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	rev := revocationKey()
	revPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(rev.Public().(ed25519.PublicKey))
	pinned := func(extra string) string {
		return `{"broker_authority_keys":["` + c.PubKey() + `"],"resource_authority_keys":["` + rc.PubKey() + `"],"tsa_keys":["` + tsaPubEncoded(tsa) + `"]` + extra + `}`
	}

	// baseline: no revocation -> verifies clean.
	if rep := c.VerifyBundleWith(anchored, pinned("")); !strings.Contains(rep, `"ok":true`) || !strings.Contains(rep, `"uses_matched":1`) {
		t.Fatalf("baseline must verify clean: %s", rep)
	}

	// FRESH list revoking THIS grant -> the use is blocked.
	rl, err := api.BuildRevocationList(c, rev, "2020-01-01T00:00:00.000Z", "2099-01-01T00:00:00.000Z", []string{grantID})
	if err != nil {
		t.Fatalf("BuildRevocationList: %v", err)
	}
	rep := c.VerifyBundleWith(attachRevocationList(t, anchored, rl), pinned(`,"revocation_keys":["`+revPub+`"]`))
	for _, want := range []string{`"ok":false`, `"revocation_status":"revoked_present"`, `"revoked_uses_blocked":1`, `"revoked_grants_matched":1`, `"uses_matched":0`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("Go-built revocation of the grant must block its use (missing %s): %s", want, rep)
		}
	}

	// FRESH list revoking a DIFFERENT grant -> must NOT block this use.
	rl2, _ := api.BuildRevocationList(c, rev, "2020-01-01T00:00:00.000Z", "2099-01-01T00:00:00.000Z", []string{"some-other-grant"})
	rep2 := c.VerifyBundleWith(attachRevocationList(t, anchored, rl2), pinned(`,"revocation_keys":["`+revPub+`"]`))
	if !strings.Contains(rep2, `"ok":true`) || !strings.Contains(rep2, `"revocation_status":"fresh"`) || !strings.Contains(rep2, `"uses_matched":1`) {
		t.Fatalf("a list revoking another grant must not block this use: %s", rep2)
	}
}
