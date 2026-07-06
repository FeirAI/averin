package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/averin-dev/averin/server/internal/core"
	"github.com/averin-dev/averin/server/internal/taxonomy"
)

// taxonomyKey is the operation-taxonomy issuer — distinct from the server/broker/resource/tsa keys (the
// verifier fatal-aborts if the taxonomy key set overlaps any signing role; ADR 0004 D4 / R2).
func taxonomyKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("taxtaxtaxtaxtaxtaxtaxtaxtaxtax12"))
}

// TestTaxonomyValidatesActionUnderAnchor (T8): a Go-SIGNED operation taxonomy, pinned into the verify opts,
// elevates a matched single_operation use to action_verified (uses_action_unverified:0). This proves the Go
// signer produces the EXACT artifact the Rust verifier validates cross-language — the RCP-canonical digest
// + the averin.taxonomy.v1 Ed25519 signature. Like T9 it needs a crypto-valid anchor (attachTestAnchor) to
// reach use-matching, since taxonomy verification only applies to matched, closed uses.
func TestTaxonomyValidatesActionUnderAnchor(t *testing.T) {
	h := newBrokerResourceServer(t)
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	taxKey := taxonomyKey()
	ak := grantAgentKey()

	grantID, cap := mkGrant(t, h, ak, "idem-grant") // single_operation grant: db.query:orders-ro on orders-db

	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(resp), &intent)
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	if code, oresp := do(t, h, "POST", "/v2/use-outcome", string(ob)); code != http.StatusCreated {
		t.Fatalf("use-outcome (%d): %s", code, oresp)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)

	// Produce the taxonomy from Go: list the grant's (resource_id, action) over a window covering the grant's
	// issued_at AND the use's used_at (both "now"-ish; [0, far-future] covers them).
	taxJSON, digest, ver, err := taxonomy.Sign(c, taxKey, 1, 0, 9_999_999_999,
		[]taxonomy.Entry{{ResourceID: "orders-db", Action: "db.query:orders-ro"}}, nil)
	if err != nil {
		t.Fatalf("taxonomy.Sign: %v", err)
	}
	taxPub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(taxKey.Public().(ed25519.PublicKey))
	opts := fmt.Sprintf(`{"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q],"taxonomy":%s,"taxonomy_keys":[%q],"taxonomy_digest":%q,"taxonomy_version":%d}`,
		c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa), taxJSON, taxPub, digest, ver)
	rep := c.VerifyBundleWith(anchored, opts)

	if !strings.Contains(rep, `"ok":true`) {
		t.Fatalf("a bundle with a pinned Go-signed taxonomy should verify clean: %s", rep)
	}
	if !strings.Contains(rep, `"taxonomy_status":"validated"`) {
		t.Fatalf("the Go-signed taxonomy should validate (signature + digest + version pins pass): %s", rep)
	}
	if !strings.Contains(rep, `"uses_matched":1`) {
		t.Fatalf("the two-phase use should match: %s", rep)
	}
	if !strings.Contains(rep, `"uses_action_unverified":0`) {
		t.Fatalf("the matched use's action should be taxonomy-verified (uses_action_unverified:0): %s", rep)
	}
}
