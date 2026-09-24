package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/store"
	"github.com/feirai/averin/server/internal/taxonomy"
)

// Plan 009 server tests: authorization ordinals on every receipt, immutable revocation events with
// a prospective cutoff from the same order, the v2 snapshot export, native introspection validation,
// and the producer-to-verifier historical judgment.

func temporalServer(t *testing.T, st store.Store, v2 bool) http.Handler {
	t.Helper()
	c, err := core.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := core.New(resourceSeed)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(resourceSeed)
	s := api.New(c, st, "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithIntrospection(ed25519.NewKeyFromSeed(raw)).
		WithRevocation(revocationKey())
	if v2 {
		s = s.WithRevocationExportV2()
	}
	return s.Routes()
}

// receiptOrder reads the resource-signed authorization_order of a use, intent, outcome or transcript.
func receiptOrder(t *testing.T, recordJSON string) (ordinal int64, project string, present bool) {
	t.Helper()
	var r struct {
		Extensions struct {
			Broker map[string]json.RawMessage `json:"broker"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal([]byte(recordJSON), &r); err != nil {
		t.Fatalf("parse record: %v", err)
	}
	for _, key := range []string{"use_evidence", "use_outcome", "introspection_evidence"} {
		raw, ok := r.Extensions.Broker[key]
		if !ok {
			continue
		}
		var ev struct {
			Order *struct {
				Format    string `json:"format"`
				ProjectID string `json:"project_id"`
				Ordinal   int64  `json:"ordinal"`
			} `json:"authorization_order"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Order == nil {
			return 0, "", false
		}
		if ev.Order.Format != "averin.authorization_order.v1" {
			t.Fatalf("authorization_order format %q", ev.Order.Format)
		}
		return ev.Order.Ordinal, ev.Order.ProjectID, true
	}
	t.Fatalf("record has no receipt payload: %s", recordJSON)
	return 0, "", false
}

func responseRecord(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		Record json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Record) == 0 {
		t.Fatalf("no record in response: %v %s", err, body)
	}
	return string(out.Record)
}

func revokeBody(grantID, mode string) string {
	b, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": grantID, "mode": mode, "reason": "test " + mode})
	return string(b)
}

type revokeReply struct {
	Mode        string `json:"mode"`
	CutoffOrder int64  `json:"cutoff_order"`
	Created     bool   `json:"created"`
}

func mustRevoke(t *testing.T, h http.Handler, grantID, mode string) revokeReply {
	t.Helper()
	code, body := do(t, h, "POST", "/v2/revoke?project=p1", revokeBody(grantID, mode))
	if code != http.StatusCreated {
		t.Fatalf("revoke %s %s (%d): %s", grantID, mode, code, body)
	}
	var r revokeReply
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTemporalReceiptsCarryMonotonicOrdinals(t *testing.T) {
	h := temporalServer(t, store.NewMem(), true)
	ak := grantAgentKey()
	g1, cap1 := mkGrant(t, h, ak, "idem-g1")
	g2, cap2 := mkGrant(t, h, ak, "idem-g2")
	code, body := do(t, h, "POST", "/v2/use", useBody(t, "idem-u1", cap1, g1, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use (%d): %s", code, body)
	}
	o1, project, ok := receiptOrder(t, responseRecord(t, body))
	if !ok || o1 != 1 || project != "p1" {
		t.Fatalf("first use ordinal=%d project=%q present=%v", o1, project, ok)
	}
	// An exact retry returns the stored receipt: same ordinal, no allocation.
	code, body = do(t, h, "POST", "/v2/use", useBody(t, "idem-u1", cap1, g1, ak, "SELECT 1", "nonce-1"))
	if o, _, _ := receiptOrder(t, responseRecord(t, body)); code != http.StatusCreated || o != o1 || !strings.Contains(body, `"idempotent":true`) {
		t.Fatalf("exact retry changed the ordinal: %d %s", code, body)
	}
	code, body = do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-i2", cap2, g2, ak, "SELECT 2", "nonce-2"))
	if code != http.StatusCreated {
		t.Fatalf("intent (%d): %s", code, body)
	}
	intent := responseRecord(t, body)
	o2, _, _ := receiptOrder(t, intent)
	if o2 != 2 {
		t.Fatalf("intent ordinal %d, want 2 (a retry must not have burned one)", o2)
	}
	var in struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(body), &in)
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-o2", "project_id": "p1", "session_id": "s1", "intent_record_id": in.UseID, "status": "ok"})
	code, body = do(t, h, "POST", "/v2/use-outcome", string(ob))
	if code != http.StatusCreated {
		t.Fatalf("outcome (%d): %s", code, body)
	}
	// The outcome is completion evidence: it inherits the intent's ordinal and allocates nothing.
	if o, _, ok := receiptOrder(t, responseRecord(t, body)); !ok || o != o2 {
		t.Fatalf("outcome ordinal %d (present %v), want the intent's %d", o, ok, o2)
	}
	r := mustRevoke(t, h, g2, "prospective")
	if r.CutoffOrder != 3 {
		t.Fatalf("cutoff %d, want the next ordinal 3 (the outcome must not have allocated)", r.CutoffOrder)
	}
}

func TestTemporalRevokeModesCutoffsAndExportFormats(t *testing.T) {
	mem := store.NewMem()
	v1 := temporalServer(t, mem, false)
	ak := grantAgentKey()
	gA, capA := mkGrant(t, v1, ak, "idem-gA")
	if code, body := do(t, v1, "POST", "/v2/revoke?project=p1", revokeBody(gA, "prospective")); code != http.StatusBadRequest || !strings.Contains(body, "v2") {
		t.Fatalf("v1 export accepted a prospective revocation it cannot represent: %d %s", code, body)
	}
	if code, body := do(t, v1, "POST", "/v2/revoke?project=p1", revokeBody(gA, "sometimes")); code != http.StatusBadRequest {
		t.Fatalf("unknown mode accepted: %d %s", code, body)
	}
	h := temporalServer(t, mem, true)
	if code, body := do(t, h, "POST", "/v2/use", useBody(t, "idem-uA", capA, gA, ak, "SELECT 1", "nonce-A")); code != http.StatusCreated {
		t.Fatalf("use (%d): %s", code, body)
	}
	first := mustRevoke(t, h, gA, "prospective")
	if first.Mode != "prospective" || first.CutoffOrder != 2 || !first.Created {
		t.Fatalf("prospective revoke = %+v, want cutoff 2 after ordinal 1", first)
	}
	// A new receipt of another grant advances the order; a retried revoke keeps the original cutoff.
	gB, capB := mkGrant(t, h, ak, "idem-gB")
	if code, body := do(t, h, "POST", "/v2/use", useBody(t, "idem-uB", capB, gB, ak, "SELECT 2", "nonce-B")); code != http.StatusCreated {
		t.Fatalf("use B (%d): %s", code, body)
	}
	retry := mustRevoke(t, h, gA, "prospective")
	if retry.Created || retry.CutoffOrder != first.CutoffOrder {
		t.Fatalf("retried revoke moved the cutoff: %+v then %+v", first, retry)
	}
	// Current validity: any mode blocks a later use immediately.
	gA2, capA2 := mkGrant(t, h, ak, "idem-gA2")
	mustRevoke(t, h, gA2, "prospective")
	if code, body := do(t, h, "POST", "/v2/use", useBody(t, "idem-uA2", capA2, gA2, ak, "SELECT 3", "nonce-A2")); code == http.StatusCreated || !strings.Contains(body, "revoked") {
		t.Fatalf("a prospectively revoked grant admitted a later use: %d %s", code, body)
	}
	// A later compromise upgrades to total; it is never lost behind the earlier cutoff.
	upgrade := mustRevoke(t, h, gA, "total")
	if upgrade.Mode != "total" || !upgrade.Created {
		t.Fatalf("total upgrade = %+v", upgrade)
	}
	if again := mustRevoke(t, h, gA, "prospective"); again.Mode != "total" {
		t.Fatalf("a prospective retry masked the total revocation: %+v", again)
	}

	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	var bundle struct {
		RevocationList struct {
			Format    string `json:"format"`
			ProjectID string `json:"project_id"`
			Snapshot  struct {
				BoundaryTime string `json:"boundary_time"`
				Watermark    int64  `json:"authorization_high_watermark"`
			} `json:"snapshot"`
			Revocations []struct {
				GrantID     string `json:"grant_id"`
				Mode        string `json:"mode"`
				CutoffOrder *int64 `json:"cutoff_order"`
			} `json:"revocations"`
			RevokedGrantIDs any `json:"revoked_grant_ids"`
		} `json:"revocation_list"`
	}
	if err := json.Unmarshal([]byte(exp), &bundle); err != nil {
		t.Fatal(err)
	}
	rl := bundle.RevocationList
	if rl.Format != "averin.revocation.list.v2" || rl.ProjectID != "p1" || rl.RevokedGrantIDs != nil {
		t.Fatalf("v2 export shape: %+v", rl)
	}
	if rl.Snapshot.Watermark != 4 {
		t.Fatalf("watermark %d, want 4 (use A, cutoff A, use B, cutoff A2)", rl.Snapshot.Watermark)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", rl.Snapshot.BoundaryTime); err != nil {
		t.Fatalf("boundary time %q: %v", rl.Snapshot.BoundaryTime, err)
	}
	got := map[string]string{}
	for _, e := range rl.Revocations {
		v := e.Mode
		if e.CutoffOrder != nil {
			v += fmt.Sprintf("@%d", *e.CutoffOrder)
		}
		got[e.GrantID] = v
	}
	if len(got) != 2 || got[gA] != "total" || got[gA2] != "prospective@4" {
		t.Fatalf("exported revocations %v", got)
	}
	// The v1 export can state only total revocations: with a prospective event it refuses rather
	// than emitting it as total or omitting it.
	if code, body := do(t, v1, "GET", "/v2/export?project=p1", ""); code == http.StatusOK || !strings.Contains(body, "prospective") {
		t.Fatalf("v1 export of a prospective revocation: %d %s", code, body)
	}
}

func nativeGrant(t *testing.T, h http.Handler, idem string, ttl int) (string, int64) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": "p1", "session_id": "s1",
		"agent_id": "agent-x", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": "read:orders write:orders", "mode": "token_exchange", "lease_id": "lease-" + idem, "ttl_seconds": ttl,
	})
	code, resp := do(t, h, "POST", "/v2/grants", string(body))
	if code != http.StatusCreated {
		t.Fatalf("native grant (%d): %s", code, resp)
	}
	var out struct {
		GrantID string          `json:"grant_id"`
		Record  json.RawMessage `json:"record"`
	}
	json.Unmarshal([]byte(resp), &out)
	return out.GrantID, grantEvidenceExp(t, out.Record)
}

func introspectBody(idem, grantID, credRef, scope string, exp, at int64) string {
	b, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": "p1", "session_id": "s1", "grant_id": grantID,
		"credential_ref": credRef, "effective_scope": scope, "effective_exp": exp, "introspected_at": at,
	})
	return string(b)
}

func TestTemporalIntrospectionValidatesGrantAndRetriesExactly(t *testing.T) {
	h := temporalServer(t, store.NewMem(), true)
	g, exp := nativeGrant(t, h, "n1", 3600)
	lease := "lease-n1"
	code, body := do(t, h, "POST", "/v2/introspection", introspectBody("intro-1", g, lease, "read:orders", exp, 0))
	if code != http.StatusCreated {
		t.Fatalf("introspection (%d): %s", code, body)
	}
	first := responseRecord(t, body)
	ordinal, _, ok := receiptOrder(t, first)
	if !ok || ordinal != 1 {
		t.Fatalf("transcript ordinal %d present=%v", ordinal, ok)
	}
	var committed struct {
		Extensions struct {
			Broker struct {
				Evidence struct {
					IntrospectedAt int64 `json:"introspected_at"`
				} `json:"introspection_evidence"`
			} `json:"broker"`
		} `json:"extensions"`
	}
	json.Unmarshal([]byte(first), &committed)
	at := committed.Extensions.Broker.Evidence.IntrospectedAt

	// Omitted time on retry reuses the committed server-selected time; the same explicit time too.
	for _, retryAt := range []int64{0, at} {
		code, body = do(t, h, "POST", "/v2/introspection", introspectBody("intro-1", g, lease, "read:orders", exp, retryAt))
		if code != http.StatusCreated || responseRecord(t, body) != first || !strings.Contains(body, `"created":false`) {
			t.Fatalf("exact retry (at=%d) did not return the committed receipt: %d %s", retryAt, code, body)
		}
	}
	// A conflicting explicit time or any other field never returns the stored receipt.
	for name, conflict := range map[string]string{
		"time":   introspectBody("intro-1", g, lease, "read:orders", exp, at-1),
		"scope":  introspectBody("intro-1", g, lease, "write:orders", exp, 0),
		"expiry": introspectBody("intro-1", g, lease, "read:orders", exp-1, 0),
	} {
		if code, body := do(t, h, "POST", "/v2/introspection", conflict); code != http.StatusConflict || strings.Contains(body, `"record"`) {
			t.Fatalf("%s conflict returned %d %s", name, code, body)
		}
	}
	// The actual grant is validated before any ordinal or signature.
	g2, exp2 := nativeGrant(t, h, "n2", 3600)
	for name, bad := range map[string]string{
		"unknown grant":   introspectBody("bad-1", "no-such-grant", lease, "read:orders", exp2, 0),
		"wrong lease":     introspectBody("bad-2", g2, lease, "read:orders", exp2, 0),
		"scope broadened": introspectBody("bad-3", g2, "lease-n2", "admin:orders", exp2, 0),
		"exp outlives":    introspectBody("bad-4", g2, "lease-n2", "read:orders", exp2+1, 0),
		"before issuance": introspectBody("bad-5", g2, "lease-n2", "read:orders", exp2, exp2-7200),
		"future":          introspectBody("bad-6", g2, "lease-n2", "read:orders", exp2, time.Now().Add(10*time.Minute).Unix()),
	} {
		if code, body := do(t, h, "POST", "/v2/introspection", bad); code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", name, code, body)
		}
	}
	// The ordinal was not burned by the refusals, and identifiers come from the stored receipt.
	code, body = do(t, h, "POST", "/v2/introspection", introspectBody("intro-2", g2, "lease-n2", "read:orders", exp2, 0))
	if o, _, _ := receiptOrder(t, responseRecord(t, body)); code != http.StatusCreated || o != 2 || !strings.Contains(body, `"grant_id":"`+g2+`"`) {
		t.Fatalf("second transcript: %d ordinal %d %s", code, o, body)
	}
	// Revocation (any mode) blocks new transcripts, but an exact committed receipt is still returned.
	mustRevoke(t, h, g, "prospective")
	if code, body := do(t, h, "POST", "/v2/introspection", introspectBody("intro-3", g, lease, "read:orders", exp, 0)); code != http.StatusBadRequest || !strings.Contains(body, "revoked") {
		t.Fatalf("revoked native grant introspected: %d %s", code, body)
	}
	if code, body := do(t, h, "POST", "/v2/introspection", introspectBody("intro-1", g, lease, "read:orders", exp, 0)); code != http.StatusCreated || responseRecord(t, body) != first {
		t.Fatalf("exact committed receipt not returned after revocation: %d %s", code, body)
	}
}

func TestTemporalIntrospectionRefusesExpiredGrantButReturnsCommittedReceipt(t *testing.T) {
	now := time.Now()
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	raw, _ := hex.DecodeString(resourceSeed)
	clock := now
	srv := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").
		WithIntrospection(ed25519.NewKeyFromSeed(raw)).WithClock(func() time.Time { return clock })
	h := srv.Routes()
	g, exp := nativeGrant(t, h, "n-exp", 60)
	code, body := do(t, h, "POST", "/v2/introspection", introspectBody("intro-e", g, "lease-n-exp", "read:orders", exp, 0))
	if code != http.StatusCreated {
		t.Fatalf("introspection (%d): %s", code, body)
	}
	first := responseRecord(t, body)
	clock = now.Add(2 * time.Minute)
	if code, body := do(t, h, "POST", "/v2/introspection", introspectBody("intro-late", g, "lease-n-exp", "read:orders", exp, 0)); code != http.StatusBadRequest {
		t.Fatalf("expired native grant introspected: %d %s", code, body)
	}
	if code, body := do(t, h, "POST", "/v2/introspection", introspectBody("intro-e", g, "lease-n-exp", "read:orders", exp, 0)); code != http.StatusCreated || responseRecord(t, body) != first {
		t.Fatalf("exact committed receipt not returned after expiry: %d %s", code, body)
	}
}

// TestTemporalProducerToVerifierHistoricalClaim exports a real two-phase use, then a prospective
// revocation, and verifies the bundle through the Rust core: current revocation still blocks `ok`,
// the counter and the capstone, while the separate historical claim is satisfied under the caller's
// db_serialized_v1 policy and never under strict.
func TestTemporalProducerToVerifierHistoricalClaim(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa := testTSAKey()
	rev := revocationKey()
	taxKey := taxonomyKey()
	ak := grantAgentKey()
	h := api.New(c, store.NewMem(), "k0").
		WithBroker(brokerIssuingKey()).
		WithResource(rc, "orders-db").
		WithRevocation(rev).
		WithRevocationExportV2().
		Routes()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	code, resp := do(t, h, "POST", "/v2/use-intent", useBody(t, "idem-intent", cap, grantID, ak, "SELECT 1", "nonce-1"))
	if code != http.StatusCreated {
		t.Fatalf("use-intent (%d): %s", code, resp)
	}
	var intent struct {
		UseID string `json:"use_id"`
	}
	json.Unmarshal([]byte(resp), &intent)
	if r := mustRevoke(t, h, grantID, "prospective"); r.CutoffOrder != 2 {
		t.Fatalf("cutoff %+v", r)
	}
	// The outcome completes an intent admitted before the cancellation: it is still recorded
	// after the revoke and inherits the intent's pre-cutoff ordinal.
	ob, _ := json.Marshal(map[string]any{"idempotency_key": "idem-outcome", "project_id": "p1", "session_id": "s1", "intent_record_id": intent.UseID, "status": "ok"})
	code, resp = do(t, h, "POST", "/v2/use-outcome", string(ob))
	if code != http.StatusCreated {
		t.Fatalf("use-outcome after revoke (%d): %s", code, resp)
	}
	if o, _, ok := receiptOrder(t, responseRecord(t, resp)); !ok || o != 1 {
		t.Fatalf("outcome after revoke carries ordinal %d (present %v), want the intent's 1", o, ok)
	}
	if code, r := do(t, h, "POST", "/v2/checkpoints?project=p1", ""); code != http.StatusCreated {
		t.Fatalf("checkpoint: %d %s", code, r)
	}
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	anchored := attachTestAnchor(t, exp, tsa)
	taxJSON, digest, ver, err := taxonomy.Sign(c, taxKey, 1, 0, 9_999_999_999,
		[]taxonomy.Entry{{ResourceID: "orders-db", Action: "db.query:orders-ro"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	evalTime := time.Now().UTC().Add(time.Second).Format("2006-01-02T15:04:05.000Z")
	optsFor := func(temporal string) string {
		return fmt.Sprintf(`{"signing_keys":[%q],"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q],"revocation_keys":[%q],"taxonomy":%s,"taxonomy_keys":[%q],"taxonomy_digest":%q,"taxonomy_version":%d,"claim_policy":{"requested":"historical_authorized_as_of_snapshot"}%s}`,
			c.PubKey(), c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa), attestPubEncoded(rev), taxJSON, attestPubEncoded(taxKey), digest, ver, temporal)
	}
	opts := optsFor(fmt.Sprintf(`,"revocation_temporal":{"policy":"db_serialized_v1","evaluation_time":%q,"max_snapshot_age_seconds":3600}`, evalTime))
	rep := c.VerifyBundleWith(anchored, opts)
	for _, want := range []string{
		`"ok":false`,
		`"revoked_uses_blocked":1`,
		`"revocation_status":"revoked_present"`,
		`"complete_brokered":"refuted"`,
		`"authorized":"refuted"`,
		`"historical_authorized_as_of_snapshot":"satisfied"`,
		`"requested_decision":"satisfied"`,
		`"current_revocation":"revoked_prospective"`,
		`"cutoff_order":2`,
		`"historical_ordering":"proven_before"`,
		`"status":"verified"`,
		`"authorization_high_watermark":2`,
	} {
		if !strings.Contains(rep, want) {
			t.Fatalf("historical verdict missing %s\nreport: %s", want, rep)
		}
	}
	strict := c.VerifyBundleWith(anchored, optsFor(""))
	if !strings.Contains(strict, `"historical_authorized_as_of_snapshot":"insufficient"`) || !strings.Contains(strict, `"revoked_uses_blocked":1`) {
		t.Fatalf("strict policy decided history or changed legacy blocking: %s", strict)
	}
	if path := os.Getenv("AVERIN_WRITE_V3_HISTORICAL_FIXTURE"); path != "" {
		fixture, _ := json.Marshal(map[string]any{"bundle": json.RawMessage(anchored), "opts": json.RawMessage(opts)})
		if err := os.WriteFile(path, fixture, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTemporalMerkleV2ProducerToVerifier builds a v2 Merkle root and proofs with the Go producer over
// the exported snapshot and verifies them through the Rust core: a membership proof authenticates the
// prospective cutoff (the use is blocked now, proven before historically); a tampered cutoff cannot.
func TestTemporalMerkleV2ProducerToVerifier(t *testing.T) {
	c, _ := core.New(seed)
	rc, _ := core.New(resourceSeed)
	tsa, rev, taxKey, ak := testTSAKey(), revocationKey(), taxonomyKey(), grantAgentKey()
	h := api.New(c, store.NewMem(), "k0").WithBroker(brokerIssuingKey()).WithResource(rc, "orders-db").
		WithRevocation(rev).WithRevocationExportV2().Routes()
	grantID, cap := mkGrant(t, h, ak, "idem-grant")
	if code, body := do(t, h, "POST", "/v2/use", useBody(t, "idem-use", cap, grantID, ak, "SELECT 1", "nonce-1")); code != http.StatusCreated {
		t.Fatalf("use: %d %s", code, body)
	}
	cutoff := mustRevoke(t, h, grantID, "prospective").CutoffOrder
	do(t, h, "POST", "/v2/checkpoints?project=p1", "")
	_, exp := do(t, h, "GET", "/v2/export?project=p1", "")
	var bundle map[string]json.RawMessage
	json.Unmarshal([]byte(exp), &bundle)
	var list struct {
		IssuedAt string `json:"issued_at"`
		NotAfter string `json:"not_after"`
		Snapshot struct {
			BoundaryTime string `json:"boundary_time"`
			Watermark    int64  `json:"authorization_high_watermark"`
		} `json:"snapshot"`
	}
	json.Unmarshal(bundle["revocation_list"], &list)
	boundary, err := time.Parse("2006-01-02T15:04:05.000Z", list.Snapshot.BoundaryTime)
	if err != nil {
		t.Fatal(err)
	}
	taxJSON, digest, ver, err := taxonomy.Sign(c, taxKey, 1, 0, 9_999_999_999, []taxonomy.Entry{{ResourceID: "orders-db", Action: "db.query:orders-ro"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := fmt.Sprintf(`{"signing_keys":[%q],"broker_authority_keys":[%q],"resource_authority_keys":[%q],"tsa_keys":[%q],"revocation_keys":[%q],"taxonomy":%s,"taxonomy_keys":[%q],"taxonomy_digest":%q,"taxonomy_version":%d,"claim_policy":{"requested":"historical_authorized_as_of_snapshot","revocation":"merkle"},"revocation_temporal":{"policy":"db_serialized_v1","evaluation_time":%q,"max_snapshot_age_seconds":3600}}`,
		c.PubKey(), c.PubKey(), rc.PubKey(), tsaPubEncoded(tsa), attestPubEncoded(rev), taxJSON, attestPubEncoded(taxKey), digest, ver,
		time.Now().UTC().Add(time.Second).Format("2006-01-02T15:04:05.000Z"))
	verifyWith := func(entries []broker.RevocationStateEntry, mutate func(map[string]any)) string {
		t.Helper()
		tree, err := broker.BuildRevocationTreeV2(entries)
		if err != nil {
			t.Fatal(err)
		}
		root, err := api.BuildRevocationMerkleRootV2(c, rev, list.IssuedAt, list.NotAfter,
			api.RevocationSnapshot{ProjectID: "p1", BoundaryTime: boundary, Watermark: list.Snapshot.Watermark}, tree)
		if err != nil {
			t.Fatal(err)
		}
		proof := tree.Proof(grantID)
		if mutate != nil {
			mutate(proof)
		}
		b := map[string]json.RawMessage{}
		for k, v := range bundle {
			if k != "revocation_list" {
				b[k] = v
			}
		}
		b["revocation_merkle_root"], _ = json.Marshal(root)
		b["revocation_proofs"], _ = json.Marshal(map[string]any{grantID: proof})
		out, _ := json.Marshal(b)
		return c.VerifyBundleWith(attachTestAnchor(t, string(out), tsa), opts)
	}
	member := []broker.RevocationStateEntry{{GrantID: grantID, Mode: "prospective", CutoffOrder: cutoff}, {GrantID: "other", Mode: "total"}}
	rep := verifyWith(member, nil)
	for _, want := range []string{`"revoked_uses_blocked":1`, `"revocation_merkle_status":"fresh"`, `"current_revocation":"revoked_prospective"`,
		`"historical_ordering":"proven_before"`, `"historical_authorized_as_of_snapshot":"satisfied"`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("Go v2 Merkle membership missing %s\n%s", want, rep)
		}
	}
	rep = verifyWith(member, func(p map[string]any) { p["cutoff_order"] = cutoff + 5 })
	if strings.Contains(rep, `"historical_ordering":"proven_before"`) || strings.Contains(rep, `"historical_authorized_as_of_snapshot":"satisfied"`) {
		t.Fatalf("a tampered cutoff still proved history:\n%s", rep)
	}
	rep = verifyWith([]broker.RevocationStateEntry{{GrantID: "other", Mode: "total"}}, nil)
	for _, want := range []string{`"ok":true`, `"revocation_nonmembership_verified":1`, `"current_revocation":"not_revoked"`, `"historical_authorized_as_of_snapshot":"satisfied"`} {
		if !strings.Contains(rep, want) {
			t.Fatalf("Go v2 Merkle non-membership missing %s\n%s", want, rep)
		}
	}
}
