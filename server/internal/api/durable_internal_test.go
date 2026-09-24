package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/pgdurable"
	"github.com/feirai/averin/server/internal/pgschema"
	"github.com/feirai/averin/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestDurable connects to AVERIN_TEST_DATABASE_URL (skipping if unset, matching the store package's
// Postgres test gate) and returns a pgdurable.Store scoped to a private, freshly-created schema, plus the
// bare dsn (with the schema pinned via search_path) so the caller can open ADDITIONAL pgdurable.Store
// instances against the SAME durable state — simulating a fresh process re-connecting to Postgres after a
// restart, as opposed to reusing one Go object across the simulated restart.
func newTestDurable(t *testing.T) (pd *pgdurable.Store, dsn string, cleanup func()) {
	t.Helper()
	base := os.Getenv("AVERIN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set AVERIN_TEST_DATABASE_URL to run Postgres-backed pgdurable tests")
	}
	schema := fmt.Sprintf("averin_pgdurable_test_%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect (admin): %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}

	scopedDSN := base + "&search_path=" + schema
	// pgdurable.New no longer applies DDL — run the versioned migration runner exactly as main() does on
	// boot, creating the durable tables (and the rest of the averin schema) in this private schema.
	if err := pgschema.Migrate(ctx, scopedDSN); err != nil {
		admin.Close()
		t.Fatalf("pgschema.Migrate: %v", err)
	}
	pd, err = pgdurable.New(ctx, scopedDSN)
	if err != nil {
		admin.Close()
		t.Fatalf("pgdurable.New: %v", err)
	}
	return pd, scopedDSN, func() {
		pd.Close()
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		if _, err := admin.Exec(dctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Logf("cleanup: drop schema %s: %v", schema, err)
		}
		admin.Close()
	}
}

// reconnectDurable opens a NEW pgdurable.Store against the same durable state (same dsn, so same schema),
// mirroring what averin-server's main() does on every process boot — a fresh pgdurable.New call, never a
// reused Go object. Used to make the "restart" in the tests below a genuine cross-process simulation rather
// than reusing one in-memory Store struct.
func reconnectDurable(t *testing.T, dsn string) *pgdurable.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pd, err := pgdurable.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgdurable.New (reconnect): %v", err)
	}
	t.Cleanup(pd.Close)
	return pd
}

func connectProjectStore(t *testing.T, dsn string) *store.Postgres {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

func testCore(t *testing.T) *core.Core {
	t.Helper()
	c, err := core.New("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDurableRevocationSurvivesRestart (M5 fail-open fix): a revoke persisted through a durable Store must
// be visible to a BRAND NEW Server instance (in-memory revoked set starts empty, as it would after a pod
// restart) once WithDurable rehydrates from Postgres — closing the gap where a revoke issued just before a
// restart was silently forgotten.
func TestDurableRevocationSurvivesRestart(t *testing.T) {
	_, dsn, cleanup := newTestDurable(t)
	defer cleanup()

	_, rev, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// "Boot 1": revoke through the same project Store that will be reopened.
	st1 := connectProjectStore(t, dsn)
	s1 := New(testCore(t), st1, "k0").WithRevocation(rev)
	body, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": "g-revoked-1", "reason": "compromised"})
	req := httptest.NewRequest("POST", "/v2/revoke?project=p1", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s1.handleRevoke(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("revoke (%d): %s", w.Code, w.Body.String())
	}
	if yes, err := st1.IsRevoked("p1", "g-revoked-1"); err != nil || !yes {
		t.Fatalf("revoke not visible in Store: %v, %v", yes, err)
	}

	// "Restart": a fresh Server, a fresh pgdurable.Store reconnecting to the SAME durable state.
	st1.Close()
	st2 := connectProjectStore(t, dsn)
	s2 := New(testCore(t), st2, "k0").WithRevocation(rev)
	if yes, err := st2.IsRevoked("p1", "g-revoked-1"); err != nil || !yes {
		t.Fatalf("revocation did not survive restart: %v, %v", yes, err)
	}

	// A revoke made BEFORE WithDurable rehydrates on this instance is unaffected by a later re-revoke.
	body2, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": "g-revoked-1"})
	req2 := httptest.NewRequest("POST", "/v2/revoke?project=p1", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	s2.handleRevoke(w2, req2)
	if w2.Code != http.StatusCreated {
		t.Fatalf("idempotent re-revoke on the rehydrated set (%d): %s", w2.Code, w2.Body.String())
	}
}

// TestDurableRevocationFailsClosedWhenPostgresUnavailable: if the durable write fails, the revoke must be
// rejected (503) and the in-memory set must NOT be mutated — a revoke that only "took" in memory would
// silently vanish on the very next restart while an operator believes it is enforced.
func TestDurableRevocationFailsClosedWhenPostgresUnavailable(t *testing.T) {
	_, dsn, cleanup := newTestDurable(t)
	defer cleanup()
	_, rev, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st := connectProjectStore(t, dsn)
	s := New(testCore(t), st, "k0").WithRevocation(rev)
	st.Close() // the authoritative Store is unavailable

	body, _ := json.Marshal(map[string]any{"project_id": "p1", "grant_id": "g-should-not-take", "reason": "test"})
	req := httptest.NewRequest("POST", "/v2/revoke?project=p1", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRevoke(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a revoke whose durable write fails must be rejected 503 (fail-closed), got %d: %s", w.Code, w.Body.String())
	}
	st2 := connectProjectStore(t, dsn)
	if yes, err := st2.IsRevoked("p1", "g-should-not-take"); err != nil || yes {
		t.Fatalf("failed revoke leaked into durable state: %v, %v", yes, err)
	}
}

// grantChallengeBody builds a POST /v2/grants/prepare (or single-phase /v2/grants) JSON body with a valid
// proof-of-possession signature, mirroring server_grant_test.go's grantBody (unavailable here — that helper
// lives in the external api_test package).
func grantChallengeBody(idem, scope string, ak ed25519.PrivateKey) string {
	pub := base64.RawURLEncoding.EncodeToString(ak.Public().(ed25519.PublicKey))
	req := broker.Request{AgentID: "agent-1", Action: "db.query:orders-ro", Resource: "orders-db", Scope: scope, AgentPubKey: pub}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ak, req.Challenge()))
	body, _ := json.Marshal(map[string]any{
		"idempotency_key": idem, "project_id": "p1", "session_id": "s1",
		"agent_id": "agent-1", "action": "db.query:orders-ro", "resource": "orders-db",
		"scope": scope, "agent_pubkey": pub, "agent_sig": sig, "ttl_seconds": 3600,
	})
	return string(body)
}

// TestDurablePendingTwoPhaseGrantSurvivesRestart (M6/M2 fail-open fix): a cosig-policy prepare mints and
// persists a pending grant; a BRAND NEW Server instance (as after a pod restart) rehydrates it from Postgres
// and can finalize it. This is also the regression test for the JSON round-trip footgun: encoding/json
// decodes every number in a map[string]any (broker.Prepared.Evidence) as float64, and
// broker.AttachCosignatures hard-requires Evidence["exp"] to be int64 — without the repair in
// pendingGrantDTO.toPendingGrant, this finalize would fail with "prepared grant_evidence has no int64 exp"
// instead of committing.
func TestDurablePendingTwoPhaseGrantSurvivesRestart(t *testing.T) {
	pd, dsn, cleanup := newTestDurable(t)
	defer cleanup()

	brokerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	a1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{40}, ed25519.SeedSize))
	a2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
	approvers := []ed25519.PublicKey{a1.Public().(ed25519.PublicKey), a2.Public().(ed25519.PublicKey)}

	newServer := func(st store.Store) *Server {
		return New(testCore(t), st, "k0").WithBroker(brokerKey).WithCosigPolicy(2, approvers)
	}
	st1 := connectProjectStore(t, dsn)

	// "Boot 1": prepare (mints + persists the pending grant, no cosig attached yet).
	s1 := newServer(st1)
	preq := httptest.NewRequest("POST", "/v2/grants/prepare", bytes.NewReader([]byte(grantChallengeBody("idem-restart-1", "read:orders", agentKey))))
	pw := httptest.NewRecorder()
	s1.handleGrantPrepare(pw, preq)
	if pw.Code != http.StatusOK {
		t.Fatalf("prepare (%d): %s", pw.Code, pw.Body.String())
	}
	var pr struct {
		GrantID           string `json:"grant_id"`
		CredentialBinding string `json:"credential_binding"`
		Exp               int64  `json:"exp"`
		CosigThreshold    int    `json:"cosig_threshold"`
	}
	if err := json.Unmarshal(pw.Body.Bytes(), &pr); err != nil {
		t.Fatalf("decode prepare: %v\n%s", err, pw.Body.String())
	}
	if pr.GrantID == "" || pr.CredentialBinding == "" || pr.CosigThreshold != 2 {
		t.Fatalf("prepare response incomplete: %s", pw.Body.String())
	}
	if _, ok, err := st1.PendingGrant("p1", "idem-restart-1"); err != nil || !ok {
		t.Fatalf("prepare did not persist pending grant: %v, %v", ok, err)
	}

	// The approvers sign the REVEALED challenge (off-server, as in production).
	mkCosig := func(ap ed25519.PrivateKey) broker.Cosignature {
		kid := broker.KeyID(ap.Public().(ed25519.PublicKey))
		sig := ed25519.Sign(ap, broker.CosigApprovalChallenge(pr.GrantID, kid, pr.CredentialBinding, 2, pr.Exp))
		return broker.Cosignature{ApproverKid: kid, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	}
	// finalize carries the SAME PoP-signed grant request as prepare, plus the collected cosignatures.
	var finMap map[string]any
	if err := json.Unmarshal([]byte(grantChallengeBody("idem-restart-1", "read:orders", agentKey)), &finMap); err != nil {
		t.Fatalf("decode grant body: %v", err)
	}
	finMap["cosignatures"] = []broker.Cosignature{mkCosig(a1), mkCosig(a2)}
	finBody, _ := json.Marshal(finMap)

	// "Restart": a fresh Server (fresh in-memory pending map AND a fresh main store — this test targets only
	// pgdurable, not the main store's independent Postgres durability), a fresh pgdurable.Store reconnecting
	// to the SAME durable state.
	st1.Close()
	st2 := connectProjectStore(t, dsn)
	s2 := newServer(st2)
	if _, ok, err := st2.PendingGrant("p1", "idem-restart-1"); err != nil || !ok {
		t.Fatalf("pending grant did not survive restart: %v, %v", ok, err)
	}

	// PHASE 2, on the POST-RESTART server: finalize -> bind cosignatures + commit. This is the load-bearing
	// assertion: it only succeeds if the rehydrated Evidence["exp"] is int64 (AttachCosignatures requires it).
	freq := httptest.NewRequest("POST", "/v2/grants/finalize", bytes.NewReader(finBody))
	fw := httptest.NewRecorder()
	s2.handleGrantFinalize(fw, freq)
	if fw.Code != http.StatusCreated {
		t.Fatalf("finalize after restart (%d): %s", fw.Code, fw.Body.String())
	}
	if !bytes.Contains(fw.Body.Bytes(), []byte(`"cosig_threshold":2`)) {
		t.Fatalf("finalized record missing cosig evidence: %s", fw.Body.String())
	}

	// The durable pending row is cleaned up once finalized.
	rows, err := pd.LoadPending(context.Background())
	if err != nil {
		t.Fatalf("LoadPending: %v", err)
	}
	for _, row := range rows {
		if row.ProjectID == "p1" && row.IdemKey == "idem-restart-1" {
			t.Fatalf("finalized pending grant's durable row was not cleaned up")
		}
	}
}

// TestDurablePendingGrantFailsClosedWhenPostgresUnavailable: mirrors the revocation fail-closed test — a
// prepare whose durable write fails must not hand out a live challenge the process cannot survive a restart
// to finalize.
func TestDurablePendingGrantFailsClosedWhenPostgresUnavailable(t *testing.T) {
	_, dsn, cleanup := newTestDurable(t)
	defer cleanup()
	brokerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	st := connectProjectStore(t, dsn)
	s := New(testCore(t), st, "k0").WithBroker(brokerKey)
	st.Close() // authoritative Store unavailable

	preq := httptest.NewRequest("POST", "/v2/grants/prepare", bytes.NewReader([]byte(grantChallengeBody("idem-unavailable-1", "read:orders", agentKey))))
	pw := httptest.NewRecorder()
	s.handleGrantPrepare(pw, preq)
	if pw.Code != http.StatusServiceUnavailable {
		t.Fatalf("a prepare whose durable write fails must be rejected 503 (fail-closed), got %d: %s", pw.Code, pw.Body.String())
	}
	st2 := connectProjectStore(t, dsn)
	if _, ok, err := st2.PendingGrant("p1", "idem-unavailable-1"); err != nil || ok {
		t.Fatalf("failed prepare leaked into durable state: %v, %v", ok, err)
	}
}
