// Command feir-server runs the ingestion + app API. Self-host: the signing seed is provided via
// FEIR_SIGNING_SEED (64 hex chars). Production backs signing with a KMS instead.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/auth"
	"github.com/feir-dev/feir/server/internal/content"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/meter"
	"github.com/feir-dev/feir/server/internal/pgledger"
	"github.com/feir-dev/feir/server/internal/store"
	"github.com/feir-dev/feir/server/internal/witness"
	"github.com/feir-dev/feir/server/migrations"
)

func main() {
	seed := os.Getenv("FEIR_SIGNING_SEED")
	if seed == "" {
		log.Fatal("FEIR_SIGNING_SEED is required (64 hex chars = 32-byte Ed25519 seed)")
	}
	c, err := core.New(seed)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	keyID := envOr("FEIR_SIGNING_KEY_ID", "k0")
	addr := envOr("FEIR_ADDR", ":8080")

	// Storage: Postgres when FEIR_DATABASE_URL is set (production / persistent self-host), else the
	// in-memory store (dev / single-process, NOT durable). Postgres is append-only (see migrations).
	st := selectStore()

	srv := api.New(c, st, keyID)
	// usage metering -> Stripe (the real revenue path). No key = local counting only. Retained so
	// graceful shutdown can drain its async queue (billable events) before exit.
	meterReporter := meter.NewStripeReporter(meter.NewMem(), meter.StripeConfig{
		APIKey: os.Getenv("STRIPE_API_KEY"),
	})
	srv.WithMeter(meterReporter)

	// project-scoped API keys: FEIR_API_KEYS="proj-a:tok1,tok2;proj-b:tok3". Unset = no auth (dev).
	if raw := os.Getenv("FEIR_API_KEYS"); raw != "" {
		ks, n := auth.ParseKeys(raw)
		if n == 0 {
			log.Fatal("FEIR_API_KEYS is set but parsed to zero keys — refusing to start in silent deny-all (use 'proj:tok' form)")
		}
		srv.WithAuth(ks)
		log.Printf("per-project API-key auth enabled (%d projects)", n)
	} else {
		log.Printf("WARNING: no FEIR_API_KEYS set — the app API is UNAUTHENTICATED (dev/single-tenant only)")
	}
	// T7: pin EXTERNAL authority verifying keys so a generic record carrying a policy_engine_signed
	// OR human_signed authority block, with an evidence_sig that verifies under the key pinned FOR
	// THAT source, is elevated to that source at ingest (else forced to the forgeable
	// caller_declared). Three env forms, all composable (each pins at most one key per source):
	//
	//   FEIR_POLICY_ENGINE_PUBKEY   — back-compat: one key for FEIR_POLICY_ENGINE_SOURCE
	//                                 (default source policy_engine_signed).
	//   FEIR_HUMAN_SIGNED_PUBKEY    — one key for the human_signed source (govder's kill/approval
	//                                 records are human_signed, signed by a DIFFERENT key than the
	//                                 policy engine — this is what lets them elevate, not normalize
	//                                 down to caller_declared on verify/export).
	//   FEIR_AUTHORITY_KEYS         — a general "source=pubkey,source=pubkey" list (the two sources
	//                                 are policy_engine_signed and human_signed).
	//
	// Each pubkey is the 32-byte ed25519 public key, hex- OR base64url-encoded (the
	// "ed25519pub:<base64url>" published form is accepted with the prefix stripped). Each external
	// authority holds the PRIVATE half out of this server. None set = Phase-1 default (every generic
	// authority is caller_declared). Pinning the SAME source twice across these forms is a fatal
	// config error (WithPolicyEngineKey rejects a duplicate source).
	if raw := os.Getenv("FEIR_POLICY_ENGINE_PUBKEY"); raw != "" {
		pub, err := decodeAuthorityPubKey(raw)
		if err != nil {
			log.Fatalf("FEIR_POLICY_ENGINE_PUBKEY: %v", err)
		}
		source := envOr("FEIR_POLICY_ENGINE_SOURCE", "policy_engine_signed")
		srv.WithPolicyEngineKey(source, pub)
		log.Printf("T7 authority key pinned (source=%s): a verifying authority evidence_sig elevates to %s", source, source)
	}
	if raw := os.Getenv("FEIR_HUMAN_SIGNED_PUBKEY"); raw != "" {
		pub, err := decodeAuthorityPubKey(raw)
		if err != nil {
			log.Fatalf("FEIR_HUMAN_SIGNED_PUBKEY: %v", err)
		}
		srv.WithPolicyEngineKey("human_signed", pub)
		log.Printf("T7 authority key pinned (source=human_signed): a verifying authority evidence_sig elevates to human_signed")
	}
	if raw := os.Getenv("FEIR_AUTHORITY_KEYS"); raw != "" {
		for source, pub := range parseAuthorityKeys(raw) {
			srv.WithPolicyEngineKey(source, pub)
			log.Printf("T7 authority key pinned (source=%s, via FEIR_AUTHORITY_KEYS): a verifying authority evidence_sig elevates to %s", source, source)
		}
	}
	// durable content store for committed low-entropy values (raw input/output/rationale). No dir =
	// in-memory (NOT durable; disclosures won't survive a restart).
	if dir := os.Getenv("FEIR_CONTENT_DIR"); dir != "" {
		cs, err := content.NewFSStore(dir)
		if err != nil {
			log.Fatalf("content store: %v", err)
		}
		srv.WithContent(cs)
		log.Printf("content store -> %s", dir)
	} else {
		log.Printf("WARNING: no FEIR_CONTENT_DIR set — committed raw values are in-memory (not durable)")
	}
	// customer witness for sealed checkpoints (append-only).
	if dir := os.Getenv("FEIR_WITNESS_DIR"); dir != "" {
		w, err := witness.NewFSWitness(dir)
		if err != nil {
			log.Fatalf("witness: %v", err)
		}
		srv.WithWitness(w)
		log.Printf("checkpoint witness -> %s", dir)
	}
	// third-party RFC 3161 timestamp anchoring for sealed checkpoints (threat #3 backdating). The
	// verifier must pin this TSA's cert out-of-band to trust the anchor.
	if url := os.Getenv("FEIR_TSA_URL"); url != "" {
		srv.WithTSA(&witness.HTTPTSA{URL: url})
		log.Printf("checkpoint anchoring -> RFC 3161 TSA %s", url)
	}
	// credential broker (Level 3 Tier-A): POST /v2/grants. The issuing key signs the capabilities;
	// the recording key (the server signing key) signs the gateway_enforced evidence. Unset = off.
	brokerEnabled := false
	var brokerPubKey string // ed25519pub:<b64url>, for the R2 broker∩resource disjointness check below
	if seed := os.Getenv("FEIR_BROKER_ISSUING_SEED"); seed != "" {
		raw, err := hex.DecodeString(seed)
		if err != nil || len(raw) != ed25519.SeedSize {
			log.Fatal("FEIR_BROKER_ISSUING_SEED must be 64 hex chars (32-byte Ed25519 seed)")
		}
		bk := ed25519.NewKeyFromSeed(raw)
		srv.WithBroker(bk)
		brokerEnabled = true
		brokerPubKey = "ed25519pub:" + base64.RawURLEncoding.EncodeToString(bk.Public().(ed25519.PublicKey))
		log.Printf("credential broker enabled (POST /v2/grants)")
		// M4 (ADR 0005): optional federation identity. When set, grants carry grant_evidence.broker_id and
		// checkpoints carry a per-broker_id broker_grant_heads map (verify with federated_broker_keys[<id>]).
		if bid := os.Getenv("FEIR_BROKER_ID"); bid != "" {
			srv.WithBrokerID(bid)
			log.Printf("federation enabled: grants tagged broker_id=%q (per-broker broker_grant_heads in checkpoints)", bid)
		}
	}
	// M6 (ADR 0005): the ONLINE two-phase cosig policy (POST /v2/grants/prepare + /v2/grants/finalize). The
	// M-of-N approver keys are role-separated GOVERNANCE keys — the offline verifier re-pins them as
	// cosig_approver_keys (a FATAL config error on overlap with any other role). Requires the broker.
	// FEIR_COSIG_APPROVER_KEYS = comma-separated ed25519 pubkeys (base64url-no-pad, optional ed25519pub:
	// prefix); FEIR_COSIG_THRESHOLD = M (default = number of approvers).
	if raw := os.Getenv("FEIR_COSIG_APPROVER_KEYS"); raw != "" {
		if !brokerEnabled {
			log.Fatal("FEIR_COSIG_APPROVER_KEYS requires FEIR_BROKER_ISSUING_SEED (cosig is a broker grant-approval policy)")
		}
		approvers := parseCosigApprovers(raw)
		if len(approvers) == 0 {
			log.Fatal("FEIR_COSIG_APPROVER_KEYS is set but parsed to zero keys")
		}
		threshold := len(approvers)
		if t := os.Getenv("FEIR_COSIG_THRESHOLD"); t != "" {
			n, err := strconv.Atoi(t)
			if err != nil || n < 1 || n > len(approvers) {
				log.Fatalf("FEIR_COSIG_THRESHOLD must be an integer in [1, %d]", len(approvers))
			}
			threshold = n
		}
		srv.WithCosigPolicy(threshold, approvers)
		log.Printf("online cosig policy enabled: %d-of-%d (POST /v2/grants/prepare + finalize)", threshold, len(approvers))
	}
	// resource gateway (Level 3 Tier-B): POST /v2/use. The resource recording key signs use-receipt
	// evidence and MUST be DISTINCT from the server signing key and the broker key (R2 role separation;
	// the verifier rejects a broker/resource key overlap). Requires the broker (capabilities are
	// verified under the broker issuing key). Unset = off.
	if rseed := os.Getenv("FEIR_RESOURCE_SEED"); rseed != "" {
		if !brokerEnabled {
			log.Fatal("FEIR_RESOURCE_SEED requires FEIR_BROKER_ISSUING_SEED (the resource verifies capabilities under the broker issuing key)")
		}
		rid := os.Getenv("FEIR_RESOURCE_ID")
		if rid == "" {
			log.Fatal("FEIR_RESOURCE_ID is required when FEIR_RESOURCE_SEED is set")
		}
		rc, err := core.New(rseed)
		if err != nil {
			log.Fatalf("FEIR_RESOURCE_SEED: %v", err)
		}
		if rc.PubKey() == c.PubKey() {
			log.Fatal("FEIR_RESOURCE_SEED must differ from FEIR_SIGNING_SEED (R2: broker and resource recording keys must be disjoint)")
		}
		// Compare DERIVED pubkeys, not raw seed hex. The broker seed is decoded by Go's case-insensitive
		// hex.DecodeString while the resource seed goes through the core's lowercase-only decoder, so an
		// UPPERCASE broker seed + a lowercase resource seed for the SAME key are byte-distinct strings that
		// a raw compare misses — silently violating R2 (broker == resource key), which the offline verifier
		// would then reject as a fatal config error. Comparing pubkeys catches it fast at startup.
		if rc.PubKey() == brokerPubKey {
			log.Fatal("FEIR_RESOURCE_SEED must differ from FEIR_BROKER_ISSUING_SEED (keep the capability-issuing and use-recording key roles distinct)")
		}
		// Durable consume-before-act ledger when Postgres is configured; else the volatile MemLedger.
		// WithLedger must precede WithResource (which installs the MemLedger default only if none is set).
		if dsn := os.Getenv("FEIR_DATABASE_URL"); dsn != "" {
			lctx, lcancel := context.WithTimeout(context.Background(), 30*time.Second)
			pl, err := pgledger.New(lctx, dsn)
			lcancel()
			if err != nil {
				log.Fatalf("resource ledger: Postgres requested but unavailable: %v", err)
			}
			srv.WithLedger(pl)
			log.Printf("consume-before-act ledger -> Postgres (durable)")
		} else {
			log.Printf("WARNING: the consume-before-act ledger is in-memory (volatile) — consumed single-use jti/nonce reset on restart, reopening a replay window for /v2/use. Set FEIR_DATABASE_URL for the durable Postgres-backed ledger.")
		}
		srv.WithResource(rc, rid)
		log.Printf("resource gateway enabled (POST /v2/use) for resource %q", rid)
		// M3 (ADR 0005 — Native/STS): enable POST /v2/introspection with the RAW resource key (the same key,
		// derived from FEIR_RESOURCE_SEED) so the resource can sign the structured introspection challenge.
		if rawSeed, e := hex.DecodeString(rseed); e == nil && len(rawSeed) == ed25519.SeedSize {
			srv.WithIntrospection(ed25519.NewKeyFromSeed(rawSeed))
			log.Printf("native introspection enabled (POST /v2/introspection)")
		} else {
			log.Printf("WARNING: could not derive the raw resource key — POST /v2/introspection disabled")
		}
	}

	// M5 (ADR 0005): optional revocation authority. POST /v2/revoke marks a grant_id revoked; every /v2/export
	// then carries a signed, time-bounded revocation_list (the verifier blocks any use of a revoked grant). The
	// key MUST be role-separated from the broker/resource/signing/attestation keys (the verifier enforces it).
	if rvseed := os.Getenv("FEIR_REVOCATION_SEED"); rvseed != "" {
		raw, err := hex.DecodeString(rvseed)
		if err != nil || len(raw) != ed25519.SeedSize {
			log.Fatal("FEIR_REVOCATION_SEED must be 64 hex chars (32-byte Ed25519 seed)")
		}
		if rvseed == seed || rvseed == os.Getenv("FEIR_BROKER_ISSUING_SEED") || rvseed == os.Getenv("FEIR_RESOURCE_SEED") {
			log.Fatal("FEIR_REVOCATION_SEED must differ from the signing/broker/resource seeds (R2 role separation)")
		}
		srv.WithRevocation(ed25519.NewKeyFromSeed(raw))
		log.Printf("revocation enabled (POST /v2/revoke; exports carry a signed revocation_list)")
	}

	log.Printf("feir-server listening on %s (pubkey %s)", addr, c.PubKey())
	// Explicit timeouts (http.ListenAndServe leaves them at 0 = unbounded → Slowloris / slow-body / idle
	// keep-alive connection exhaustion). The server reads bounded bodies (8 MiB) and does not stream long
	// responses, so finite read/write timeouts are safe.
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// Graceful shutdown: serve in a goroutine, then on SIGINT/SIGTERM drain in-flight requests
	// before exiting. feir holds in-memory two-phase grant + revocation state (Phase 1), so a clean
	// drain on a rollout / scale-down avoids dropping in-flight ingest and the request currently
	// executing a finalize (the cross-request prepare->finalize window is still lost on any stop —
	// full persistence is feir Phase 2). After the HTTP drain we flush the async Stripe meter queue
	// and close the store pool, all within the same deadline.
	//
	// DEADLINE: keep it UNDER the orchestrator's stop grace or it gets SIGKILLed mid-drain. Default
	// 25s, override with FEIR_SHUTDOWN_TIMEOUT. The Kubernetes manifest sets terminationGracePeriod=30s
	// (no preStop, so the full grace covers the drain); for docker-compose set stop_grace_period >= this.
	drainTimeout := 25 * time.Second
	if v := os.Getenv("FEIR_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			drainTimeout = d
		} else {
			log.Printf("feir-server: ignoring invalid FEIR_SHUTDOWN_TIMEOUT %q (using %s)", v, drainTimeout)
		}
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.ListenAndServe() }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	case sig := <-stop:
		log.Printf("feir-server: received %s — draining (timeout %s)", sig, drainTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("feir-server: HTTP graceful shutdown timed out (some in-flight work was cut): %v", err)
		}
		// Handlers have drained (no more send()) → flush the Stripe meter queue, then release the
		// store pool, within whatever deadline remains.
		meterReporter.Close(ctx)
		if c, ok := st.(interface{ Close() }); ok {
			c.Close()
		}
		log.Print("feir-server: shutdown complete")
	}
}

// selectStore returns a Postgres store when FEIR_DATABASE_URL is set, else the in-memory store. For
// Postgres it applies the (idempotent) schema on startup so `docker compose up` is turnkey. A failed
// DB connection is fatal — if the operator asked for Postgres, silently falling back to a volatile
// in-memory store would lose evidence, so we refuse to start instead.
func selectStore() store.Store {
	dsn := os.Getenv("FEIR_DATABASE_URL")
	if dsn == "" {
		log.Printf("WARNING: no FEIR_DATABASE_URL set — storage is IN-MEMORY: evidence is NOT durable " +
			"(lost on restart) and the heads->seal->put ingest path is not a single transaction (only the " +
			"Postgres store is serializable). Dev/single-process only; set FEIR_DATABASE_URL for the durable " +
			"append-only Postgres store.")
		return store.NewMem()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pg, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		log.Fatalf("storage: Postgres requested but unavailable: %v", err)
	}
	if err := pg.Migrate(ctx, migrations.Schema); err != nil {
		log.Fatalf("storage: migrate: %v", err)
	}
	log.Printf("storage: Postgres (append-only)")
	return pg
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// parseCosigApprovers parses a comma-separated list of base64url-no-pad ed25519 public keys (each with an
// optional "ed25519pub:" prefix) into the M6 cosig approver set. A malformed entry is fatal (fail-closed —
// a typo'd governance key must not silently shrink the approver set).
func parseCosigApprovers(raw string) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimPrefix(strings.TrimSpace(part), "ed25519pub:")
		if s == "" {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) != ed25519.PublicKeySize {
			log.Fatalf("FEIR_COSIG_APPROVER_KEYS: %q is not a base64url-no-pad ed25519 public key (32 bytes)", part)
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out
}

// parseAuthorityKeys parses the general FEIR_AUTHORITY_KEYS form: a comma-separated list of
// "<source>=<pubkey>" pairs, where <source> is policy_engine_signed or human_signed and <pubkey> is a
// hex- or base64url-encoded ed25519 public key (optional "ed25519pub:" prefix). A malformed entry, an
// unknown source, or a duplicate source within the list is fatal (fail-closed: a typo'd pin must not
// silently disable elevation). The returned map is then fed one-per-source into WithPolicyEngineKey,
// which also fatals on a source already pinned by FEIR_POLICY_ENGINE_PUBKEY/FEIR_HUMAN_SIGNED_PUBKEY.
func parseAuthorityKeys(raw string) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, 2)
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		source, key, ok := strings.Cut(entry, "=")
		source = strings.TrimSpace(source)
		if !ok || source == "" {
			log.Fatalf("FEIR_AUTHORITY_KEYS: %q is not a source=pubkey pair", part)
		}
		if source != "policy_engine_signed" && source != "human_signed" {
			log.Fatalf("FEIR_AUTHORITY_KEYS: unknown source %q (want policy_engine_signed or human_signed)", source)
		}
		if _, dup := out[source]; dup {
			log.Fatalf("FEIR_AUTHORITY_KEYS: source %q listed more than once", source)
		}
		pub, err := decodeAuthorityPubKey(strings.TrimSpace(key))
		if err != nil {
			log.Fatalf("FEIR_AUTHORITY_KEYS (%s): %v", source, err)
		}
		out[source] = pub
	}
	return out
}

// decodeAuthorityPubKey parses an ed25519 public key from either hex (64 chars) or the
// published "ed25519pub:<base64url-no-pad>" / bare base64url-no-pad form. It is used to
// pin the external policy-engine verifying key (T7). A wrong length or bad encoding is an
// error (fail-closed: a typo'd pin must not silently disable elevation).
func decodeAuthorityPubKey(raw string) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "ed25519pub:")
	// hex (64 chars => 32 bytes).
	if len(s) == ed25519.PublicKeySize*2 {
		if b, err := hex.DecodeString(s); err == nil {
			return ed25519.PublicKey(b), nil
		}
	}
	// base64url-no-pad (the published "ed25519pub:" body).
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	return nil, fmt.Errorf("not a 32-byte ed25519 public key (accepts 64-hex or base64url-no-pad, optional ed25519pub: prefix): %q", raw)
}
