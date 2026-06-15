// Command feir-server runs the ingestion + app API. Self-host: the signing seed is provided via
// FEIR_SIGNING_SEED (64 hex chars). Production backs signing with a KMS instead.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/feir-dev/feir/server/internal/api"
	"github.com/feir-dev/feir/server/internal/auth"
	"github.com/feir-dev/feir/server/internal/content"
	"github.com/feir-dev/feir/server/internal/core"
	"github.com/feir-dev/feir/server/internal/meter"
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
	// usage metering -> Stripe (the real revenue path). No key = local counting only.
	srv.WithMeter(meter.NewStripeReporter(meter.NewMem(), meter.StripeConfig{
		APIKey: os.Getenv("STRIPE_API_KEY"),
	}))

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
	if seed := os.Getenv("FEIR_BROKER_ISSUING_SEED"); seed != "" {
		raw, err := hex.DecodeString(seed)
		if err != nil || len(raw) != ed25519.SeedSize {
			log.Fatal("FEIR_BROKER_ISSUING_SEED must be 64 hex chars (32-byte Ed25519 seed)")
		}
		srv.WithBroker(ed25519.NewKeyFromSeed(raw))
		log.Printf("credential broker enabled (POST /v2/grants)")
	}

	log.Printf("feir-server listening on %s (pubkey %s)", addr, c.PubKey())
	log.Fatal(http.ListenAndServe(addr, srv.Routes()))
}

// selectStore returns a Postgres store when FEIR_DATABASE_URL is set, else the in-memory store. For
// Postgres it applies the (idempotent) schema on startup so `docker compose up` is turnkey. A failed
// DB connection is fatal — if the operator asked for Postgres, silently falling back to a volatile
// in-memory store would lose evidence, so we refuse to start instead.
func selectStore() store.Store {
	dsn := os.Getenv("FEIR_DATABASE_URL")
	if dsn == "" {
		log.Printf("storage: in-memory (set FEIR_DATABASE_URL for a durable Postgres store)")
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
