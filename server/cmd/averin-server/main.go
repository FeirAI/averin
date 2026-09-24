// Command averin-server runs the ingestion + app API. Self-host: the signing seed is provided via
// AVERIN_SIGNING_SEED (64 hex chars). Production backs signing with a KMS instead.
//
// Every Ed25519 root seed (AVERIN_SIGNING_SEED, AVERIN_BROKER_ISSUING_SEED, AVERIN_RESOURCE_SEED,
// AVERIN_REVOCATION_SEED, AVERIN_ATTESTATION_SEED) also accepts a <NAME>_FILE form pointing at a mounted secret file (e.g. a
// CSI/Kubernetes secret volume), keeping the seed off the env block. Set at most one of
// <NAME>/<NAME>_FILE per seed.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/feirai/averin/server/internal/api"
	"github.com/feirai/averin/server/internal/auth"
	"github.com/feirai/averin/server/internal/content"
	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/meter"
	"github.com/feirai/averin/server/internal/pgdurable"
	"github.com/feirai/averin/server/internal/pgledger"
	"github.com/feirai/averin/server/internal/pgschema"
	"github.com/feirai/averin/server/internal/scrub"
	"github.com/feirai/averin/server/internal/store"
	"github.com/feirai/averin/server/internal/witness"
)

func main() {
	seed := secretEnvOrFile("AVERIN_SIGNING_SEED")
	if seed == "" {
		log.Fatal("AVERIN_SIGNING_SEED (or AVERIN_SIGNING_SEED_FILE) is required (64 hex chars = 32-byte Ed25519 seed)")
	}
	if raw := strings.TrimSpace(os.Getenv("AVERIN_SECRET_PATTERNS")); raw != "" {
		var patterns []string
		if err := json.Unmarshal([]byte(raw), &patterns); err != nil {
			log.Fatalf("AVERIN_SECRET_PATTERNS must be a JSON string array: %v", err)
		}
		if err := scrub.ConfigurePatterns(patterns); err != nil {
			log.Fatalf("AVERIN_SECRET_PATTERNS: %v", err)
		}
	}

	// AVERIN_REQUIRE_PROD_SECRETS (prod): fail closed if a prod-mandatory secret is empty/absent OR is a
	// globally-known dev value. An empty CSI/KMS value otherwise satisfies envFrom and starts averin
	// FAIL-OPEN: no AVERIN_API_KEYS leaves the app API UNAUTHENTICATED, and no AVERIN_DATABASE_URL leaves the
	// store volatile in-memory (consumed jti/nonce + two-phase grants reset on restart, reopening a
	// /v2/use replay window). Mirrors govder's GOVDER_REQUIRE_AUTHORITY_SEED and leria's
	// LERIA_REQUIRE_PROD_SECRETS.
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("AVERIN_REQUIRE_PROD_SECRETS"))); v == "1" || v == "true" {
		var missing []string
		if strings.TrimSpace(os.Getenv("AVERIN_API_KEYS")) == "" {
			missing = append(missing, "AVERIN_API_KEYS (the app API would be UNAUTHENTICATED)")
		}
		if strings.TrimSpace(os.Getenv("AVERIN_DATABASE_URL")) == "" {
			missing = append(missing, "AVERIN_DATABASE_URL (the store would be volatile in-memory — reopening a /v2/use replay window)")
		}
		// The signing seed is the integrity ROOT. The committed dev seed is globally known — anyone can
		// forge/verify records under it — so REQUIRE_PROD_SECRETS must not boot on it (mirrors the empty-
		// secret checks above; the value is public, rotate to a fresh `openssl rand -hex 32`).
		if isDevSigningSeed(seed) {
			missing = append(missing, "AVERIN_SIGNING_SEED is the well-known committed dev seed (a globally-known, forgeable integrity root)")
		}
		if len(missing) > 0 {
			log.Fatalf("AVERIN_REQUIRE_PROD_SECRETS is set but required prod secret(s) are empty/absent: %s", strings.Join(missing, "; "))
		}
	}

	c, err := core.New(seed)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	keyID := envOr("AVERIN_SIGNING_KEY_ID", "k0")
	addr := envOr("AVERIN_ADDR", ":8080")

	// Storage: Postgres when AVERIN_DATABASE_URL is set (production / persistent self-host), else the
	// in-memory store (dev / single-process, NOT durable). Postgres is append-only (see migrations).
	//
	// Schema migration runs ONCE here, under an advisory lock, BEFORE any of averin's three Postgres
	// stores (evidence store + consume-before-act ledger + durable revocation/two-phase state) opens its
	// pool — they all share this one DSN and now run against an already-migrated DB, applying no DDL of
	// their own. A stored version NEWER than this binary is a loud, fail-CLOSED refusal (averin's
	// immutable evidence is never re-migrated backward across a downgrade); a steady-state boot issues
	// zero DDL. No-op when storage is in-memory (no AVERIN_DATABASE_URL).
	// Use the SAME raw DSN the stores connect with (selectStore/pgledger/pgdurable read os.Getenv
	// untrimmed) so migrate and connect operate on a byte-identical string.
	if dsn := os.Getenv("AVERIN_DATABASE_URL"); dsn != "" {
		mctx, mcancel := context.WithTimeout(context.Background(), 60*time.Second)
		err := pgschema.Migrate(mctx, dsn)
		if err != nil {
			mcancel()
			log.Fatalf("storage: schema migration: %v", err)
		}
		if err := pgschema.CheckRuntime(mctx, dsn); err != nil {
			mcancel()
			log.Fatalf("storage: runtime credential readiness: %v", err)
		}
		mcancel()
		log.Printf("storage: schema migrated (averin DB at version %d)", pgschema.CurrentSchemaVersion)
	}
	st := selectStore()

	srv := api.New(c, st, keyID)
	// GET /readyz probes the Postgres store's pool (short-timeout Ping); GET /metrics gets its live
	// connection-pool gauges. The in-memory store (no AVERIN_DATABASE_URL) registers neither — nothing
	// to be unready about, nothing to gauge.
	if pg, ok := st.(*store.Postgres); ok {
		srv.WithReadiness("store", pg)
		srv.WithGauge("averin_store_pool_total_conns", "Store Postgres pool: total connections.",
			func() float64 { return float64(pg.PoolStat().TotalConns) })
		srv.WithGauge("averin_store_pool_acquired_conns", "Store Postgres pool: connections currently acquired.",
			func() float64 { return float64(pg.PoolStat().AcquiredConns) })
		srv.WithGauge("averin_store_pool_idle_conns", "Store Postgres pool: idle connections.",
			func() float64 { return float64(pg.PoolStat().IdleConns) })
		srv.WithGauge("averin_store_pool_max_conns", "Store Postgres pool: configured max connections.",
			func() float64 { return float64(pg.PoolStat().MaxConns) })
	}
	// usage metering -> Stripe (the real revenue path). No key = local counting only. Retained so
	// graceful shutdown can drain its async queue (billable events) before exit.
	meterReporter := meter.NewStripeReporter(meter.NewMem(), meter.StripeConfig{
		APIKey: os.Getenv("STRIPE_API_KEY"),
	})
	srv.WithMeter(meterReporter)

	// project-scoped API keys: AVERIN_API_KEYS="proj-a:tok1,tok2;proj-b:tok3". Unset = no auth (dev).
	var writerKeys auth.KeyStore
	if raw := os.Getenv("AVERIN_API_KEYS"); raw != "" {
		ks, n := auth.ParseKeys(raw)
		if n == 0 {
			log.Fatal("AVERIN_API_KEYS is set but parsed to zero keys — refusing to start in silent deny-all (use 'proj:tok' form)")
		}
		srv.WithAuth(ks)
		writerKeys = ks
		log.Printf("per-project API-key auth enabled (%d projects)", n)
	} else {
		log.Printf("WARNING: no AVERIN_API_KEYS set — the app API is UNAUTHENTICATED (dev/single-tenant only)")
	}
	// AVERIN_RECOVERY_KEYS is a separate broker_seq:recover authority. An absent
	// configuration denies all recovery actions even when ordinary auth is open.
	recoveryKeys, recoveryCount, err := auth.ParseRecoveryKeys(os.Getenv("AVERIN_RECOVERY_KEYS"), writerKeys)
	if err != nil {
		log.Fatal(err)
	}
	srv.WithRecoveryAuth(recoveryKeys)
	log.Printf("project-scoped recovery auth configured (%d credentials)", recoveryCount)
	// T7: pin EXTERNAL authority verifying keys so a generic record carrying a policy_engine_signed
	// OR human_signed authority block, with an evidence_sig that verifies under the key pinned FOR
	// THAT source, is elevated to that source at ingest (else forced to the forgeable
	// caller_declared). Three env forms, all composable (each pins at most one key per source):
	//
	//   AVERIN_POLICY_ENGINE_PUBKEY   — back-compat: one key for AVERIN_POLICY_ENGINE_SOURCE
	//                                 (default source policy_engine_signed).
	//   AVERIN_HUMAN_SIGNED_PUBKEY    — one key for the human_signed source (govder's kill/approval
	//                                 records are human_signed, signed by a DIFFERENT key than the
	//                                 policy engine — this is what lets them elevate, not normalize
	//                                 down to caller_declared on verify/export).
	//   AVERIN_DELEGATE_SIGNED_PUBKEY — one key for the delegate_signed source (govder's delegate-agent
	//                                 approval records). This is the third value
	//                                 `govder-derive-pubkeys` prints; without it EVERY delegate-agent
	//                                 approval record sealed at the forgeable caller_declared (F2).
	//   AVERIN_AUTHORITY_KEYS         — a general "[project:]source=pubkey,..." list. `source` is one of
	//                                 policy_engine_signed / human_signed / delegate_signed. With a
	//                                 `project:` prefix the key is pinned for THAT averin project only and
	//                                 wins over the un-prefixed global default for the same source.
	//
	// MULTI-TENANT (F1). The upstream authority (govder) derives its signing key per (tenant, role), and a
	// govder tenant IS an averin project. A single GLOBAL key per source can therefore only elevate ONE
	// tenant — every other tenant's policy_engine_signed / human_signed / delegate_signed records fail key
	// verification. Pin each tenant's key against its project:
	//
	//   AVERIN_AUTHORITY_KEYS="acme:policy_engine_signed=<hex>,acme:human_signed=<hex>,acme:delegate_signed=<hex>,\
	//                          globex:policy_engine_signed=<hex>,globex:human_signed=<hex>,globex:delegate_signed=<hex>"
	//
	// (run `GOVDER_AUTHORITY_SEED=... go run ./cmd/govder-derive-pubkeys <tenant>` in govder once per tenant).
	//
	// Each pubkey is the 32-byte ed25519 public key, hex- OR base64url-encoded (the
	// "ed25519pub:<base64url>" published form is accepted with the prefix stripped). Each external
	// authority holds the PRIVATE half out of this server. None set = every generic authority is
	// caller_declared — which, with the now-default-ON AVERIN_REQUIRE_PINNED_AUTHORITY below, means an
	// authority-CLAIMING record is REJECTED rather than silently downgraded. Pinning the SAME
	// (project, source) twice across these forms is a fatal config error.
	//
	// The four env forms are resolved by authorityPinsFromEnv (a pure function over a getenv seam) so the
	// COMPLETE pin set the binary installs is directly testable — the F2 defect was exactly an env var that
	// the operator tooling printed, the docs implied, and main() never read.
	for _, p := range authorityPinsFromEnv(os.Getenv) {
		srv.WithProjectAuthorityKey(p.pin.project, p.pin.source, p.key)
		scope := "all projects"
		if p.pin.project != "" {
			scope = "project=" + p.pin.project
		}
		log.Printf("T7 authority key pinned (source=%s, %s, via %s): a verifying authority evidence_sig elevates to %s",
			p.pin.source, scope, p.env, p.pin.source)
	}
	// AVERIN_REQUIRE_PINNED_AUTHORITY (default ON since F3): a record that CLAIMS an elevated authority
	// source (policy_engine_signed/human_signed/delegate_signed) whose evidence fails to verify under the
	// pinned key — or that names a source UNPINNED for its project — is REJECTED (a retryable 500) instead
	// of silently sealed downgraded to the forgeable caller_declared.
	//
	// WHY THE DEFAULT FLIPPED. Off-by-default was what made F1 and F2 SILENT: a multi-tenant deployment, or
	// any deployment recording delegate-agent approvals, permanently recorded kill/approval/policy evidence
	// at forgeable authority and said nothing but a rate-limited WARNING. No shipped config ever set this
	// variable, so nothing in the product was fail-closed here. Ordinary caller_declared traffic is
	// unaffected in either mode (it claims no elevation to fail), so the flip only bites a producer that
	// CLAIMS authority averin cannot verify — which is precisely the case that must not be sealed silently.
	//
	// OPTING OUT is explicit and loud: AVERIN_REQUIRE_PINNED_AUTHORITY=0 restores the Phase-1 silent
	// downgrade and logs a WARNING naming what that means. Use it only as a migration step while the
	// AVERIN_*_PUBKEY / AVERIN_AUTHORITY_KEYS pins are being aligned.
	requirePinned, err := requirePinnedAuthorityFromEnv(os.Getenv("AVERIN_REQUIRE_PINNED_AUTHORITY"))
	if err != nil {
		log.Fatalf("%v", err)
	}
	srv.WithRequirePinnedAuthority(requirePinned)
	// Reader-first rollout: enable after every external authority producer has
	// moved to v3. This never changes the classification of immutable v2 history.
	switch raw := os.Getenv("AVERIN_REQUIRE_BODY_BOUND_AUTHORITY"); raw {
	case "", "0", "false":
		srv.WithRequireBodyBoundAuthority(false)
	case "1", "true":
		srv.WithRequireBodyBoundAuthority(true)
	default:
		log.Fatalf("AVERIN_REQUIRE_BODY_BOUND_AUTHORITY must be 1/true/0/false (got %q)", raw)
	}
	if requirePinned {
		log.Printf("AVERIN_REQUIRE_PINNED_AUTHORITY on (default): a claimed authority elevation that fails key verification is REJECTED (fail-closed), not downgraded to caller_declared")
	} else {
		log.Printf("WARNING: AVERIN_REQUIRE_PINNED_AUTHORITY=0 — FAIL-OPEN authority posture explicitly selected. A record CLAIMING policy_engine_signed/human_signed/delegate_signed whose evidence does not verify under a pinned key (or whose source is unpinned for its project) will be PERMANENTLY SEALED at the forgeable caller_declared instead of rejected. Kill/approval/policy evidence recorded in this mode is not cryptographically distinguishable from a forgery.")
	}
	// durable content store for committed low-entropy values (raw input/output/rationale). No dir =
	// in-memory (NOT durable; disclosures won't survive a restart).
	if dir := os.Getenv("AVERIN_CONTENT_DIR"); dir != "" {
		key, err := hex.DecodeString(secretEnvOrFile("AVERIN_CONTENT_MASTER_KEY"))
		if err != nil || len(key) != 32 {
			log.Fatal("AVERIN_CONTENT_MASTER_KEY must be 64 hex chars (32 bytes) when AVERIN_CONTENT_DIR is set")
		}
		cs, err := content.NewEncryptedFSStore(dir, key)
		if err != nil {
			log.Fatalf("content store: %v", err)
		}
		retentionDays := 30
		if raw := strings.TrimSpace(os.Getenv("AVERIN_RAW_RETENTION_DAYS")); raw != "" {
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr != nil || parsed < 1 {
				log.Fatal("AVERIN_RAW_RETENTION_DAYS must be a positive integer")
			}
			retentionDays = parsed
		}
		purge := func() {
			removed, purgeErr := cs.PurgeOlderThan(time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour))
			if purgeErr != nil {
				log.Printf("WARNING: raw payload retention purge failed: %v", purgeErr)
			} else if removed > 0 {
				log.Printf("raw payload retention purge removed %d expired blobs", removed)
			}
		}
		purge()
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				purge()
			}
		}()
		srv.WithContent(cs)
		log.Printf("tenant-encrypted content store -> %s (raw retention: %d days)", dir, retentionDays)
	} else {
		log.Printf("WARNING: no AVERIN_CONTENT_DIR set — committed raw values are in-memory (not durable)")
	}
	// customer witness for sealed checkpoints (append-only).
	if dir := os.Getenv("AVERIN_WITNESS_DIR"); dir != "" {
		w, err := witness.NewFSWitness(dir)
		if err != nil {
			log.Fatalf("witness: %v", err)
		}
		srv.WithWitness(w)
		log.Printf("checkpoint witness -> %s", dir)
	}
	// third-party RFC 3161 timestamp anchoring for sealed checkpoints (threat #3 backdating). The
	// verifier must pin this TSA's cert out-of-band to trust the anchor.
	if url := os.Getenv("AVERIN_TSA_URL"); url != "" {
		srv.WithTSA(&witness.HTTPTSA{URL: url})
		log.Printf("checkpoint anchoring -> RFC 3161 TSA %s", url)
	}
	// credential broker (Level 3 Tier-A): POST /v2/grants. The issuing key signs the capabilities;
	// the recording key (the server signing key) signs the gateway_enforced evidence. Unset = off.
	brokerEnabled := false
	var brokerPubKey string   // ed25519pub:<b64url>, for the R2 broker∩resource∩revocation disjointness checks below
	var resourcePubKey string // ed25519pub:<b64url> when the resource gateway is enabled; "" otherwise (R2 vs revocation)
	if seed := secretEnvOrFile("AVERIN_BROKER_ISSUING_SEED"); seed != "" {
		raw, err := hex.DecodeString(seed)
		if err != nil || len(raw) != ed25519.SeedSize {
			log.Fatal("AVERIN_BROKER_ISSUING_SEED must be 64 hex chars (32-byte Ed25519 seed)")
		}
		bk := ed25519.NewKeyFromSeed(raw)
		srv.WithBroker(bk)
		brokerEnabled = true
		brokerPubKey = "ed25519pub:" + base64.RawURLEncoding.EncodeToString(bk.Public().(ed25519.PublicKey))
		log.Printf("credential broker enabled (POST /v2/grants)")
		// M4 (ADR 0005): optional federation identity. When set, grants carry grant_evidence.broker_id and
		// checkpoints carry a per-broker_id broker_grant_heads map (verify with federated_broker_keys[<id>]).
		if bid := os.Getenv("AVERIN_BROKER_ID"); bid != "" {
			srv.WithBrokerID(bid)
			log.Printf("federation enabled: grants tagged broker_id=%q (per-broker broker_grant_heads in checkpoints)", bid)
		}
		// D6 operator remediation (POST /v2/broker-seq/void): how old a reserved-but-unrecorded broker_seq must be
		// before it may be filled with a grant_void tombstone. A SAFETY parameter: it must comfortably exceed the
		// longest time a grant can still be committing (statement timeout 30s, two-phase pending TTL 15m), so the
		// floor rejects anything shorter at startup. Default 1h.
		if raw := strings.TrimSpace(os.Getenv("AVERIN_BROKER_SEQ_VOID_MIN_AGE")); raw != "" {
			const voidMinAgeFloor = 20 * time.Minute
			d, perr := time.ParseDuration(raw)
			if perr != nil || d <= 0 {
				log.Fatalf("AVERIN_BROKER_SEQ_VOID_MIN_AGE must be a positive Go duration (e.g. 1h): %v", perr)
			}
			if d < voidMinAgeFloor {
				log.Fatalf("AVERIN_BROKER_SEQ_VOID_MIN_AGE %s is below the safe floor %s — a void could race a grant commit (or a two-phase finalize) that is still landing", d, voidMinAgeFloor)
			}
			srv.WithBrokerSeqVoidMinAge(d)
		}
	}
	// M6 (ADR 0005): the ONLINE two-phase cosig policy (POST /v2/grants/prepare + /v2/grants/finalize). The
	// M-of-N approver keys are role-separated GOVERNANCE keys — the offline verifier re-pins them as
	// cosig_approver_keys (a FATAL config error on overlap with any other role). Requires the broker.
	// AVERIN_COSIG_APPROVER_KEYS = comma-separated ed25519 pubkeys (base64url-no-pad, optional ed25519pub:
	// prefix); AVERIN_COSIG_THRESHOLD = M (default = number of approvers).
	if raw := os.Getenv("AVERIN_COSIG_APPROVER_KEYS"); raw != "" {
		if !brokerEnabled {
			log.Fatal("AVERIN_COSIG_APPROVER_KEYS requires AVERIN_BROKER_ISSUING_SEED (cosig is a broker grant-approval policy)")
		}
		approvers := parseCosigApprovers(raw)
		if len(approvers) == 0 {
			log.Fatal("AVERIN_COSIG_APPROVER_KEYS is set but parsed to zero keys")
		}
		threshold := len(approvers)
		if t := os.Getenv("AVERIN_COSIG_THRESHOLD"); t != "" {
			n, err := strconv.Atoi(t)
			if err != nil || n < 1 || n > len(approvers) {
				log.Fatalf("AVERIN_COSIG_THRESHOLD must be an integer in [1, %d]", len(approvers))
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
	if rseed := secretEnvOrFile("AVERIN_RESOURCE_SEED"); rseed != "" {
		if !brokerEnabled {
			log.Fatal("AVERIN_RESOURCE_SEED requires AVERIN_BROKER_ISSUING_SEED (the resource verifies capabilities under the broker issuing key)")
		}
		rid := os.Getenv("AVERIN_RESOURCE_ID")
		if rid == "" {
			log.Fatal("AVERIN_RESOURCE_ID is required when AVERIN_RESOURCE_SEED is set")
		}
		rc, err := core.New(rseed)
		if err != nil {
			log.Fatalf("AVERIN_RESOURCE_SEED: %v", err)
		}
		if rc.PubKey() == c.PubKey() {
			log.Fatal("AVERIN_RESOURCE_SEED must differ from AVERIN_SIGNING_SEED (R2: broker and resource recording keys must be disjoint)")
		}
		// Compare DERIVED pubkeys, not raw seed hex. The broker seed is decoded by Go's case-insensitive
		// hex.DecodeString while the resource seed goes through the core's lowercase-only decoder, so an
		// UPPERCASE broker seed + a lowercase resource seed for the SAME key are byte-distinct strings that
		// a raw compare misses — silently violating R2 (broker == resource key), which the offline verifier
		// would then reject as a fatal config error. Comparing pubkeys catches it fast at startup.
		if rc.PubKey() == brokerPubKey {
			log.Fatal("AVERIN_RESOURCE_SEED must differ from AVERIN_BROKER_ISSUING_SEED (keep the capability-issuing and use-recording key roles distinct)")
		}
		resourcePubKey = rc.PubKey() // for the R2 revocation∩resource disjointness check below
		// The store transaction owns replay claims and the signed use receipt.
		// pgledger is retained for maintenance sweeping and a separate readiness probe.
		if dsn := os.Getenv("AVERIN_DATABASE_URL"); dsn != "" {
			lctx, lcancel := context.WithTimeout(context.Background(), 30*time.Second)
			pl, err := pgledger.New(lctx, dsn)
			lcancel()
			if err != nil {
				log.Fatalf("resource ledger: Postgres requested but unavailable: %v", err)
			}
			// Periodic TTL sweep of the consume_ledger (it otherwise grows one row per PoP nonce + per jti
			// forever; only a Release ever deletes). AVERIN_LEDGER_RETENTION sets how long a consumed
			// nonce/jti is kept — a CORRECTNESS parameter, NOT tuning: it MUST exceed the longest credential
			// validity window (broker.MaxTTL = 1h) or a pruned-but-still-live nonce/jti becomes replayable.
			// Default 720h (30d) is ~720x MaxTTL; a floor rejects a dangerously small value at startup.
			retention := 720 * time.Hour
			const ledgerRetentionFloor = 24 * time.Hour // >> broker.MaxTTL (1h); a value under this reopens replay
			if raw := strings.TrimSpace(os.Getenv("AVERIN_LEDGER_RETENTION")); raw != "" {
				d, perr := time.ParseDuration(raw)
				if perr != nil || d <= 0 {
					log.Fatalf("AVERIN_LEDGER_RETENTION must be a positive Go duration (e.g. 720h): %v", perr)
				}
				if d < ledgerRetentionFloor {
					log.Fatalf("AVERIN_LEDGER_RETENTION %s is below the safe floor %s — pruning a nonce/jti still inside a live credential's validity window would reopen the single-use replay this ledger closes", d, ledgerRetentionFloor)
				}
				retention = d
			}
			pl.StartSweeper(context.Background(), retention, time.Hour)
			log.Printf("consume_ledger TTL sweep enabled (retention %s, hourly)", retention)
			srv.WithReadiness("resource_ledger", pl)
			srv.WithGauge("averin_ledger_pool_total_conns", "Resource ledger Postgres pool: total connections.",
				func() float64 { return float64(pl.PoolStat().TotalConns) })
			srv.WithGauge("averin_ledger_pool_acquired_conns", "Resource ledger Postgres pool: connections currently acquired.",
				func() float64 { return float64(pl.PoolStat().AcquiredConns) })
			srv.WithGauge("averin_ledger_pool_idle_conns", "Resource ledger Postgres pool: idle connections.",
				func() float64 { return float64(pl.PoolStat().IdleConns) })
			srv.WithGauge("averin_ledger_pool_max_conns", "Resource ledger Postgres pool: configured max connections.",
				func() float64 { return float64(pl.PoolStat().MaxConns) })
			log.Printf("consume-before-act claims -> project store transaction; pgledger sweep/readiness enabled")
		} else {
			log.Printf("WARNING: consume-before-act claims use the volatile in-memory project store; set AVERIN_DATABASE_URL for durable claims")
		}
		srv.WithResource(rc, rid)
		log.Printf("resource gateway enabled (POST /v2/use) for resource %q", rid)
		// M3 (ADR 0005 — Native/STS): enable POST /v2/introspection with the RAW resource key (the same key,
		// derived from AVERIN_RESOURCE_SEED) so the resource can sign the structured introspection challenge.
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
	revocationEnabled := false
	if rvseed := secretEnvOrFile("AVERIN_REVOCATION_SEED"); rvseed != "" {
		raw, err := hex.DecodeString(rvseed)
		if err != nil || len(raw) != ed25519.SeedSize {
			log.Fatal("AVERIN_REVOCATION_SEED (or AVERIN_REVOCATION_SEED_FILE) must be 64 hex chars (32-byte Ed25519 seed)")
		}
		rvk := ed25519.NewKeyFromSeed(raw)
		// R2 role separation: the revocation key MUST be disjoint from the signing/broker/resource keys.
		// Compare DERIVED pubkeys, NOT raw seed hex: the broker/resource/revocation seeds can each now
		// arrive via <NAME>_FILE and through different decoders, so an UPPERCASE-vs-lowercase hex form of
		// the SAME key is byte-distinct as a string but identical as a key — a raw-string compare (the
		// pre-_FILE form) would miss it, AND it read the broker/resource seeds via os.Getenv, which is
		// empty when they are file-mounted, so a raw-string compare would silently skip this check. That
		// is NOT an exploitable bypass — api.Server.WithRevocation independently re-derives + enforces R2
		// (it panics on overlap), so a colliding key never installs; this check just turns that deep
		// panic into a clean startup fatal (defense-in-depth + operator UX). brokerPubKey/resourcePubKey
		// are "" when that role is disabled, so a disabled role never spuriously matches. (Same rationale
		// as the resource-vs-broker pubkey compare above.)
		rvPubKey := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(rvk.Public().(ed25519.PublicKey))
		if rvPubKey == c.PubKey() ||
			(brokerPubKey != "" && rvPubKey == brokerPubKey) ||
			(resourcePubKey != "" && rvPubKey == resourcePubKey) {
			log.Fatal("AVERIN_REVOCATION_SEED must differ from the signing/broker/resource seeds (R2 role separation)")
		}
		srv.WithRevocation(rvk)
		revocationEnabled = true
		log.Printf("revocation enabled (POST /v2/revoke; exports carry a signed revocation_list)")
	}

	// Auxiliary durable-state connection for startup diagnostics, readiness and
	// legacy cache rehydration. Request-time pending and revocation authority uses
	// the transaction-bound project Store, connected to the same database.
	var durableStore *pgdurable.Store
	if dsn := os.Getenv("AVERIN_DATABASE_URL"); dsn != "" {
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		pd, err := pgdurable.New(dctx, dsn)
		dcancel()
		if err != nil {
			log.Fatalf("durable revocation/two-phase state: Postgres requested but unavailable: %v", err)
		}
		durableStore = pd
		srv.WithDurable(pd)
		srv.WithReadiness("durable", pd)
		srv.WithGauge("averin_durable_pool_total_conns", "Durable (revocation/two-phase) Postgres pool: total connections.",
			func() float64 { return float64(pd.PoolStat().TotalConns) })
		srv.WithGauge("averin_durable_pool_acquired_conns", "Durable (revocation/two-phase) Postgres pool: connections currently acquired.",
			func() float64 { return float64(pd.PoolStat().AcquiredConns) })
		srv.WithGauge("averin_durable_pool_idle_conns", "Durable (revocation/two-phase) Postgres pool: idle connections.",
			func() float64 { return float64(pd.PoolStat().IdleConns) })
		srv.WithGauge("averin_durable_pool_max_conns", "Durable (revocation/two-phase) Postgres pool: configured max connections.",
			func() float64 { return float64(pd.PoolStat().MaxConns) })
		log.Printf("revocation + two-phase grant state -> Postgres (durable; survives restart)")
	} else {
		if revocationEnabled {
			log.Printf("WARNING: no AVERIN_DATABASE_URL set — the revoked-grant set (M5) is in-memory (volatile): a revoke issued just before a restart is forgotten. Set AVERIN_DATABASE_URL for durable revocation.")
		}
		if brokerEnabled {
			log.Printf("WARNING: no AVERIN_DATABASE_URL set — pending two-phase grant state (M6/M2 prepare→finalize) is in-memory (volatile): a restart during the cosig/delegation approval window loses the pending mint (the caller must re-prepare). Set AVERIN_DATABASE_URL for durable two-phase state.")
		}
	}

	// D7 deployment attestation. The issuer private key is role-separated from every evidence/enforcement
	// role. The product-facing verifier only evaluates this claim when the deployment also supplies BOTH
	// public out-of-band auditor pins below (issuer key + RFC 3161 TSA SPKI).
	if aseed := secretEnvOrFile("AVERIN_ATTESTATION_SEED"); aseed != "" {
		raw, err := hex.DecodeString(aseed)
		if err != nil || len(raw) != ed25519.SeedSize {
			log.Fatal("AVERIN_ATTESTATION_SEED (or AVERIN_ATTESTATION_SEED_FILE) must be 64 hex chars (32-byte Ed25519 seed)")
		}
		srv.WithAttestation(ed25519.NewKeyFromSeed(raw))
		log.Printf("deployment attestation enabled (exports bind the latest checkpoint under a role-separated issuer)")
	}
	if manifest := strings.TrimSpace(os.Getenv("AVERIN_COVERAGE_MANIFEST")); manifest != "" {
		var parsed any
		if err := json.Unmarshal([]byte(manifest), &parsed); err != nil {
			log.Fatalf("AVERIN_COVERAGE_MANIFEST must be valid JSON: %v", err)
		}
		srv.WithCoverageManifest(manifest)
		log.Printf("deployment coverage manifest enabled")
	}
	verifyAttestation := strings.TrimSpace(os.Getenv("AVERIN_VERIFY_ATTESTATION_PUBKEY"))
	verifyTSA := strings.TrimSpace(os.Getenv("AVERIN_VERIFY_TSA_SPKI_B64"))
	if (verifyAttestation == "") != (verifyTSA == "") {
		log.Fatal("AVERIN_VERIFY_ATTESTATION_PUBKEY and AVERIN_VERIFY_TSA_SPKI_B64 must be configured together — partial D7 trust roots cannot evaluate attestation")
	}
	if verifyAttestation != "" {
		attestationKeys := parsePublicKeys("AVERIN_VERIFY_ATTESTATION_PUBKEY", verifyAttestation)
		var tsaSPKI [][]byte
		for _, part := range strings.Split(verifyTSA, ",") {
			encoded := strings.TrimSpace(part)
			if encoded == "" {
				continue
			}
			der, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil || len(der) == 0 {
				log.Fatalf("AVERIN_VERIFY_TSA_SPKI_B64: %q is not base64url-no-pad DER SubjectPublicKeyInfo", part)
			}
			tsaSPKI = append(tsaSPKI, der)
		}
		if len(tsaSPKI) == 0 {
			log.Fatal("AVERIN_VERIFY_TSA_SPKI_B64 is set but parsed to zero keys")
		}
		srv.WithExternalVerificationRoots(attestationKeys, tsaSPKI)
		log.Printf("external D7 verification roots pinned (%d attestation issuer, %d RFC 3161 TSA SPKI)", len(attestationKeys), len(tsaSPKI))
	}

	// D4/D8 signed operation taxonomy. This is an all-or-nothing independent pinning tuple:
	// the server must never derive a taxonomy from the same records it is verifying.
	taxonomyFile := strings.TrimSpace(os.Getenv("AVERIN_VERIFY_TAXONOMY_FILE"))
	taxonomyPub := strings.TrimSpace(os.Getenv("AVERIN_VERIFY_TAXONOMY_PUBKEY"))
	taxonomyDigest := strings.TrimSpace(os.Getenv("AVERIN_VERIFY_TAXONOMY_DIGEST"))
	taxonomyVersionRaw := strings.TrimSpace(os.Getenv("AVERIN_VERIFY_TAXONOMY_VERSION"))
	taxonomySet := 0
	for _, value := range []string{taxonomyFile, taxonomyPub, taxonomyDigest, taxonomyVersionRaw} {
		if value != "" {
			taxonomySet++
		}
	}
	if taxonomySet != 0 && taxonomySet != 4 {
		log.Fatal("AVERIN_VERIFY_TAXONOMY_FILE, _PUBKEY, _DIGEST, and _VERSION must be configured together — partial D4 roots cannot validate an operation taxonomy")
	}
	if taxonomySet == 4 {
		taxonomyJSON, err := os.ReadFile(taxonomyFile)
		if err != nil {
			log.Fatalf("AVERIN_VERIFY_TAXONOMY_FILE: %v", err)
		}
		version, err := strconv.ParseInt(taxonomyVersionRaw, 10, 64)
		if err != nil || version <= 0 {
			log.Fatal("AVERIN_VERIFY_TAXONOMY_VERSION must be a positive integer")
		}
		taxonomyKeys := parsePublicKeys("AVERIN_VERIFY_TAXONOMY_PUBKEY", taxonomyPub)
		srv.WithExternalTaxonomy(taxonomyJSON, taxonomyKeys, taxonomyDigest, version)
		log.Printf("external D4 taxonomy pinned (version=%d, %d issuer key(s))", version, len(taxonomyKeys))
	}

	log.Printf("averin-server listening on %s (pubkey %s)", addr, c.PubKey())
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
	// before exiting. A clean drain on a rollout / scale-down avoids dropping in-flight ingest and the
	// request currently executing a finalize. With AVERIN_DATABASE_URL set, the cross-request
	// prepare->finalize window (and the revoked-grant set) now survive a restart too — see WithDurable
	// above; without it, both stay in-memory only and the drain is what limits the blast radius of a
	// stop. After the HTTP drain we flush the async Stripe meter queue and close the store pool, all
	// within the same deadline.
	//
	// DEADLINE: keep it UNDER the orchestrator's stop grace or it gets SIGKILLed mid-drain. Default
	// 25s, override with AVERIN_SHUTDOWN_TIMEOUT. The Kubernetes manifest sets terminationGracePeriod=30s
	// (no preStop, so the full grace covers the drain); for docker-compose set stop_grace_period >= this.
	drainTimeout := 25 * time.Second
	if v := os.Getenv("AVERIN_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			drainTimeout = d
		} else {
			log.Printf("averin-server: ignoring invalid AVERIN_SHUTDOWN_TIMEOUT %q (using %s)", v, drainTimeout)
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
		log.Printf("averin-server: received %s — draining (timeout %s)", sig, drainTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("averin-server: HTTP graceful shutdown timed out (some in-flight work was cut): %v", err)
		}
		// Handlers have drained (no more send()) → flush the Stripe meter queue, then release the
		// store pool, within whatever deadline remains.
		meterReporter.Close(ctx)
		if c, ok := st.(interface{ Close() }); ok {
			c.Close()
		}
		if durableStore != nil {
			durableStore.Close()
		}
		log.Print("averin-server: shutdown complete")
	}
}

// selectStore returns a Postgres store when AVERIN_DATABASE_URL is set, else the in-memory store. The
// schema is applied by the versioned migration runner (pgschema.Migrate) BEFORE this is called, so the
// store just opens its pool against an already-migrated DB. A failed DB connection is fatal — if the
// operator asked for Postgres, silently falling back to a volatile in-memory store would lose evidence,
// so we refuse to start instead.
func selectStore() store.Store {
	dsn := os.Getenv("AVERIN_DATABASE_URL")
	if dsn == "" {
		log.Printf("WARNING: no AVERIN_DATABASE_URL set — storage is IN-MEMORY: evidence is NOT durable " +
			"(lost on restart) and the heads->seal->put ingest path is not a single transaction (only the " +
			"Postgres store is serializable). Dev/single-process only; set AVERIN_DATABASE_URL for the durable " +
			"append-only Postgres store.")
		return store.NewMem()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pg, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		log.Fatalf("storage: Postgres requested but unavailable: %v", err)
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

// devSigningSeed is the well-known, globally-published dev signing seed baked into the self-host
// quickstart and used as a test vector across the repo (deploy/docker-compose.yml, core/src/ffi.rs,
// *_test.go). It is intentionally NOT secret — which is exactly why booting a AVERIN_REQUIRE_PROD_SECRETS
// deployment on it means running on a forgeable, globally-known integrity ROOT. The gate must reject it.
const devSigningSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // == core_test.go:8

// isDevSigningSeed reports whether seed is the well-known dev seed, tolerant of hex casing and the
// trailing newline a _FILE-mounted secret carries (secretEnvOrFile trims _FILE but returns inline raw).
func isDevSigningSeed(seed string) bool {
	return strings.EqualFold(strings.TrimSpace(seed), devSigningSeed)
}

// maxSeedFileBytes caps a _FILE read. A 64-hex Ed25519 seed is 64 bytes; the generous cap rejects a
// mispointed path at a device/huge file before it can consume memory, while tolerating a trailing
// newline or a slightly larger secret.
const maxSeedFileBytes = 4096

// secretEnvOrFile resolves a sensitive value (an Ed25519 root seed) from EITHER name
// (inline env) OR name+"_FILE" (a path to a mounted secret file — e.g. a CSI/Kubernetes
// secret volume). The _FILE form keeps the seed OFF the process env block, where it
// would otherwise be readable by any child process, leak into a crash dump / `ps e`, or
// be captured by `kubectl exec ... env`.
//
// FAIL-LOUD + FAIL-CLOSED (do not let a fumbled config silently disable a security role):
//   - both forms set => fatal "set exactly one".
//   - name_FILE set but blank/whitespace => fatal (a fumbled path must not silently fall back to env).
//   - the _FILE target must be a REGULAR, size-bounded file (a FIFO/device/dir/huge file is fatal);
//     symlinks ARE followed (k8s/CSI secret files are symlinks) — only the final target is checked.
//   - file contents are trimmed (mounted secrets carry a trailing newline).
//   - an inline value is returned RAW (never trimmed away): a whitespace/garbage value must reach the
//     caller's decoder and fail loud, not silently resolve to "" and DISABLE an optional role.
func secretEnvOrFile(name string) string {
	rawInline := os.Getenv(name)
	rawFile := os.Getenv(name + "_FILE")
	if rawInline != "" && rawFile != "" {
		log.Fatalf("%s and %s_FILE are both set — set exactly one (the _FILE form reads from a mounted secret file)", name, name)
	}
	if rawFile != "" {
		path := strings.TrimSpace(rawFile)
		if path == "" {
			log.Fatalf("%s_FILE is set but blank — provide a path to a mounted secret file (or unset it)", name)
		}
		st, err := os.Stat(path) // follows symlinks (k8s/CSI secret files are symlinks) to the final target
		if err != nil {
			log.Fatalf("%s_FILE (%s): %v", name, path, err)
		}
		if !st.Mode().IsRegular() {
			log.Fatalf("%s_FILE (%s) is not a regular file (mode %v) — refusing a FIFO/device/dir as a seed source", name, path, st.Mode())
		}
		if st.Size() > maxSeedFileBytes {
			log.Fatalf("%s_FILE (%s) is %d bytes, over the %d-byte seed cap — refusing to read", name, path, st.Size(), maxSeedFileBytes)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("%s_FILE (%s): %v", name, path, err)
		}
		return strings.TrimSpace(string(b))
	}
	return rawInline
}

// parseCosigApprovers parses a comma-separated list of base64url-no-pad ed25519 public keys (each with an
// optional "ed25519pub:" prefix) into the M6 cosig approver set. A malformed entry is fatal (fail-closed —
// a typo'd governance key must not silently shrink the approver set).
func parseCosigApprovers(raw string) []ed25519.PublicKey {
	return parsePublicKeys("AVERIN_COSIG_APPROVER_KEYS", raw)
}

func parsePublicKeys(name, raw string) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimPrefix(strings.TrimSpace(part), "ed25519pub:")
		if s == "" {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) != ed25519.PublicKeySize {
			log.Fatalf("%s: %q is not a base64url-no-pad ed25519 public key (32 bytes)", name, part)
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out
}

// parseAuthorityKeys parses the general AVERIN_AUTHORITY_KEYS form: a comma-separated list of
// "<source>=<pubkey>" pairs, where <source> is policy_engine_signed or human_signed and <pubkey> is a
// hex- or base64url-encoded ed25519 public key (optional "ed25519pub:" prefix). A malformed entry, an
// unknown source, or a duplicate source within the list is fatal (fail-closed: a typo'd pin must not
// silently disable elevation). The returned map is then fed one-per-source into WithPolicyEngineKey,
// which also fatals on a source already pinned by AVERIN_POLICY_ENGINE_PUBKEY/AVERIN_HUMAN_SIGNED_PUBKEY.
// authorityPinEnv is one parsed AVERIN_AUTHORITY_KEYS entry: the averin project the key is authoritative
// for ("" = the global default, authoritative in any project with no project-scoped pin for that source)
// and the authority source it vouches for.
type authorityPinEnv struct {
	project string
	source  string
}

// resolvedAuthorityPin is one pin the binary will install, plus the env var it came from (named in the
// startup log so an operator can see WHICH variable produced WHICH pin).
type resolvedAuthorityPin struct {
	pin authorityPinEnv
	key ed25519.PublicKey
	env string
}

// requirePinnedAuthorityFromEnv resolves the AVERIN_REQUIRE_PINNED_AUTHORITY posture.
//
// F3: the DEFAULT (unset) is now ON — fail-closed. Off-by-default was what made the F1 multi-tenant gap and
// the F2 missing delegate_signed config path SILENT: an authority-claiming record averin could not verify was
// permanently sealed at the forgeable caller_declared with nothing but a rate-limited WARNING, and no shipped
// config ever set this variable. Only "0"/"false" opts out, and an unrecognized value is a FATAL config error
// rather than a guessed posture (a typo like "yes" or "on" must never silently select fail-open).
func requirePinnedAuthorityFromEnv(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "1", "true":
		return true, nil
	case "0", "false":
		return false, nil
	default:
		return false, fmt.Errorf("AVERIN_REQUIRE_PINNED_AUTHORITY must be one of 1/true/0/false (got %q) — refusing to guess a fail-open authority posture", raw)
	}
}

// authorityPinsFromEnv resolves EVERY authority-key env form into the complete set of pins the server will
// install, in a deterministic order. `getenv` is the seam that makes this testable.
//
//	AVERIN_POLICY_ENGINE_PUBKEY   -> global pin for AVERIN_POLICY_ENGINE_SOURCE (default policy_engine_signed)
//	AVERIN_HUMAN_SIGNED_PUBKEY    -> global pin for human_signed
//	AVERIN_DELEGATE_SIGNED_PUBKEY -> global pin for delegate_signed        (F2: previously read by NOTHING)
//	AVERIN_AUTHORITY_KEYS         -> "[project:]source=pubkey,..."          (F1: per-project pins)
//
// A malformed value is fatal (fail-closed: a typo'd pin must never silently disable elevation, which under
// the default fail-closed posture would turn into a blanket ingest rejection rather than a silent downgrade —
// loud either way, but the operator gets the precise variable name here).
func authorityPinsFromEnv(getenv func(string) string) []resolvedAuthorityPin {
	var out []resolvedAuthorityPin
	single := func(envName, source string) {
		raw := getenv(envName)
		if strings.TrimSpace(raw) == "" {
			return
		}
		pub, err := decodeAuthorityPubKey(raw)
		if err != nil {
			log.Fatalf("%s: %v", envName, err)
		}
		out = append(out, resolvedAuthorityPin{pin: authorityPinEnv{source: source}, key: pub, env: envName})
	}
	peSource := strings.TrimSpace(getenv("AVERIN_POLICY_ENGINE_SOURCE"))
	if peSource == "" {
		peSource = "policy_engine_signed"
	}
	single("AVERIN_POLICY_ENGINE_PUBKEY", peSource)
	single("AVERIN_HUMAN_SIGNED_PUBKEY", "human_signed")
	// F2: delegate_signed is a first-class verified source in the core AND in WithPolicyEngineKey, and
	// govder's operator tool `govder-derive-pubkeys` prints exactly this variable — but nothing read it, so
	// every delegate-agent approval record on every shipped deployment sealed at the forgeable
	// caller_declared. AVERIN_AUTHORITY_KEYS additionally rejected the source outright.
	single("AVERIN_DELEGATE_SIGNED_PUBKEY", "delegate_signed")
	if raw := getenv("AVERIN_AUTHORITY_KEYS"); strings.TrimSpace(raw) != "" {
		pins := parseAuthorityKeys(raw)
		keys := make([]authorityPinEnv, 0, len(pins))
		for pin := range pins {
			keys = append(keys, pin)
		}
		// Deterministic install order so a duplicate-pin fatal is reproducible (map iteration is random).
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].project != keys[j].project {
				return keys[i].project < keys[j].project
			}
			return keys[i].source < keys[j].source
		})
		for _, pin := range keys {
			out = append(out, resolvedAuthorityPin{pin: pin, key: pins[pin], env: "AVERIN_AUTHORITY_KEYS"})
		}
	}
	return out
}

// parseAuthorityKeys parses AVERIN_AUTHORITY_KEYS: a comma-separated list of `[<project>:]<source>=<pubkey>`.
//
// Without a `project:` prefix the key is the GLOBAL default for that source (the historical form —
// unchanged, and source names contain no ':' so an existing value cannot be re-read as project-scoped).
// With one, the key is pinned for THAT averin project only and wins over the global default (F1: govder
// derives its authority key per (tenant, role) and its tenant is the averin project, so one global key per
// source can only ever elevate a single tenant).
//
// `delegate_signed` is accepted here (F2): it is a first-class verified source in the core and in
// WithPolicyEngineKey, and rejecting it left govder's delegate-agent approval records with no way to be
// pinned at all.
func parseAuthorityKeys(raw string) map[authorityPinEnv]ed25519.PublicKey {
	out := make(map[authorityPinEnv]ed25519.PublicKey, 2)
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		lhs, key, ok := strings.Cut(entry, "=")
		lhs = strings.TrimSpace(lhs)
		if !ok || lhs == "" {
			log.Fatalf("AVERIN_AUTHORITY_KEYS: %q is not a [project:]source=pubkey pair", part)
		}
		// Optional `project:` prefix. Project ids carry no ':' (AVERIN_API_KEYS already uses ':' as the
		// project/token separator), so the split is unambiguous.
		project := ""
		source := lhs
		if p, s, hasProject := strings.Cut(lhs, ":"); hasProject {
			project = strings.TrimSpace(p)
			source = strings.TrimSpace(s)
			if project == "" {
				log.Fatalf("AVERIN_AUTHORITY_KEYS: %q has an empty project (use source=pubkey for the global default)", part)
			}
		}
		switch source {
		case "policy_engine_signed", "human_signed", "delegate_signed":
		default:
			log.Fatalf("AVERIN_AUTHORITY_KEYS: unknown source %q (want policy_engine_signed, human_signed, or delegate_signed)", source)
		}
		pin := authorityPinEnv{project: project, source: source}
		if _, dup := out[pin]; dup {
			log.Fatalf("AVERIN_AUTHORITY_KEYS: source %q listed more than once for project %q", source, project)
		}
		pub, err := decodeAuthorityPubKey(strings.TrimSpace(key))
		if err != nil {
			log.Fatalf("AVERIN_AUTHORITY_KEYS (%s): %v", source, err)
		}
		out[pin] = pub
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
