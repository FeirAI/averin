# Configuration reference

Every environment variable / flag each averin binary reads, its default, whether it is required, and
the fail-closed behavior on a missing/invalid value. Verified against `server/cmd/*/main.go` and
the wiring in `server/internal/api/server.go`.

All keys are configured via **environment variables** (the `averin-taxonomy` tool is the exception —
it takes CLI flags). A general rule across the server: a **malformed** value for a security-relevant
key is **fatal at startup** (the process `log.Fatal`s) rather than silently disabling the feature —
e.g. a typo'd authority pubkey must not silently drop you back to forgeable `caller_declared`.

---

## `averin-server` (`server/cmd/averin-server`)

The ingestion + app API. Started with `./averin-server`.

> Every Ed25519 root seed below (`AVERIN_SIGNING_SEED`, `AVERIN_BROKER_ISSUING_SEED`,
> `AVERIN_RESOURCE_SEED`, `AVERIN_REVOCATION_SEED` — plus the AES master key
> `AVERIN_CONTENT_MASTER_KEY`) also accepts a `<NAME>_FILE` form pointing at a mounted secret
> file (e.g. a CSI/Kubernetes secret volume), keeping the seed off the env block. **Setting
> both the inline and `_FILE` form for the same name is fatal** ("set exactly one"); the
> `_FILE` target must be a regular, size-bounded file (a FIFO/device/dir/oversized file is
> fatal — symlinks are followed, so k8s/CSI secret files work); file contents are trimmed
> (mounted secrets carry a trailing newline).

### Core

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_SIGNING_SEED` (or `_FILE`) | — | **Yes** | 64 hex chars = 32-byte Ed25519 seed; the key all records/checkpoints are signed with. **Missing ⇒ fatal** (`log.Fatal`). Invalid (bad hex / wrong length) ⇒ fatal. Production backs signing with a KMS instead of a raw seed. |
| `AVERIN_SIGNING_KEY_ID` | `k0` | No | The `signing_key_id` stamped into each record's `key` block and the export key descriptor. |
| `AVERIN_ADDR` | `:8080` | No | Listen address (`host:port`). |

### Storage & durability

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_DATABASE_URL` | unset ⇒ **in-memory** | No (but see note) | Postgres DSN. When set, uses the append-only Postgres store. A persisted per-project guard row serializes each project write; the authoritative reads and inserts share one transaction and connection. At startup a single **versioned migration** (see "Schema versioning & upgrades" below) brings the DB to the current schema under an advisory lock. **Connection failure — or a DB newer than this binary — is fatal**: it refuses to silently fall back to a volatile store and lose evidence, and refuses to open a DB it might misread. Unset ⇒ in-memory store (NOT durable; logs a loud WARNING). The same project transaction owns durable consume-before-act claims and the signed use receipt. |
| `AVERIN_CONTENT_DIR` | unset ⇒ in-memory | No | Filesystem directory for the durable content store (the raw low-entropy `input`/`output`/`rationale` values committed at ingest, revealed on selective disclosure). Blobs are stored **AES-256-GCM encrypted at rest**, under a per-tenant subdirectory (`<dir>/tenant-<hash>/sha256-<hex>`); the per-tenant key is derived from `AVERIN_CONTENT_MASTER_KEY` via HMAC, with tenant+plaintext-digest as GCM additional-authenticated-data. Encryption is **at-rest only** — a disclosing export still ships the plaintext value, so offline verification is unchanged. A bad/uncreatable dir is fatal. Unset ⇒ in-memory (disclosures don't survive a restart; logs a WARNING). |
| `AVERIN_CONTENT_MASTER_KEY` (or `_FILE`) | — | **Yes** when `AVERIN_CONTENT_DIR` is set | 64 hex chars = 32-byte master key from which each tenant's content-encryption key is derived. **Missing/invalid with the dir set ⇒ fatal** (`log.Fatal`) — the content store never runs unencrypted. The `_FILE` form reads the value from a mounted secret file (setting both the inline and `_FILE` form is fatal). No effect when the content store is in-memory. |
| `AVERIN_RAW_RETENTION_DAYS` | `30` | No | Retention window for the encrypted raw payloads: a daily purge deletes blobs older than N days (by file mtime). Must be a positive integer (else fatal). Re-committing identical content refreshes its mtime, restarting the window. Purging removes only the raw opening material — the sealed record keeps its hiding commitment, so a post-purge export reports `raw_content_available:false` while the proofs stay verifiable. Only applies when `AVERIN_CONTENT_DIR` is set. |
| `AVERIN_WITNESS_DIR` | unset ⇒ no witness | No | Filesystem directory for a customer-controlled append-only checkpoint witness (`<dir>/<project>/checkpoint-<seq>.json`). Best-effort: a witness write failure is a warning, not fatal. Defends omission/rewrite (threats #1/#15). |
| `AVERIN_TSA_URL` | unset ⇒ no anchoring | No | URL of a third-party RFC 3161 timestamp authority. When set, sealed checkpoints are anchored with an RFC 3161 token (attached at export), defending backdating (threat #3). The verifier must pin this TSA's cert out-of-band (`tsa_keys` in `opts.json`) to trust the anchor. |
| `AVERIN_ATTESTATION_SEED` (or `_FILE`) | unset ⇒ no deployment attestation | Yes | 64 hex chars = role-separated Ed25519 issuer seed. When set, exports carry a signed `deployment_attestation` bound to the latest checkpoint. This alone does not make `/v2/verify` attested; the verifier roots below must also be independently pinned. |
| `AVERIN_VERIFY_ATTESTATION_PUBKEY` | unset ⇒ D7 unevaluated | No | Comma-separated `ed25519pub:` issuer keys pinned out of band by the operator/auditor. Must be configured together with `AVERIN_VERIFY_TSA_SPKI_B64`; partial configuration is fatal. |
| `AVERIN_VERIFY_TSA_SPKI_B64` | unset ⇒ D7 unevaluated | No | Comma-separated base64url-no-pad DER SubjectPublicKeyInfo values from the chosen RFC 3161 TSA signing certificate. These public roots make the product-facing `/v2/verify` endpoint evaluate the timestamp and attestation instead of trusting producer-supplied cert material. |
| `AVERIN_VERIFY_TAXONOMY_FILE` | unset ⇒ D4 absent | No | Path to the signed operation-taxonomy JSON artifact. Must be configured with the issuer key, digest, and version below; a partial tuple is fatal. |
| `AVERIN_VERIFY_TAXONOMY_PUBKEY` | unset ⇒ D4 absent | No | Comma-separated role-separated Ed25519 taxonomy issuer keys pinned out of band. |
| `AVERIN_VERIFY_TAXONOMY_DIGEST` | unset ⇒ D4 absent | No | Canonical `sha256:` digest emitted by `averin-taxonomy`, pinning the exact signed artifact. |
| `AVERIN_VERIFY_TAXONOMY_VERSION` | unset ⇒ D4 absent | No | Positive taxonomy version emitted by `averin-taxonomy`; the verifier requires it to match the artifact. |
| `AVERIN_COVERAGE_MANIFEST` | unset | No | Valid JSON operator declaration emitted in exports and cryptographically bound into the attestation. Required for the D8 completeness-over-declared-brokered-surface capstone; it does not turn a declaration into observed runtime fact. |

#### Schema versioning & upgrades

averin's three Postgres-backed stores — the append-only evidence store, the consume-before-act ledger,
and the durable revocation / two-phase grant state — share the one `AVERIN_DATABASE_URL`. At startup a
single **versioned migration runner** (`server/internal/pgschema`) brings that DB to the schema version
this binary understands, under a `pg_advisory_xact_lock` so two replicas booting against one DB (a
rolling deploy) cannot race the DDL. It writes one `schema_migrations(version int PRIMARY KEY, applied_at
timestamptz)` ledger for the whole averin DB, so an operator sees **one** version, not three. (It is
named `schema_migrations`, distinct from the flight-recorder record's own `schema_version` field.)

The runner reads the stored version (an existing **unstamped** DB reads as `0`) and:

- **stored < binary** ⇒ applies the ordered forward steps and stamps each in the same transaction as its
  DDL (a crash can never leave version-ahead-of-schema). An unstamped DB adopts version 1, whose step is
  exactly today's idempotent `CREATE ... IF NOT EXISTS` baseline — **a no-op on existing data** (no
  rebuild, no drop); just take a backup first, as always.
- **stored == binary** ⇒ no-op; a steady-state boot issues **zero DDL**. This is what lets the runtime
  role drop `CREATE`/`ALTER` (run migrations as a privileged role, the server as a least-privilege one;
  see the append-only role split in `migrations/0001_init.sql`).
- **stored > binary** ⇒ **fatal, fail-closed refusal to start.** averin's evidence is immutable, so a
  binary older than the DB never re-migrates it backward or risks misreading it. **Downgrades are not
  supported**: to roll back a schema change, roll the DB back from a backup taken before the upgrade,
  then start the older binary against it.

**To add a migration:** bump `CurrentSchemaVersion` and append one ordered DDL step in
`server/internal/pgschema` — it is a version stamp, not a framework.

Versions: **1** is the baseline above; **2** (`migrations/0002_record_id_unique.sql`) adds a per-project
`record_id` uniqueness index (an expression index over the sealed JSON — no new column, no row rewrite).
If the DB already holds a historical duplicate `record_id`, v2 still applies but builds a non-unique index
and logs a `WARNING`; new duplicates are still rejected by the application.

### Authentication (project-scoped API keys)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_API_KEYS` | unset ⇒ **no auth** | No | Project-scoped API keys in the form `proj-a:tok1,tok2;proj-b:tok3`. When set, every `/v2/*` route is gated; `/healthz` stays open. If set but parses to **zero** keys ⇒ **fatal** (refuses to start in a silent deny-all). Unset ⇒ the app API is **UNAUTHENTICATED** (dev/single-tenant; logs a WARNING). See [SECURITY.md](SECURITY.md) for the auth model and its Phase-1 limits. |

### Authority elevation (external authority keys, T7)

These pin **external** authorities' published verifying keys so a generic record carrying a matching
`authority.source` + a verifying `evidence_sig` is **elevated** to that verified source at ingest
(else it is forced to the forgeable `caller_declared`, threat #4). Each key may be hex (64 chars) or
base64url-no-pad (optionally with the `ed25519pub:` prefix). The private half stays out of this
server — averin only **verifies**. **A bad pubkey or a duplicate-pinned (project, source) is fatal.**
The three valid sources are `policy_engine_signed`, `human_signed`, and `delegate_signed`.

Pins are keyed by **(project, source)**. An un-prefixed pin is the **global default** for that source
(the historical single-key behavior); a `project:`-prefixed pin applies to that averin project only and
**wins** over the global default. This matters because govder derives its authority signing key per
**(tenant, role)** and a govder tenant *is* an averin project: a deployment recording more than one
tenant MUST pin each tenant's key against its project, or every tenant but one has its
kill/approval/policy evidence rejected (or, under the explicit fail-open opt-out, silently sealed at
`caller_declared`). Derive a tenant's three pubkeys with
`GOVDER_AUTHORITY_SEED=... go run ./cmd/govder-derive-pubkeys <tenant>` in govder.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_POLICY_ENGINE_PUBKEY` | unset | No | Pins one **global** key for the source named by `AVERIN_POLICY_ENGINE_SOURCE`. Bad value ⇒ fatal. |
| `AVERIN_POLICY_ENGINE_SOURCE` | `policy_engine_signed` | No | The source the above key vouches for. |
| `AVERIN_HUMAN_SIGNED_PUBKEY` | unset | No | Pins one **global** key for the `human_signed` source (e.g. a separate human-approval service, signing with a different key than the policy engine). Bad value ⇒ fatal. |
| `AVERIN_DELEGATE_SIGNED_PUBKEY` | unset | No | Pins one **global** key for the `delegate_signed` source (govder's delegate-agent approval records). This is the third value `govder-derive-pubkeys` prints. Bad value ⇒ fatal. |
| `AVERIN_AUTHORITY_KEYS` | unset | No | General `[project:]source=pubkey,...` list (sources: `policy_engine_signed`, `human_signed`, `delegate_signed`). Without a `project:` prefix the key is the global default for that source; with one it is pinned for that project only. A malformed entry, an unknown source, an empty project, or a duplicate `(project, source)` is fatal. Pinning the **same** `(project, source)` twice across any of these forms is a fatal config error. |
| `AVERIN_REQUIRE_PINNED_AUTHORITY` | **`1` (on)** | No | **Fail-closed authority posture (the default).** A record that CLAIMS an elevated source (`policy_engine_signed`/`human_signed`/`delegate_signed`) whose `evidence_sig` fails to verify under the key pinned for its `(project, source)` — or whose source is **unpinned for that project** — is **REJECTED** with a retryable `500` instead of silently sealed downgraded to the forgeable `caller_declared`. `0`/`false` is the **explicit fail-OPEN opt-out** (restores the Phase-1 silent downgrade + a rate-limited WARNING + the `averin_authority_downgrades_total` counter) and logs a loud WARNING naming what that means; any other value is **fatal** (a typo must not select a security posture). Ordinary `caller_declared` traffic is never affected either way. |

Every pinned authority key must be role-separated (it is rejected if it equals the server signing
key or the resource key, or if one key is reused across two **sources**; the same key across two
**projects** for the same source is allowed — the preimage binds `project_id`).

#### Migration: the fail-closed default (was off before)

`AVERIN_REQUIRE_PINNED_AUTHORITY` used to default to `0`, and no shipped config set it. Upgrading a
running deployment therefore **changes behavior** wherever a producer claims an authority averin cannot
verify: what was a silent downgrade-and-seal is now a `500` and no record. Before upgrading:

1. **Inventory the producers.** Only records whose `authority.source` is `policy_engine_signed`,
   `human_signed`, or `delegate_signed` are affected. Plain `caller_declared` traffic (SDKs, OTel spans)
   is not. `averin_authority_downgrades_total` on the running server counts exactly the records that
   would now be rejected — **if it is 0, the flip is a no-op for you.**
2. **Pin every producing (project, source).** For govder: run `govder-derive-pubkeys` **per tenant** and
   pin the three pubkeys with the `project:` prefix. `delegate_signed` in particular had no configuration
   path at all before this release, so any deployment recording delegate-agent approvals must add it.
3. **Only if you cannot align the pins immediately**, set `AVERIN_REQUIRE_PINNED_AUTHORITY=0` as a
   temporary, explicit step — and understand that kill/approval/policy evidence recorded in that mode is
   not cryptographically distinguishable from a forgery.

Whether or not the fail-closed toggle is on, a **failed** elevation increments
`averin_authority_downgrades_total` and emits a rate-limited `WARNING` naming the claimed source and
the pinned-key id — so a govder/averin key misalignment is visible in both metrics and logs.

### Credential broker (Level 3 Tier-A — `POST /v2/grants`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_BROKER_ISSUING_SEED` (or `_FILE`) | unset ⇒ broker disabled | No | 64-hex (32-byte) Ed25519 seed; the key that signs the minted capabilities. Bad value ⇒ fatal. Unset ⇒ `POST /v2/grants` returns `501 Not Implemented`. The recording key for the grant's `gateway_enforced` evidence is the server's own signing key (Tier-A `broker_trust: assumed`). |
| `AVERIN_BROKER_SEQ_VOID_MIN_AGE` | `1h` | No | Safety age a reserved-but-unrecorded `broker_seq` must reach before `POST /v2/broker-seq/void` may fill it with a signed `grant_void` tombstone (the operator remediation for a checkpoint refused over a broker_seq gap). A Go duration; below the floor of `20m` (it must exceed any in-flight commit and the 15-minute two-phase pending window) or unparseable ⇒ fatal. The age runs from the latest of the reservation (`allocated_at`, the Postgres clock), the grant's latest attempt on this server and the server's start (attempt times are in memory), so keep it far above any DB-to-app clock skew. Requires the broker. |
| `AVERIN_BROKER_ID` | unset | No | This broker's federation identity (ADR 0005 M4). When set, grants carry `grant_evidence.broker_id` and checkpoints carry a per-broker `broker_grant_heads` map (verify under `federated_broker_keys[<id>]`). Requires the broker. |

### Online M-of-N cosign policy (`POST /v2/grants/prepare` + `/finalize`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_COSIG_APPROVER_KEYS` | unset ⇒ cosig off | No | Comma-separated base64url-no-pad Ed25519 approver pubkeys (optional `ed25519pub:` prefix). Requires the broker (fatal otherwise). Parsing to zero keys, or a malformed key, is fatal. When set, single-phase `POST /v2/grants` is refused (would bypass cosig) — issuance must use the two-phase prepare/finalize flow. |
| `AVERIN_COSIG_THRESHOLD` | = number of approvers | No | The M in M-of-N. Must be an integer in `[1, len(approvers)]`; otherwise fatal. |

### Resource gateway (Level 3 Tier-B — `POST /v2/use`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_RESOURCE_SEED` (or `_FILE`) | unset ⇒ `/v2/use` disabled | No | 64-hex (32-byte) Ed25519 seed for the resource recording key, which signs use-receipt evidence. **Must be role-separated**: distinct from `AVERIN_SIGNING_SEED` and `AVERIN_BROKER_ISSUING_SEED` (checked by derived pubkey — fatal on overlap). Requires the broker (fatal otherwise). Also enables `POST /v2/introspection` (native/STS, M3) with the raw resource key. |
| `AVERIN_RESOURCE_ID` | — | **Yes** when `AVERIN_RESOURCE_SEED` is set | This resource's audience id. Missing (with the seed set) ⇒ fatal. |

When the resource gateway is on, replay claims and the receipt use the configured
project Store transaction. PostgreSQL makes both durable; in-memory mode is
volatile and reopens a replay window on restart. `pgledger` runs the retention
sweeper and its own readiness probe, not a separate request-time claim path.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_LEDGER_RETENTION` | `720h` (30 days) | No | TTL for the Postgres consume-before-act ledger. A background hourly sweep deletes consumed `nonce`/`jti` rows older than this (the ledger otherwise grows one row per PoP nonce + per credential double-spend key, forever). **This is a correctness parameter, not tuning:** it MUST exceed the longest credential validity window (`broker.MaxTTL` = 1h) — a value that prunes a still-live nonce/jti would reopen the single-use replay this ledger closes. A configured value **below the 24h safe floor is fatal at startup**; a non-positive/malformed duration is fatal. Only applies with the durable (Postgres) ledger. |

### Revocation authority (`POST /v2/revoke`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_REVOCATION_SEED` (or `_FILE`) | unset ⇒ revocation off | No | 64-hex (32-byte) Ed25519 seed for the revocation issuer. Bad value ⇒ fatal. **Must differ from the signing/broker/resource seeds** (role separation) ⇒ fatal otherwise. When set, `POST /v2/revoke` marks a `grant_id` revoked and every `/v2/export` carries a signed, time-bounded `revocation_list`. The revoked set (and, when the M6/M2 online two-phase grant flow is used, the pending prepare→finalize mint state) is **durable Postgres-backed** if `AVERIN_DATABASE_URL` is set — a revoke or an in-flight cosig/delegation approval survives a pod restart or `SIGTERM` — else in-memory only (a revoke issued or a mint prepared just before restart is forgotten). |

### Metering (Stripe)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `STRIPE_API_KEY` | unset ⇒ local counting only | No | When set, usage (records ingested, exports issued) is reported to Stripe. Unset ⇒ usage is counted locally only (visible via `GET /v2/usage`). |

**Metering loss bounds (best-effort, volatile — read before relying on it for revenue).** The base
usage counter is **in-memory** (`meter.Mem`) and the Stripe reporter is best-effort. The exact,
deliberate loss modes:

- **Restart re-grants the free tier.** The counter is not durable, so on a process restart every
  project's `records` count resets to 0 and the first `FreeTierRecords` (1000) records are billed as
  free **again**. Under-billing is bounded by `free_tier × restarts`.
- **Queue-full drops.** Billable events are forwarded over a bounded async queue; under a Stripe
  outage/overload the queue fills and further events are **dropped, not retried**. Surfaced on
  `GET /metrics` as **`averin_meter_queue_drops_total`** (a growing value ⇒ silently lost revenue).
- **Delivery-failure drops.** A meter-event POST that gets a transport error or a **non-2xx** (most
  often an unmapped `project → stripe_customer_id` — averin maps `project` verbatim onto
  `stripe_customer_id`) is logged and **dropped, not retried**. Surfaced on `GET /metrics` as
  **`averin_meter_post_failures_total`**. Map every project to a real Stripe customer id out-of-band
  and **alert on both counters**.

**Deferred (documented, not built):** a durable per-project counter (a Postgres table beside the store,
surviving restart) + **idempotent, retried** Stripe delivery (meter-event ids) would close all three
losses. Until then treat metering as advisory and reconcile against Stripe.

### Operational hardening (prod secret gate, egress scrubbing, graceful shutdown)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_REQUIRE_PROD_SECRETS` | `0` (off) | No | **Fail-closed prod gate.** When on (`1`/`true`), refuses to start unless `AVERIN_API_KEYS` is set (else the app API would be UNAUTHENTICATED), `AVERIN_DATABASE_URL` is set (else the store would be volatile in-memory, reopening a `/v2/use` replay window), and `AVERIN_SIGNING_SEED` is **not** the well-known committed dev seed (a globally-known, forgeable integrity root). Any of the three missing/failing is fatal (`log.Fatal`, names each missing one). Mirrors govder's `GOVDER_REQUIRE_AUTHORITY_SEED` and leria's `LERIA_REQUIRE_PROD_SECRETS`. Off preserves the fail-open Phase-1 default (each condition individually just logs a WARNING). |
| `AVERIN_SECRET_PATTERNS` | unset ⇒ built-in patterns only | No | JSON string array of extra RE2 regexes, atomically appended to the built-in credential-scrubbing rules (`server/internal/scrub`) that redact provider API keys, PEM private keys, JWTs, `Bearer`/`Basic` auth, generic `key: value` secrets, and high-entropy hex from captured I/O before it is stored or hashed. Each match is replaced with `[REDACTED:configured]`. **A malformed pattern (bad regex) is fatal at startup** — a typo must not silently create a secret-capture gap. Scrubbing is defense-in-depth (RE2 is linear-time / no ReDoS, but cannot catch every secret shape); the primary protection is that self-hosted data never leaves customer infra. |
| `AVERIN_SHUTDOWN_TIMEOUT` | `25s` | No | Graceful-drain deadline on SIGINT/SIGTERM: `http.Server.Shutdown` lets in-flight requests (and, with `AVERIN_DATABASE_URL` set, the cross-request prepare→finalize window) finish before exit, then flushes the async Stripe meter queue and closes the store pool — all within this deadline. An unparseable or non-positive value logs a warning and keeps the default. **Must stay under the orchestrator's stop grace** (the shipped Kubernetes manifest sets `terminationGracePeriod=30s`; for docker-compose set `stop_grace_period >=` this) or the process is SIGKILLed mid-drain. `averin-proxy` reads the same variable with a different default (`60s`, below — it streams long completions and needs more room to drain). |

### Deployment hard requirements (rate limit + storage growth)

The app API is **Phase-1**: no per-project authz or storage quota of its own, and the record store is
**append-only** (nothing can be deleted). Two operator controls are therefore **hard requirements**, not
options (see [LIMITATIONS.md](LIMITATIONS.md) *Storage growth is unbounded*):

- **Put a reverse-proxy / API-gateway rate limit in front of averin.** This is the PRIMARY defense
  against a leaked token (or an unauthenticated dev-posture deploy) driving unbounded billable,
  append-only DB growth. As an **opt-in** in-process backstop the server library exposes
  `WithIngestBudget(IngestBudget{...})` — a coarse per-project + global token bucket that answers `429`
  on state-mutating `POST /v2/*` ingest (GET reads pass through). It is **off by default** (so no
  existing deployment is throttled) and is **defense-in-depth**, never a substitute for the gateway
  limit. Not yet exposed as an `averin-server` env var — wire it via an embedder (like `WithDeniedGrantLog`).
- **Monitor database growth and alert on capacity.** Storage only ever grows; there is no in-store
  eviction. Watch DB size / per-project record counts and alert well before exhaustion.

> Note on options not exposed as env vars in the binary: the server library
> (`server/internal/api`) also supports `WithAttestation` (deployment-attestation export) and
> `WithCoverageManifest` (the operator-declared `side_effect_closure`, required for the
> `attested_complete_over_brokered_surface` capstone), `WithDeniedGrantLog` (B11), and the two rate
> backstops `WithIngestBudget` (coarse per-project ingest `429`, above) and `WithDeniedGrantBudget`
> (bounds best-effort B11 denial seals). These are wired by embedders / the e2e harness, not by a
> `averin-server` env var in the current `main.go`.

---

## `averin-proxy` (`server/cmd/averin-proxy`)

OpenAI-compatible reverse proxy that records `llm_call` evidence to a averin server.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_UPSTREAM` | `https://api.openai.com` | No | Upstream LLM base URL. |
| `AVERIN_SERVER_URL` | `http://localhost:8080` | No | The averin server to record evidence to. |
| `AVERIN_PROJECT_ID` | `default` | No | Project the proxied calls are recorded under. |
| `AVERIN_PROXY_ADDR` | `:8081` | No | Inbound listen address. |
| `AVERIN_PROXY_AVERIN_TOKEN` | unset | No | API token used when recording to the averin server (needed if the server has `AVERIN_API_KEYS` set). |
| `AVERIN_PROXY_INBOUND_TOKEN` | unset | No | If set, inbound auth is REQUIRED (`X-Averin-Proxy-Token` or `Authorization: Bearer`). **Unset ⇒ OPEN RELAY + evidence-injection surface** (logs a WARNING — bind to loopback or place behind your own auth). |
| `AVERIN_SHUTDOWN_TIMEOUT` | `60s` | No | Graceful-drain deadline on SIGINT/SIGTERM: `http.Server.Shutdown` lets active streamed completions finish before exit (an instant kill would cut an agent's in-flight response). Longer than `averin-server`'s default (25s) since completions stream. An unparseable or non-positive value logs a warning and keeps the default. Must stay under the orchestrator's stop grace. |

---

## `averin-mcp` (`server/cmd/averin-mcp`)

Experimental MCP server over stdio, exposing averin to agents as tools.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_SERVER_URL` | `http://localhost:8080` | No | The averin server the MCP tools call. |

---

## `averin-taxonomy` (`server/cmd/averin-taxonomy`)

CLI tool that mints a **signed operation taxonomy** artifact (D4). Flags (`flag` package):

| Flag | Default | Meaning |
|------|---------|---------|
| `-key` | — | Taxonomy issuer signing key: 64 hex chars (a 32-byte Ed25519 seed). |
| `-key-file` | — | Owner-only regular file (mode `0600`) containing the 64-hex seed. Exactly one of `-key` or `-key-file` is required; deployments should use the file form so the seed never enters argv. |
| `-version` | `1` | Taxonomy version (bump to rotate; pinned as `taxonomy_version`). |
| `-from` | `0` | `effective_from`, unix seconds. |
| `-until` | `0` | `effective_until`, unix seconds (must be `>= from`). |
| `-out` | stdout | Write the signed taxonomy JSON here. |
| `-single` | — | A `single_operation` entry `resource_id=action` (repeatable). |
| `-escalating` | — | An escalating entry `resource_id=action` (repeatable). |

---

## `averin-verify` CLI (`core/src/bin/averin_verify.rs`)

Not env-configured; arguments only:

```
averin-verify bundle <bundle.json> [opts.json]    # full offline verification
averin-verify record <record.json> [ed25519pub:<key>]   # single record (integrity, or authentic with a key)
```

With `opts.json`, the role-disjoint authority key sets are pinned (authentic verification + the
mode gates). The `opts.json` keys are documented in [`../operator-verification.md`](../operator-verification.md):
`broker_authority_keys`, `resource_authority_keys`, `tsa_keys`, `taxonomy`/`taxonomy_keys`/
`taxonomy_digest`/`taxonomy_version`, `attestation_keys`, `cosig_approver_keys`, `revocation_keys`,
`federated_broker_keys` (a `{broker_id: [keys]}` map), and `authority_keys`. Exit codes: `0` PASS,
`1` FAIL, `2` usage/IO error.

---

## Docker Compose extras (`deploy/docker-compose.yml`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `AVERIN_DB_PASSWORD` | `averin` | Postgres password (and folded into the server's `AVERIN_DATABASE_URL`). |
| `AVERIN_SIGNING_SEED` | **none — required** | Server signing seed. Compose uses `${AVERIN_SIGNING_SEED:?...}`, so `docker compose up` refuses to start without it; generate a fresh one with `openssl rand -hex 32`. |
| `AVERIN_PROXY_INBOUND_TOKEN` | **none — required** | Inbound auth token for `averin-proxy`. Compose uses `${AVERIN_PROXY_INBOUND_TOKEN:?...}`, so the stack refuses to start without it (without it the proxy would be an open relay); generate one with `openssl rand -hex 24`. |
| `AVERIN_UPSTREAM` | `https://api.openai.com` | Overrides the proxy's upstream LLM base URL. |
| `AVERIN_PROJECT_ID` | `default` | Overrides the project the proxied calls are recorded under. |

`stop_grace_period` is set per service to exceed `AVERIN_SHUTDOWN_TIMEOUT`'s default for that
binary (`server`: 30s > the 25s default; `proxy`: 65s > the 60s default) — raise both together if
you override `AVERIN_SHUTDOWN_TIMEOUT`.
