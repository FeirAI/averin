# Configuration reference

Every environment variable / flag each feir binary reads, its default, whether it is required, and
the fail-closed behavior on a missing/invalid value. Verified against `server/cmd/*/main.go` and
the wiring in `server/internal/api/server.go`.

All keys are configured via **environment variables** (the `feir-taxonomy` tool is the exception —
it takes CLI flags). A general rule across the server: a **malformed** value for a security-relevant
key is **fatal at startup** (the process `log.Fatal`s) rather than silently disabling the feature —
e.g. a typo'd authority pubkey must not silently drop you back to forgeable `caller_declared`.

---

## `feir-server` (`server/cmd/feir-server`)

The ingestion + app API. Started with `./feir-server`.

### Core

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_SIGNING_SEED` | — | **Yes** | 64 hex chars = 32-byte Ed25519 seed; the key all records/checkpoints are signed with. **Missing ⇒ fatal** (`log.Fatal`). Invalid (bad hex / wrong length) ⇒ fatal. Production backs signing with a KMS instead of a raw seed. |
| `FEIR_SIGNING_KEY_ID` | `k0` | No | The `signing_key_id` stamped into each record's `key` block and the export key descriptor. |
| `FEIR_ADDR` | `:8080` | No | Listen address (`host:port`). |

### Storage & durability

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_DATABASE_URL` | unset ⇒ **in-memory** | No (but see note) | Postgres DSN. When set, uses the append-only Postgres store (auto-applies the idempotent schema on startup, runs the ingest critical section in a serializable transaction). **Connection failure is fatal** — it refuses to silently fall back to a volatile store and lose evidence. Unset ⇒ in-memory store (NOT durable; logs a loud WARNING). Also enables the durable consume-before-act ledger for the resource gateway when that is configured. |
| `FEIR_CONTENT_DIR` | unset ⇒ in-memory | No | Filesystem directory for the durable content store (the raw low-entropy `input`/`output`/`rationale` values committed at ingest, revealed on selective disclosure). A bad/uncreatable dir is fatal. Unset ⇒ in-memory (disclosures don't survive a restart; logs a WARNING). |
| `FEIR_WITNESS_DIR` | unset ⇒ no witness | No | Filesystem directory for a customer-controlled append-only checkpoint witness (`<dir>/<project>/checkpoint-<seq>.json`). Best-effort: a witness write failure is a warning, not fatal. Defends omission/rewrite (threats #1/#15). |
| `FEIR_TSA_URL` | unset ⇒ no anchoring | No | URL of a third-party RFC 3161 timestamp authority. When set, sealed checkpoints are anchored with an RFC 3161 token (attached at export), defending backdating (threat #3). The verifier must pin this TSA's cert out-of-band (`tsa_keys` in `opts.json`) to trust the anchor. |

### Authentication (project-scoped API keys)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_API_KEYS` | unset ⇒ **no auth** | No | Project-scoped API keys in the form `proj-a:tok1,tok2;proj-b:tok3`. When set, every `/v2/*` route is gated; `/healthz` stays open. If set but parses to **zero** keys ⇒ **fatal** (refuses to start in a silent deny-all). Unset ⇒ the app API is **UNAUTHENTICATED** (dev/single-tenant; logs a WARNING). See [SECURITY.md](SECURITY.md) for the auth model and its Phase-1 limits. |

### Authority elevation (external authority keys, T7)

These pin **external** authorities' published verifying keys so a generic record carrying a matching
`authority.source` + a verifying `evidence_sig` is **elevated** to that verified source at ingest
(else it is forced to the forgeable `caller_declared`, threat #4). Each key may be hex (64 chars) or
base64url-no-pad (optionally with the `ed25519pub:` prefix). The private half stays out of this
server — feir only **verifies**. **A bad pubkey or a duplicate-pinned source is fatal.** The only
two valid sources are `policy_engine_signed` and `human_signed`.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_POLICY_ENGINE_PUBKEY` | unset | No | Pins one key for the source named by `FEIR_POLICY_ENGINE_SOURCE`. Bad value ⇒ fatal. |
| `FEIR_POLICY_ENGINE_SOURCE` | `policy_engine_signed` | No | The source the above key vouches for. |
| `FEIR_HUMAN_SIGNED_PUBKEY` | unset | No | Pins one key for the `human_signed` source (e.g. a separate human-approval service, signing with a different key than the policy engine). Bad value ⇒ fatal. |
| `FEIR_AUTHORITY_KEYS` | unset | No | General `source=pubkey,source=pubkey` list (sources: `policy_engine_signed`, `human_signed`). A malformed entry, an unknown source, or a duplicate source is fatal. Pinning the **same** source twice across any of these three forms is a fatal config error. |

Every pinned authority key must be role-separated (it is rejected if it equals the server signing
key or the resource key, or if one key is reused across two sources).

### Credential broker (Level 3 Tier-A — `POST /v2/grants`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_BROKER_ISSUING_SEED` | unset ⇒ broker disabled | No | 64-hex (32-byte) Ed25519 seed; the key that signs the minted capabilities. Bad value ⇒ fatal. Unset ⇒ `POST /v2/grants` returns `501 Not Implemented`. The recording key for the grant's `gateway_enforced` evidence is the server's own signing key (Tier-A `broker_trust: assumed`). |
| `FEIR_BROKER_ID` | unset | No | This broker's federation identity (ADR 0005 M4). When set, grants carry `grant_evidence.broker_id` and checkpoints carry a per-broker `broker_grant_heads` map (verify under `federated_broker_keys[<id>]`). Requires the broker. |

### Online M-of-N cosign policy (`POST /v2/grants/prepare` + `/finalize`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_COSIG_APPROVER_KEYS` | unset ⇒ cosig off | No | Comma-separated base64url-no-pad Ed25519 approver pubkeys (optional `ed25519pub:` prefix). Requires the broker (fatal otherwise). Parsing to zero keys, or a malformed key, is fatal. When set, single-phase `POST /v2/grants` is refused (would bypass cosig) — issuance must use the two-phase prepare/finalize flow. |
| `FEIR_COSIG_THRESHOLD` | = number of approvers | No | The M in M-of-N. Must be an integer in `[1, len(approvers)]`; otherwise fatal. |

### Resource gateway (Level 3 Tier-B — `POST /v2/use`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_RESOURCE_SEED` | unset ⇒ `/v2/use` disabled | No | 64-hex (32-byte) Ed25519 seed for the resource recording key, which signs use-receipt evidence. **Must be role-separated**: distinct from `FEIR_SIGNING_SEED` and `FEIR_BROKER_ISSUING_SEED` (checked by derived pubkey — fatal on overlap). Requires the broker (fatal otherwise). Also enables `POST /v2/introspection` (native/STS, M3) with the raw resource key. |
| `FEIR_RESOURCE_ID` | — | **Yes** when `FEIR_RESOURCE_SEED` is set | This resource's audience id. Missing (with the seed set) ⇒ fatal. |

When the resource gateway is on, the consume-before-act ledger is **durable Postgres-backed** if
`FEIR_DATABASE_URL` is set, else an in-memory (volatile) ledger (logs a WARNING that a single-use
replay window reopens on restart).

### Revocation authority (`POST /v2/revoke`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_REVOCATION_SEED` | unset ⇒ revocation off | No | 64-hex (32-byte) Ed25519 seed for the revocation issuer. Bad value ⇒ fatal. **Must differ from the signing/broker/resource seeds** (role separation) ⇒ fatal otherwise. When set, `POST /v2/revoke` marks a `grant_id` revoked and every `/v2/export` carries a signed, time-bounded `revocation_list`. The revoked set is in-memory in Phase 1 (a production deployment persists it). |

### Metering (Stripe)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `STRIPE_API_KEY` | unset ⇒ local counting only | No | When set, usage (records ingested, exports issued) is reported to Stripe. Unset ⇒ usage is counted locally only (visible via `GET /v2/usage`). |

> Note on options not exposed as env vars in the binary: the server library
> (`server/internal/api`) also supports `WithAttestation` (deployment-attestation export) and
> `WithCoverageManifest` (the operator-declared `side_effect_closure`, required for the
> `attested_complete_over_brokered_surface` capstone) and `WithDeniedGrantLog` (B11). These are
> wired by embedders / the e2e harness, not by a `feir-server` env var in the current `main.go`.

---

## `feir-proxy` (`server/cmd/feir-proxy`)

OpenAI-compatible reverse proxy that records `llm_call` evidence to a feir server.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_UPSTREAM` | `https://api.openai.com` | No | Upstream LLM base URL. |
| `FEIR_SERVER_URL` | `http://localhost:8080` | No | The feir server to record evidence to. |
| `FEIR_PROJECT_ID` | `default` | No | Project the proxied calls are recorded under. |
| `FEIR_PROXY_ADDR` | `:8081` | No | Inbound listen address. |
| `FEIR_PROXY_FEIR_TOKEN` | unset | No | API token used when recording to the feir server (needed if the server has `FEIR_API_KEYS` set). |
| `FEIR_PROXY_INBOUND_TOKEN` | unset | No | If set, inbound auth is REQUIRED (`X-Feir-Proxy-Token` or `Authorization: Bearer`). **Unset ⇒ OPEN RELAY + evidence-injection surface** (logs a WARNING — bind to loopback or place behind your own auth). |

---

## `feir-mcp` (`server/cmd/feir-mcp`)

Experimental MCP server over stdio, exposing feir to agents as tools.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `FEIR_SERVER_URL` | `http://localhost:8080` | No | The feir server the MCP tools call. |

---

## `feir-taxonomy` (`server/cmd/feir-taxonomy`)

CLI tool that mints a **signed operation taxonomy** artifact (D4). Flags (`flag` package):

| Flag | Default | Meaning |
|------|---------|---------|
| `-key` | — | Taxonomy issuer signing key: 64 hex chars (a 32-byte Ed25519 seed). |
| `-version` | `1` | Taxonomy version (bump to rotate; pinned as `taxonomy_version`). |
| `-from` | `0` | `effective_from`, unix seconds. |
| `-until` | `0` | `effective_until`, unix seconds (must be `>= from`). |
| `-out` | stdout | Write the signed taxonomy JSON here. |
| `-single` | — | A `single_operation` entry `resource_id=action` (repeatable). |
| `-escalating` | — | An escalating entry `resource_id=action` (repeatable). |

---

## `feir-verify` CLI (`core/src/bin/feir_verify.rs`)

Not env-configured; arguments only:

```
feir-verify bundle <bundle.json> [opts.json]    # full offline verification
feir-verify record <record.json> [ed25519pub:<key>]   # single record (integrity, or authentic with a key)
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
| `FEIR_DB_PASSWORD` | `feir` | Postgres password (and folded into the server's `FEIR_DATABASE_URL`). |
| `FEIR_SIGNING_SEED` | a dev default (override!) | Server signing seed. |
