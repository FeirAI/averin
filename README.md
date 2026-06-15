# feir — Flight Recorder for AI Agents

> **Verifiable incident reconstruction for production agents.** When an agent costs you
> $900 overnight, goes off-script, or does something destructive, you get a tamper-evident,
> replayable record of *what was observed, why, and under whose declared authority* — that
> you (and later an auditor) can independently verify, offline, anchored to a third-party
> timestamp.

Accountability, not just observability. Apache-2.0, self-hostable.

## The claim we actually make (and its limits)

A signed, hash-chained record proves **provenance and integrity**, not **reality**. We prove:

> a specific observed event record was sealed by a specific tenant-controlled key, has not
> been altered since sealing, is linked into a verifiable run history, and was accompanied by
> declared (and where available, independently verified) authority evidence.

Three honest trust levels (used verbatim in product copy):

| Level | Claim | Phase 1 |
|-------|-------|---------|
| **1 Record integrity** | sealed by this key, unchanged since | **Yes** |
| **2 Event observation** | this event was observed by us | **Partial** (explicit coverage limits) |
| **3 Complete accountability** | this is *everything* the agent did | **Not yet** (needs the credential broker) |

## Monorepo layout

| Path | What |
|------|------|
| `core/` | **Rust `decision-core`** — canonicalize → commit → hash → sign → DAG-link → checkpoint → verify. One crate → FFI lib + verify CLI + WASM. The single source of truth. |
| `proxy/` | Go: OpenAI-compatible reverse proxy + ingestion |
| `server/` | Go: app API, MCP server, x402 meter, export, anchoring |
| `web/` | Svelte 5 + Vite SPA (client-only) — trace-waterfall run view |
| `verifier/` | Vanilla TS + WASM standalone offline verifier (no framework) |
| `landing/` | Separate static marketing site (3D-DAG hero, deps quarantined) |
| `sdk/python`, `sdk/typescript` | Client SDKs |
| `cli/` | verify CLI distribution (wraps `core`) |
| `spec/` | **schema v2, RCP v1, golden vectors, adversarial fixtures** |
| `deploy/` | docker-compose self-host |
| `docs/` | quickstart, coverage limits, verification guide, ADRs |

## Status

**Phase 1 M0–M4 are built, tested, and reviewed** — see [`docs/PHASE1-TASKS.md`](docs/PHASE1-TASKS.md).
Every piece was Codex-reviewed before commit. End to end:

- **Integrity core** (Rust) — canonicalize → commit → hash → sign → DAG-link → checkpoint → anchor
  → verify, from one crate to **three targets**: verify CLI, WASM, and cgo FFI. Golden vectors;
  real RFC 3161 (DER/CMS) anchoring.
- **Go server** (cgo → core) — ingestion (`/v2/records`, idempotency, DAG-linking, sealing),
  app/verify/export API, OpenAI-compatible recording proxy (secret-scrubbed), Stripe metering,
  MCP server, experimental x402.
- **SDKs** — Python + TypeScript. **Web** — Svelte 5 SPA (trace waterfall) + a frameworkless
  **offline verifier** (vanilla + WASM). **Self-host** — `docker compose up`.

Adversarial matrix defended & tested: **#1, #2, #3, #4, #6, #7, #8, #9, #10, #11** plus tamper —
with Phase 2 closing #4 (*declared → verified*), #6 (hiding commitments wired end-to-end), and #3
(RFC 3161 anchoring). Tests: Rust 56 (lib) + 18 adversarial, Go (incl. real-Postgres-gated store
+ append-only), Python, TS, web, WASM verifier — all green.

```bash
cargo test --workspace
cargo run -p feir-decision-core --bin feir-verify -- bundle spec/fixtures/bundle-valid.json
FEIR_SIGNING_SEED=$(openssl rand -hex 32) docker compose -f deploy/docker-compose.yml up --build
```

Every claim is bounded by [`docs/coverage-limits.md`](docs/coverage-limits.md) (Level 1 / 2 / 3).

**Phase 2 in progress** (enforcement + production-readiness, each commit adversarially reviewed):
- ☑ **Authority verification** — `evidence_sig` checked under pinned authority keys (#4 *declared → verified*), record_id-bound so an evidence triple can't be replayed.
- ☑ **Project API-key auth** (`auth`), **OTel/OpenInference ingest** (`/v2/otel/traces`), **content-addressed blob store** (`content`), **append-only checkpoint witness + RFC 3161 TSA client** (`witness`) — four packages built in parallel via a workflow, wired into the server.
- ☑ **Production Postgres store** — append-only at the database (REVOKE UPDATE/DELETE/TRUNCATE, verified under a least-privilege role), idempotency + content-hash collapse + DAG-derived frontier in SQL; auto-migrates; `docker compose up` is turnkey. Validated against real Postgres 16.
- ☑ **Content commitments + selective-disclosure export** (#6) — low-entropy `input`/`output`/`rationale` are hiding-committed at ingest (plaintext → content store, never the signed body); a `selective_disclosure` export reveals `(value, nonce)` the offline verifier checks against each record's commitment. Disclosure secrets are written atomically with the record.
- ☑ **RFC 3161 checkpoint anchoring** (#3) — checkpoints are timestamp-anchored to a third-party TSA, decoupled (out of the checkpoint lock, back-anchorable) and joined into the bundle at export.
- ◐ **Credential broker (Level 3 — the moat)** — **design recorded** in [`docs/decisions/0002-credential-broker-level-3.md`](docs/decisions/0002-credential-broker-level-3.md), hardened across three adversarial-review rounds (Tier A grant-accountability vs Tier B action-accountability; honest, surfaced trust boundaries). *Built when a design partner pulls* (per spec §scope).

## Verify an export offline

```
feir-verify bundle ./export.json        # records + checkpoint history + TSA tokens + public keys
```

No network, no trust in the vendor. The same Rust core runs in your browser (WASM) and on CI.

## Build

```
cargo build --workspace          # Rust core + CLI
cargo test  --workspace          # golden vectors + adversarial fixtures (the acceptance gates)
```

## Security model

See [`docs/decisions/0001-who-is-the-evidence-for.md`](docs/decisions/0001-who-is-the-evidence-for.md)
and §14 of the spec. Key property: in self-host the customer holds the signing key, so the
vendor cannot forge or alter records. The honest limit — a malicious customer holding the only
key — is defended *partially* by external anchoring (RFC 3161 + witness copy), and stated plainly.
