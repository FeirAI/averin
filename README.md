# feir — Flight Recorder for AI Agents

> **Verifiable incident reconstruction for production agents.** When an agent costs you
> $900 overnight, goes off-script, or does something destructive, you get a tamper-evident,
> replayable record of *what was observed, why, and under whose declared authority* — that
> you (and later an auditor) can independently verify, offline, anchored to a third-party
> timestamp.

Accountability, not just observability. Apache-2.0, self-hostable.

> **New here? Start with the developer docs:** [`docs/dev/`](docs/dev/README.md) —
> [Quickstart](docs/dev/QUICKSTART.md) (build, run, an end-to-end curl example) ·
> [Architecture](docs/dev/ARCHITECTURE.md) · [API](docs/dev/API.md) ·
> [Configuration](docs/dev/CONFIGURATION.md) · [Security](docs/dev/SECURITY.md) ·
> [Integration](docs/dev/INTEGRATION.md) · [Testing](docs/dev/TESTING.md). feir is usable
> **standalone** — a single Go binary plus an offline verifier; the four-plane composition is optional.

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
| **3 Complete accountability** | this is *everything* the agent did | **Demonstrated over the brokered surface** (credential broker Tier A+B); full coverage still needs deployment attestations + a reduced broker TCB |

## Monorepo layout

| Path | What |
|------|------|
| `core/` | **Rust `decision-core`** — canonicalize → commit → hash → sign → DAG-link → checkpoint → verify. One crate → FFI lib + the `feir-verify` CLI (`src/bin`) + WASM. The single source of truth. |
| `server/` | Go: app API + ingestion, OpenAI-compatible recording proxy (`internal/proxy`), credential broker + resource gateway, MCP server, export, anchoring. (Experimental x402 metering lives in `internal/x402`, not yet wired into the binary.) |
| `web/` | Svelte 5 + Vite SPA (client-only) — trace-waterfall run view |
| `verifier/` | Vanilla JS + WASM standalone offline verifier (no framework) |
| `sdk/python`, `sdk/typescript` | Client SDKs |
| `spec/` | **schema v2, RCP v1, golden vectors, adversarial fixtures** |
| `deploy/` | docker-compose self-host |
| `docs/` | coverage limits, deployment readiness, vultrino integration, ADRs (0001–0005) |

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
(RFC 3161 anchoring), and the credential broker adding Tier-A grant accountability and Tier-B
action accountability (use↔grant join, role separation, PoP-at-use). Tests: **Rust 193**
(`cargo test --workspace`; incl. 135 adversarial — 199/137 with the `test-tsa` real-anchor feature),
Go (14 packages, incl. the `resourceshim` + `/v2/use` end-to-end and a real-Postgres-gated store),
Python, TS, web, WASM verifier — all green.

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
- ☑ **Credential broker (Level 3 — the moat)** — design in [`docs/decisions/0002-credential-broker-level-3.md`](docs/decisions/0002-credential-broker-level-3.md) (Tier A grant-accountability vs Tier B action-accountability), with the implementation design [`docs/decisions/0003-tier-b-demonstrator.md`](docs/decisions/0003-tier-b-demonstrator.md) hardened across two more Codex rounds to **READY**. **Tier A** (`POST /v2/grants`): a signed `gateway_enforced` grant (record-before-issue, idempotent) + a sender-constrained, single-use, proof-of-possession capability. **Tier B** (`POST /v2/use`, built across five adversarially-reviewed commits): the resource gateway validates a capability + PoP-at-use and consumes it before acting (`resourceshim`, consume-before-act ledger), then seals a **resource-signed** use receipt; the offline verifier re-derives each `evidence_hash` from canonical `grant_evidence`/`use_evidence` (R1), enforces **role-separated** broker/resource authority keys (R2, disjoint-or-fatal), and **joins each use to its grant over the verified-anchored CLOSED set** (R3) under the full match predicate — reporting `uses_matched` / `unmatched_violation` / `unmatched_pending` / `grants_unused`. Honest residuals (resource is TCB, taxonomy/attestations unevaluated, never-anchored suppression) are stated, not papered over; the strongest `action_completeness` verdict is `attested_complete_over_brokered_surface` — and it is always paired with `resource_trust: assumed_truthful` (complete over the brokered surface *if* the resource labeled truthfully, never "everything the agent did"). **Since shipped** (each finder + Opus-adversarially reviewed): the **N-Use `bounded_reuse` mode** ([ADR 0005 §M1](docs/decisions/0005-deferred-producer-modes.md) — one credential good for N uses of the identical `(action, resource_id)`, deduped per `(grant_id, use_sequence_number)`, capstone-eligible); a **durable Postgres-backed consume-before-act ledger** (`internal/pgledger`, auto-injected when `FEIR_DATABASE_URL` is set — a single-use/bounded capability's consumption survives a restart and serializes across instances); and the **D8 capstone is now provable end-to-end from a real Go-produced bundle** (`WithCoverageManifest` → `attested_complete_over_brokered_surface`), not only in native Rust fixtures.

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
