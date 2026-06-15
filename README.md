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

Phase 1 build in progress — see [`docs/PHASE1-TASKS.md`](docs/PHASE1-TASKS.md). The integrity
core (M0 + M1) is the current focus: frozen schema/RCP, golden vectors, and a tested offline
verify CLI. Downstream components (Go services, SDKs, web app) are scaffolded.

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
