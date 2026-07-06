# averin developer documentation

Developer-facing docs for **averin**, the tamper-evident evidence service: hash-chained,
signed decision records with offline verification, authority elevation, and selective-disclosure
export. This set describes the **shipped implementation** (read against the source); the
`docs/decisions/` ADRs and `spec/` cover the design *why*.

averin is **usable standalone**. You build it from source, run a single Go binary, POST records,
and verify exported bundles offline with a CLI/WASM verifier — no other service required. The
optional [Integration](INTEGRATION.md) section covers the client API and, separately, how it
composes with sibling planes.

> Status: **alpha** (`v0.1.0`, Apache-2.0). Phase 1 (integrity core, ingest, verify, export) is
> built, tested, and reviewed; Phase 2 (authority verification, credential broker, resource
> gateway, Postgres durability) is largely landed. See [Limitations](#limitations) for the honest
> v1 bounds.

## Contents

| Doc | What |
|-----|------|
| [QUICKSTART.md](QUICKSTART.md) | Prerequisites, build from source, run the server, an end-to-end curl example. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, the domain model, the core algorithms (hash chain, DAG, checkpoints, commitments), and the storage model. |
| [API.md](API.md) | Every HTTP route (method, path, auth), request/response shapes, the record/checkpoint/bundle objects, enums, and error codes. |
| [CONFIGURATION.md](CONFIGURATION.md) | Every environment variable / flag each binary reads, its default, whether it's required, and fail-closed behavior. |
| [SECURITY.md](SECURITY.md) | Threat model, invariants, authn/authz, trust boundaries, and what averin deliberately does **not** do. |
| [INTEGRATION.md](INTEGRATION.md) | Standalone client integration (SDKs + raw API); optional cross-plane composition via the contracts. |
| [TESTING.md](TESTING.md) | Running the tests + the offline-verifier conformance vectors; a contributing note. |

## The claim, precisely

A signed, hash-chained record proves **provenance and integrity**, not **reality**:

> a specific observed event record was sealed by a specific tenant-controlled key, has not been
> altered since sealing, is linked into a verifiable run history, and was accompanied by declared
> (and where a key was pinned, independently verified) authority evidence — all verifiable offline.

That is *provenance + integrity*, not a claim that the bytes describe what truly happened. The
honest bounds (the three trust levels, what each ingestion path sees, what the verifier detects)
are normative in [`../coverage-limits.md`](../coverage-limits.md); [SECURITY.md](SECURITY.md)
summarizes them for developers.

## Repository layout

| Path | What |
|------|------|
| `core/` | **Rust `averin-decision-core`** — canonicalize → commit → hash → sign → DAG-link → checkpoint → verify. One crate, three targets: the `averin-verify` CLI (`src/bin`), a cgo staticlib (FFI), and WASM. The single source of truth for all crypto. |
| `server/` | **Go** ingestion + app API (`internal/api`), the credential broker + resource gateway, OpenAI-compatible recording proxy (`internal/proxy`), MCP server, Postgres/in-memory stores. cgo-links the Rust core. Binaries in `server/cmd/`. |
| `verifier/` | Frameworkless (vanilla JS + WASM) offline verifier. Same Rust core, in the browser. |
| `web/` | Svelte 5 SPA — trace-waterfall run view. |
| `sdk/python`, `sdk/typescript` | Client SDKs. |
| `spec/` | schema v2, RCP v1, golden vectors, adversarial fixtures. |
| `deploy/` | `docker compose` self-host. |
| `docs/` | coverage limits, operator verification, ADRs, and this `dev/` set. |
