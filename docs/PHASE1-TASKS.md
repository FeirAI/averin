# Phase 1 Task List — "Flight Recorder for AI Agents" (feir)

Derived from the Phase 1 Engineering Spec v2. Status legend: ☐ not started · ◔ in progress · ☑ done · ⏸ deferred (post-Phase-1).

The **adversarial tests are the acceptance gates** (spec §15, §17). A milestone is not "done" until its threats are defended on a fixture dataset.

---

## M0 — Foundations & spec  (~2–3 wks)  — *executing now*

| # | Task | Status |
|---|------|--------|
| M0.1 | Monorepo layout (spec §16) + git + CI skeleton | ☑ |
| M0.2 | Freeze **Decision Record schema v2** → `/spec/schema-v2.md` + JSON Schema | ☑ |
| M0.3 | Freeze **Record Canonical Profile (RCP) v1** → `/spec/rcp-v1.md` | ☑ |
| M0.4 | **Golden test vectors** (`/spec/golden-vectors/`) — canonical bytes + digests + sigs, language-agnostic | ☑ |
| M0.5 | Adversarial fixture datasets (`/spec/fixtures/`) for threats #1,2,3,9,10 | ☑ |
| M0.6 | Decision: "who is the evidence FOR?" recorded in `/docs/decisions/` | ☑ |
| M0.7 | CI: `cargo test` + golden-vector byte-for-byte gate | ☑ |
| **Done when** | schema + RCP frozen; golden vectors defined; CI green | ☑ |

## M1 — Integrity core + verify CLI + anchoring  (~4 wks)  — *executing now*

| # | Task | Status |
|---|------|--------|
| M1.1 | Rust `decision-core`: RCP v1 canonicalization | ☑ |
| M1.2 | Hashing (SHA-256, algorithm-prefixed `sha256:`) | ☑ |
| M1.3 | Hiding commitments `H(domain‖value‖nonce)` (threat #6) | ☑ |
| M1.4 | Ed25519 signing, domain-separated payloads | ☑ |
| M1.5 | DAG-linking via `causal_prev_hashes`; acyclic/connected validation | ☑ |
| M1.6 | Frontier checkpoints (commit head-hash set) | ☑ |
| M1.7 | Key-epoch model + verification semantics for revoked/compromised | ☑ |
| M1.8 | Verify logic → per-record trust-level annotations | ☑ |
| M1.9 | Build target: FFI lib (cdylib + C header) | ☑ |
| M1.10 | Build target: **verify CLI** (offline) | ☑ |
| M1.11 | Build target: **WASM** (wasm-bindgen) | ☑ |
| M1.12 | External anchoring — verify in core (test-anchor ☑; rfc3161 = `Unsupported` until feature-gated DER/CMS parser ships with the Go job) | ◔ |
| M1.13 | FFI lib + C header + cgo-style smoke test | ☑ |
| M1.14 | WASM build target (`--no-default-features --features wasm`) | ☑ |
| M1.15 | Parser nesting-depth cap (DoS hardening) | ☑ |
| **Acceptance (adversarial)** | defends #1 omitted session, #2 forked history, #3 backdated, #9 key compromise, #10 verifier skew on fixtures; CLI verifies offline + per-record trust-levels | ☑ **#1,2,3,9,10** (52 tests, all Codex-reviewed) |

> **M1 status:** the integrity core is feature-complete and reviewed for Phase 1. Remaining
> within M1 = the real RFC 3161 DER/CMS wire-format parser (test-anchor proves the detection
> logic now; production uses a third-party TSA via the Go anchoring job).

## M2 — Ingestion + storage + SDKs  (~4–6 wks)  — *done (Postgres/content-store deferred)*

| # | Task | Status |
|---|------|--------|
| M2.1 | Go OpenAI-compatible proxy (streaming/SSE) + secret scrubbing | ☑ |
| M2.2 | Go ingestion API `POST /v2/records` (single+batch, idempotency-key) | ☑ |
| M2.3 | OTel / OpenInference ingest | ⏸ (SDK is OTel-shaped; ingest deferred) |
| M2.4 | Postgres schema (append-only; revoke UPDATE/DELETE) | ◔ (Store interface + in-mem; Postgres swap deferred) |
| M2.5 | Content-addressed S3/MinIO (digest + object version) | ◔ (schema fields ☑; blob store deferred) |
| M2.6 | Python SDK (`record()` + authority) | ☑ |
| M2.7 | TypeScript SDK (BigInt i64) | ☑ |
| M2.8 | Go↔Rust FFI wiring (cgo) | ☑ |
| **Acceptance** | #4 authority-declared, #7 partial-stream, #8 retry-dup, #11 clock-skew tested; real agent run → verifiable DAG w/ tool calls. #5/#14 schema-present, integration deferred | ☑ (tested gates) |

## M3 — Web app + export  (~4–6 wks)  — *done*

| # | Task | Status |
|---|------|--------|
| M3.1 | Svelte 5 SPA (client-only): session list | ☑ |
| M3.2 | Trace-waterfall run view (causal depth) | ☑ |
| M3.3 | In-browser WASM verify (standalone page) | ☑ |
| M3.4 | Export modes (`proof_only`/`full_evidence`) + `gap_report` | ☑ (selective_disclosure needs content store) |
| M3.5 | Broken-chain error UX | ☑ (first_broken_link surfaced) |
| M3.6 | Standalone offline verifier (vanilla + WASM) | ☑ |
| **Acceptance** | #12 offline-export verified in-browser with no server access | ☑ (tested) |

## M4 — Launch + experimental agent rail  (~3–4 wks)  — *done*

| # | Task | Status |
|---|------|--------|
| M4.1 | Stripe usage metering + free tier | ☑ |
| M4.2 | Apache-2.0 OSS release | ☑ |
| M4.3 | `docker compose up` full self-host | ☑ (cgo image builds; compose valid) |
| M4.4 | Docs incl. explicit coverage limits | ☑ |
| M4.5 | MCP server + experimental x402 (guards §9) | ☑ |
| **Acceptance** | self-host from one compose; exit #4/#5 demonstrated; honest L1/2/3 messaging | ☑ |

---

## Adversarial matrix coverage (spec §17)

| # | Attack | Milestone | Defended in this build |
|---|--------|-----------|------------------------|
| 1 | Omitted session + rewrite latest checkpoint | M1 | ☑ frontier omission + latest-frontier==heads + anchor; **tested** |
| 2 | Forked history | M1 | ☑ same-seq + shared-prev fork detect; **tested** |
| 3 | Backdated records | M1 | ☑ anchored-time monotonic; **tested** (test-anchor) |
| 4 | Authority lie | M2 | ◑ key-pinning + worst-status done; authority `evidence_sig` UI = M2 |
| 5 | Blob substitution | M2 | ☐ (schema digest+object_version ☑) |
| 6 | Hash dictionary | M1 | ☑ hiding commitments; **tested** |
| 7 | Partial SSE stream | M2 | ☐ (incomplete event_type in schema ☑) |
| 8 | Retry duplication | M1 | ☑ DAG duplicate-collapse; **tested** (ingest idempotency = M2) |
| 9 | Key compromise | M1 | ☑ key-epoch + anchored-before + TrustedKey pinning; **tested** |
| 10 | Verifier skew | M1 | ☑ one Rust core → CLI+WASM+FFI + golden vectors; **tested** |
| 11 | Clock skew | M2 | ◑ three clocks in schema; divergence flag = M2 ingest |
| 12 | Offline export w/o blobs | M3 | ⏸ |
| 13 | Uninstrumented action | (limit) | documented limit (needs credential broker) |
| 14 | Policy version drift | M2 | ◑ resolve-by-hash in schema; integration = M2 |
| 15 | Malicious customer | M1+(limit) | partial: anchor + out-of-band key/TSA pinning; fork-suppression limit documented |
