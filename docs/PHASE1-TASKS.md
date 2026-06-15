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
| M1.12 | RFC 3161 anchoring — token parse/verify in core; Go job stub | ◔ (core verify ☑; Go job stub ☑) |
| **Acceptance (adversarial)** | defends #1 omitted session, #2 forked history, #3 backdated, #9 key compromise, #10 verifier skew on fixtures; CLI verifies offline with checkpoint history + TSA tokens, emits per-record trust-levels | ☑ #1,2,3,9,10 |

## M2 — Ingestion + storage + SDKs  (~4–6 wks)  — *scaffolded*

| # | Task | Status |
|---|------|--------|
| M2.1 | Go OpenAI-compatible proxy (streaming/SSE) + secret scrubbing | ☐ scaffold |
| M2.2 | Go ingestion API `POST /v2/records` (single+batch, idempotency-key) | ☐ scaffold |
| M2.3 | OTel / OpenInference ingest | ☐ |
| M2.4 | Postgres schema (append-only; revoke UPDATE/DELETE) | ☐ scaffold |
| M2.5 | Content-addressed S3/MinIO (digest + object version) | ☐ |
| M2.6 | Python SDK (`record()` + authority + commitments) | ☐ scaffold |
| M2.7 | TypeScript SDK | ☐ scaffold |
| M2.8 | Go↔Rust FFI wiring (cgo, golden-vector guarded) | ☐ |
| **Acceptance** | defends #4 authority-lie, #5 blob-substitution, #6 hash-dictionary, #7 partial-stream, #8 retry-dup, #11 clock-skew, #14 policy-drift; real agent run → verifiable DAG w/ tool calls + authority | ☐ |

## M3 — Web app + export  (~4–6 wks)  — *deferred*

| # | Task | Status |
|---|------|--------|
| M3.1 | Svelte 5 SPA (client-only): session list | ⏸ |
| M3.2 | Trace-waterfall run view + replay | ⏸ |
| M3.3 | In-browser WASM verify | ⏸ |
| M3.4 | Three export modes + `gap_report` | ⏸ |
| M3.5 | Broken-chain error UX | ⏸ |
| M3.6 | Standalone offline verifier (vanilla TS + WASM) | ⏸ |
| **Acceptance** | defends #12 offline-export-without-blobs; auditor verifies export with no access to us | ⏸ |

## M4 — Launch + experimental agent rail  (~3–4 wks)  — *deferred*

| # | Task | Status |
|---|------|--------|
| M4.1 | Stripe usage metering + cloud free tier | ⏸ |
| M4.2 | Apache-2.0 OSS release | ◔ (LICENSE added) |
| M4.3 | `docker compose up` full self-host | ☐ scaffold |
| M4.4 | Docs incl. explicit coverage limits | ◔ |
| M4.5 | MCP server + experimental x402 (guards §9) | ⏸ |
| **Acceptance** | self-host from one compose; exit criteria #4/#5 demonstrated; honest L1/2/3 messaging | ⏸ |

---

## Adversarial matrix coverage (spec §17)

| # | Attack | Milestone | Defended in this build |
|---|--------|-----------|------------------------|
| 1 | Omitted session + rewrite latest checkpoint | M1 | ☑ (checkpoint history + anchor) |
| 2 | Forked history | M1 | ☑ (frontier single-commit detect) |
| 3 | Backdated records | M1 | ☑ (RFC 3161 token verify) |
| 4 | Authority lie | M2 | ☐ (schema fields ☑) |
| 5 | Blob substitution | M2 | ☐ (schema fields ☑) |
| 6 | Hash dictionary | M2 | ☑ (hiding commitments in core) |
| 7 | Partial SSE stream | M2 | ☐ (incomplete event_type ☑) |
| 8 | Retry duplication | M2 | ☐ (idempotency in DAG collapse ☑) |
| 9 | Key compromise | M1 | ☑ (key-epoch + anchor-before) |
| 10 | Verifier skew | M1 | ☑ (one core + golden vectors) |
| 11 | Clock skew | M2 | ☑ (three clocks in schema) |
| 12 | Offline export w/o blobs | M3 | ⏸ |
| 13 | Uninstrumented action | (limit) | documented limit |
| 14 | Policy version drift | M2 | ☑ (resolve-by-hash in schema) |
| 15 | Malicious customer | M1+(limit) | partial (anchor) + documented |
