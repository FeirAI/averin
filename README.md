# averin — Flight Recorder for AI Agents

**Try it in your browser:** https://verify.feir.ai (paste a bundle, or load a sample; runs entirely
offline, in WASM, no server involved).

> **Verifiable incident reconstruction for AI agents.** When an agent costs you
> $900 overnight, goes off-script, or does something destructive, you get a tamper-evident,
> replayable record of *what was observed, why, and under whose declared authority* — that
> you can independently check offline. Optional checkpoint anchoring needs a separately trusted
> TSA and bounds checkpoint existence, not event time; no live TSA round trip was validated.
> Verifying against a bundle's own embedded keys proves internal consistency; an
> authentic, out-of-band verdict needs your own pinned keys (see
> [`docs/operator-verification.md`](docs/operator-verification.md)). RFC 3161 anchor
> verification is a native-build feature: the browser/WASM verifier reports an RFC 3161 anchor as
> `Unsupported`, never a silent pass (see [`docs/dev/SECURITY.md`](docs/dev/SECURITY.md)).

Accountability, not just observability. Apache-2.0, self-hostable.

> **First alpha: source-only.** No Docker image is supplied with this release.
> The server and web Docker recipes remain in `deploy/` as source, not as a
> validated image-build or deployment path for this alpha. Start with the
> [native-build instructions](docs/dev/QUICKSTART.md); prerequisites and local
> dependency/toolchain acquisition still apply.
> The tracked browser verifier includes a checksum pin, not a prebuilt WASM
> binary. See [the verifier build and pin notes](verifier/SUPPLY-CHAIN.md).

> **New here? Start with the developer docs:** [`docs/dev/`](docs/dev/README.md) —
> [Quickstart](docs/dev/QUICKSTART.md) (build, run, an end-to-end curl example) ·
> [Architecture](docs/dev/ARCHITECTURE.md) · [API](docs/dev/API.md) ·
> [Configuration](docs/dev/CONFIGURATION.md) · [Security](docs/dev/SECURITY.md) ·
> [Integration](docs/dev/INTEGRATION.md) · [Testing](docs/dev/TESTING.md). averin is usable
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
| `core/` | **Rust `decision-core`** — canonicalize → commit → hash → sign → DAG-link → checkpoint → verify. One crate → FFI lib + the `averin-verify` CLI (`src/bin`) + WASM. The single source of truth. |
| `server/` | Go: app API + ingestion, OpenAI-compatible recording proxy (`internal/proxy`), credential broker + resource gateway, MCP server, export, anchoring. (Experimental x402 metering lives in `internal/x402`, not yet wired into the binary.) |
| `web/` | Svelte 5 + Vite SPA (client-only) — trace-waterfall run view |
| `verifier/` | Vanilla JS + WASM standalone offline verifier (no framework) |
| `sdk/python`, `sdk/typescript` | Client SDKs |
| `spec/` | **schema v2, RCP v1, golden vectors, adversarial fixtures** |
| `deploy/` | Docker Compose source recipes; not validated for the source-only alpha |
| `docs/` | coverage limits, deployment readiness, vultrino integration, ADRs (0001–0006) |
| `formal/` | **Formal verification**: Lean 4 proofs of the seal, TLA+ models of the server protocols, Kani bounded proofs of the core, and a Rust↔Lean refinement gate ([`formal/README.md`](formal/README.md)) |

## Status

Implementation status is summarized below. Validation is limited to the dated
procedures and candidate named in the test-evidence paragraph.

- **Integrity core** (Rust) — canonicalize → commit → hash → sign → DAG-link → checkpoint → anchor
  → verify, from one crate to **three targets**: verify CLI, WASM, and cgo FFI. Golden vectors;
  Native RFC 3161 verification requires the `rfc3161` build feature; WASM reports such anchors as `Unsupported`.
- **Go server** (cgo → core) — ingestion (`/v2/records`, idempotency, DAG-linking, sealing),
  app/verify/export API, OpenAI-compatible recording proxy (secret-scrubbed), Stripe metering,
  MCP server, experimental x402.
- **SDKs** — Python + TypeScript. **Web** — Svelte 5 SPA (trace waterfall) + a frameworkless
  **offline verifier** (vanilla + locally built WASM). The retained Docker Compose
  recipes are not a validated self-host path for this source-only alpha.

Historical validation at commit `8ac16313` (not a claim about later revisions):
- Gate C: Rust 313 passed, zero failures; Go 446 pass events, zero failures,
  23 skips (22 database-gated, one fixture regeneration); verifier 20 passed.
- A separate PostgreSQL 16.14 run at that commit: 468 pass events, zero failures,
  one fixture skip; all 22 required database tests passed in one synthetic configuration.
- Separate SDK runs: Python 5 and TypeScript 10 passes. Later web work recorded
  a build, four Vitest passes and a clean TypeScript SDK typecheck.
These scoped, cached procedures do not establish production durability, a
clean-machine installation, a Docker image build or results for a later candidate.

```bash
cargo test --workspace
cargo run -p averin-decision-core --bin averin-verify -- bundle spec/fixtures/bundle-valid.json
# Source-only alpha: use docs/dev/QUICKSTART.md for native-build instructions.
# Docker Compose recipes remain in deploy/ but are not a validated alpha path.
```

Every claim is bounded by [`docs/coverage-limits.md`](docs/coverage-limits.md) (Level 1 / 2 / 3).

**Phase 2 in progress** (enforcement + production-readiness, each commit adversarially reviewed):
- ☑ **Authority verification** — `evidence_sig` checked under pinned authority keys (#4 *declared → verified*), record_id-bound so an evidence triple can't be replayed.
- ☑ **Project API-key auth** (`auth`), **OTel/OpenInference ingest** (`/v2/otel/traces`), **content-addressed blob store** (`content`), **append-only checkpoint witness + RFC 3161 TSA client** (`witness`) — four packages built and wired into the server.
- ☑ **Production Postgres store** — append-only at the database (REVOKE UPDATE/DELETE/TRUNCATE, verified under a least-privilege role), idempotency + content-hash collapse + DAG-derived frontier in SQL; auto-migrates. Docker image build and deployment are not validated for this source-only alpha. Validated against real Postgres 16.
- ☑ **Content commitments + selective-disclosure export** (#6) — low-entropy `input`/`output`/`rationale` are hiding-committed at ingest (plaintext → content store, never the signed body); a `selective_disclosure` export reveals `(value, nonce)` the offline verifier checks against each record's commitment. Disclosure secrets are written atomically with the record.
- ☑ **RFC 3161 checkpoint anchoring** (#3) — checkpoints are timestamp-anchored to a third-party TSA, decoupled (out of the checkpoint lock, back-anchorable) and joined into the bundle at export. The Go server's TSA client is implemented and tested against a mock RFC 3161 responder; the production round-trip against a real third-party TSA is the remaining open item (see [`docs/dev/SECURITY.md`](docs/dev/SECURITY.md)).
- ☑ **Credential broker (Level 3)** — design in [`docs/decisions/0002-credential-broker-level-3.md`](docs/decisions/0002-credential-broker-level-3.md) (Tier A grant-accountability vs Tier B action-accountability), with the implementation design [`docs/decisions/0003-tier-b-demonstrator.md`](docs/decisions/0003-tier-b-demonstrator.md) adversarially reviewed and tested to **READY**. **Tier A** (`POST /v2/grants`): a signed `gateway_enforced` grant (record-before-issue, idempotent) + a sender-constrained, single-use, proof-of-possession capability. **Tier B** (`POST /v2/use`, built across five adversarially-reviewed commits): the resource gateway validates a capability + PoP-at-use and consumes it before acting (`resourceshim`, consume-before-act ledger), then seals a **resource-signed** use receipt; the offline verifier re-derives each `evidence_hash` from canonical `grant_evidence`/`use_evidence` (R1), enforces **role-separated** broker/resource authority keys (R2, disjoint-or-fatal), and **joins each use to its grant over the verified-anchored CLOSED set** (R3) under the full match predicate — reporting `uses_matched` / `unmatched_violation` / `unmatched_pending` / `grants_unused`. Honest residuals (resource is TCB, taxonomy/attestations unevaluated, never-anchored suppression) are stated, not papered over; the strongest `action_completeness` verdict is `attested_complete_over_brokered_surface` — and it is always paired with `resource_trust: assumed_truthful` (complete over the brokered surface *if* the resource labeled truthfully, never "everything the agent did"). **Since shipped** (adversarially reviewed and tested): the **N-Use `bounded_reuse` mode** ([ADR 0005 §M1](docs/decisions/0005-deferred-producer-modes.md) — one credential good for N uses of the identical `(action, resource_id)`, deduped per `(grant_id, use_sequence_number)`, capstone-eligible); a **durable Postgres-backed consume-before-act ledger** (`internal/pgledger`, auto-injected when `AVERIN_DATABASE_URL` is set — a single-use/bounded capability's consumption survives a restart and serializes across instances); and the **D8 capstone is now provable end-to-end from a real Go-produced bundle** (`WithCoverageManifest` → `attested_complete_over_brokered_surface`), not only in native Rust fixtures.

## Verify an export offline

```
averin-verify bundle ./export.json        # records + checkpoint history + TSA tokens + public keys
```

With the verifier and required inputs available locally, bundles can be checked offline.
Embedded keys establish internal consistency; signer authentication needs independently
trusted out-of-band pins. Integrity is not event truth or complete action coverage.
Native and browser/WASM feature coverage differ; build acquisition and asset loading
are not covered by this offline-verification statement.

## Build

```
cargo build --workspace          # Rust core + CLI
cargo test  --workspace          # golden vectors + adversarial fixtures (the acceptance gates)
```

## Formal verification

The Level-1 claim, *"sealed by this key, unchanged since, in a verifiable history"*, rests on a few
properties. These are checked by machine in [`formal/`](formal/README.md), not only by tests:

- **Lean 4** (no `sorry`; only Lean's three standard axioms):
  - **the seal theorem.** If a record or checkpoint verifies under the pinned key, its body is
    *exactly* one the key holder sealed, unless SHA-256 has a collision;
  - canonical JSON (RCP v1) is injective;
  - every hashed or signed preimage family is domain-separated from every other, so a signature
    cannot be replayed across contexts even if roles share a key;
  - hiding commitments are binding;
  - **no omission, no injection.** A verified bundle is exactly the signed ancestor-closure of the
    latest checkpoint;
  - the checkpoint history is unique.
- **TLA+** models the gapless grant-transparency log and the consume-before-act ledger.
  Model checking reproduced one grant-sequence bug found in the audit and found a second one,
  both fixed.
- **Kani** checks the real Rust encoders (base64url, `sha256:<hex>`, LP framing, key order).
- **`formal/check-refinement.py`** fails CI when the Rust drifts from what the proofs model.

What is *not* proved yet (verifier verdict logic, authority-evidence body binding, and a
mechanised Rust↔Lean refinement) is listed in [`formal/README.md`](formal/README.md).

```
cd formal/lean && lake build --wfail && ./check-axioms.sh   # Lean proofs
bash formal/tla/run-tlc.sh                                  # TLA+ models (expected outcomes)
bash formal/run-kani.sh                                     # Kani bounded proofs
python3 formal/check-refinement.py                          # model/code drift gate
```

## Security model

See [`docs/decisions/0001-who-is-the-evidence-for.md`](docs/decisions/0001-who-is-the-evidence-for.md)
and §14 of the spec. Key property: in self-host the customer holds the signing key, so the
vendor cannot forge or alter records. The honest limit — a malicious customer holding the only
key — is defended *partially* by external anchoring (RFC 3161 + witness copy), and stated plainly.
