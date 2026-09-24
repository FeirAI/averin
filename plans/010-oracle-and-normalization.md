# Plan 010: Compare production preimage bytes and test normalization boundaries

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving on. If a STOP condition occurs, stop and report. Do not alter the checkout or branch as part of this plan.
>
> **Drift check (run first)**: `git diff --stat e81aa90adaf7ca90bb78f397839b51935e81c699..HEAD -- core/src/verify.rs core/src/canon.rs core/tests server sdk formal/lean/Oracle formal/oracle formal/check-refinement.py` . Any changed in-scope path requires re-reading the cited symbols before proceeding.

## Status

- **Accepted**: `03eaf11`, 2026-09-24. Primary reviewed the complete source/tests/docs diff and reran the full core suite (45 unit, 270 adversarial, 15 golden, 10 oracle, 5 signing tests), fresh RFC3161 `make test-server` with real Postgres, uncached `make test-server-postgres`, exact Lean oracle regeneration, refinement inventory, TypeScript tests/typecheck, Python tests, formatting/diff and staticlib freshness checks. All passed. Combined-branch gates remain required after integration.

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Depends on**: `plans/001-assurance-baseline.md`
- **Category**: tests
- **Planned at**: commit `e81aa90`, 2026-09-23

## Why this matters

The Lean oracle currently compares production Rust with the model over a fixed corpus. `formal/README.md:127-130` records that eight verifier builders expose digests, so CI does not compare their preimage bytes directly. Under the existing SHA-256 assumption, digest comparison already detects differing sampled inputs; this is a precision/debuggability improvement, not a credible collision exploit. This plan makes byte agreement observable, exercises the contract through actual Go and SDK producer paths, and establishes an explicit NFC/identity boundary. Neither a larger corpus nor byte comparisons are an exhaustive refinement proof; plan 012 addresses that gap.

## Current state

- `core/src/verify.rs` contains the eight production-called challenge/preimage helpers: `ledger_commitment`, `grant_head_root`, `revocation_leaf`, `use_pop_challenge`, `cosig_approval_challenge`, `delegation_hop_challenge`, `introspection_transcript_challenge`, and `federation_cert_challenge` (around lines 1873-2233). Their current test contract compares SHA-256 digests against model-derived bytes.
- `formal/lean/Oracle/Main.lean` and `core/tests/oracle.rs` generate/check `formal/oracle/expected.json`; `formal/README.md:120-143` describes the fixed corpus and its coverage.
- `core/src/canon.rs:194-197,484-491` NFC-normalizes parsed strings and rejects post-NFC duplicate keys. The formal model starts after normalization (`formal/README.md:94-97`).
- `core/src/authority.rs:52-69` signs authority evidence over source/project/record/evidence hash; its API contract must not be changed in this plan.
- Follow existing test conventions in `core/tests/oracle.rs`, `core/tests/adversarial.rs`, and the Go package tests under `server/internal`; test-only hidden Rust helpers are already used by the oracle.

For example, `verify.rs:1873` currently builds `ledger_commitment` by appending `lp4` for `["averin.broker.use.ledger.v1", jti, nonce]`, `be8(used_at as u64)`, then hashing `pre`. Extract those exact construction bytes and have that production function call the helper. `core/tests/oracle.rs:97` currently uses `check_digest`, hashing the model preimage before comparison.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Core tests | `cargo test --manifest-path core/Cargo.toml` | exit 0 |
| Server tests | `make test-server` with `AVERIN_TEST_DATABASE_URL` set to a disposable Postgres database | rebuilt native staticlib, vet and tests exit 0 |
| Oracle gate | `python3 formal/check-refinement.py && cargo test -p averin-decision-core --test oracle` | inventory and oracle pass |
| CI-shaped formal gate | `cd formal/lean && lake build --wfail oracle && lake exe oracle ../oracle/inputs.json ../oracle/expected.json && git diff --exit-code -- ../oracle/expected.json` | exit 0 and no expected-file diff |
| SDK tests | `(cd sdk/typescript && bun test && bun run typecheck)` and `(cd sdk/python && python3 -m pytest)` | tests collected, all pass |

## Scope

**In scope:** `core/src/verify.rs` (production-called, hidden-public byte helpers), `core/src/canon.rs` for boundary validation if needed, `core/tests/oracle.rs`, oracle evaluator changes under `formal/lean/Oracle`, corpus files under `formal/oracle`, core adversarial tests, producer conformance tests under `server/internal` and `sdk/`, narrowly scoped boundary validators and their documentation. Every production change must have a failing boundary regression first.

**Out of scope:** changing the wire format, changing authority v2, normalizing opaque tokens, project IDs, idempotency keys, record IDs, or historical identifiers; changing Lean theorem statements; implementing verdict monotonicity (plan 002); mechanized Rust extraction (plan 012).

## Steps

### Step 1: Expose exact verifier challenge bytes for tests

Extract or add `#[doc(hidden)]`/test-visible helpers for the eight named helpers, preserving one source of truth so production digest functions call the same byte builders. For aggregate helpers (`grant_head_root` and `revocation_merkle_root`), expose the per-step preimages and the Merkle leaf/node bytes that are actually production-called; do not replace the aggregate algorithm with a test-only reimplementation. Keep public behavior and digest outputs unchanged. Add a table-driven Rust oracle assertion that compares exact bytes to Lean model bytes, then separately hashes both and checks the digest.

**Verify**: `cargo test -p averin-decision-core --test oracle` → byte and digest assertions pass.

### Step 2: Expand the deterministic corpus and producer conformance

Add vectors that vary every field independently, empty/boundary values, Unicode ordering, escaped controls, malformed/duplicate keys, and all eight challenge families. Add Go and SDK tests that construct the same producer inputs and compare their emitted canonical request/challenge bytes or documented digest contract to the Rust/Lean vectors. Keep fixtures deterministic and committed.

**Verify**: the core oracle, server tests, and each existing SDK test/typecheck command pass; regenerated `expected.json` is byte-identical.

### Step 3: Define identity normalization contracts

For each API field, specify whether RCP text equivalence is intended, or whether it is an opaque identity/token. Authorization must use the same semantic value later authenticated by the signed bytes. RCP normalizes JSON strings; therefore an opaque ID represented as an RCP string may need non-NFC input rejected at the boundary, not silently preserved upstream and normalized inside the record. Preserve historical lookup semantics and flag ambiguity rather than rewriting stored IDs. Do not apply human-text rules blindly to actions, resource names, tokens or policy strings. Add decomposed/precomposed tests through ingest, deduplication, authority lookup, idempotency and authorization, including post-NFC duplicate keys. Pin/document the normalization-library Unicode version and test its conformance corpus; do not claim to have formally proved the Unicode implementation.

**Verify**: targeted core/server/SDK tests pass and a repository search confirms no new normalization call is applied to opaque IDs or tokens.

## Test plan

Use `core/tests/oracle.rs` as the structural pattern. Cover all eight builders, one-field-at-a-time mutations, NFC-equivalent text, duplicate post-NFC keys, malformed UTF-8/JSON, and opaque identity preservation/rejection. Add one producer conformance case per Go/SDK path that previously bypassed the Rust oracle.

## Done criteria

- [x] Every production-called verifier builder has direct byte and digest assertions.
- [x] Oracle corpus includes all eight families and NFC/identity boundary cases.
- [x] Go and SDK producer conformance tests pass.
- [x] No opaque identifier/token is silently NFC-normalized.
- [x] Formal oracle output is reproducible with no diff.
- [x] Only scoped files are modified.

## STOP conditions

Stop if a builder has multiple production implementations, if exposing bytes would alter the public ABI, if an SDK has no stable test command, or if a caller cannot classify a field as structured text versus opaque identity without changing the protocol. Stop if the proposed fix requires changing authority v2 or historical IDs.

## Maintenance notes

Every new verifier challenge must add a byte vector and a producer conformance case before its tag is accepted by the refinement gate. Reviewers should check that test helpers call production builders and that normalization is applied consistently to authorization and deduplication, while opaque identifiers remain stable.

Execute in a separate PR-descendant worktree (main was `c30bd2f` during planning), with a branch such as `advisor/010-oracle-and-normalization`; no push is authorized by this plan. Update the index after review. Coordinate schema changes in plans 003/004/009 through additive vectors; their new families must receive the same checks. Any dependency acquisition uses Socket Firewall.
