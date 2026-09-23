# Plan 007: Put per-project serialization and authoritative state in the database

## Status and execution contract

- Priority: P1; effort: L; implementation risk: HIGH; confidence: HIGH.
- Category: correctness / architecture. Depends on: 001; integrate 004/005 before claiming full HA use-path safety.
- Planned at `e81aa90adaf7ca90bb78f397839b51935e81c699`, 2026-09-23.
- Use `advisor/007-project-transactions` on a PR descendant. Run `git diff --stat e81aa90..HEAD -- server/internal server/migrations formal/tla docs` and reconcile drift. Work in small reviewed commits; no publish implied. Update the index only when all completion gates pass.

## Why this matters

The documented single-writer-per-project rule is currently an operator obligation. The UNIQUE record-ID backstop solves grant-versus-tombstone exclusion, not project frontier/checkpoint consistency, stale revocation caches, or cross-replica pending-grant lookup. Establish one database serialization contract and test the supported deployment as a whole.

## Current state

`server/internal/api/server.go:1586` reads `s.st.Heads(projectID, sessionID)` before `sealAndStore` eventually calls the store insertion. The enclosing `ingestMu` is process-local. The comment claiming a single Postgres transaction at line 1582 is misleading: these API reads are separate store calls. `createCheckpoint:3466` reads frontier, count, grant records and allocation max under that local lock; checkpoint sequence/history are also read separately.

`store/postgres.go:737` takes `pg_advisory_xact_lock(hashtext($1))` only within allocation. `api/durable.go:40,54` reloads revocations and pending grants at boot; it does not make another running process's cache current. `buildBundle:4076` safely reads checkpoints before records, allowing an uncheckpointed tail. `docs/dev/LIMITATIONS.md` expressly requires a single writer per project.

## Scope

`server/internal/{store,api,pgdurable,pgledger,pgschema}/`, necessary forward migrations and startup wiring, real-Postgres concurrency tests, `formal/tla/` protocol models, deployment/API/architecture/limitations docs. Preserve Mem for standalone/testing with matching semantics. No distributed cache service, streaming export format, incremental grant-head optimization or broad storage rewrite.

## Target contract

Introduce a transaction-bound project write/session API. One transaction/connection owns the project advisory lock and all authoritative reads, final seal inputs and inserts through commit. Every participating route uses it: generic/batch ingest, grants, finalize, uses/outcomes, void and checkpoint creation. Do not acquire a lock then call old store methods that open a second transaction/connection: that can deadlock or escape the protected snapshot. Establish one lock order shared with allocation/recovery/consume operations.

Build slow immutable content outside the project transaction where possible. Revalidate authoritative request/idempotency/authorization state inside it. Keep consumption durably before permission to act; ambiguous persistence never permits release. Serializing per project allows other projects to make progress. Do not release the project lock between frontier selection and insertion.

Make revocation/pending checks authoritative at request time. A notification/cache may accelerate reads but cannot be the safety authority. Define revoke/use linearization: a use authorized after a successful revoke commit is rejected on every replica; already-authorized in-flight work has an explicit bound. Finalize and void consult durable pending state, not just a boot snapshot. Preserve no-action-on-failure behavior.

An authoritative read failure yields rejection/retry, never fallback to a stale cache. Tests must disconnect one replica from the authoritative state while another commits a revoke or pending grant. This transaction-order contract is a prerequisite for plan 009's temporal artifacts; no producer may emit a trusted prospective cutoff before it is implemented and exercised.

## Steps and verification

1. Model two replicas, separate local caches/locks, database transactions, ambiguous commit, crash/restart, checkpoint/anchor completion, revocation and pending grants. Define safety independently from liveness and retain the single-process counterexamples. Add schedules that genuinely exercise two writers and late transactions.
   **Verify:** `bash formal/tla/run-tlc.sh` passes its old outcomes and the new expected outcomes; disabling project serialization yields a named frontier/checkpoint counterexample, not just a state-bound error.
2. Add transaction-bound store methods and Mem equivalents. Put frontier/display sequence/insert/disclosures and checkpoint history/frontier/grant head/max allocation into their respective atomic project operations. Keep external TSA calls after commit and attach anchors idempotently. Use database constraints plus transactions; check the actual valid required unique index/constraint at readiness, not its name alone.
   **Verify:** from `server/`, `go test -count=1 ./internal/store/... ./internal/pgschema/...` with disposable Postgres; private-schema tests use two independent pools and a runtime role without evidence UPDATE/DELETE privileges.
3. Migrate route callers and durable revocation/pending queries. Define bounded retry handling for serialization failure and ambiguous commit; retry by operation identity, never by blindly reminting/reconsuming. Adopt per-project locking and preserve request-level duplicate arbitration while moving content I/O outside the lock.
   **Verify:** `make test-server` with Postgres and `go test -race ./internal/api/... ./internal/store/... ./internal/pgdurable/... ./internal/pgledger/...` from `server/` after rebuild. Assert one outcome per intent and request-match behavior across independent server instances.
4. Define export snapshot semantics. Either retain checkpoint-first plus allowed tail with a demonstrated invariant, or provide a consistent read transaction selecting records/checkpoints/authority artifacts at one cutoff. Do not silently discard records or suppress an unanchored tail to manufacture completeness. Verify newest history cannot be paired with an older revocation snapshot and called current.
   **Verify:** extend `api/export_snapshot_test.go`; concurrent writers/checkpointers/anchor attachment/revoke operations never export missing committed ancestors or falsely fresh authority evidence.
5. Add process-level integration schedules: two servers, one database, crossed prepare/finalize/revoke/use requests, process termination after each durability boundary, and concurrent checkpoints. Keep the one-writer deployment warning until this complete matrix passes, including 008 recovery and 004/005 tenant checks.
   **Verify:** `make test`, the required Postgres API job and new process tests pass; model traces have matching executable regression schedules.

## Done criteria

- Database serialization protects complete frontier/sequence/commit boundaries; no supporting call escapes onto another transaction.
- Two live replicas observe authoritative revocation and pending state, and no contradictory checkpoint chain or duplicate outcome is accepted.
- A blocked operation in project A does not stall project B through a global application lock.
- Invalid/missing uniqueness backstops prevent unsafe write/recovery modes; existing damaged history stays readable with an explicit degraded status.

## STOP conditions and maintenance

Stop on nested-transaction lock deadlocks, a need to mutate signed evidence, unsupported external side effects inside retryable transactions, or tests that replace two servers with one shared mutex. Do not claim unconditional availability during database outage. Future handlers must use the same transaction contract. Coordinate schema numbering with 005/008/009; all migrations remain forward-only. Socket Firewall applies to new dependencies.
