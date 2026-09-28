# Plan 008: Recover abandoned sequences despite perpetual failed retries

## Status and execution contract

- Priority: P1; effort: L; implementation risk: HIGH; confidence: HIGH.
- Category: correctness / liveness. Depends on: 001, 006, 007.
- Planned at `e81aa90adaf7ca90bb78f397839b51935e81c699`, 2026-09-23.
- Use `advisor/008-bounded-sequence-recovery` on a PR descendant; run `git diff --stat e81aa90..HEAD -- server/internal/api/broker_seq_void.go server/internal/store server/internal/pgdurable server/migrations formal/tla docs`. Reconcile drift including the completed 007 transaction seam. No publishing; update index after review.

## Why this matters

The current recovery design is safe but a client that continually retries and fails can indefinitely reset the void age. Restart forgets attempts and imposes another boot delay. A blocked tombstone insert also holds a process-global ingest lock. Add a narrowly authorized durable fence and progress protocol; merely reducing the age threshold would reintroduce the race.

## Current state

`broker_seq_void.go:145` holds `s.ingestMu` over the complete operation; lines 92–96 document up to a 30-second index wait. At lines 307/329, latest attempts are stored only as:

```go
s.seqAttempts[projectID+"\x00"+grantID] = now
```

The safe ordering at lines 254–266 is seal/store the `grant_void` first, then write the void marker. A grant and tombstone share record ID and the required UNIQUE index decides which can land. `GrantLog_void_starved.cfg` deliberately violates `CheckpointRecovers`; the safe liveness configuration assumes an endlessly retried grant eventually commits.

## Scope

Recovery handlers and grant/use/finalize checks in `server/internal/api/`, transaction/store operational state from 007, forward migrations, auth capability from 006, TLA grant-log models/configs, tests and runbook. No automatic age-only cancellation, unbounded background worker platform, or mutation/deletion of evidence. Retain append-only signed recovery history.

## Target contract

### Execution reconciliation, 2026-09-24

The 007 implementation stages external content before the project transaction and allocates broker sequence plus seals/inserts the grant within that transaction. Failed new grants therefore do not leave orphan allocations. Recovery chiefly serves legacy or residual reservations; do not add expiring leases merely to duplicate the project transaction's mutual exclusion. Preserve the durable fence and progress guarantee because process-local attempt/boot age still lets failed retries starve recovery.

Use migration `0005`, immediately after 007's project transactions. (The unimplemented 005 nonce migration is assigned `0006`; this follows actual dependencies without a placeholder schema step.) One immutable recovery/fence row per `(project, sequence)` binds the exact grant, generation, operation identity, authenticated actor, NFC reason, request digest, and database time. An append-only terminal result binds `recorded` or `voided` to the winning record hash. A committed fence never expires or resets on retry. The exact project guard drains earlier supported writer transactions; every supported prepare/direct/finalize/native grant path must check the fence, and final allocation/insertion must enforce its state within that same transaction. Reconcile in a second guarded transaction: an already-landed grant yields a recorded no-op without revocation; otherwise atomically persist tombstone, marker, optional durable revoke, and terminal result. Do not silently treat a pending grant as a landed one. If operational fence/result rows are exposed as offline proof, sign them and specify their verification; the existing signed 006 tombstone remains the audit evidence for actor/reason/operation.

Keep the existing operator POST route as the recovery operation and add a recovery-authenticated read-only preflight. Preflight must use `WithProjectRead`, because `WithProjectWrite` rejects an invalid unique backstop before invoking its callback. Report reservation, pending, winning record, marker, fence/result, and actual uniqueness status without mutation. Its response is diagnostic; revalidate inside recovery.

The selected diagnostic route is `GET /v2/broker-seq/void`, protected by the same exact recovery middleware, with project and sequence query parameters. For a landed grant, retain the existing HTTP 409 while returning machine-readable operation identity, terminal `recorded` outcome and winning record hash; this is a completed no-op, distinct from a retryable 503. Exact readback of that prior grant remains permitted; the fence blocks fresh issuance.

Preserve 006's exact actor/operation/session/reason match for any tombstone carrying signed recovery identity. A wholly pre-006 tombstone can be recognized only when both actor and operation fields are absent (null, empty or partially present fields are not legacy), and its record ID, project, credential-broker role, void domain, sequence and grant tuple match the reservation. A new authenticated fence may reconcile only its operational marker/revoke/result, referencing the unchanged original JSON/hash. Response and preflight must distinguish the new reconciliation actor from the unattributed original void, and subsequent retries must match the new fence's immutable action. These operational rows are local diagnostics, not new offline proof or retroactive signed attribution. If that distinction cannot be maintained, refuse and surface the legacy state through preflight; do not invent a new evidence type without review.

The selected rollout is a coordinated maintenance cutoff, also used by 004/005. Pre-007 writers are unsupported during the new protocol. The runbook must enforce the barrier: stop traffic/producers and old servers/workers; drain or terminate their database sessions; explicitly resolve prepared transactions; revoke/rotate the old runtime credential; verify the old credential/session cannot write; only then enable the new writers/recovery. Schema-version startup checks alone do not fence an already-running old process. Add an executable old-connection refusal regression for this barrier. Do not add record-content-parsing database triggers to support an unrequested rolling mixed-binary mode.

Provide an operator-only durable recovery operation for a specific project/grant reservation: fence new attempts, reconcile any already-started database transaction, then either recognize the landed grant or commit its tombstone. A monotone fencing generation/state is checked at the database commit boundary by every grant path; a wall-clock lease by itself is insufficient. Persist operation identity, authenticated actor and reason. Retries cannot extend a fence's recovery wait.

Use database time on durable pending/fence/result state for diagnostics; base exclusion on transactions/fencing and the uniqueness backstop. After 007, a separate durable log of every failed attempt would add write traffic and state without strengthening exclusion or progress, so it is not required. Local attempt metrics may remain diagnostic but cannot extend the fence's wait. A granted/voided ID cannot be reissued. Consult terminal void state before permitting capability use even if the optional revocation-list feature is disabled; when enabled, publish its durable revoke idempotently and report any incomplete publication honestly.

## Steps and verification

1. Extend the model with `active → fenced → recorded|voided` and idempotent recovery. Allow crash after every transition, late old-generation commit, competing operators and expired/live pending grants. Keep tombstone-first compatibility for legacy partially completed voids; new atomic transaction may commit tombstone and marker together.
   **Verify:** `bash formal/tla/run-tlc.sh`; safe recovery has no duplicate sequence/anchored gap and eventually resolves despite an indefinitely failing retry client, assuming the database resolves in-flight transactions and an authorized recovery is eventually scheduled. Preserve the old starvation counterexample as a historical unsafe variant. No claim of liveness during permanent database failure.
2. Implement a narrow fence/recovery API using 006's permission and 007's project transaction. Once fenced, grant attempts fail before allocation/mint and cannot change the recovery deadline. If a grant already won, preserve it and return an explicit recorded result; never revoke a grant just because a losing void raced it. Do not erase evidence to make a unique index build.
   **Verify:** `make test-server` with disposable Postgres; retain `TestBrokerSeqVoidGrantLandsFirstPostgres`, `TestBrokerSeqVoidMarkerFailsPostgres`, inert-marker, boot-floor and concurrent-void cases.
3. Bound lock acquisition and statement waits for recovery, honor request cancellation, and return retryable status plus stable operation ID on bounded waits. Do not hold process-global ingest locks during waits. A canceled/ambiguous response does not mean rollback succeeded: query/retry the same recovery operation to reconcile.
   **Verify:** deterministic blocked-transaction tests assert the configured deadline and independent project progress. Commit the competing transaction both before and after client cancellation; each outcome is safe and retries converge.
4. Add a read-only preflight report for reservation/pending/backstop/fence/recovery status, and precise operator steps for the non-unique historical fallback. A dirty project remains degraded; preserve its original bundle. A replacement project/history requires an explicit linked migration procedure, not deletion or rewriting of duplicate signed records.
   **Verify:** tests show missing/invalid unique backstop refuses recovery without mutation; preflight identifies that condition. Runbook replay on synthetic interrupted operations reaches one stable outcome.

## Done criteria

- Perpetual failed retries cannot prevent an authorized fence from reaching a terminal recovery result under the stated database/fairness assumptions.
- Restart and replica changes preserve attempt/recovery state; local clocks are not the exclusion mechanism.
- Grant/tombstone mutual exclusion, allocation maximum, authority classification and consume-before-act remain intact.
- No other project stalls behind a blocked void; the operation's own waits are bounded and reconcilable.
- TLA expected outcomes, `make test`, Postgres API race tests and added crash schedules pass.

## STOP conditions and maintenance

Stop if a late old writer can commit without checking fencing, if an operator override bypasses uniqueness, or if timeout handling assumes an unknown commit aborted. Fence state must not be automatically garbage-collected while an old attempt may still complete. Plan 009 may enrich revocation history later but must not weaken permanent retirement of a voided grant.
