# Plan 005: Isolate nonce replay state without reopening old replays

## Status and execution contract

- Priority: P1; effort: L; implementation risk: HIGH; confidence: HIGH.
- Category: correctness / migration. Depends on: 001 and 004's authenticated capability-project contract.
- Planned at `e81aa90adaf7ca90bb78f397839b51935e81c699`, 2026-09-23.
- Use a PR descendant in `advisor/005-tenant-nonce-ledger`; run `git diff --stat e81aa90..HEAD -- server/internal/resourceshim server/internal/pgledger server/internal/pgschema server/migrations server/internal/api formal/tla` and reconcile drift. Do not publish; update the index after review.

## Why this matters

An otherwise valid use in one tenant can consume a nonce needed by another tenant. A schema change alone is unsafe: migrating global consumption rows into guessed projects, or letting the request choose the namespace, can make previously spent credentials replayable.

## Current state

`server/internal/pgledger/pgledger.go:33` defines:

```sql
CREATE TABLE IF NOT EXISTS consume_ledger (
    kind text NOT NULL,
    consume_key text NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, consume_key)
);
```

`ConsumeNonce(nonce string)` and `ReleaseNonce(nonce string)` at lines 118/137 are global. The Mem implementation has the same contract in `resourceshim/resourceshim.go:47`. `ValidateUse:267` consumes nonce before JTI; failure of JTI consumption releases the nonce. Ambiguous receipt commit must never release either. Retention is already a correctness parameter; preserve its startup floor and conservative sweep behavior.

## Scope

`server/internal/{resourceshim,pgledger,pgschema}/`, a new forward migration in `server/migrations/`, API shim construction and rollback calls, startup wiring, matching tests, core adversarial composition tests, `formal/tla/ConsumeLedger*`, configuration and migration docs. Do not rewrite sealed records, change evidence ledger commitments gratuitously, or partition JTI by resource/session in a way that increases an existing capability's use budget.

## Target contract

Scope nonce claims by authenticated project. Get this from the signed capability and authorized request context validated by plan 004, not merely a request body. Keep JTI single-use/bounded-use uniqueness across all consumers of the same capability. Only widen its physical key if equivalence to that invariant is separately demonstrated; no need to change JTI namespace to fix nonce collisions.

Represent global legacy nonce rows explicitly. Their owner is unknown and must not be invented. A new scoped consume checks relevant unexpired legacy-global exclusions and inserts scoped state atomically. A compatibility period may conservatively reject an innocent collision; it must not allow a replay. Release identifies exactly the scope and claim acquired by this request; it cannot delete another tenant's or an inherited legacy exclusion.

Keep the existing receipt ledger commitment only with an explicit composition argument: `verify.rs:4161` binds all signed records/checkpoints to one project, plan 004 binds the capability to that same authorized project, and the verifier's `(resource_id, nonce)` duplicate set is therefore already evaluated inside one authenticated project. Test both same-nonce separate-project bundles and a mixed-project bundle (which must fail), including omitted top-level project. Do not add a redundant receipt wire version merely for physical storage scoping. If this composition no longer holds after other changes, stop and version the authenticated receipt/commitment before shipping namespace changes.

## Steps and verification

1. Specify the key/claim types and versioned migration. Prefer a maintenance cutover: quiesce all old writers, migrate, start new writers, verify readiness, then reopen traffic. A startup schema check alone does not stop an already-running old writer. If rolling upgrade is required, implement a database-enforced writer epoch and atomic dual-namespace transition; do not assume mixed binaries are safe.
   **Verify:** from `server/`, `go test ./internal/pgschema/... ./internal/pgledger/... ./internal/resourceshim/...` against a disposable Postgres database. Add fresh DB, upgrade-from-v3, repeated migration and old-writer rejection cases.
2. Thread trusted project context through Mem/Postgres consumption and release. Preserve consume-before-act, nonce→JTI failure cleanup, idempotent retry and ambiguous-commit burn semantics.
   **Verify:** `make test-server` with `AVERIN_TEST_DATABASE_URL` set; two different projects using the same nonce succeed independently, same-project replay fails, and cross-project rollback cannot remove a claim.
3. Implement and test legacy transition retention using database time. Remove legacy exclusions only after every capability that could rely on them is expired, considering maximum accepted TTL, clock-skew allowance and the last possible old issuance/consume. Preserve old consumed rows until that condition is demonstrable; never reset the ledger at migration.
   **Verify:** deterministic clock tests cover the exact expiry boundary, restart during migration, sweep failure, transaction ambiguity and concurrent claims. Replay remains rejected across the entire transition.
4. Extend `ConsumeLedger.tla` with project identity and legacy/new transition states. Assert at-most-once per capability/use index and tenant isolation separately. Preserve the short-retention replay counterexample; add an unsafe migration counterexample.
   **Verify:** `bash formal/tla/run-tlc.sh` produces every expected outcome; the safe migration model passes and the intentionally unsafe transition fails its named property.

## Test plan and done criteria

Follow `server/internal/pgledger/pgledger_test.go` and `resourceshim/resourceshim_test.go` patterns. Use independent pools to race equal and distinct tenant nonces. Test legacy rows with no recoverable project, same nonce under a new capability, migration interrupted before commit, capability expiry during retry and mixed-version refusal. The 001 required CI job must execute these database tests without skips. `make test-server`, `go test -race ./internal/resourceshim/... ./internal/pgledger/...` from `server/` after the static-library build, and the TLA gate pass.

## STOP conditions and maintenance

Stop if namespace selection precedes capability-project verification, historical row ownership cannot be recovered but code tries to guess it, or rollback could delete an unowned row. An availability improvement must not weaken replay protection. Any future TTL increase, new credential mode or ledger sweep change must rerun the migration/retention model. Use forward migrations through `pgschema`, not runtime ad-hoc DDL.
