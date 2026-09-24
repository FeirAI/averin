# Plan 005: Isolate nonce replay state without reopening old replays

## Status and execution contract

- Priority: P1; effort: L; implementation risk: HIGH; confidence: HIGH.
- Category: correctness / migration. Depends on: 001, 004's authenticated capability-project contract, 007's transaction-bound ledger, and 008's preceding schema step.
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

`server/internal/{resourceshim,pgledger,pgschema,store}/` (including 007's transaction-bound ledger implementations), a new forward migration in `server/migrations/`, API shim construction and rollback calls, startup wiring, a narrow `server/cmd/averin-migrate` maintenance command (or equivalent existing-binary subcommand), matching tests, core adversarial composition tests, `formal/tla/ConsumeLedger*`, configuration and migration docs. Do not rewrite sealed records, change evidence ledger commitments gratuitously, or partition JTI by resource/session in a way that increases an existing capability's use budget.

## Target contract

Scope nonce claims by authenticated project plus server-configured resource identity. Get the project from the signed capability and authorized request context validated by plan 004, not merely a request body. This matches the offline `(resource_id, nonce)` duplicate key within a single authenticated project. Keep JTI single-use/bounded-use uniqueness across all consumers of the same capability. Only widen its physical key if equivalence to that invariant is separately demonstrated; no need to change JTI namespace to fix nonce collisions. Use migration 0006 and the transaction-bound ledger seam from 007; nonce/JTI claims and receipt insertion commit together. Migration 0005 belongs to 008 recovery, which can proceed directly after 007. Integrate that actual schema step before the nonce migration; do not insert an empty placeholder. Upgrade tests cover existing schema versions 3, 4 and 5, and repeated migration to 6.

Represent global legacy nonce rows explicitly. Their owner is unknown and must not be invented. A new scoped consume checks relevant unexpired legacy-global exclusions and inserts scoped state atomically. A compatibility period may conservatively reject an innocent collision; it must not allow a replay. Release identifies exactly the scope and claim acquired by this request; it cannot delete another tenant's or an inherited legacy exclusion.

Execution preflight selected a maintenance cutover and separate new nonce/JTI tables. Rename the old table to an explicit legacy exclusion table and leave no writable compatibility relation under its old name. Renaming alone does not stop already-prepared statements, which can remain bound to the table's OID: make legacy INSERT/UPDATE/DELETE fail with a database-side immutability guard. Explicitly test old prepared DELETE and INSERT as well as ordinary old SQL. Drain old servers/workers and database sessions, resolve prepared transactions, and revoke/rotate old runtime credentials before enabling new writers. Retain all legacy exclusions until a database-time cutoff plus maximum accepted capability TTL/skew and the existing minimum retention floor have elapsed. Ordinary sweepers must never delete legacy exclusions; removal is a separate controlled maintenance operation. Do not guess project ownership or silently retire the older ledger implementation while leaving a callable bypass.

Execution refinement (2026-09-24): use an explicit maintenance command for existing or unstamped legacy databases moving to v6. Normal startup must refuse that upgrade with an actionable command hint, including when the old ledger is empty; a truly fresh database can bootstrap automatically. The command uses a separate migration credential, takes explicit old runtime roles and the new runtime role, and validates the old roles are NOLOGIN, have no active sessions or unresolved prepared transactions, and retain no effective write privileges on the actual old Averin tables (including inherited permissions). Old, migration and new runtime identities must be distinct. The operator runbook performs quiescence, privilege/credential rotation and session termination; the command validates that narrow barrier and applies migration plus database-time cutover metadata atomically under the existing migration lock. It is not a general role-management service. State the remaining deployment assumption: new runtime credentials are supplied only to new binaries. Test the actual guarded Averin writer after cutover and required new-role privileges, rather than substituting a generic probe table.

Acceptor preflight found that issuance caps TTL at one hour but the use shim does not bound signed descriptor lifetime. A finite legacy exclusion deadline therefore requires a corresponding online acceptance bound. Before any ledger claim, require `exp > iat`, a lifetime no greater than `broker.MaxTTL`, no future issuance beyond the documented request-clock skew, and producer-compatible not-before ordering. Preserve the actual `now >= nbf && now < exp` use window; do not widen it implicitly. Comparisons must resist signed-integer overflow and cover minimum/maximum timestamps. Previously committed exact receipt retries remain readable under004's full request-matching contract; historical signed bytes and offline legacy verification are unchanged. Retention uses the new maximum accepted lifetime plus skew and the existing 24-hour minimum, measured from database cutover after old issuers are excluded. Use explicit opaque claim ownership for scoped nonce release (and any JTI release), including the standalone memory ledger; key-only deletion is insufficient.

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
