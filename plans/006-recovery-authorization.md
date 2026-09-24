# Plan 006: Require project-scoped operator authority for sequence recovery

## Status and execution contract

- Priority: P1; effort: M; implementation risk: MED; confidence: HIGH.
- Category: security. Depends on: 001.
- Planned at `e81aa90adaf7ca90bb78f397839b51935e81c699`, 2026-09-23.
- Use `advisor/006-recovery-authorization` on a PR descendant. Run `git diff --stat e81aa90..HEAD -- server/internal/auth server/internal/api server/cmd/averin-server docs` and reconcile drift. No external publishing; update the plan index after review.

## Why this matters

Writing ordinary evidence and permanently retiring an unrecorded grant reservation are different powers. Compromising a writer key should not confer the operator recovery privilege. A narrow capability is sufficient; building a generic role-management service would add unnecessary scope.

## Current state

`server/internal/api/broker_seq_void.go:104` explicitly documents that any project writer may void that project's aged reservations. The handler enters the global ingest lock at line 145 after ordinary project checks. `server/internal/auth/auth.go:28` defines only:

```go
type KeyStore interface {
    ValidFor(project, token string) bool
}
```

MapStore is fail-closed and constant-time; `NewOpenStore` is an explicit development exception. Preserve those properties. The tombstone's `Reason` is optional and there is no authenticated operator identity in its signed evidence.

## Scope

`server/internal/auth/`, operator route wiring and `broker_seq_void.go`, startup configuration, focused auth/API tests, void evidence schema/vector/model if fields change, operator/API/security docs. No SSO, general RBAC UI, delegated permission administration or external identity platform. This plan adds the one recovery privilege; audit unrelated route permissions separately.

## Steps and verification

1. Define a project-scoped `broker_seq:recover` credential capability with a stable nonsecret operator/key identifier. Use a separate configured operator store or scoped identity returned by authentication. Never infer recovery authority from possession of a project writer key. Missing operator configuration denies recovery. Dev-open ordinary auth does not silently enable this destructive privilege.
   **Verify:** from `server/`, `go test ./internal/auth/...`; tests cover absent config, ordinary writer, wrong-project operator, expired/revoked operator if supported, and explicitly authorized project operator. Preserve generic failure messages and token secrecy.
2. Enforce the capability before reading sensitive recovery state or acquiring locks, on the existing void route and the future fence/resume operations in 008. Keep project query/body consistency checks and all existing void safety checks. Return authorization failure without allocating, revoking or signing anything.
   **Verify:** `make test-server` with a disposable database; writer requests fail with 403 (unauthenticated requests may be 401), correct operator succeeds, and record/sequence/ledger counts remain unchanged on denial.
3. Bind authenticated operator ID, recovery operation ID and a required bounded reason into the signed recovery evidence. Identity comes from authentication, never an untrusted body field. Preserve retry identity: return the original evidence on identical replay; conflicting reason/operation parameters cannot rewrite an existing tombstone. If old verifier interpretation requires a schema version, add it explicitly and retain old evidence reads.
   **Verify:** `cargo test --workspace`, `make test-server`, and `make formal-lean formal-refinement` when tags/schema change. Test spoofed identity, conflicting retry, evidence stripping/relabeling and old tombstones.
4. Add setup, rotation and emergency recovery examples using placeholders, and test startup validation. Do not create real operator credentials in the repository.
   **Verify:** `git diff --check`, auth tests and `make test` pass; the operator runbook commands use the privileged route configuration and ordinary ingest still follows its existing policy.

## Done criteria

Execution reconciliation: implementation changes only Go/server documentation; the existing grant-void evidence hash already authenticates added actor/operation fields, so no Rust tag/schema/formal change is needed. Run the full native rebuild, Go vet/test and mandatory uncached Postgres gate here. Run the unchanged core/WASM/formal suites once on the integrated result alongside 003/007/008 rather than rebuilding them repeatedly for this Go-only step. This sequences the same required final coverage; it does not waive it. Human-readable reasons use Rust RCP NFC before both sealing and retry comparison; new actor/operation machine IDs are restricted to 1–128 visible non-whitespace ASCII bytes.

- Ordinary project writers cannot void, fence or resume recovery operations.
- Recovery is independently authorized for the exact project and actor identity is authenticated in evidence.
- Denied operations have no durable side effect; operator credential failure never falls back to writer/open mode.
- Existing sequence safety and idempotency tests still pass under explicitly configured test operator identities.

## STOP conditions and maintenance

Stop if this requires inventing a broad identity framework or silently granting existing writers admin privilege. Do not log secrets. Adding new recovery actions requires an explicit permission mapping and a no-side-effect denial test. Coordinate overlapping API files with 007/008 rather than editing them concurrently.
