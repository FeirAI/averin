# Plan 001: Make correctness claims traceable to mandatory gates

## Status and execution contract

- Priority: P1; effort: M; implementation risk: LOW; confidence: HIGH.
- Category: tests / docs. Depends on: none.
- Planned at Averin PR #1 commit `e81aa90adaf7ca90bb78f397839b51935e81c699`, 2026-09-23.
- Execute on that commit or a descendant, in a separate branch such as `advisor/001-assurance-baseline`. The workspace's `averin/` checkout was `c30bd2f` during planning; do not apply against main without the PR changes.
- First run `git diff --stat e81aa90..HEAD -- .github/workflows/ci.yml Makefile scripts formal/README.md docs README.md`. Reconcile any drift against the excerpts below. Do not commit, publish, or change branch in someone else's working tree. Update this plan's row in `plans/README.md` after review.

## Why this matters

The PR's 14 GitHub correctness/build jobs were green at the reviewed head, but a green suite does not imply every database race test ran. Separate claims about models, actual implementation, bounded proofs and deployed behavior, and give each an executable gate. This foundation prevents the later plans from acquiring stronger documentation than their evidence supports.

## Current state

`.github/workflows/ci.yml:79` runs `go vet ./...` and `go test ./...` without a Postgres service. The Postgres job at line 128 runs only:

```sh
go test -count=1 ./internal/store/... ./internal/pgledger/... ./internal/pgdurable/...
```

`server/internal/api/broker_seq_void_pg_test.go:24` does:

```go
base := os.Getenv("AVERIN_TEST_DATABASE_URL")
if base == "" {
    t.Skip("set AVERIN_TEST_DATABASE_URL to run the Postgres-backed broker_seq void tests")
}
```

Consequently the API's real database ordering tests are not exercised by those CI jobs. Local PR validation reports a database run; that is useful historical evidence, not a recurring gate. `Makefile:test-server` correctly rebuilds the native Rust static library before Go tests. Preserve that order.

`docs/dev/LIMITATIONS.md` still describes revocation as audit-only and two-phase pending state as wholly in-memory. `server/internal/api/revocation_server.go:81` rejects later live uses; `durable.go:21` persists and reloads revocations and pending grants at boot. Durability does not imply live replica coherence.

## Scope

Modify `.github/workflows/ci.yml`, `Makefile`, focused gate scripts/tests under `scripts/`, `formal/README.md`, `README.md`, `docs/dev/{LIMITATIONS,SECURITY,TESTING,ARCHITECTURE,API}.md`, `docs/operator-verification.md`. Add a compact claim manifest under `formal/`. No cryptographic, storage, authorization or verifier semantics change here.

## Steps and verification

1. Add a Postgres API job, or extend the existing database job with the Rust toolchain/static-library build, freshness guard, and the API suite. Match the existing private-schema test setup and least-privilege append-only tests. Fail if the database configuration is missing in this required job.
   **Verify:** `cargo build -p averin-decision-core --features rfc3161`, then `./scripts/check-staticlib-fresh.sh`, then, from `server/` with `AVERIN_TEST_DATABASE_URL` pointing at a disposable Postgres 16 database, `go test -json -count=1 ./internal/api/... ./internal/store/... ./internal/pgledger/... ./internal/pgdurable/...`. All pass.
2. Add a gate that consumes the Go JSON test events and requires pass events, not merely package success, for `TestBrokerSeqVoidPostgres`, `TestBrokerSeqVoidGrantLandsFirstPostgres`, and `TestBrokerSeqVoidMarkerFailsPostgres`. Expand the required list when later plans add concurrency/migration tests. Unit-test the gate with pass, skip, missing and fail events; a skip/missing must fail the gate. Do not treat unrelated deliberate fixture-generation skips as failure.
   **Verify:** the new gate's self-test exits 0; running it on the actual test event stream passes; its negative fixtures exit nonzero.
3. Record each trust claim, source symbols, assumptions, required test/proof, supported target and bounded/unbounded status. Include native RFC3161 versus WASM unsupported status, model versus production distinction, external pins, single writer, resource truthfulness and liveness fairness. Correct stale limitation statements; retain the actual remaining constraints.
   **Verify:** add a local manifest checker that verifies referenced files/symbols and CI job names exist; it exits 0 and rejects a fixture naming a missing gate. Semantic accuracy still requires review; do not claim text validation proves the claim.
4. Wire the checks into required pull-request CI and record validation at the final implementation SHA. Keep named unsafe TLA variants and mutation kills required.
   **Verify:** `make test-server` with the disposable DSN set, `python3 formal/check-refinement.py`, and `git diff --check` exit 0. A workflow run must show the named database API tests passed, not skipped.

## Done criteria

- Required CI executes the three named Postgres API tests and rejects missing/skip results.
- Claim inventory distinguishes proved model properties, sampled conformance, bounded implementation proofs, and unproved deployment assumptions.
- Revocation and pending-state docs match the code without claiming cross-replica coherence.
- No production source behavior changes; no results are asserted for a SHA or platform not actually checked.

## STOP conditions and maintenance

Stop if the target PR changed, the named database tests no longer exist, or a proposed CI shortcut links a stale/default-feature library while claiming native RFC3161 coverage. New proof or safety claims must add a manifest entry and a recurring gate. Use Socket Firewall for any dependency acquisition; this plan should need no new application dependency.
