# Averin correctness and trust implementation plans

Reviewed [PR #1](https://github.com/FeirAI/averin/pull/1), its commit descriptions and review discussion, at **`e81aa90adaf7ca90bb78f397839b51935e81c699`**, 2026-09-23. This includes the latest partial-anchor/PoP fix, following the earlier revision rounds. The working `averin/` checkout was `main` at `c30bd2f`; the existing `averin-pr1-review` worktree was `485f0d7`. Evidence was checked against the fetched PR head; the latter worktree's server/formal files are identical to that head. Govder producer references were checked at `a9a2948`.

**Recommendation: execute all twelve plans.** Every remaining PR gap with a material correctness, isolation, recovery or assurance benefit is included. Work size did not determine inclusion or priority. Priorities reflect trust impact and dependencies; effort labels inside plans are descriptive. This is a plan, not implementation or approval to deploy.

The largest immediate gains are body-bound authority, verifier claim monotonicity, request/tenant binding and safe recovery. The larger proof and concurrency work remains included: green model proofs cannot substitute for production-code refinement, and one UNIQUE index does not establish whole-server HA safety.

## Execution order and status

| Plan | Result | Priority | Depends on | Change risk | Status |
|---|---|---|---|---|---|
| [001](001-assurance-baseline.md) | Mandatory real-Postgres API race tests; accurate claim/gate inventory | P1 | — | Low | TODO |
| [002](002-verdict-monotonicity.md) | Evidence deletion cannot strengthen a requested trust claim; proved verdict model | P1 | 001 | High | TODO |
| [003](003-authority-body-binding.md) | Authority v3 authenticates the semantic record it approves, including Govder producers | P1 | 001; align 002 report contract | High | TODO |
| [004](004-grant-pop-context.md) | PoP binds the effective request; capability tenant identity stays authenticated at use | P1 | 001 | High | TODO |
| [005](005-tenant-nonce-ledger.md) | Tenant-isolated nonce state with replay-safe migration | P1 | 001, 004 | High | TODO |
| [006](006-recovery-authorization.md) | Project writers cannot exercise operator sequence-recovery powers | P1 | 001 | Medium | TODO |
| [007](007-project-transactions.md) | Database-enforced project serialization and authoritative replica state | P1 | 001; integrate 004/005 for full use-path HA | High | TODO |
| [008](008-bounded-sequence-recovery.md) | Durable fencing resolves retry-starved reservations without global ingest stalls | P1 | 001, 006, 007 | High | TODO |
| [009](009-temporal-revocation.md) | Proven historical ordering separated from current revocation, with conservative fallback | P2 | 001, 002, 007; coordinate 003/004 formats | High | TODO |
| [010](010-oracle-and-normalization.md) | Exact production preimage bytes and systematic identity/NFC conformance | P1 | 001 | Medium | TODO |
| [011](011-bounded-parser-proofs.md) | Extended parser/encoding proofs actually pass; reproducible fuzzing | P1 | 001 | Medium | TODO |
| [012](012-production-refinement.md) | Production seal and verdict code connected to checked proofs | P1 | 002, 010, 011 | High | TODO |

Status values: TODO, IN PROGRESS, DONE, BLOCKED (reason), REJECTED (new evidence and rationale). A successful tool spike is not completion of 012. A proof timing out is not completion of 011. Writing a migration is not completion of 005/007 without upgrade and concurrency gates.

After 001, work can proceed in independent tracks: verifier/proofs (002/010/011), authority producer migration (003), request/ledger migration (004→005), and operator/database recovery (006/007→008). Coordinate overlapping `verify.rs`, API and migration edits; these are not independent write scopes. Give migrations monotonic numbers at integration, never edit an already-shipped migration. Integrate 009 only after the authoritative ordering and verifier claim contracts exist. Continue 012 into the verdict kernel after 002; retain independent golden/oracle tests.

## Limitation-to-plan coverage

This inventory covers the PR's six “Known gaps” bullets, limitations embedded in its formal-verification description, the linked formal trust boundary, and directly necessary deployment/migration conditions. It does not treat already-fixed findings as open defects.

| Stated limitation or necessary adjacent gap | Decision and evidence |
|---|---|
| Authority evidence lacks body binding | **003.** [authority.rs:52](https://github.com/FeirAI/averin/blob/e81aa90adaf7ca90bb78f397839b51935e81c699/core/src/authority.rs#L52) authenticates source/project/ID/evidence hash. Define a non-circular semantic subject and visible legacy status; preserve historical evidence. |
| Grant PoP omits project/idempotency and other request inputs | **004.** [broker.go:163](https://github.com/FeirAI/averin/blob/e81aa90adaf7ca90bb78f397839b51935e81c699/server/internal/broker/broker.go#L163). Bind the full effective authorization request, freshness and tenant context, not only the two named omissions. |
| Eight oracle builders compared only by digest | **010.** [oracle.rs:96](https://github.com/FeirAI/averin/blob/e81aa90adaf7ca90bb78f397839b51935e81c699/core/tests/oracle.rs#L96). Improve exact conformance and diagnostics; digest comparison was not a realistic collision vulnerability. |
| Consume nonce namespace global across projects | **005**, gated on **004**. [pgledger.go:32](https://github.com/FeirAI/averin/blob/e81aa90adaf7ca90bb78f397839b51935e81c699/server/internal/pgledger/pgledger.go#L32). Preserve old spent-state and authenticated project selection through migration. |
| Revocation invalidates prior uses | **009.** [verify.rs:5642](https://github.com/FeirAI/averin/blob/e81aa90adaf7ca90bb78f397839b51935e81c699/core/src/verify.rs#L5642). This is deliberate conservative behavior, not an authorization bypass. Add historical accuracy only with defensible ordering evidence. |
| Void has no separate operator privilege | **006.** [broker_seq_void.go:104](https://github.com/FeirAI/averin/blob/e81aa90adaf7ca90bb78f397839b51935e81c699/server/internal/api/broker_seq_void.go#L104). One narrowly scoped recovery capability; no general role-management platform. |
| Void last-attempt guard is process-local; restart adds boot floor | **007/008.** Same handler lines 22–35 and 298 onward. Durable state/fencing replaces local memory as the operational authority; retain uniqueness as a backstop. |
| Void insert holds ingest lock during potentially long database wait | **007/008.** Same handler lines 92–96. Per-project transaction boundaries and bounded/reconcilable waits preserve safety while isolating stalls. |
| TLA grant model has one process; only index race result carries across replicas | **007.** [formal/README.md](https://github.com/FeirAI/averin/blob/e81aa90adaf7ca90bb78f397839b51935e81c699/formal/README.md). Add multi-replica checkpoint/frontier/anchor/revoke/pending models and executable database schedules. Preserve single-writer deployment bounds until the complete gate passes. |
| Liveness needs eventual successful retry; failed retries can starve void | **008.** Add an operator fence that retries cannot refresh; prove progress under explicit database-resolution/operator fairness assumptions. Keep the old starvation counterexample. |
| Liveness checked for two grants; safety finite-state and bounded | **007/008**, plus **001** claim precision. Add representative replica/crash schedules, non-vacuity and nonbinding-bound checks. Larger counts may supplement this, but are not a proof for arbitrary deployments. Seek an inductive argument where claiming unbounded safety; do not relabel TLC results. |
| Extended Kani harnesses timed out/OOM and are not verified | **011.** [run-kani.sh:27](https://github.com/FeirAI/averin/blob/e81aa90adaf7ca90bb78f397839b51935e81c699/formal/run-kani.sh#L27). Include all eight; real success, explicit bounds and mutation checks. Existing parser/escape harnesses also stub NFC, which must remain a visible component boundary or be discharged. |
| Verifier joins/capstone/key-status logic unproved | **002**, then **012**. Generalize the recently fixed anchor-deletion class into typed claims, executable properties, a model theorem and production refinement. |
| Lean↔Rust link is finite differential testing, not mechanized refinement | **012**, with **010/011** as complementary evidence. Prove the production path, not a second hand-written implementation. Aeneas first compatibility assessment, one selected checked toolchain. |
| Lean starts after NFC; caller identity/authorization may use raw strings | **010/011/012.** Specify boundaries, test normalization and post-NFC duplicate handling, and keep any unproved Unicode/runtime assumption explicit. Never silently rewrite opaque IDs. |
| Tag inventory is textual; corpus and eight mutations cannot catch every drift | **010/011/012.** Keep the existing inventory, add property-specific mutants and actual source-linked proof coverage. Do not market the lexer as a complete signing-call analysis. |
| Historical duplicate IDs can leave migration 0002 without a UNIQUE index | **007/008.** Validate backstop availability and preserve fail-closed recovery. Diagnose damaged histories without deleting/re-signing immutable records. |
| Green CI can skip real-Postgres void API race tests | **001**, directly verified in workflow/package selection. Required pass-event checks close this recurring-evidence gap. |
| Limitations docs lag shipped behavior | **001**, then update in every implementation plan. Live revocation now exists; pending/revocation state is durable at boot, but that does not establish live cross-replica coherence. |

## Considered and intentionally not expanded

- **Proving SHA-256 collision resistance, Ed25519 unforgeability, the entire compiler/OS or physical event truth:** retain as explicit assumptions. More internal model layers cannot manufacture these guarantees. Keep strict verification, pinned identities, collision disjuncts, resource-truth qualification and transparent proof-tool trust boundaries.
- **Undoing NFC equivalence:** it is intentional RCP semantics. Address inconsistent boundary handling, not canonically equivalent text becoming the same canonical value. A full new Unicode formalization is not required to claim the narrower, post-normalization seal theorem; the unproved boundary remains listed.
- **K framework or a separate hand-built Z3 model:** not selected. They add another implementation/model to keep aligned without closing the identified production-refinement gap. 012 selects one actual Rust verification route.
- **Domain-tagging every unsigned server-local digest:** no evidence here of cross-family signature use; content addresses, cache/idempotency comparisons and witness-local IDs are currently compared within their own type/context. Keep the catalogue exclusions explicit. Reopen if such values cross a signed or verifier-recomputed boundary.
- **Replacing the MD5 expression index merely because MD5 is not collision-resistant:** it is an index key, not the evidence integrity primitive. Exact-value probes and conservative UNIQUE conflicts preserve the current security direction; a same-project collision can cause rejection, not forge a record. Preserve those predicates and refuse missing-backstop recovery. Additional collision-handling infrastructure has marginal trust value compared with the selected invariants.
- **Full RBAC/SSO administration, generic recovery automation and more public prepare endpoints:** avoid unless a selected protocol cannot be implemented safely without them. The current needs are narrow operator authority, durable fencing, and internally consistent subject construction.
- **Cursor streaming, incremental grant-head caches and broader performance/billing features:** outside this PR-limitations trust plan. The existing whole-history and conservative grant-log checks are sound constraints; adding caches or alternate export paths without a demonstrated capacity/correctness requirement enlarges the state to verify. This is not a conclusion that scale, quotas or billing durability never matter.
- **Treating the latest partial-anchor regression as still open:** rejected; `e81aa90` moves PoP validation before closure branches and adds the targeted regression. 002 addresses recurrence of the class, not an already-fixed instance.

## Verification and handoff rules

Before implementation, use the planned PR revision or reconcile against its merged descendant; these plans are intentionally stored on the local main checkout without switching it. Each file is self-contained with scope, current behavior, migration contract, tests and STOP conditions. Any unknown prerequisite must be resolved without weakening a trust claim to satisfy a test.

Repository gates discovered during review:

- Core: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; retain native RFC3161 and 32-bit CI variants.
- Server: `make test-server` rebuilds the Rust static library **before** Go vet/tests. Set `AVERIN_TEST_DATABASE_URL` to disposable Postgres for database tests and enforce no skips for required named cases.
- WASM/browser: `make test-verifier` rebuilds WASM and pins; web: `(cd web && bun run test && bun run build)`.
- Formal: `make formal-lean formal-refinement`, `bash formal/check-mutants.sh`, `bash formal/run-kani.sh`, `bash formal/tla/run-tlc.sh`; plan 011 adds genuinely passing extended proofs.
- Cross-plane authority wiring: in Govder, `make test lint` and `go test -tags e2e ./e2e/ -timeout 600s -v -run TestFourPlaneE2E`. Each subproject is a separate repository.

No dependency installs or source changes were made in this planning pass. Use Socket Firewall for future dependency acquisition. The local read-only tag inventory passed on the unchanged PR formal files. GitHub reported all 14 workflow checks successful at `e81aa90` (plus the deployment check); this review did **not** rerun the full Rust/Go/database/Lean/TLA/Kani suites. Those green checks are baseline evidence, not proof that the future work is already done.

Scope not audited: an exhaustive new vulnerability scan of every package, dependency advisories, production infrastructure, real TSA operation, all deployment configurations, or the complete other-plane codebases. Cross-plane research focused on the actual Govder authority producer needed by plan 003. No GitHub comments, issues, commits or deployments were created.
