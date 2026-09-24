# Implementation continuation checkpoint

Updated 2026-09-24. User asked to implement all twelve selected trust plans with **gpt-6-sol, high** subagents. Work size is not a reason to drop a plan. User subsequently reported 13% usage remaining and explicitly selected **checkpoint after nonce verification/integration**, then authorized pushing the work and preparing a handover for a different agent. This turn publishes the checkpoint only; implementation remains stopped until resumed. Unresolved tasks remain selected and must not be relabeled complete. Publication is scoped to the four task branches listed below; no deployment or merge to main is included.

## Published handoff layout

- Averin accepted implementation and these plans: `FeirAI/averin`, branch `advisor/averin-trust-implementation`. The final checkpoint adds documentation to accepted source commit `52518ab`; inspect the branch HEAD for the documentation commit.
- Averin unaccepted parser work: `FeirAI/averin`, branch `advisor/011-bounded-parser-proofs`, `a8d1db0f291aeeb7aae3680f022fa1cc0bcd83d7`. Keep it separate until proof gates and primary review pass.
- Govder accepted producer changes: `FeirAI/govder`, branch `advisor/003-authority-body-binding`, `0a22220`.
- Vultrino accepted producer changes: `FeirAI/vultrino`, branch `advisor/004-grant-pop-context`, `85b386f`.

Use [HANDOVER.md](HANDOVER.md) as the continuation prompt. [Preflight notes](preflight/README.md) preserve the production extraction results and tool pins; executables, caches and `/tmp` logs remain local and are not Git artifacts. The original Averin PR #1 branch is not updated by this publication.

## Accepted work

Plans **001, 002, 003, 004, 005, 006, 007, 008, 010** are accepted. Accepted source is `52518ab8cc6d39b354f88144207d2c6321fd40d8` on `advisor/averin-trust-implementation`, in `.worktrees/averin-trust-implementation` relative to the umbrella workspace. Primary independently verified the clean worktree after fast-forward. The subsequent publication commit contains only the plans and handoff documentation.

- PR baseline: `e81aa90adaf7ca90bb78f397839b51935e81c699`, Averin PR #1.
- User Averin main remains `c30bd2f94be4f8181bb23815ebfb99140adfffd3`. Its local `plans/` copy remains untracked; the integration branch now carries the handoff documents. Preserve the local copy and the user's pre-existing untracked `feir-os/` directory.
- Cross-plane producer branches: `.worktrees/govder-003` at `0a22220`; `.worktrees/vultrino-004` at `85b386f`. Both were reviewed and tested, including two real four-plane runs before the later server-only changes.
- Primary verification for recovery at the accepted integration source: `/tmp/averin008-primary-final-server.log` records fresh RFC3161 staticlib, full Go vet/test, and required uncached PostgreSQL JSON gate. New recovery TLC safe config passes96 states; old-writer config produces its required counterexample. Source review includes real child-process crash cuts, durable revocation atomicity and signed legacy-tombstone use denial.
- Earlier accepted combined core/WASM/Lean/refinement and cross-plane evidence is in `EXECUTION.md`. Do not infer that later source changes have passed these gates automatically. The integration WASM pins still require a rebuild before final delivery of the whole integrated task.

## Latest accepted change and remaining work

**005 nonce migration is DONE:** worktree `.worktrees/averin-005`, branch `advisor/005-tenant-nonce-ledger`, final `52518ab`. Primary reviewed scoped tuple keys, opaque claim ownership, global JTI uniqueness, immutable legacy exclusions, missing-metadata rejection, lifetime overflow, maintenance barrier and non-owner runtime checks. Prepared DELETE, seeded legacy sweep preservation, offline project composition, migration rollback/retry and TLC non-vacuity have real positive controls. Primary fresh full server/vet plus mandatory uncached PG passed on production-equivalent35394bb (`/tmp/averin005-primary-final-server.log`); the final test-only rollback commit and required-event union passed primary mandatory PG at52518ab (`/tmp/averin005-primary-final-pg.log`). All30 required tests passed without skipped children. Primary reran all six ConsumeLedger configs with expected outcomes; executor race checks passed resourceshim/pgledger/store/API. Final source is integrated and clean.

**009 temporal revocation:** source implementation has not begun. Read-only preflight completed in `/root/temporal_preflight`. Its dependencies are now accepted. After the user resumes, dispatch the full reconciled `009-temporal-revocation.md` inlined on a descendant of52518ab. Use migration0007 and a fresh maintenance writer barrier. Keep existing revocation/capstone blocking; historical authorization is a separate caller-selected claim. Native introspection requires actual grant validation and exact retry matching. Outcomes inherit intent authorization order. Capture snapshot boundary time/high watermark inside the database read transaction. Existing revoked branches skip later validation and cannot be relabeled historical positives without fixing that control flow.

**011 parser proofs:** clean checkpoint `a8d1db0` on `.worktrees/averin-011`; executor `/root/kani_contract` stopped its approved probe. NOT accepted or integrated. Three base64 extended families passed on unchanged relevant source. Integer, UTF16, spelling, string and panic families remain unverified. Latest integer positive1 probe spent5:05 CBMC CPU expanding recursive enum Drop and was interrupted; status15/FAILED is not a counterexample. Log `/tmp/averin-011-proof-integer-roundtrip-positive1-early-return.log`. Full ordinary core tests pass. Final-source numeric guard/mutants and full extended/mutation gate remain pending. Exact original-domain partitions and checked fail-closed unreachable-branch guard are documented; no reachable parser/NFC stubs, smaller replacement domains or timeout-as-pass.

**012 production refinement:** no implementation/proof yet. Pinned isolated Charon/Aeneas toolchain and a toy identity theorem work. Actual production extraction preflight is `.verification-tools/aeneas-557f7a/production-preflight/RESULTS.md`. Rooting a free forwarding wrapper extracts the actual serializer call graph without parser functions. Aeneas produces partial Lean containing `sorry` for write/write_string and external assumptions for sorting, UTF16, NFC, strings and integer formatting. This is not a refinement proof. Close those reachable obligations, then the production checked-value/signing/verdict joins per plan012; do not accept a handwritten replacement model or partial extraction as completion.

## Operational notes

- Primary follows the improve skill: review/plan only; source edits use isolated executors. Use **gpt-6-sol high**, `fork_turns: none`, and inline full plans at new implementation dispatch.
- Max two ordinary Rust jobs, normally one CBMC solver and one Lean/OCaml worker. Use `CARGO_BUILD_JOBS=1`, `GOMAXPROCS=2`, `GOFLAGS=-p=1`. Coordinate feature-changing Rust builds with cgo tests.
- Always rebuild RFC3161 Rust staticlib before Go tests via `make test-server`; mandatory PG gate uses `-count=1`. Never borrow local-crate build artifacts between worktrees. Some obsolete targets were intentionally cleaned; source/logs remain.
- Task-owned PG16 container `averin-trust-postgres`, port55432. Set `AVERIN_TEST_DATABASE_URL` from its local test configuration, without printing credentials. Tests isolate schemas/roles. Do not disturb the user's port5432 instance.
- Dependency fetches use Socket Firewall. Kani0.68 wrapper: `.verification-tools/kani-0.68/with-kani.sh`. Pinned TLC jar: `.verification-tools/tla/tla2tools-v1.7.4.jar`, SHA256 `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
- Disk last measured about14GiB free. Preserve reusable Aeneas/mathlib tool caches. All dispatched implementation, proof and verification workers have finished; no task build, solver or extraction should remain active. The task-owned PostgreSQL service remains available for resumption.

Use `README.md` as the plan status index and `EXECUTION.md` for the detailed evidence trail. This checkpoint records incomplete work; it is not a completion report.
