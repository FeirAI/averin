# Continuation prompt

Continue the Averin PR #1 correctness/trust improvement project. This prompt resumes implementation after the previous agent's quota checkpoint. Complete all remaining valuable work; amount of work is not a reason to skip it. Use **gpt-6-sol subagents with high reasoning**, overriding the workspace's default Luna preference. The primary agent owns architecture, security decisions, diff review and independent verification. Give executors isolated worktrees and self-contained contracts with the full relevant plan inlined.

Workspace: `/Users/dzcodes/Projects/feir-ai`; each plane is a separate Git repository. Read workspace `AGENTS.md`, then the following files from Averin's **`advisor/averin-trust-implementation`** branch, in order:

1. `plans/CONTINUATION.md` — exact state, branch locations, acceptance evidence and pitfalls.
2. `plans/README.md` — status/dependency index and deliberately excluded scope.
3. `plans/EXECUTION.md` — detailed verification trail.
4. Full plans `009-temporal-revocation.md`, `011-bounded-parser-proofs.md`, `012-production-refinement.md`, plus `plans/preflight/README.md` and its linked extraction notes.

GitHub repositories and checkpoint branches:

| Repository | Branch | State |
|---|---|---|
| `FeirAI/averin` | `advisor/averin-trust-implementation` | Accepted source `52518ab8cc6d39b354f88144207d2c6321fd40d8`, followed by documentation-only handoff commit |
| `FeirAI/averin` | `advisor/011-bounded-parser-proofs` | Unaccepted checkpoint `a8d1db0f291aeeb7aae3680f022fa1cc0bcd83d7`; not integrated |
| `FeirAI/govder` | `advisor/003-authority-body-binding` | Accepted producer changes `0a22220` |
| `FeirAI/vultrino` | `advisor/004-grant-pop-context` | Accepted producer changes `85b386f` |

On the existing machine, accepted work is in `.worktrees/averin-trust-implementation`, parser work in `.worktrees/averin-011`, and producers in `.worktrees/govder-003` and `.worktrees/vultrino-004`. Inspect these first; preserve uncommitted user work. On a new machine, fetch the named remote branches and create equivalent isolated worktrees. The original PR branch remains `claude/averin-formal-verification-wo3x44` at reviewed baseline `e81aa90`; do not mistake it or user main for the implementation branch.

**Nine of twelve plans are accepted:** 001, 002, 003, 004, 005, 006, 007, 008, 010. Do not redo them from scratch or silently discard their contracts. Three remain:

- **009: temporal revocation.** Implementation has not begun; dependencies are now accepted. Use additive migration 0007 and a fresh writer maintenance barrier. Preserve current conservative revocation/capstone blocking; historical authorization is a separate explicit caller policy. Fix native introspection's actual grant validation and exact retry checks; outcomes inherit the intent's authorization order. Snapshot time and watermark must come from the same database read transaction. Read the full plan before editing.
- **011: extended parser proofs.** Preserve and reconcile the separate checkpoint. Three base64 proof families passed; integer, UTF16, numeric spelling, string escaping and parser-panic families remain unverified. Ordinary tests passing does not establish these proofs. A timed-out or interrupted solver is not a counterexample or a successful proof. Keep the original domains, checked decomposition and honest NFC boundary; no reachable parser/Unicode stubs, invented success, or smaller replacement domains. Final-source guard/mutant checks and the full extended/mutation gate remain pending.
- **012: production refinement.** Toolchain preflight succeeded only on a toy identity theorem. Actual serializer extraction emits partial Lean with `sorry` and unproved external operations. No production refinement is established. Complete a source-linked proof of the actual checked-value, serialization/framing/signing and verdict construction/join paths. A second handwritten algorithm, partial extraction or finite differential testing cannot substitute for this.

Start 009 from the integration checkpoint. Coordinate 011 and 012 so proofs apply to the final production source; do not allow overlapping edits or feature-changing builds to corrupt verification. Retain independent golden/oracle tests and all existing conservative behavior while adding claims.

Operational requirements:

- All dependency acquisitions go through Socket Firewall (`sfw`). Preserve existing tool caches. See `CONTINUATION.md` for Kani, TLC and Aeneas paths/pins. Binaries/caches and `/tmp` logs are local, not pushed; on another machine, reconstruct tools from the pinned provenance and rerun missing evidence.
- Keep resource usage bounded: normally `CARGO_BUILD_JOBS=1`, `GOMAXPROCS=2`, `GOFLAGS=-p=1`; at most two ordinary Rust jobs, one CBMC solver and one Lean/OCaml worker concurrently.
- Rebuild the RFC3161 Rust static library before cgo tests via `make test-server`. Never borrow local-crate build artifacts across worktrees. Mandatory real-Postgres tests use `-count=1` and the required JSON-event gate; skips do not count as verification.
- Existing task Postgres is container `averin-trust-postgres` on port 55432. Use its local test configuration; leave the user's port 5432 instance alone.
- Before accepting a change, the primary reads the diff, checks the load-bearing claims in actual code and independently runs relevant gates. Update plans/status/evidence only after acceptance.
- Final combined delivery still requires refreshed WASM artifacts/pins, all relevant Rust/Go/real-Postgres/browser/formal/mutation/extended-proof gates, and the real four-plane e2e with the accepted Govder/Vultrino branches. Prior partial or earlier-revision passes do not establish final-source success.

Keep user main unchanged, preserve the pre-existing untracked `averin/feir-os/` and local plans copy, and do not deploy or merge to main. The prior user authorized checkpoint branch pushes; continue on these task branches and follow any new publication instructions. Keep the user informed with concise progress updates. Finish the remaining plans and final verification without asking again whether already-selected work is wanted.
