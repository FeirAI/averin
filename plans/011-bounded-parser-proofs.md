# Plan 011: Make the extended Kani parser proofs pass in CI

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving on. If a STOP condition occurs, stop and report. Do not weaken harnesses with target stubs or unbounded assumptions.
>
> **Drift check (run first)**: `git diff --stat e81aa90adaf7ca90bb78f397839b51935e81c699..HEAD -- core/src/b64.rs core/src/canon.rs core/src/hashx.rs formal/run-kani.sh formal/check-mutants.sh .github/workflows/ci.yml formal/README.md` . Re-read harnesses if any path changed.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Depends on**: `plans/001-assurance-baseline.md`
- **Category**: tests
- **Planned at**: commit `e81aa90`, 2026-09-23

## Why this matters

CI currently runs only six default Kani harnesses. The eight extended harnesses for complete base64 chunks, strict UTF-16 decoding, integer and string round trips, and parser panic-freedom are explicitly unverified because CBMC exhausted memory or timed out (`formal/README.md:201-212`). The result is a gap precisely at malformed-input and parser boundaries. This plan makes those named harnesses genuinely pass on the production parser and keeps their bounds, diagnostics, and mutation coverage visible in CI.

## Current state

- `formal/run-kani.sh:16-25` runs the default set; lines 27-38 add eight extended harnesses: `one_byte_tail_is_canonical`, `two_byte_tail_is_canonical`, `full_chunk_is_canonical`, `utf16_strict_matches_std`, `integer_roundtrip`, `accepted_integer_spelling_is_canonical`, `string_escape_roundtrip`, `parse_never_panics`.
- Harnesses live under `#[cfg(kani)]` in `core/src/b64.rs`, `core/src/canon.rs`, and `core/src/hashx.rs` (`formal/README.md:177-181`).
- The current failure includes Unicode diagnostic formatting pulling large tables into CBMC; the README records the 8/16 GB memory and 25-minute timeout limits.
- `formal/check-mutants.sh:104-112` requires named Kani counterexamples for the UTF-16 ordering and LP-width mutants. Preserve this load-bearing behavior.
- Production functions must remain the targets. Do not stub parsing, NFC, or the target algorithm merely to satisfy Kani.
- There is an additional present limitation: `canon.rs:617` and `:730` already use `#[kani::stub(nfc, nfc_identity)]`. Their current claim is about escaping/parser mechanics with normalization abstracted. Simply making those harnesses green does not establish production parser/NFC panic freedom. Remove that abstraction for the end-to-end bounded claim, or retain a separately labeled component proof and add a real-normalization composition gate with proved obligations.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Default proofs | `bash formal/run-kani.sh` | all default harnesses pass |
| Extended proofs | `bash formal/run-kani.sh --extended` | all eight extended harnesses pass, no skip |
| Mutation gate | `bash formal/check-mutants.sh` | baseline passes and every mutant is killed |
| Core tests | `cargo test --manifest-path core/Cargo.toml` | exit 0 |

## Scope

**In scope:** Kani harnesses and semantics-preserving error-data factoring in `core/src/b64.rs`, `core/src/canon.rs`, `core/src/hashx.rs`; `formal/run-kani.sh`; CI job sharding/resources; formal documentation; targeted mutation fixtures; a reproducible fuzz harness/corpus under `formal/` and `core/tests/` with `formal/run-fuzz.sh` as its local entrypoint. Scope includes feature/manifest wiring necessary to run those test harnesses, not unrelated dependency changes.

**Out of scope:** changing RCP semantics, replacing the production parser, stubbing target parsing/NFC, dropping parser harnesses, claiming unbounded proofs from bounded results, or changing unrelated verifier logic.

## Steps

### Step 1: Establish per-harness failures and explicit bounds

Run each extended harness individually and record memory, time, unwind, and solver behavior. Add explicit finite input sizes/unwind bounds with assertions that the bound is sufficient for the harness domain; a proof must fail or report unsupported when the bound is exceeded, not silently truncate a loop.

**Verify**: each harness has a named command and documented expected bound; the unmodified default suite still passes.

### Step 2: Remove diagnostic blowups without changing targets

If needed, factor production parsing/decoding error data into typed codes and leave human-readable formatting at `Display`/API boundaries; do not substitute a simpler success/rejection algorithm only under `cfg(kani)`. Preserve user-visible errors with regression tests. Shard full-chunk, UTF-16, integer, string and panic-freedom proofs so solver memory is isolated; larger runners are acceptable. Retain the original named input domains at minimum. Any additional component proof with a smaller domain must state its composition argument and cannot silently replace the original goal. Remove the current identity-NFC stubs for any claim about actual normalization.

**Verify**: `bash formal/run-kani.sh --extended` → every named harness reports `VERIFICATION SUCCESSFUL`; no skipped obligation, reachable target replacement, or timeout-as-pass path exists.

Execution refinement (2026-09-24): exhaustive disjoint sign/decimal-width shards may discharge the original integer domain only when a machine-checked union covers every integer in `[-99999,99999]` exactly once and every shard passes the same production round-trip obligations. A prefix lemma must be asserted before it is assumed; its failure remains a failing proof, as checked by an intentionally false lemma. Diagnostic formatting and a numeric-first top-level dispatch may be factored without changing accepted input, errors or trailing-data handling.

CBMC symbolic expansion still visits generic string/object branches for formatted integers even after the checked prefix lemma. A narrowly scoped compositional proof may replace a separately factored, unreachable general-dispatch helper with an unconditional assertion failure, subject to primary review. This replacement supplies no successful behavior: a passing proof must establish that the helper is never entered over the entire original shard domain. The real public typed entry dispatch, number parser, value equality, serializer and trailing checks remain executed. Require an exact wrong-route mutant to fail that guard, source wiring checks rejecting an empty/successful guard, and explicit documentation that the numeric proof establishes branch unreachability. General-parser and NFC obligations still require their actual reachable production paths; this exception cannot justify replacing a reachable parser or normalization function. Do not claim the exception accepted until its actual proof and mutant pass.

### Step 3: Wire the extended set into CI and mutations

Add a dedicated CI job or resource-sharded jobs using a pinned Kani version and explicit timeouts. Require the extended command to run. Add at least one parser mutation per high-value property (base64 tail/full chunk, strict UTF-16, integer/string canonicality, panic path) and require the intended harness or a documented stronger gate to kill it.

**Verify**: CI-shaped local commands pass; `bash formal/check-mutants.sh` reports every mutant killed and baseline harnesses passing.

### Step 4: Retain independent complement checks

Keep Lean proofs, golden vectors and adversarial tests as complements. Make the historical differential-fuzz evidence reproducible: commit the generator/harness, seed handling and minimized regression corpus, run a bounded deterministic campaign in pull-request CI and a larger scheduled campaign. Compare documented RCP behavior, not blanket equality to a permissive JSON library. Include nested/large inputs beyond symbolic bounds and native/WASM/FFI entrypoint handling. Document that Kani is bounded and state exact input/loop bounds and runner resources.

**Verify**: add a pinned local `formal/run-fuzz.sh` entrypoint (new deliverable), run it twice with the same seed and verify the same corpus/results; `cargo test --workspace`, `make test-server` and `make test-verifier` pass. The CI job runs the new command and fails on a saved counterexample. `formal/README.md` lists only actually checked properties and exact domains.

## Test plan

Exercise full accepted/rejected base64 chunks and tail bits, strict UTF-16/lone surrogates, integer spellings, escaped strings, malformed/truncated parser input, and panic-freedom through production functions. Include targeted cases that previously triggered Unicode-table memory blowup. Re-run both default and extended suites plus mutations.

## Done criteria

- [ ] All eight extended harnesses pass by name in CI.
- [ ] No reachable target parser/NFC behavior is stubbed; any reviewed fail-closed unreachable-branch guard has a proved domain and mandatory wrong-route mutant.
- [ ] Bounds are explicit, checked, and documented.
- [ ] Mutation coverage demonstrates the proofs are load-bearing.
- [ ] Lean/golden/fuzz complements remain enabled.
- [ ] Only scoped files are modified.

## STOP conditions

Stop if a harness can pass only by substituting behavior for a reachable production function, disabling NFC/Unicode behavior, omitting reachable parser branches, hiding an unwind failure, or treating timeout as success. The checked fail-closed unreachable-branch exception above must not conceal any successful execution. Stop if resource needs exceed the available CI class without an approved runner change.

## Maintenance notes

New parser branches require a named bounded harness or an explicit justification. Reviewers should inspect assumptions and unwind assertions, especially any `kani::assume`, and confirm error-code refactors do not change user-visible production errors.

Use a separate PR-descendant worktree, branch `advisor/011-bounded-parser-proofs`, and update the plan index after review. Main was `c30bd2f` during planning. Do not push or change hosted runner billing as part of this handoff without the applicable operational authorization; a proposed larger runner is a concrete resource requirement, not a reason to drop the proof obligation. Dependency acquisition uses Socket Firewall.
