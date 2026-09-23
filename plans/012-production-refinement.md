# Plan 012: Replace corpus refinement with production Rust-to-Lean refinement

> **Executor instructions**: Follow this plan step by step. Run every verification command and stop on the stated conditions. This is an implementation plan, not an invitation to maintain a second hand-copied model.
>
> **Drift check (run first)**: `git diff --stat e81aa90adaf7ca90bb78f397839b51935e81c699..HEAD -- core/src/canon.rs core/src/hashx.rs core/src/b64.rs core/src/record.rs core/src/checkpoint.rs core/src/verify.rs formal/lean formal/check-refinement.py formal/README.md .github/workflows/ci.yml` . A mismatch requires re-evaluating the target symbols.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Depends on**: `plans/010-oracle-and-normalization.md`, `plans/011-bounded-parser-proofs.md`, `plans/002-verdict-monotonicity.md`
- **Category**: tech-debt
- **Planned at**: commit `e81aa90`, 2026-09-23

## Why this matters

The current Lean oracle is an executable model compared with Rust over a committed corpus; `formal/README.md:98-104` explicitly says it is not a mechanized refinement proof. The formal seal theorem is therefore stronger than the implementation link that carries it to production. This plan implements that link for the seal core, then extends it through the verdict kernel after monotonicity is proved, using one demonstrated extraction/proof tool rather than creating another manually synchronized implementation.

## Current state

- `core/src/canon.rs`, `hashx.rs`, `b64.rs`, `record.rs`, and `checkpoint.rs` implement the encoding and hash paths modeled in `formal/lean/Averin`.
- `formal/lean/Oracle/Main.lean` and `core/tests/oracle.rs` provide the current corpus-based bridge.
- `formal/lean/check-axioms.sh` audits the whole `Averin` namespace and oracle glue; preserve this audit for generated/extracted glue.
- `formal/README.md:284-292` names Aeneas or Verus as future options. Aeneas documentation describes a Rust-to-Lean path through the Charon LLBC intermediate representation and a pinned Lean backend; Verus is an alternative Rust verification system. Do not assume arbitrary Rust is supported: compatibility must be demonstrated on this code.
- The verdict kernel is intentionally deferred until `plans/002-verdict-monotonicity.md` lands.

The current model theorem `formal/lean/Averin/Seal.lean:89`, `recordHashOf_binding`, concludes `a = b ∨ Collision H` from equal modeled hashes, with an injective formatting hypothesis. The actual Rust `hashx.rs:41` computes `format!("sha256:{}", hex_lower(&sha256(data)))`. The missing deliverable is a production-linked theorem justifying such implementation hypotheses, plus the record/checkpoint projection and serialization equivalence, not another proof of the same model lemma.

## Commands and references

Primary tool references: [Aeneas](https://github.com/AeneasVerif/aeneas) and [Verus](https://github.com/verus-lang/verus). Read their current compatibility/build instructions before selecting a tool.

| Purpose | Command | Expected on success |
|---|---|---|
| Existing proof gate | `cd formal/lean && lake build --wfail && ./check-axioms.sh` | standard axioms only; no forbidden escape hatches |
| Existing oracle | `cd formal/lean && lake build --wfail oracle && lake exe oracle ../oracle/inputs.json ../oracle/expected.json` | deterministic output |
| Rust tests | `cargo test --manifest-path core/Cargo.toml` | exit 0 |
| Refinement/mutations | `python3 formal/check-refinement.py && bash formal/check-mutants.sh` | inventory and all mutants pass |

## Scope

**In scope:** a compatibility spike under `formal/`, one selected pinned toolchain, generated/extracted definitions and proofs, semantics-preserving refactors in `core/src/{canon,hashx,b64,record,checkpoint}.rs` needed for verified production paths, verifier decision kernel after 002, formal manifests/build scripts/axiom audit, CI regeneration and source/call-path checks. Full DAG traversal, external cryptographic primitives and the Go server remain separately modeled/tested boundaries unless explicitly brought into a later reviewed proof scope.

**Out of scope:** selecting both tools, hand-copying Rust into a second model, proving SHA-256/Ed25519 security, proving the host runtime/compiler, proving Unicode normalization implementation/version equivalence unless separately supported, changing wire formats, or removing the existing corpus/mutation gates before replacement evidence is complete.

## Steps

### Step 1: Demonstrate compatibility and select one tool

Build a spike for the canonical serializer plus one hash/preimage function using the same source compiled into production. Try Aeneas first because the project already targets Lean. Its extracted implementation semantics still rely on the compiler/extractor toolchain; explicitly record that trust. Evaluate Verus only if Aeneas cannot cover the required subset or the evidence favors it. Verus results do not automatically become Lean theorems: a switch must specify a checked composition with the existing model, or an independently complete verified argument with clearly revised proof claims. Never insert a Lean axiom asserting a Verus result. Record pinned versions, unsupported constructs, generated artifacts and proof obligations. Do not proceed on documentation-only compatibility.

**Verify**: the spike extracts/verifies a production function, and the selected checked proof path composes its theorem with the existing seal definitions in CI. Record the exact reproducible extraction/proof command in a new `formal/run-production-refinement.sh` wrapper. Otherwise STOP and report the precise missing obligation; do not mark the plan done after a spike alone.

### Step 2: Extract/prove the seal core incrementally

Cover production `canon`, `hashx`, `b64`, record, and checkpoint paths. Generated definitions must be the source of implementation facts; Lean wrappers may state theorems but must not duplicate function logic manually. Prove the same injectivity/framing/hash-preimage obligations currently used by `Seal`, and retain the corpus oracle while migration is in progress.

**Verify**: Lean build and axiom audit pass; a deliberately changed production preimage fails the generated refinement proof, not merely a stale vector.

### Step 3: Prove reachability and CI regeneration

Make CI regenerate extraction artifacts from the checked-out Rust source and selected feature/target configuration. Maintain a manifest mapping source hashes, extracted symbols, build features and production callers to the corresponding proofs. Extend the axiom audit to all imported proof/glue declarations, not just an easy-to-audit namespace; no unsupported external body may hide a load-bearing implementation fact. Use call-path/source checks and runtime conformance tests to show the compiled production entrypoints use the proved functions. A runtime test does not execute a theorem. Keep tag inventory and mutation suite; add a mutation that bypasses a proved helper at a production call site and require it to fail.

**Verify**: `bash formal/run-production-refinement.sh` (new deliverable) regenerates and proves every manifest entry; intentionally stale extraction, changed feature selection and bypass mutations fail for their named reason. Existing `make formal-lean formal-refinement` and Rust tests pass.

### Step 4: Extend through verdict logic after plan 002

Only after the monotonicity model exists, refine the relevant `verify.rs` verdict kernel against it, including capstone/key-status joins. Preserve adversarial tests and plan 010’s byte-level conformance as independent evidence.

**Verify**: verdict refinement catches a mutation that makes deletion strengthen a required trust claim or the capstone according to plan 002's claim order. Do not substitute an undifferentiated Boolean ordering that wrongly treats removal of a malformed optional attachment as new authority.

## Test plan

Use existing Lean axiom, oracle, mutation, and core test commands. Add generated-proof reachability tests for each target module, production-call-site mutation tests, and verdict mutations after plan 002. Keep crypto, runtime, and Unicode-version assumptions explicit unless the selected tool actually proves them.

## Done criteria

- [ ] One tool is selected from a successful compatibility spike.
- [ ] Production seal-core implementation is connected by generated/proved refinement.
- [ ] CI regenerates and audits glue from source.
- [ ] Production reachability and mutation tests are load-bearing.
- [ ] Verdict kernel refinement lands only after plan 002.
- [ ] Crypto/runtime/Unicode trusted boundaries remain explicit.
- [ ] Only scoped files are modified.

## STOP conditions

Stop if neither tool can handle the required production subset, if proof requires manually duplicating Rust logic, if generated code cannot be tied to the current source in CI, or if a theorem depends on unreviewed `axiom`, `sorry`, `native_decide`, `partial`, `extern`, or equivalent escape hatches. Stop if the proposed change requires wire-format or historical-record migration beyond this plan.

## Maintenance notes

Pin the selected tool and Lean backend, review generated diffs, and keep the current oracle until generated refinement has been stable through at least one release. Any new encoder/preimage family must be reachable from the generated proof and killed by the mutation suite before its formal claim is expanded.

Use a PR-descendant worktree such as `advisor/012-production-refinement`; main was `c30bd2f` during planning. Keep oracle/golden/mutation tests even after refinement as independent regression evidence. Run `make test` after production refactors, rebuilding staticlib and WASM through the Makefile. Update the plan index only when the implementation proof and verdict refinement pass, not merely after choosing a tool. Dependencies/tool downloads must follow the workspace's Socket Firewall policy. No source/ABI/wire migration is allowed without revising this plan's contract.
