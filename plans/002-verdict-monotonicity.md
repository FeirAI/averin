# Plan 002: Prove the verifier's evidence and verdict rules

## Status and execution contract

- Priority: P1; effort: L; implementation risk: HIGH; confidence: HIGH as an assurance gap.
- Category: correctness / formal verification. Depends on: 001-assurance-baseline.md.
- Planned at `e81aa90adaf7ca90bb78f397839b51935e81c699`, 2026-09-23.
- Work on a PR descendant in `advisor/002-verdict-monotonicity`. Run `git diff --stat e81aa90..HEAD -- core/src/verify.rs core/tests formal verifier web/src` and reconcile changes before editing. No push or merge is implied. Update `plans/README.md` after reviewed completion.

## Why this matters

The seal theorem does not establish that Tier-B joins, key status and the final report interpret evidence correctly. PR revision `e81aa90` fixed a concrete counterexample: removing only the outcome checkpoint's anchor bypassed PoP validation of an intent. Preserve that fix and generalize the protection into properties over the production decision path.

## Current state

At the planned head, `core/src/verify.rs:5799` performs `pop_reverify(rec, &g.credential_binding)` before completion branches. Failure increments `unmatched_violation` and continues without consuming the outcome. The regression is `tier_b_partial_anchor_strip_keeps_failed_pop_intent_a_violation` in `core/tests/adversarial.rs`.

`ActionCompleteness::of`, around line 112, derives the capstone from a conjunction beginning:

```rust
let base = r.ok
    && has_manifest
    && !r.one_phase_use_present
    && r.intent_without_outcome == 0
    && r.taxonomy_status == "validated";
```

The actual conjunction continues through PoP, grant log, attestation, delegation, revocation, federation and coverage checks; preserve every term. `evaluate_revocation` distinguishes missing pinned evidence from benign absence. `formal/README.md:105` explicitly excludes verdict logic from the proofs.

## Scope

`core/src/verify.rs` and a focused extracted decision module if needed; `core/tests/{adversarial,oracle}.rs` plus new property tests; `formal/lean/Averin/`, `formal/lean/Oracle/`, oracle fixtures, mutation suite and CI; report consumers in `verifier/` and `web/src` only for explicit status handling; protocol/report docs and schemas. No unrelated verifier rewrite or new external trust service.

## Design contract

Model separate dimensions: integrity, authenticated provenance, authorization, temporal certainty and completeness. Use an explicit information/claim order; do not order string labels lexically. An unknown result cannot satisfy a caller's required claim. A malformed optional disclosure disappearing may remove a parsing error; that alone must not become proof of a stronger claim. Thus do not assert the impossible property that every textual issue persists under arbitrary deletion.

For fixed signed records/checkpoints, fixed authenticated adverse evidence (including independent revocation statements, validated commitment openings and contradictory verified TSA anchors), fixed out-of-band pins, fixed verification policy/time and a fixed requested claim:

- Deleting supporting attachments such as anchors, disclosures or Merkle paths cannot add authenticated/authorized/complete claims.
- Any contradiction derivable from unchanged committed records remains a contradiction, regardless of closure branches.
- Missing required revocation, attestation or disclosure evidence yields insufficient evidence, never affirmative satisfaction of that claim.
- A capstone implies integrity success and all necessary externally pinned role evidence, including record provenance; embedded keys alone never satisfy authentication.
- `grant_void` can close a sequence gap but cannot supply grant authority; no failed intent consumes an outcome.

Execution review identified a necessary mathematical bound: a fresh non-revoking list plus a separately signed root proving revocation must be rejected, but removing that adverse root can leave sufficient disclosed evidence. A validated commitment opening that contradicts a credential label has the same limitation when its disclosure is optional: deleting the opening hides the contradiction. No verifier can retain unseen adverse evidence without a committed or out-of-band inventory. Do not claim monotonic acceptance under arbitrary deletion of authenticated adverse evidence. Keep both counterexamples as regressions/documented boundaries; always honor adverse authenticated evidence that is present. Do not require disclosure of every credential secret or add an inventory protocol merely to rescue an overbroad theorem. Prove committed-record contradiction preservation under all attachment deletion, and separately prove missing required artifacts/paths cannot satisfy a fixed caller policy. Default pinned mode resolves to disclosed evidence; Merkle or both modes are explicit caller choices, never selected from bundle presence. Where an existing signed deployment attestation commits artifact digests, test its omission protection. This correction does not weaken the implementation checks or substitute for production evidence-to-fact proofs.

The executable Lean decision function must be related to its support predicate. Enumerate every production capstone prerequisite in the model, rather than hiding them in a single opaque completeness boolean. A contradiction-preservation theorem must conclude that authorization/completeness are refuted across attachment changes; an identity implication on a contradiction field is insufficient. Plan 012 closes the remaining source-refinement boundary.

## Steps and verification

1. Freeze the claim order and compatibility of `ok`. Keep integrity reporting distinct from an authorization/completeness acceptance predicate. Explicitly enumerate policies and missing-evidence behavior. Add executable table tests against the current Rust implementation, including the latest regression.
   **Verify:** `cargo test -p averin-decision-core --test adversarial`; baseline passes. New properties that expose gaps must reproduce before fixes; never weaken their expected claim to get green.
2. Extract a small pure verdict kernel and structured validated facts from the existing parser/signature/join passes. Run all committed negative checks before selecting anchored subsets for positive claims. Attach provenance to facts so an untrusted timestamp or embedded key cannot enter a trusted fact constructor.
   **Verify:** `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` pass; existing golden reports change only where the contract deliberately tightens acceptance.
3. Implement Lean verdict definitions and prove deletion monotonicity, committed-contradiction preservation, capstone prerequisites and key-status conservatism. Connect the executable oracle to the actual production kernel over generated fact sets; register all glue in the axiom audit. This is model proof plus differential conformance until plan 012 proves refinement.
   **Verify:** `make formal-lean formal-refinement` passes without new axioms, `sorry`, or omitted declarations.
4. Add generated end-to-end bundles with mixed valid/invalid grants, use/intent/outcome joins, voids, key rotations, disclosed/Merkle revocation and native/federated paths. Enumerate all anchor subsets for small histories, then delete individual/nested attachments and combinations. Run the same corpus through native, WASM and cgo. Add mutations for moving PoP after closure, missing→absent, omitting a capstone conjunct, and consuming failed intents.
   **Verify:** `make test`, `bash formal/check-mutants.sh`, and `(cd web && bun run test)` pass; every added mutant has a named detecting property.

## Done criteria

- The named latest PR regression and generated partial-anchor cases pass on all supported verifier targets.
- Lean proves the four stated properties; production kernel conformance is required in CI and honestly labeled differential until plan 012.
- A pinned-policy caller cannot interpret missing required evidence as a successful authorization/completeness decision.
- CLI/browser/app documentation and consumers use the same claim semantics.

## STOP conditions and maintenance

Stop if compatibility requires silently strengthening `ok`, if the model can construct trusted facts that production cannot justify, or if a proof only restates a conjunction without relating input evidence to facts. Schema/API changes require explicit versioning. Preserve the three product trust levels and the `resource_trust: assumed_truthful` qualification. Add a property and mutation for every new verdict branch.
