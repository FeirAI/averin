# Formal claims register (kit)

This page describes the second, machine-checked register of what Averin's formal and
test evidence covers. It does not replace `formal/README.md` (the evidence itself) or
`formal/claims.json` (the full inventory, checked by `scripts/check-claims.py`). It adds
three things the inventory does not have: a drift lock on the code each claim protects,
a mutant that proves each detector can fail, and a denylist of overclaim phrases.

## What the register is

`formal/kit-claims.json` is read by the shared kit vendored in `scripts/formal/`
(`check_claims.py`, `check_mutants.py`, `formal_kit.py`; byte-identical to the kit, do not
edit them here). Each claim carries:

- `statement`: one bounded sentence about what the detector checks.
- `method`: one of the kit's methods (`scripts/formal/README.md`); this register uses lean, kani,
  differential-vectors, exhaustive, fuzz and test.
- `gates`: CI job ids that run the evidence on pull requests or on the schedule.
- `detector`: a shell command, run from the repo root, that passes on the real tree.
- `covers`: the exact functions the claim protects, each with a sha256 (the drift lock).
- `mutants`: ids of patches in `formal/mutants/`; the detector must fail on each one.
- `does_not_establish`: what the claim leaves open.

The two registers are linked: every kit claim names the claim in `formal/claims.json` it
backs in its `$comment` ("legacy register: <id>"), and `scripts/check-claims.py` fails if
that id does not exist. Kit statements are narrower than the legacy ones on purpose: a kit
claim says what its cheap detector checks, not what the whole proof program shows.

## How to add a claim

1. Write the proof or test and make a CI job run it.
2. Add the claim to `formal/kit-claims.json` with `"sha256": ""` in each cover.
3. Write a mutant: change the covered code so the claim should be false, then
   `git diff -- <covered file> > formal/mutants/<id>.patch` and `git checkout -- <covered file>`.
   The patch must apply with `git apply` (the legacy suite uses `patch`, which is more lenient;
   m9, m11, m43 and m63 do not pass `git apply --check` and so cannot be used here yet).
4. Add the id to the `mutants` map with a `tier` (`fast` or `full`). Mutants that edit Lean
   sources must be named `lean-*`; the legacy `formal/check-mutants.sh` skips those, since it
   only knows Rust gates.
5. `python3 scripts/formal/check_claims.py --claims formal/kit-claims.json --relock --symbol <path>:<symbol>`
   fills the empty hashes.
6. Commit, then `python3 scripts/formal/check_mutants.py --claims formal/kit-claims.json --only <id>`
   must report `killed` (it tests HEAD, not the working tree).
7. Say plainly in `does_not_establish` what remains open.

The Aeneas production-proof mutants (m50, m54 to m58, and m60 to m64 as proof mutants) run in the
legacy suite on every pull request (`formal-production`), not here, because the Aeneas toolchain is not
set up for the kit. m61, m62 and m64 are also killed by the native parser tests, so they are in this
register under `parser-differential-and-fuzz`. m60 survives the native fuzz and differential tests
(they only pass valid UTF-8 strings); only the totality proof kills it, so it is not in this register.
m63 is not here yet because its patch does not pass `git apply --check`.

## Drift lock and relock policy

A hash mismatch means a covered function changed after the claim was written. Re-read the
claim, decide it still holds (or downgrade or remove it), then relock only the symbols you
changed on purpose with `--relock --symbol path:symbol`. Never relock everything to turn CI
green. The PR text names every relocked symbol and why. A drift lock says the text is unchanged,
not that the claim is still true: a callee can change without changing the hash.

## Mutants and tiers

`check_mutants.py` makes a scratch worktree at HEAD, applies each mutant, runs the detector and
requires it to fail. A mutant that does not change a covered symbol is reported as a vacuous
kill, not a kill. Fast-tier mutants (one per claim that has a native detector) run in the
`formal-fast` job on every pull request, which `ci-required` needs. All mutants, including
the Kani and Lean ones, run in `formal-nightly` (schedule and manual dispatch only), which
uploads a JSON report as an artifact kept 90 days. The older suite (`formal/check-mutants.sh`,
`formal-mutants-fast`, `formal-mutants-full`) is unchanged and still runs.

## Overclaim denylist

`overclaim_denylist` lists phrases the README and `docs/` must not contain (wording that
claims whole-system or complete verification; the list is in the JSON file). The legacy checker's sentence rules stay in force too.
Matching ignores case and line breaks.

## Evidence of record

Only a CI run counts as evidence for a claim. Local runs of the detectors or mutants are
informative only. The kit does not fetch run ids; `evidence_run` is optional.

## Current claims

| Claim | Method | Covers | Does NOT establish |
|---|---|---|---|
| `preimage-oracle-conformance` | differential vectors | authority, commitment and record preimages, taxonomy tag | Agreement outside the committed corpus; not a refinement proof; nothing about keys or verdicts |
| `authority-v3-subject-digest-bound` | differential vectors | v3 authority preimage and subject digest | That the projection covers every semantic field; one vector only |
| `verdict-differential-vs-model` | exhaustive corpus | capstone, revocation readiness, historical claim | States outside the corpus; that verify.rs computes the facts the kernel consumes |
| `temporal-revocation-ordering-tests` | test | classify, Merkle v2 proof check, snapshot evaluation | Inputs the tests do not build; example tests, not a proof |
| `pop-intent-and-disclosure-regressions` | test | per-use checks, bundle verification | Bundle shapes the suite does not build; not a monotonicity proof |
| `production-call-path-gate` | textual test | signature verify, content hash, bundle verification | Correctness of the extracted code; anything beyond the call sites and cfg forms it scans |
| `parser-differential-and-fuzz` | fuzz and differential | parser escape, literal, number and whitespace paths | Totality for all inputs (the Lean proof is stronger); input that is not valid UTF-8; allocation failure; stack depth |
| `kani-encoder-harnesses` | Kani (nightly) | LP framing, base64url tail canonicality | Anything outside the harness bounds; the other Kani harnesses; not distinguishing an unwinding failure from a counterexample |
| `lean-seal-model` | Lean (nightly) | the hand seal model in `Seal.lean` | That the model matches the Rust; SHA-256, Ed25519, honest signer and NFC are assumptions |

Not yet in the register (still tracked in `formal/claims.json`): the TLA+ configurations, the
Postgres-backed API tests, RFC 3161 target-specific tests, and the Charon/Aeneas production
proofs. Each needs a mutant and a detector that can run in the kit's scratch tree first.
