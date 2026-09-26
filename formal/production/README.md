# Production refinement of the seal core and the verdict kernel (plan 012)

This project proves that the **production Rust** that computes record and checkpoint hashes and
signature messages (phase A), and the verifier's claim decision kernel (phase B), implement the
Averin model in `formal/lean`, so the model's seal and verdict theorems apply to the code that runs,
not only to a model of it.

The Rust is not re-implemented in Lean. `formal/run-production-refinement.sh` extracts it from
`core/src` with [Charon](https://github.com/AeneasVerif/charon) and
[Aeneas](https://github.com/AeneasVerif/aeneas) into `Extracted/Types.lean` and `Extracted/Funs.lean`,
and the proofs in `Refinement/` are about those generated definitions. The committed generated files
must equal what the pinned toolchain produces from the checked-out source, or the run fails as
stale. The Averin model is compiled into the same Lean environment (`lean_lib Averin` with
`srcDir = "../lean"`, unchanged files) and its theorems are applied to the production functions.

## What is proved

All theorems are **partial correctness**: they describe the result when the extracted function
returns `Ok` (Aeneas `ok`). They say nothing about whether it returns: a panic, an arithmetic
overflow, an abort (for example on allocation failure) or a `RecordError` produces no hash and no
signature message, so no claim is needed about it. The two `sign_preimage_*` theorems also prove
termination with `Some` for the production tags.

| Production function (`core/src`) | Theorem (`Refinement/`) | Statement |
|---|---|---|
| `canon::escape_into` | `Escape.escape_into_model` | appends exactly `utf8 (Canon.serStr cs)` for the UTF-8 bytes of any scalar list `cs` |
| `canon::write_int` | `Int.write_int_model` | appends exactly `utf8 (Canon.serInt n)` |
| `canon::utf16_units`, `units_lt` | `Utf16.utf16_units_model`, `units_lt_model` | UTF-16 code units of the decoded scalars; lexicographic `<` |
| `canon::sort_by_units` | `Sort.sort_ok` | a permutation of the positions, sorted by key |
| `canon::write_canonical` | `Canonical.write_canonical_model` | if no duplicate key after NFC anywhere: the value denotes `m` (`Canon v m`) and the bytes are `utf8 (ser m)` |
| `canon::write_object` | `Canonical.write_object_ok` | the same for an object with a strip list |
| `canon::member` (`CanonValue::get`) | `Preimage.member_ok` | the first member with that raw key |
| `hashx::lp_into` | `Hash.lp_into_model` | `LP(b) = uint32_be(len) ‖ b` (`Averin.lp`), or refuses when `len ≥ 2^32` |
| `hashx::sha256_prefixed` | `Hash.sha256_prefixed_model`, `fmtP_inj`, `fmtM_inj` | `"sha256:" ‖ lowercase hex (SHA-256 data)`; this formatting is injective |
| `record::body_preimage` | `Preimage.body_preimage_model` | `LP(domain) ‖ LP(canon_version) ‖ utf8 (ser m)` for the denotation `m` of the body minus the stripped members |
| `record::record_preimage` / `record_hash` | `record_preimage_model`, `record_hash_model` | the record strip list is `[content_hash, sig]` |
| `checkpoint::checkpoint_preimage` / `checkpoint_hash` | `checkpoint_preimage_model`, `checkpoint_hash_model` | strip list `[anchor, checkpoint_hash, sig]` |
| `sign::preimage` | `Sign.sign_preimage_model`, `sign_preimage_record`, `sign_preimage_checkpoint` | `Some(LP(tag) ‖ ch)`, `None` exactly for a tag too long to frame; for the production tags always `Some(recordSig.msg [] ch)` / `Some(checkpointSig.msg [] ch)` |

**Seal theorems for production** (`Seal.lean`):

* `record_hash_binding`, `checkpoint_hash_binding` — two production bodies with the same production
  hash have the same `domain`, `canon_version` and denotation (`SameBody`), **or** the two production
  preimages are different byte strings with the same SHA-256 output: an explicit collision on the
  inputs the code actually hashed. This is the load-bearing binding statement.
* `record_hash_is_model`, `checkpoint_hash_is_model` — with the pinned profile (the checks
  `verify_content_hash` / `verify_checkpoint_sealed` perform, stated with the extracted
  `RECORD_DOMAIN`/`CANON_VERSION`/`CHECKPOINT_DOMAIN` constants) the production hash string is exactly
  the model's `Seal.recordHashOf prodH fmtM m`. The model's `hfmt` hypothesis is `fmtM_inj` and its
  `hlen` hypothesis is `prodH_len`.
* `production_record_binding_model`, `production_record_seal_sound`,
  `production_checkpoint_seal_sound`, `production_record_ne_checkpoint` — the model's
  `recordHashOf_binding`, `record_seal_sound`, `checkpoint_seal_sound` and `record_ne_checkpoint_hash`
  applied to production hashes and the production signature message. All are in explicit-witness
  form: the second arm is `Seal.CollidesOn prodH p q`, a SHA-256 collision on the two **specific**
  preimages `p`, `q` (`Seal.recordPre m` / `Seal.checkpointPre m`, which `record_preimage_is_model`
  shows are the bytes production hashes). For example, `production_record_seal_sound` concludes
  `m ∈ records ∨ ∃ B ∈ records, recordPre m ≠ recordPre B ∧ H (recordPre m) = H (recordPre B)`.
  Turning a counterexample into a SHA-256 collision is the standard reduction to collision
  resistance. (An earlier model form ended in `∃ x y, x ≠ y ∧ H x = H y`, which holds for every
  compressing `H` and so was vacuous; it has been removed.)

**What a value means** (`Spec.lean`). `Canon v m` relates a production `CanonValue` to the model value
it denotes: strings and keys are NFC-normalized (through the trusted `nfc`), and an object denotes its
members as a set, strictly sorted by UTF-16 key order (`keyLt`). `canon_functional` shows each value
denotes at most one model value; `canon_perm_members` shows that permuting an object's members does
not change its denotation. A value with two keys equal after NFC at any depth denotes nothing, and the
production hash paths reject it (`RecordError::DuplicateKey`).

## The verdict kernel (phase B)

`verify::verdict::decide_claims` maps the verifier's checked facts (`ValidatedFacts`: seals, pins,
anchors, attestation, revocation freshness and paths, role authority, use validity, the capstone
checks, the plan 009 historical facts, the adverse facts) and the caller's `ClaimPolicy` to the
claim results. It and every function it calls are extracted from `core/src/verify/verdict.rs`.

**The correspondence.** `Refinement.Corresponds f m a` says, fact by fact, which model predicate
each checked fact is, for a model evidence state (`Averin.Verdict.Fixed` `m`, attachments `a`): for
example `structural_integrity` is `IntegrityP m`, the seal vector attests `RecordProven` for every
record, `pinned_role_authority` is `RoleContributorsProven m a`, `disclosed_revocation_fresh` is
`m.disclosedFresh ∧ HasAnchor m a`, `capstone.every_pop_reverified` is "every use is PoP-verified",
`historical.snapshot_verified` is "an attached snapshot is fresh for the caller's clock, age and
watermark", and all snapshot attachments name one signed snapshot (`SingleSnapshot`, which
production requires of v2 artifacts and the model does not). It names meanings; it contains no
kernel logic. It is not vacuous: `corresponds_exists` builds a corresponding fact vector for every
single-snapshot model state, so the theorems below constrain the kernel on that whole domain.

| Production function (`core/src/verify/verdict.rs`) | Theorem (`Refinement/`) | Statement |
|---|---|---|
| `key_pinned`, `seal_pinned`, `seals_pinned` | `VerdictLists.key_pinned_ok`, `seal_pinned_ok`, `seals_pinned_ok` | return (total) whether every seal names a record hash and a pinned key |
| `anchors_checkpoint`, `anchored_at` | `anchors_checkpoint_ok`, `anchored_at_ok` | return (total) whether some anchor names the latest checkpoint |
| `pinned_record_keys`, `revocation_ready`, `adverse`, `policy_evidence_ready`, `authorization_ready`, `authorization_refuted`, `authorized`, `temporal`, `historical_adverse`, `historical_revocation`/`historical_ready`, `CapstoneFacts::{base,brokered,introspected}` | `Verdict.*_ok` | under `Corresponds`, return the model predicate (`RevocationReady`, `BrokeredCapstone`, the caller-mode `SnapshotReady` of plan 009, ...) |
| `integrity_claim`, `authenticated_claim`, `authorized_claim`, `temporal_claim`, `historical_claim`, `complete_claim` | `integrity_claim_ok`, ..., `complete_claim_ok` | each claim is `decideClaim m a c` |
| `decide_claims` | `decide_claims_refines` | returns, and every claim of the result, including the requested one, is `decideClaim m a c` |

**The model's theorems for production** (`Refinement/VerdictClaims.lean`, all total, standard
axioms only):

* `production_support_erasure` — two kernel runs on facts corresponding to the same fixed evidence
  `m` with attachments `small ⊆ large`: every claim satisfied with `small` is satisfied with
  `large`, and a claim is refuted with one exactly when it is refuted with the other (plan 002's
  claim order: deleting support can only move a claim from satisfied to insufficient).
* `production_satisfied_supports`, `production_requested_supports` — a satisfied production claim
  has a `Supports` derivation; with `production_capstone_prerequisites` (pinned signers and role
  keys, revocation and attestation readiness, no committed contradiction, every capstone check) and
  `production_introspected_capstone_prerequisites`.
* `production_committed_contradiction_refuted` — authorized and both capstones are refuted.
* Plan 009: `production_historical_requires_policy`, `production_historical_requires_order`,
  `production_historical_requires_snapshot`, `production_at_or_after_refutes`,
  `production_total_revocation_refutes`, `production_historical_supports`.

**Not covered.** That `verify.rs` computes facts satisfying `Corresponds` is not proved: the
signature, pin, join, Merkle-path and snapshot passes and the counter-to-fact joins in
`verify_bundle_with` are the trusted boundary. `check-production.py` pins the call path (the
kernel's result is the only value written to `report.claims`; no `ClaimResults` is built in
`verify.rs`), and the verdict oracle differential and the adversarial suite test the projection.
The claim-policy parser (`ClaimPolicy::parse`), `ClaimDecision::as_str` and the report
serialization are not extracted. Finding the kernel's model while refining it exposed one fact the
model lacked (`checkedContradiction`, added to `Averin.Verdict.Fixed`).

**Extraction constraints** (documented at the kernel): search loops instead of closures and
iterator adapters, helper functions instead of derived `PartialEq`, helpers called before a
function branches on a field of the facts, a negation first in a disjunction, and `&`/`|` for a
conjunction with a `bool` parameter. All are semantics-preserving; the tests are unchanged.

## Trusted base

* **Axioms** (the only ones; `scripts/Audit.lean` fails on any other):
  `AverinTrusted.nfc` — Unicode NFC normalization (`unicode-normalization` 0.1.25, behind `canon::nfc`),
  and `AverinTrusted.sha256` — SHA-256 (`sha2` 0.10.9, behind `hashx::sha256`). Both are arbitrary total
  functions: no property of either is assumed.
* **Rust standard library models** (definitions in `Extracted/FunsExternal.lean`, not axioms):
  `str::as_bytes` is the identity on Aeneas' UTF-8 representation of `&str`; `String::as_bytes` and
  `Deref<Target = str>` are the UTF-8 bytes of the Lean `String` Aeneas uses for `String`;
  `String::from_utf8` is `Ok` with the same bytes exactly on valid UTF-8 (Lean's verified decoder);
  `FromUtf8Error` is `Unit` (never inspected); `String::is_empty` is true exactly when the string has
  no UTF-8 bytes (verdict kernel). `averin_decision_core.toStr` is Aeneas' literal
  conversion with a kernel-checked instead of `decide +native` bound.
* **Toolchain**: rustc (the pinned nightly for extraction; production builds use 1.92.0), Charon
  `6258597`, Aeneas `557f7a1` and its Lean standard library (the semantics of `Vec`, slices, scalars,
  `Result`, `partial_fixpoint`), Lean 4.31.0 and mathlib `fabf563`. See `manifest.json`.
* **Ed25519** is outside this project: the seal theorems take the model's `Signed` predicate as the
  statement of what verifies.

## Not covered (by design, or later phases)

* The verifier's seal checks and evidence passes (`verify_content_hash`, `verify_checkpoint_sealed`,
  `verify_signature`, Tier-B joins, the counters feeding the capstone) are not extracted.
  `check-production.py` requires those functions to call the proved code (`manifest.json` `callers`),
  but their comparisons are glue checked by the existing tests and mutants. The claim kernel they
  feed is refined (phase B, above).
* The parser (`CanonValue::parse`) is plan 011 (Kani).
* **Unextracted glue.** `serialize()`'s final `String::from_utf8` (a debug-asserted conversion of the
  proved byte output) and the public error mapping (`PreimageFault::into_record_error`, and the
  `compute_*`/`*_preimage` wrappers' `map_err`) are not extracted. `check-production.py` pins them
  with call-path checks (`manifest.json` `callers`, exact-body and contains checks): the public
  functions may only call the proved function and map its error.
* **base64 (`core/src/b64.rs`) is excluded.** It is not on the hashed or signed preimage path (it only
  spells signature and key bytes after hashing/signing), so it is not extracted here. It is covered by
  plan 011's full-domain Kani proofs (alphabet bijection, chunk harnesses) and its tests.

## Running

```sh
bash formal/run-production-refinement.sh           # regenerate, require equality, build, audit
bash formal/run-production-refinement.sh --write   # after an intended change to the extracted Rust
python3 formal/production/check-production.py      # toolchain-free: freshness, call paths, cfg, glue
```

The pinned toolchain is described in `plans/preflight/PROVENANCE.md`; `setup-toolchain.sh` builds it
from the pinned sources. The first build compiles the Aeneas library and needs mathlib at the
manifest revision (use `lake exe cache get`, or point `AVERIN_LAKE_PACKAGES` at an existing build).

Mutants `m50`–`m53` in `formal/mutants` keep these gates load-bearing: a changed preimage byte order
fails the regenerated proof (`proof`), an edited but unregenerated source fails as `stale`, a call site
that bypasses `sign::preimage` fails `call-path`, and a feature-selected alternative fails `cfg`.
For the verdict kernel, `m54`–`m58` each make a refinement theorem false and fail the regenerated
proof: the capstone skips `temporal` when unanchored (deleting the anchor strengthens the capstone),
dual mode needs Merkle paths only alongside the list (deleting the list strengthens `authorized`),
the historical claim drops the verified-snapshot gate or the Merkle-mode path gate, and a seal
counts with an unpinned key. `m59` overwrites a claim after the kernel and fails `call-path`.
