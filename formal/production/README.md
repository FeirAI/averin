# Production refinement of the seal core (plan 012, phase A)

This project proves that the **production Rust** that computes record and checkpoint hashes and
signature messages implements the Averin model in `formal/lean`, so the model's seal theorems apply
to the code that runs, not only to a model of it.

The Rust is not re-implemented in Lean. `formal/run-production-refinement.sh` extracts it from
`core/src` with [Charon](https://github.com/AeneasVerif/charon) and
[Aeneas](https://github.com/AeneasVerif/aeneas) into `Extracted/Types.lean` and `Extracted/Funs.lean`,
and the proofs in `Refinement/` are about those generated definitions. The committed generated files
must equal what the pinned toolchain produces from the checked-out source, or the run fails as
stale. The Averin model is compiled into the same Lean environment (`lean_lib Averin` with
`srcDir = "../lean"`, unchanged files) and its theorems are applied to the production functions.

## What is proved

All theorems are **partial correctness**: they describe the result whenever the production
function returns (it may otherwise panic or abort, for example on allocation failure, and then
produces nothing). The two `sign_preimage_*` theorems also prove termination with `Some`.

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
  applied to production hashes and the production signature message. Caveat: the model states
  collisions as `Seal.Collision H := ∃ x y, x ≠ y ∧ H x = H y`, which is provable for any compressing
  `H`; the explicit `*_hash_binding` theorems above do not have this weakness.

**What a value means** (`Spec.lean`). `Canon v m` relates a production `CanonValue` to the model value
it denotes: strings and keys are NFC-normalized (through the trusted `nfc`), and an object denotes its
members as a set, strictly sorted by UTF-16 key order (`keyLt`). `canon_functional` shows each value
denotes at most one model value; `canon_perm_members` shows that permuting an object's members does
not change its denotation. A value with two keys equal after NFC at any depth denotes nothing, and the
production hash paths reject it (`RecordError::DuplicateKey`).

## Trusted base

* **Axioms** (the only ones; `scripts/Audit.lean` fails on any other):
  `AverinTrusted.nfc` — Unicode NFC normalization (`unicode-normalization` 0.1.25, behind `canon::nfc`),
  and `AverinTrusted.sha256` — SHA-256 (`sha2` 0.10.9, behind `hashx::sha256`). Both are arbitrary total
  functions: no property of either is assumed.
* **Rust standard library models** (definitions in `Extracted/FunsExternal.lean`, not axioms):
  `str::as_bytes` is the identity on Aeneas' UTF-8 representation of `&str`; `String::as_bytes` and
  `Deref<Target = str>` are the UTF-8 bytes of the Lean `String` Aeneas uses for `String`;
  `String::from_utf8` is `Ok` with the same bytes exactly on valid UTF-8 (Lean's verified decoder);
  `FromUtf8Error` is `Unit` (never inspected). `averin_decision_core.toStr` is Aeneas' literal
  conversion with a kernel-checked instead of `decide +native` bound.
* **Toolchain**: rustc (the pinned nightly for extraction; production builds use 1.92.0), Charon
  `6258597`, Aeneas `557f7a1` and its Lean standard library (the semantics of `Vec`, slices, scalars,
  `Result`, `partial_fixpoint`), Lean 4.31.0 and mathlib `fabf563`. See `manifest.json`.
* **Ed25519** is outside this project: the seal theorems take the model's `Signed` predicate as the
  statement of what verifies.

## Not covered (by design, or later phases)

* The verifier's decision logic (`verify_content_hash`, `verify_checkpoint_sealed`, `verify_signature`,
  Tier-B joins, capstone) is not extracted. `check-production.py` requires those functions to call the
  proved code (`manifest.json` `callers`), but their comparisons are glue checked by the existing tests
  and mutants. Refining the verdict kernel is plan 012 phase B (after plan 009).
* The parser (`CanonValue::parse`) is plan 011 (Kani). `serialize()`'s final `String::from_utf8` and the
  public error mapping (`PreimageFault::into_record_error`) are not extracted; the call-path check pins
  that the public functions only map errors.
* base64 is not on the hashed or signed path (it only spells the signature bytes); it is not extracted
  here and remains covered by its Kani harnesses and tests.

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
