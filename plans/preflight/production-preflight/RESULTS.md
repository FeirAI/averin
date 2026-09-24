# Bounded production extraction compatibility preflight

This is a tool compatibility result, not a refinement proof. No Averin source
was copied or changed. Source identity, dependency pins, and hashes are in
`PROVENANCE.md`; tool install pins are in `../PROVENANCE.md`.

The wrapper `src/lib.rs` imports the actual `canon.rs` and `hashx.rs` from
5e10548485241e50b03cf6ed92430386227b3198 with absolute `#[path]` attributes.
Charon used `nightly-2026-09-17-aarch64-apple-darwin` (rustc 1.100.0-nightly,
923c95cdf, 2026-09-16) and the pinned Charon commit
62585970fc75f61d83c7898ff8dfdd7edaa3c073. Aeneas is pinned to
557f7a15f3b75e18ddae224fc65db0807b70acdf.

## Commands and outcome

From `production-preflight` (the wrapper sets isolated PATH, rustup, cargo,
opam, and Lean toolchains):

```sh
sfw bash ../with-aeneas.sh env CARGO_BUILD_JOBS=1 charon cargo --preset=aeneas \
  --start-from 'crate::canon::CanonValue::serialize' \
  --start-from 'crate::hashx::lp_into' \
  --dest-file out/production.llbc
bash ../with-aeneas.sh aeneas -backend lean -split-files -dest out/Lean out/production.llbc

sfw bash ../with-aeneas.sh env CARGO_BUILD_JOBS=1 charon cargo --preset=aeneas \
  --start-from 'crate::canon' --dest-file out/production-canon-module.llbc
bash ../with-aeneas.sh aeneas -backend lean -split-files \
  -print-error-diagnostics -abort-on-error \
  -dest out/CanonLean out/production-canon-module.llbc
bash ../with-aeneas.sh aeneas -backend lean -split-files \
  -print-error-diagnostics -dest out/CanonLeanContinue \
  out/production-canon-module.llbc
```

The first LLBC reports `has_errors=false`, with 16 ordered declarations. It
contains `hashx::lp_into` in the ordered translation, and generated Lean
`out/Lean/Funs.lean` defines `hashx.lp_into` (line 33). Its implementation
uses the checked u32 length cast, `to_be_bytes`, and `extend_from_slice`.
Those standard library operations still require semantic justification;
the generated output alone is not a proof of framing correctness.

`CanonValue::serialize` has a transparent body in the first LLBC's raw
function declaration array, but **is absent from the ordered declarations
and generated Lean**. Charon's `--start-from` path resolver does not support
inherent impl methods (source: `charon/src/bin/charon-driver/translate/resolve_path.rs`).
Thus raw LLBC presence cannot be counted as a successful serializer extraction.

Selecting `--start-from 'crate::canon'` yields `has_errors=false` and 400
ordered declarations, including the actual `CanonValue::serialize` and its
helper functions. Aeneas cannot translate this module to Lean. The aborting
pass fails at `canon.rs:361-388`, `Parser::parse_array`, with `Early returns
inside of loops are not supported yet` (`out/aeneas-canon.log`). A continuation
pass additionally flags `Parser::parse_object`, then fails on a higher-ranked
versus free lifetime constraint in `core::slice::iter::Iterator::find`,
transitively called at `canon.rs:102,117,125,147`, followed by an internal
signature translation error (`out/aeneas-canon-continue.log`). Neither pass
emits serializer Lean.

The serializer calls NFC normalization, UTF-16 key comparison/sorting, string
escaping, and integer formatting. Charon retained these source bodies in its
module LLBC, but Aeneas did not generate a Lean serializer; their semantics
and support remain unverified. No production Lean proof was attempted. The
toy smoke proof in `../smoke` runs under isolated Lean 4.31, whereas Averin's
repository formal project remains on Lean 4.30. Import compatibility and
production reachability/configuration equivalence remain open plan-012 work.

## Minimal production serializer call graph

To exclude the unrelated parser while retaining the production implementation,
the task-cache wrapper additionally defines only:

```rust
pub fn production_serialize(v: &canon::CanonValue) -> String { v.serialize() }
```

`src/lib.rs` SHA256 after that addition is
`f6455173790149e1d57c38bd568eeb734840bc2fd8580884c52884e909dd54cc`.
No serializer logic is copied into the wrapper. A single bounded pass used:

```sh
sfw bash ../with-aeneas.sh env CARGO_BUILD_JOBS=1 charon cargo --preset=aeneas \
  --start-from 'crate::production_serialize' \
  --start-from 'crate::hashx::lp_into' --dest-file out/production-rooted.llbc
bash ../with-aeneas.sh aeneas -backend lean -split-files \
  -print-error-diagnostics -dest out/RootedLean out/production-rooted.llbc
```

Charon succeeded with `has_errors=false` and 145 ordered declarations. The
ordered graph contains transparent bodies for `production_serialize`, the
actual `canon::CanonValue::serialize` and `write`, `write_string`, `nfc`,
`utf16_cmp`, and `hashx::lp_into`. Neither parser function is in that ordered
graph. This is the meaningful production call graph for this preflight.

Aeneas exited 1 and emitted **partial** Lean. `out/RootedLean/Funs.lean`
contains definitions for the wrapper, actual serializer, and framing helper.
The serializer calls `canon.CanonValue.write`, whose generated body is `sorry`
at line 406. `canon.write_string` is also `sorry` at line 229. Diagnostics in
`out/aeneas-rooted.log` identify `Unsupported switch scrutinee` at
`canon.rs:203-217` (string escaping), `Could not match the contexts` at
`canon.rs:126-128` (object write loop), and `Unreachable` at `canon.rs:223-229`
(`hex_digit` fallback). Those are serializer-path limitations, not parser
limitations. The generated external template also axiomatizes `sort_by`,
`encode_utf16`, Unicode NFC, String operations, and `ToString` (used by
integer formatting). Their semantics are unproven here. The partial Lean
artifact cannot establish serializer correctness; a successful Lean build of
these partial files was neither attempted nor claimed.
