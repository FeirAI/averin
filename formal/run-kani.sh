#!/usr/bin/env bash
# Bounded model checking (Kani/CBMC) of the integrity core's encoders and parser, over the Rust code as
# written. Complements the unbounded Lean model in formal/lean (see formal/README.md).
#
#   bash formal/run-kani.sh              # default set: verified on a 4-core / 16 GB runner (each < 2 min)
#   bash formal/run-kani.sh --extended   # also the parser-level harnesses (need more memory: CBMC
#                                        # symbolically executes the full RCP parser / heap strings)
set -euo pipefail

cd "$(dirname "$0")/.."

run_harness() {
  cargo kani -p averin-decision-core --no-default-features -Z stubbing --harness "$1"
}

# b64.rs — base64url: the alphabet is a bijection.
run_harness alphabet_is_a_bijection
# hashx.rs — "sha256:<hex>" is injective and canonical (per byte, at fixed width); LP framing is exact.
run_harness hex_byte_roundtrip
run_harness hex_digit_is_canonical
run_harness lp_into_frames_exactly
# canon.rs — member-key order is exactly UTF-16 code-unit order (checked against a reference order,
# including the BMP-vs-astral region where byte order disagrees) and is transitive.
run_harness utf16_key_order_is_exact
run_harness utf16_key_order_is_transitive

if [ "${1:-}" = "--extended" ]; then
  run_harness one_byte_tail_is_canonical
  run_harness two_byte_tail_is_canonical
  # Full 4-symbol chunk. Heap-light (no from_utf8, no formatted asserts), but decode's error path still
  # formats a char with {:?}, which drags Unicode tables into CBMC: out of memory under an 8 GB cap after
  # ~12 min on a 16 GB box, so it is extended-only until a larger runner verifies it.
  run_harness full_chunk_is_canonical
  run_harness utf16_strict_matches_std
  run_harness integer_roundtrip
  run_harness accepted_integer_spelling_is_canonical
  run_harness string_escape_roundtrip
  run_harness parse_never_panics
fi
