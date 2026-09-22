#!/usr/bin/env bash
# Bounded model checking (Kani/CBMC) of the integrity core's encoders and parser, over the Rust code as
# written. Complements the unbounded Lean model in formal/lean (see formal/README.md).
#
#   bash formal/run-kani.sh              # default set: verified on a 4-core / 16 GB runner (seconds each)
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
# canon.rs — member-key order is total and exact.
run_harness utf16_key_order_is_exact

if [ "${1:-}" = "--extended" ]; then
  run_harness one_byte_tail_is_canonical
  run_harness two_byte_tail_is_canonical
  run_harness decode_inverts_encode
  run_harness utf16_strict_matches_std
  run_harness integer_roundtrip
  run_harness accepted_integer_spelling_is_canonical
  run_harness string_escape_roundtrip
  run_harness parse_never_panics
fi
