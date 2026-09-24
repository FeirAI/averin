#!/usr/bin/env bash
# Bounded model checking (Kani/CBMC) of the integrity core's encoders and parser, over the Rust code as
# written. Complements the unbounded Lean model in formal/lean (see formal/README.md).
#
#   bash formal/run-kani.sh              # default set: verified on a 4-core / 16 GB runner (each < 2 min)
#   bash formal/run-kani.sh --extended   # also all eight extended property families
#   bash formal/run-kani.sh --harness NAME  # one named harness for profiling and CI sharding
set -euo pipefail

cd "$(dirname "$0")/.."

run_harness() {
  local module qualified log proof_exit
  case "$1" in
    alphabet_is_a_bijection|one_byte_tail_is_canonical|two_byte_tail_is_canonical|full_chunk_is_canonical) module=b64 ;;
    hex_byte_roundtrip|hex_digit_is_canonical|lp_into_frames_exactly) module=hashx ;;
    *) module=canon ;;
  esac
  qualified="$module::kani_proofs::$1"
  log="$(mktemp)"
  # Stream progress as well as saving it: an outer CI timeout must not hide the last CBMC phase.
  set +e
  cargo kani -p averin-decision-core --lib --no-default-features --exact --harness "$qualified" 2>&1 | tee "$log"
  proof_exit=${PIPESTATUS[0]}
  set -e
  if ! python3 formal/check-kani-success.py "$log" "$proof_exit" "$qualified"; then
    echo "run-kani: proof log retained at $log" >&2
    # Preserve Kani's actual exit for the mutant checker: exit 1 is a completed
    # counterexample, while tool errors and signals must never count as kills.
    if [ "$proof_exit" -ne 0 ]; then
      return "$proof_exit"
    fi
    return 1
  fi
  rm "$log"
}

if [ "${1:-}" = "--harness" ]; then
  [ "$#" -eq 2 ] || { echo "usage: $0 --harness NAME" >&2; exit 2; }
  case "$2" in
    alphabet_is_a_bijection|hex_byte_roundtrip|hex_digit_is_canonical|lp_into_frames_exactly|utf16_key_order_is_exact|utf16_key_order_is_transitive|one_byte_tail_is_canonical|two_byte_tail_is_canonical|full_chunk_is_canonical|utf16_strict_matches_std|integer_roundtrip|accepted_integer_spelling_is_canonical|string_escape_roundtrip|parse_never_panics)
      run_harness "$2" ;;
    integer_roundtrip_*)
      python3 formal/check-kani-domains.py --has-integer "$2" || { echo "unknown integer shard: $2" >&2; exit 2; }
      run_harness "$2" ;;
    *) echo "unknown Kani harness: $2" >&2; exit 2 ;;
  esac
  exit
fi

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--extended" ]; }; then
  echo "usage: $0 [--extended | --harness NAME]" >&2
  exit 2
fi

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
  # Full 4-symbol chunk, checked through the fixed-width functions used by the public codec.
  run_harness full_chunk_is_canonical
  run_harness utf16_strict_matches_std
  # Prove the original [-99999,99999] obligation as an exhaustive, checked union of eleven
  # disjoint sign/decimal-width ranges. The original unsplit harness remains available above.
  integer_shards="$(python3 formal/check-kani-domains.py --list-integer)"
  while IFS= read -r integer_harness; do
    run_harness "$integer_harness"
  done <<< "$integer_shards"
  run_harness accepted_integer_spelling_is_canonical
  run_harness string_escape_roundtrip
  run_harness parse_never_panics
fi
