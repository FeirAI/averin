#!/usr/bin/env bash
# Bounded model checking (Kani/CBMC) of the integrity core's encoders and parser, over the Rust code as
# written. Complements the unbounded Lean model in formal/lean (see formal/README.md).
#
#   bash formal/run-kani.sh              # default set: verified on a 4-core / 16 GB runner (each < 2 min)
#   bash formal/run-kani.sh --extended   # also all eight extended property families
#   bash formal/run-kani.sh --harness NAME  # one named harness (or checked shard) for profiling and CI sharding
#   bash formal/run-kani.sh --group NAME...  # several checked family shards in one Kani invocation
#                                            # (KANI_JOBS=N verifies them N at a time); used by run-kani-shards.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Kani builds the crate into a fresh target/kani/.../build/averin-decision-core/<hash> directory for
# every distinct harness selection (about 90 MB each), so thousands of shard runs fill a disk.
# KANI_PRUNE_BUILD=1 deletes the directory this invocation used once Kani has finished with it.
prune_build() {
  [ "${KANI_PRUNE_BUILD:-0}" = 1 ] || return 0
  local dir
  for dir in $(grep -o 'target/kani/[^ ]*/build/averin-decision-core/[0-9a-f]\{16\}' "$1" | sort -u); do
    rm -rf "$dir"
  done
}

run_harness() {
  local module qualified log proof_exit
  local -a kani_flags=() guard_flag=()
  case "$1" in
    alphabet_is_a_bijection|one_byte_tail_is_canonical|two_byte_tail_is_canonical|full_chunk_is_canonical) module=b64 ;;
    hex_byte_roundtrip|hex_digit_is_canonical|lp_into_frames_exactly) module=hashx ;;
    *) module=canon ;;
  esac
  qualified="$module::kani_proofs::$1"
  if [[ "$1" == integer_roundtrip* ]]; then
    # The original full-domain harness and every shard must keep their checked domain,
    # production route, and fail-closed guard wiring before any Kani run.
    python3 formal/check-kani-domains.py >/dev/null || return 2
    kani_flags=(-Z stubbing)
    guard_flag=(--expect-guard)
  elif [[ "$1" == utf16_key_order_is_* || "$1" == string_escape_roundtrip_* || "$1" == utf16_strict_matches_std ]]; then
    # The key-order proofs carry the fail-closed Vec::push growth guard (G1), the string cases the
    # align_offset selection (A1), and the strict UTF-16 decoder both (it preallocates its output
    # and validates it with String::from_utf8); bodies and attachment sites are pinned by
    # check-kani-shards.py, stub lines by check-kani-success.py.
    python3 formal/check-kani-shards.py >/dev/null || return 2
    kani_flags=(-Z stubbing)
  fi
  log="$(mktemp)"
  # Stream progress as well as saving it: an outer CI timeout must not hide the last CBMC phase.
  set +e
  cargo kani ${kani_flags[@]+"${kani_flags[@]}"} -p averin-decision-core --lib --no-default-features --exact --harness "$qualified" 2>&1 | tee "$log"
  proof_exit=${PIPESTATUS[0]}
  set -e
  prune_build "$log"
  if ! python3 formal/check-kani-success.py "$log" "$proof_exit" "$qualified" ${guard_flag[@]+"${guard_flag[@]}"}; then
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

if [ "${1:-}" = "--group" ]; then
  shift
  [ "$#" -ge 1 ] || { echo "usage: $0 --group NAME..." >&2; exit 2; }
  # Only shards of checked families; the checker also re-proves their exact partitions first.
  python3 formal/check-kani-shards.py --has-all "$@" || { echo "run-kani: --group takes checked family shards only" >&2; exit 2; }
  qualified=() harness_args=() job_args=()
  for h in "$@"; do
    qualified+=("canon::kani_proofs::$h")
    harness_args+=(--harness "canon::kani_proofs::$h")
  done
  [ -n "${KANI_JOBS:-}" ] && job_args=(-j "$KANI_JOBS")
  log="$(mktemp)"
  set +e
  cargo kani -Z stubbing ${job_args[@]+"${job_args[@]}"} -p averin-decision-core --lib --no-default-features --exact "${harness_args[@]}" 2>&1 | tee "$log"
  proof_exit=${PIPESTATUS[0]}
  set -e
  prune_build "$log"
  # Every selected harness needs its own complete successful section (check-kani-success.py).
  if ! python3 formal/check-kani-success.py "$log" "$proof_exit" --many "${qualified[@]}"; then
    echo "run-kani: proof log retained at $log" >&2
    [ "$proof_exit" -ne 0 ] && exit "$proof_exit"
    exit 1
  fi
  rm "$log"
  exit 0
fi

if [ "${1:-}" = "--harness" ]; then
  [ "$#" -eq 2 ] || { echo "usage: $0 --harness NAME" >&2; exit 2; }
  case "$2" in
    alphabet_is_a_bijection|hex_byte_roundtrip|hex_digit_is_canonical|lp_into_frames_exactly|utf16_key_order_is_transitive|one_byte_tail_is_canonical|two_byte_tail_is_canonical|full_chunk_is_canonical|utf16_strict_matches_std|integer_roundtrip|parse_never_panics)
      run_harness "$2" ;;
    integer_roundtrip_*)
      python3 formal/check-kani-domains.py --has-integer "$2" || { echo "unknown integer shard: $2" >&2; exit 2; }
      run_harness "$2" ;;
    *)
      # A shard or lemma of a checked sharded family (formal/check-kani-shards.py).
      python3 formal/check-kani-shards.py --has "$2" || { echo "unknown Kani harness: $2" >&2; exit 2; }
      run_harness "$2" ;;
  esac
  exit
fi

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--extended" ]; }; then
  echo "usage: $0 [--extended | --harness NAME | --group NAME...]" >&2
  exit 2
fi

# b64.rs — base64url: the alphabet is a bijection.
run_harness alphabet_is_a_bijection
# hashx.rs — "sha256:<hex>" is injective and canonical (per byte, at fixed width); LP framing is exact.
run_harness hex_byte_roundtrip
run_harness hex_digit_is_canonical
run_harness lp_into_frames_exactly
# canon.rs — member-key order is exactly UTF-16 code-unit order (checked against a reference order,
# including the BMP-vs-astral region where byte order disagrees; four checked scalar-count shards
# plus the steered conjunct) and is transitive.
bash formal/run-kani-shards.sh utf16_key_order_is_exact
run_harness utf16_key_order_is_transitive

if [ "${1:-}" = "--extended" ]; then
  run_harness one_byte_tail_is_canonical
  run_harness two_byte_tail_is_canonical
  # Full 4-symbol chunk, checked through the fixed-width functions used by the public codec.
  run_harness full_chunk_is_canonical
  run_harness utf16_strict_matches_std
  # The original unsplit [-99999,99999] harness. Its eleven checked disjoint shards
  # (check-kani-domains.py --list-integer) remain available through --harness for CI sharding.
  run_harness integer_roundtrip
  # Sixty checked (length, first byte) shards plus the alphabet lemma; every shard must pass.
  bash formal/run-kani-shards.sh accepted_integer_spelling
  # 17,031 checked concrete cases, one harness each (see formal/README.md for resources).
  KANI_SHARD_GROUP="${KANI_SHARD_GROUP:-64}" bash formal/run-kani-shards.sh string_escape_roundtrip
  # parse_never_panics is NOT verified on its original domain (formal/README.md) and is not run here.
fi
