#!/usr/bin/env bash
# Bounded model checking (Kani/CBMC) of the integrity core's encoders and parser, over the Rust code as
# written. Complements the unbounded Lean model in formal/lean (see formal/README.md).
#
#   bash formal/run-kani.sh              # default set: verified on a 4-core / 16 GB runner (each < 2 min)
#   bash formal/run-kani.sh --extended   # also all eight extended property families
#   bash formal/run-kani.sh --harness NAME  # one named harness (or checked shard) for profiling and CI sharding
#   bash formal/run-kani.sh --group NAME...  # several checked family shards in one Kani invocation
#                                            # (KANI_JOBS=N verifies them N at a time); used by run-kani-shards.sh
#   bash formal/run-kani.sh --negative-controls  # only the negative controls (each must FAIL on its guard)
#
# KANI_LOG_DIR=DIR keeps every harness log there (CI uploads it as evidence); otherwise a log is
# kept only when its check fails.
set -euo pipefail

cd "$(dirname "$0")/.."

# Kani must see this crate's MIR with every call site intact, because `#[kani::stub]` replaces
# calls. The workspace dev profile sets opt-level 3 (Cargo.toml, for the Go server's staticlib), and
# in a non-incremental build (CI sets CARGO_INCREMENTAL=0) rustc's MIR inliner then inlines
# `Vec::push` into `utf16_units` before Kani applies the stub: G1 is silently bypassed, the
# key-order and strict UTF-16 formulas grow several-fold, and the hosted runner is killed. Kani
# still prints the stub line, so only the negative control below shows it. `-Zinline-mir=no` turns
# the MIR inliner off whatever the profile and incremental setting (Kani appends RUSTFLAGS to its
# own rustc flags); the other MIR optimizations stay, which some formulas need (at opt-level 0,
# integer_roundtrip runs the hosted runner out of memory).
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Zinline-mir=no"

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
    keep_log "$log" "$1" copy
    # Preserve Kani's actual exit for the mutant checker: exit 1 is a completed
    # counterexample, while tool errors and signals must never count as kills.
    if [ "$proof_exit" -ne 0 ]; then
      return "$proof_exit"
    fi
    return 1
  fi
  keep_log "$log" "$1"
}

# keep_log LOG NAME [copy]: save LOG as $KANI_LOG_DIR/NAME.log when KANI_LOG_DIR is set; remove LOG
# unless `copy` (a failed check keeps its log in place as well).
keep_log() {
  if [ -n "${KANI_LOG_DIR:-}" ]; then
    mkdir -p "$KANI_LOG_DIR"
    cp "$1" "$KANI_LOG_DIR/$2.log"
  fi
  [ "${3:-}" = copy ] || rm -f "$1"
}

# A negative control is a harness that must FAIL with a completed counterexample on exactly the
# named guard assertion (check-kani-mutant.py, the same rule as a mutant kill). It proves that the
# replacement it exercises is in force in this build; a success, timeout or tool error fails it.
run_negative_control() {
  local qualified="canon::kani_proofs::$1" log proof_exit
  log="$(mktemp)"
  set +e
  cargo kani -Z stubbing -p averin-decision-core --lib --no-default-features --exact --harness "$qualified" 2>&1 | tee "$log"
  proof_exit=${PIPESTATUS[0]}
  set -e
  prune_build "$log"
  if ! python3 formal/check-kani-mutant.py "$log" "$proof_exit" "$qualified" core/src/canon.rs "$2"; then
    echo "run-kani: negative control $1 did not fail on its guard, so a proof replacement is not in force (log $log)" >&2
    keep_log "$log" "negative-control-$1" copy
    return 1
  fi
  keep_log "$log" "negative-control-$1"
  echo "run-kani: negative control $1 failed on its guard as required"
}

run_negative_controls() {
  # G1 must be in force: a push into a full vector reaches the guard.
  run_negative_control push_guard_is_in_force 'Vec::push reached reallocation in a no-growth proof'
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
    keep_log "$log" "group-$1" copy
    [ "$proof_exit" -ne 0 ] && exit "$proof_exit"
    exit 1
  fi
  keep_log "$log" "group-$1"
  exit 0
fi

if [ "${1:-}" = "--negative-controls" ]; then
  [ "$#" -eq 1 ] || { echo "usage: $0 --negative-controls" >&2; exit 2; }
  run_negative_controls
  exit
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
  echo "usage: $0 [--extended | --harness NAME | --group NAME... | --negative-controls]" >&2
  exit 2
fi

# First, the replacements the proofs below rely on must be in force in this build.
run_negative_controls
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
