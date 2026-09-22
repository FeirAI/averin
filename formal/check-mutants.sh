#!/usr/bin/env bash
# Mutation suite for the formal gates: each formal/mutants/*.patch is a known way the Rust can drift from
# what the proofs model (a reordered or dropped preimage field, a serializer that is no longer injective, a
# wrong key order, a wrong length prefix, an unpinned profile, an unmodelled tag). For every mutant this
# copies the sources to a scratch tree, applies the patch, and runs the cheap gates:
#
#   inventory  python3 formal/check-refinement.py            (tag literals <-> Preimage.lean families)
#   oracle     cargo test --test oracle                        (Rust bytes == executable Lean model)
#   golden     cargo test --test golden                        (committed golden vectors)
#   kani       the named bounded proof, only for m3 / m4       (see kani_harness below); for those two
#              mutants the harness itself must report VERIFICATION:- FAILED, in addition to any other kill
#
# The suite passes only if every mutant is killed by at least one gate; it prints which gates killed each.
# It first checks that every gate passes on the unmutated tree, so a gate that is simply broken cannot
# count as a kill.
#
#   bash formal/check-mutants.sh            # all gates for every mutant
#   bash formal/check-mutants.sh --first    # stop at the first killing gate per mutant (faster)
#   SKIP_KANI=1 bash formal/check-mutants.sh  # without cargo-kani (m3/m4 must then die to another gate)
set -uo pipefail

cd "$(dirname "$0")/.."
first=0
[ "${1:-}" = "--first" ] && first=1

work="${MUTANTS_WORK:-${TMPDIR:-/tmp}/averin-mutants}"
tree="$work/tree"
logs="$work/logs"
mkdir -p "$logs"
# One fixed tree path and target dir across mutants, so each rebuild is incremental.
export CARGO_TARGET_DIR="$work/target"

kani_harness() {
  case "$1" in
    m3-*) echo utf16_key_order_is_exact ;;
    m4-*) echo lp_into_frames_exactly ;;
  esac
}

fresh_tree() {
  rm -rf "$tree"
  mkdir -p "$tree/formal"
  cp -R core spec server Cargo.toml Cargo.lock rust-toolchain.toml "$tree/"
  # formal/ minus build outputs (the Lean .lake dir is large and irrelevant here).
  (cd formal && find . -path ./lean/.lake -prune -o -type f -print) | while read -r f; do
    mkdir -p "$tree/formal/$(dirname "$f")"
    cp "formal/$f" "$tree/formal/$f"
  done
}

# run_gate <label> <gate> [harness]: 0 if the gate passes on the current tree.
run_gate() {
  local label="$1" gate="$2" log="$logs/$1-$2.log"
  (
    cd "$tree" || exit 2
    case "$gate" in
      inventory) python3 formal/check-refinement.py ;;
      oracle) cargo test -q -p averin-decision-core --test oracle ;;
      golden) cargo test -q -p averin-decision-core --test golden ;;
      kani) cargo kani -p averin-decision-core --no-default-features -Z stubbing --harness "$3" ;;
    esac
  ) >"$log" 2>&1
}

use_kani=1
if [ "${SKIP_KANI:-0}" = 1 ]; then
  use_kani=0
elif ! command -v cargo-kani >/dev/null 2>&1; then
  echo "check-mutants: cargo-kani not found (install it, or set SKIP_KANI=1)" >&2
  exit 2
fi

echo "== baseline (unmutated): every gate must pass"
fresh_tree
for g in inventory oracle golden; do
  if ! run_gate baseline "$g"; then
    echo "check-mutants: FAIL: gate '$g' fails on the unmutated tree (see $logs/baseline-$g.log)" >&2
    exit 1
  fi
done
if [ "$use_kani" = 1 ]; then
  for h in utf16_key_order_is_exact lp_into_frames_exactly; do
    if ! run_gate "baseline-$h" kani "$h"; then
      echo "check-mutants: FAIL: Kani harness $h fails on the unmutated tree" >&2
      exit 1
    fi
  done
fi
echo "   ok"

survivors=0
for patch in formal/mutants/*.patch; do
  name="$(basename "$patch" .patch)"
  fresh_tree
  if ! patch -s -p1 -d "$tree" <"$patch" >"$logs/$name-apply.log" 2>&1; then
    echo "check-mutants: FAIL: $name no longer applies (update the patch to the current source)" >&2
    cat "$logs/$name-apply.log" >&2
    exit 1
  fi
  gates=(inventory oracle golden)
  h="$(kani_harness "$name")"
  killed=()
  # A mutant with a named harness must be killed by that harness itself (a real counterexample, not an
  # unwinding bound), whatever the other gates do: that is what keeps the Kani claim load-bearing.
  if [ -n "$h" ] && [ "$use_kani" = 1 ]; then
    if ! run_gate "$name" kani "$h" && grep -q "VERIFICATION:- FAILED" "$logs/$name-kani.log"; then
      killed+=("kani:$h")
    else
      echo "check-mutants: FAIL: Kani harness $h did not refute $name (see $logs/$name-kani.log)" >&2
      survivors=$((survivors + 1))
    fi
  fi
  for g in "${gates[@]}"; do
    if ! run_gate "$name" "$g"; then
      killed+=("$g")
      [ "$first" = 1 ] && break
    fi
  done
  if [ "${#killed[@]}" -eq 0 ]; then
    echo "SURVIVED  $name"
    survivors=$((survivors + 1))
  else
    echo "killed    $name  by: ${killed[*]}"
  fi
done

if [ "$survivors" -ne 0 ]; then
  echo "check-mutants: FAIL: $survivors mutant(s) survived, or escaped their named Kani harness (logs in $logs)" >&2
  exit 1
fi
echo "check-mutants: OK (every mutant killed)"
