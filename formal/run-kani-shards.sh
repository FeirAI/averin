#!/usr/bin/env bash
# Run every shard of one sharded Kani property family and fail unless each shard reports its own
# complete VERIFICATION SUCCESSFUL (checked per shard by run-kani.sh / check-kani-success.py).
#
#   bash formal/run-kani-shards.sh FAMILY            # run (and resume) every shard of FAMILY
#   bash formal/run-kani-shards.sh --list FAMILY     # print the shard harness names
#   bash formal/run-kani-shards.sh --families        # print the sharded family names
#
# The shard list comes from check-kani-shards.py, which first proves that the shards partition the
# family's original input domain exactly once. Per-shard outcomes are recorded in
# $KANI_SHARD_STATE (default target/kani-shards/FAMILY.state) as "PASS <harness>" or
# "FAIL <harness> <exit>"; a rerun skips only shards already recorded as PASS against the same
# source digest, so an interrupted batch resumes without trusting stale results. A timeout,
# signal, tool error or counterexample is a FAIL; nothing but a recorded PASS counts.
#
# KANI_SHARD_GROUP=N verifies N pending shards per Kani invocation (`run-kani.sh --group`, one
# build, each shard still checked for its own complete success); KANI_JOBS=N lets Kani verify
# them N at a time. KANI_SHARD_SLICE=I/N restricts this run to the I-th of N contiguous slices
# of the shard list (CI matrix jobs); the family passes only when every slice passes.
# KANI_SHARD_ONLY=FILE restricts this run to the listed shards (one name per line; each must be in
# the checked list), e.g. to run cheap cases in parallel and slow ones later with longer limits.
# All of these change scheduling only, never the obligations: the family is verified only when a
# run over the whole list finds every shard recorded as PASS on the same source digest.
set -euo pipefail

cd "$(dirname "$0")/.."

case "${1:-}" in
  --families) exec python3 formal/check-kani-shards.py --families ;;
  --list)
    [ "$#" -eq 2 ] || { echo "usage: $0 --list FAMILY" >&2; exit 2; }
    exec python3 formal/check-kani-shards.py --list "$2" ;;
esac
[ "$#" -eq 1 ] || { echo "usage: $0 FAMILY | --list FAMILY | --families" >&2; exit 2; }
family="$1"

shards="$(python3 formal/check-kani-shards.py --list "$family")" || {
  echo "run-kani-shards: shard partition check failed for $family" >&2
  exit 2
}
count="$(printf '%s\n' "$shards" | grep -c .)"
[ "$count" -gt 0 ] || { echo "run-kani-shards: $family has no shards" >&2; exit 2; }
if [ -n "${KANI_SHARD_ONLY:-}" ]; then
  [ -f "$KANI_SHARD_ONLY" ] || { echo "run-kani-shards: KANI_SHARD_ONLY file not found" >&2; exit 2; }
  unknown="$(printf '%s\n' "$shards" | awk 'NR == FNR { known[$0] = 1; next } NF && !($0 in known)' - "$KANI_SHARD_ONLY")"
  [ -z "$unknown" ] || { echo "run-kani-shards: KANI_SHARD_ONLY names unknown shards: $unknown" >&2; exit 2; }
  shards="$(printf '%s\n' "$shards" | awk 'NR == FNR { if (NF) want[$0] = 1; next } ($0 in want)' "$KANI_SHARD_ONLY" -)"
  count="$(printf '%s\n' "$shards" | grep -c . || true)"
  [ "$count" -gt 0 ] || { echo "run-kani-shards: KANI_SHARD_ONLY selects no shard" >&2; exit 2; }
  family_label="$family (subset $KANI_SHARD_ONLY)"
fi
if [ -n "${KANI_SHARD_SLICE:-}" ]; then
  slice_i="${KANI_SHARD_SLICE%/*}" slice_n="${KANI_SHARD_SLICE#*/}"
  case "$slice_i/$slice_n" in
    *[!0-9/]*|/*|*/) echo "run-kani-shards: KANI_SHARD_SLICE must be I/N" >&2; exit 2 ;;
  esac
  if [ "$slice_n" -lt 1 ] || [ "$slice_i" -lt 1 ] || [ "$slice_i" -gt "$slice_n" ]; then
    echo "run-kani-shards: KANI_SHARD_SLICE must satisfy 1 <= I <= N" >&2
    exit 2
  fi
  # Slice I holds shards (I-1)*ceil(count/N)+1 .. I*ceil(count/N) of the checked list.
  per=$(( (count + slice_n - 1) / slice_n ))
  shards="$(printf '%s\n' "$shards" | sed -n "$(( (slice_i - 1) * per + 1 )),$(( slice_i * per ))p")"
  count="$(printf '%s\n' "$shards" | grep -c . || true)"
  [ "$count" -gt 0 ] || { echo "run-kani-shards: slice $KANI_SHARD_SLICE of $family is empty" >&2; exit 2; }
  family_label="$family (slice $KANI_SHARD_SLICE)"
fi

# Results are only reusable for byte-identical proof sources and runners.
digest="$(cat core/src/canon.rs core/src/kani_string_cases.rs core/src/b64.rs core/src/hashx.rs core/src/lib.rs \
  formal/run-kani.sh formal/run-kani-shards.sh formal/check-kani-success.py \
  formal/check-kani-shards.py formal/check-kani-domains.py formal/gen-kani-string-cases.py \
  | shasum -a 256 | cut -d' ' -f1)"
state="${KANI_SHARD_STATE:-target/kani-shards/$family.state}"
family_label="${family_label:-$family}"
mkdir -p "$(dirname "$state")"
if [ ! -f "$state" ] || [ "$(head -n1 "$state")" != "SOURCE $digest" ]; then
  printf 'SOURCE %s\n' "$digest" >"$state"
fi

group="${KANI_SHARD_GROUP:-1}"
case "$group" in ''|*[!0-9]*|0) echo "run-kani-shards: KANI_SHARD_GROUP must be a positive integer" >&2; exit 2 ;; esac

pending=()
while IFS= read -r harness; do
  [ -n "$harness" ] && pending+=("$harness")
done < <(printf '%s\n' "$shards" | awk 'NR == FNR { if ($1 == "PASS") passed[$2] = 1; next } !($0 in passed)' "$state" -)
echo "run-kani-shards: $family: $((count - ${#pending[@]})) of $count shards already passed on this source"

done_count=$((count - ${#pending[@]}))
i=0
while [ "$i" -lt "${#pending[@]}" ]; do
  batch=("${pending[@]:$i:$group}")
  i=$((i + ${#batch[@]}))
  echo "run-kani-shards: [$((done_count + i))/$count] ${batch[*]}"
  start=$(date +%s)
  set +e
  if [ "${#batch[@]}" -eq 1 ]; then
    bash formal/run-kani.sh --harness "${batch[0]}"
  else
    bash formal/run-kani.sh --group "${batch[@]}"
  fi
  code=$?
  set -e
  secs=$(( $(date +%s) - start ))
  if [ "$code" -eq 0 ]; then
    for harness in "${batch[@]}"; do
      printf 'PASS %s\n' "$harness" >>"$state"
    done
    echo "run-kani-shards: PASS ${#batch[@]} shard(s) (${secs}s)"
  else
    for harness in "${batch[@]}"; do
      printf 'FAIL %s %s\n' "$harness" "$code" >>"$state"
    done
    echo "run-kani-shards: FAIL ${batch[*]} exit=$code (${secs}s); state in $state" >&2
    exit 1
  fi
done

passed="$(printf '%s\n' "$shards" | awk 'NR == FNR { if ($1 == "PASS") passed[$2] = 1; next } ($0 in passed) { n++ } END { print n + 0 }' "$state" -)"
if [ "$passed" -ne "$count" ]; then
  echo "run-kani-shards: $family_label has $passed recorded passes for $count shards" >&2
  exit 1
fi
echo "run-kani-shards: $family_label OK ($count of $count shards VERIFICATION SUCCESSFUL)"
