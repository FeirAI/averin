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

# Results are only reusable for byte-identical proof sources and runners.
digest="$(cat core/src/canon.rs core/src/b64.rs core/src/hashx.rs core/src/lib.rs \
  formal/run-kani.sh formal/run-kani-shards.sh formal/check-kani-success.py \
  formal/check-kani-shards.py formal/check-kani-domains.py | shasum -a 256 | cut -d' ' -f1)"
state="${KANI_SHARD_STATE:-target/kani-shards/$family.state}"
mkdir -p "$(dirname "$state")"
if [ ! -f "$state" ] || [ "$(head -n1 "$state")" != "SOURCE $digest" ]; then
  printf 'SOURCE %s\n' "$digest" >"$state"
fi

n=0
while IFS= read -r harness; do
  n=$((n + 1))
  if grep -qxF "PASS $harness" "$state"; then
    echo "run-kani-shards: [$n/$count] $harness already passed on this source"
    continue
  fi
  echo "run-kani-shards: [$n/$count] $harness"
  start=$(date +%s)
  set +e
  bash formal/run-kani.sh --harness "$harness"
  code=$?
  set -e
  secs=$(( $(date +%s) - start ))
  if [ "$code" -eq 0 ]; then
    printf 'PASS %s\n' "$harness" >>"$state"
    echo "run-kani-shards: PASS $harness (${secs}s)"
  else
    printf 'FAIL %s %s\n' "$harness" "$code" >>"$state"
    echo "run-kani-shards: FAIL $harness exit=$code (${secs}s); state in $state" >&2
    exit 1
  fi
done <<<"$shards"

passed="$(grep -c '^PASS ' "$state" || true)"
if [ "$passed" -ne "$count" ]; then
  echo "run-kani-shards: $family has $passed recorded passes for $count shards" >&2
  exit 1
fi
echo "run-kani-shards: $family OK ($count of $count shards VERIFICATION SUCCESSFUL)"
