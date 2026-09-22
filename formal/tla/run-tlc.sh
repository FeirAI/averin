#!/usr/bin/env bash
# Model-check the server protocol specs. Each line asserts ONE claim with its EXPECTED outcome: the
# shipped designs must pass, and each pre-fix / unsafe variant must still produce the counterexample
# the README names (so the model keeps demonstrating the bug it guards against).
set -euo pipefail
cd "$(dirname "$0")"

TLA_VERSION="v1.8.0"
TLA_SHA256="9d36716ffb5e49d1ba8fae4651eba59f3189887e12eb90e204a42d2e6e993fef"
JAR="${TLA2TOOLS_JAR:-${XDG_CACHE_HOME:-$HOME/.cache}/averin-formal/tla2tools-${TLA_VERSION}.jar}"
if [ ! -f "$JAR" ]; then
  mkdir -p "$(dirname "$JAR")"
  curl -sSfL -o "$JAR.tmp" "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
  mv "$JAR.tmp" "$JAR"
fi
echo "${TLA_SHA256}  ${JAR}" | sha256sum -c --quiet - || { echo "tla2tools.jar checksum mismatch" >&2; exit 1; }

check() { # spec config expected: pass | <invariant or temporal property that must be violated>
  local out
  out="$(java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -cleanup -noGenerateSpecTE \
    -config "$2" "$1" 2>&1 || true)"
  if [ "$3" = pass ]; then
    echo "$out" | grep -q "No error has been found" || { echo "$out" | tail -30; echo "FAIL: $2 expected to pass" >&2; exit 1; }
  else
    echo "$out" | grep -qE "(Invariant|Temporal property) $3 (is|was) violated" \
      || { echo "$out" | tail -30; echo "FAIL: $2 expected a $3 violation" >&2; exit 1; }
  fi
  echo "ok  $2 (${3})"
}

# Grant-transparency log (GrantLog.tla).
check GrantLog.tla GrantLog_current.cfg AnchoredGapless        # pre-fix: a gap gets anchored
check GrantLog.tla GrantLog_release_lost.cfg AnchoredGapless   # a lost release, no fail-closed checkpoint
check GrantLog.tla GrantLog_failclosed.cfg HoleFree            # release of a non-max orphan leaves a hole
check GrantLog.tla GrantLog_reuse_release.cfg NoDuplicateSeq   # release of a seq reused after an ambiguous commit
check GrantLog.tla GrantLog_fixed.cfg pass                     # shipped design: no anchored gap, no duplicate seq
check GrantLog.tla GrantLog_wedge.cfg CheckpointRecovers       # without void, a client that never retries wedges checkpoints
check GrantLog.tla GrantLog_fair_retry.cfg pass                # ...recovers only if every client retries until it commits
check GrantLog.tla GrantLog_fixed_live.cfg pass                # with operator void: no permanent checkpoint outage

# Consume-before-act ledger (ConsumeLedger.tla).
check ConsumeLedger.tla ConsumeLedger_safe.cfg pass                               # Retention >= MaxTTL: at most once per key
check ConsumeLedger.tla ConsumeLedger_short_retention_replay.cfg AtMostOncePerKey # Retention < MaxTTL: replay
check ConsumeLedger.tla ConsumeLedger_short_retention.cfg InFlightRecorded       # ...and a live in-flight key is pruned
rm -rf states
