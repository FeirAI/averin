#!/usr/bin/env bash
# Model-check the server protocol specs. Each config asserts an EXPECTED outcome: the fixed designs
# must pass, and the pre-fix / unsafe variants must still produce a counterexample (so the model
# keeps demonstrating the bug it guards against).
set -euo pipefail
cd "$(dirname "$0")"

TLA_VERSION="v1.8.0"
JAR="${TLA2TOOLS_JAR:-${XDG_CACHE_HOME:-$HOME/.cache}/averin-formal/tla2tools-${TLA_VERSION}.jar}"
if [ ! -f "$JAR" ]; then
  mkdir -p "$(dirname "$JAR")"
  curl -sSfL -o "$JAR" "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
fi

check() { # spec config expected(pass|<violated invariant>)
  local out
  out="$(java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -cleanup -noGenerateSpecTE -config "$2" "$1" 2>&1 || true)"
  if [ "$3" = pass ]; then
    echo "$out" | grep -q "No error has been found" || { echo "$out" | tail -30; echo "FAIL: $2 expected to pass" >&2; exit 1; }
  else
    echo "$out" | grep -q "Invariant $3 is violated" || { echo "$out" | tail -30; echo "FAIL: $2 expected $3 violation" >&2; exit 1; }
  fi
  echo "ok  $2 ($3)"
}

check GrantLog.tla GrantLog_current.cfg AnchoredGapless
check GrantLog.tla GrantLog_release_lost.cfg AnchoredGapless
check GrantLog.tla GrantLog_failclosed.cfg HoleFree
check GrantLog.tla GrantLog_fixed.cfg pass
check ConsumeLedger.tla ConsumeLedger_safe.cfg pass
check ConsumeLedger.tla ConsumeLedger_short_retention.cfg InFlightRecorded
rm -rf states
