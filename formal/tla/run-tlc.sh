#!/usr/bin/env bash
# Model-check the server protocol specs. Each line asserts ONE claim with its EXPECTED outcome: the
# shipped designs must pass, and each pre-fix / unsafe variant must still produce the counterexample
# the README names (so the model keeps demonstrating the bug it guards against).
set -euo pipefail
cd "$(dirname "$0")"

TLA_VERSION="v1.7.4"  # a stable, immutable release (v1.8.0 is a rolling pre-release that is re-published)
TLA_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
JAR="${TLA2TOOLS_JAR:-${XDG_CACHE_HOME:-$HOME/.cache}/averin-formal/tla2tools-${TLA_VERSION}.jar}"
if [ ! -f "$JAR" ]; then
  mkdir -p "$(dirname "$JAR")"
  curl -sSfL -o "$JAR.tmp" "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
  mv "$JAR.tmp" "$JAR"
fi
echo "${TLA_SHA256}  ${JAR}" | sha256sum -c --quiet - || { echo "tla2tools.jar checksum mismatch" >&2; exit 1; }

check() { # spec config expected: pass | <invariant or temporal property that must be violated>
  local out
  out="$(java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -cleanup \
    -config "$2" "$1" 2>&1 || true)"
  # A state/action CONSTRAINT makes TLC's liveness checking unsound; the models bound themselves in
  # their actions instead, and any such warning (or a CONSTRAINT line) fails the run.
  if echo "$out" | grep -qi "constraints during liveness checking is dangerous" \
     || grep -qE '^\s*(CONSTRAINTS?|ACTION_CONSTRAINTS?)\b' "$2"; then
    echo "$out" | tail -30; echo "FAIL: $2 uses a state/action constraint" >&2; exit 1
  fi
  if [ "$3" = pass ]; then
    echo "$out" | grep -q "No error has been found" || { echo "$out" | tail -30; echo "FAIL: $2 expected to pass" >&2; exit 1; }
  else
    # TLC names a violated invariant; for liveness it reports "Temporal properties were violated", so
    # a liveness config must declare exactly the one expected property.
    if echo "$out" | grep -qE "Invariant $3 is violated"; then :
    elif [ "$(grep -E '^PROPERTIES' "$2")" = "PROPERTIES $3" ] \
      && echo "$out" | grep -qE "Temporal propert(y $3 was|ies were) violated"; then :
    else echo "$out" | tail -30; echo "FAIL: $2 expected a $3 violation" >&2; exit 1
    fi
  fi
  echo "ok  $2 (${3}; $(echo "$out" | grep -oE '[0-9]+ distinct states found' | tail -1))"
}

# Grant-transparency log (GrantLog.tla).
check GrantLog.tla GrantLog_current.cfg AnchoredGapless        # pre-fix: a gap gets anchored
check GrantLog.tla GrantLog_release_lost.cfg AnchoredGapless   # a lost release, no fail-closed checkpoint
check GrantLog.tla GrantLog_failclosed.cfg HoleFree            # release of a non-max orphan leaves a hole
check GrantLog.tla GrantLog_reuse_release.cfg NoDuplicateSeq   # release of a seq reused after an ambiguous commit
check GrantLog.tla GrantLog_void_race.cfg NoDuplicateSeq      # void age from allocation, no UNIQUE index: void races a retry
check GrantLog.tla GrantLog_void_age_only.cfg pass             # ...either guard alone closes it: age from the last attempt (one process)
check GrantLog.tla GrantLog_void_index_only.cfg pass           # ...or the UNIQUE record_id index
check GrantLog.tla GrantLog_void_backstop.cfg NoVoidDuringFlight # ...which really is exercised: the void races an in-flight retry
check GrantLog.tla GrantLog_void_reachable.cfg NoVoid           # non-vacuity: the guarded void does happen
check GrantLog.tla GrantLog_fixed.cfg pass                     # shipped design: no anchored gap, no duplicate seq
check GrantLog.tla GrantLog_wedge.cfg CheckpointRecovers       # without void, a client that never retries wedges checkpoints
check GrantLog.tla GrantLog_fair_retry.cfg pass                # ...recovers only if every client retries until it commits
check GrantLog.tla GrantLog_void_starved.cfg CheckpointRecovers # a client retrying forever, every attempt failing, starves the void
check GrantLog.tla GrantLog_fixed_live.cfg pass                # with operator void: no permanent checkpoint outage

# Consume-before-act ledger (ConsumeLedger.tla).
check ConsumeLedger.tla ConsumeLedger_safe.cfg pass                               # Retention >= MaxTTL: at most once per key
check ConsumeLedger.tla ConsumeLedger_short_retention_replay.cfg AtMostOncePerKey # Retention < MaxTTL: replay
check ConsumeLedger.tla ConsumeLedger_short_retention.cfg InFlightRecorded       # ...and a live in-flight key is pruned
check ConsumeLedger.tla ConsumeLedger_tenant_safe.cfg pass               # unknown-owner legacy rows block replays through expiry
check ConsumeLedger.tla ConsumeLedger_tenant_unsafe.cfg TenantAtMostOnce # premature legacy exclusion deletion reopens replay
check ConsumeLedger.tla ConsumeLedger_tenant_isolation.cfg pass          # equal nonce in separate projects is independent

# Exact project guard and authoritative operational state across two replicas.
check ProjectTx.tla ProjectTx_unserialized.cfg NoFrontierFork        # process-local locks fork a project frontier
check ProjectTx.tla ProjectTx_checkpoint_fork.cfg NoCheckpointFork   # concurrent snapshots reuse checkpoint_seq
check ProjectTx.tla ProjectTx_stale_cache.cfg NoRevokedUse          # a stale replica admits a revoked capability
check ProjectTx.tla ProjectTx_pending_cache.cfg NoGhostFinalize    # a cached expired challenge can finalize
check ProjectTx.tla ProjectTx_safe.cfg pass                         # DB guard, ambiguity, crash and post-commit anchor
check ProjectTx.tla ProjectTx_operational_safe.cfg pass             # durable pending/revocation reads
rm -rf states
