#!/usr/bin/env bash
# Model-check the server protocol specs. Each line asserts ONE claim with its EXPECTED outcome: each
# configuration marked pass must pass, and each pre-fix / unsafe variant must still produce the
# counterexample the README names (so the model keeps demonstrating the bug it guards against).
# GrantLog.tla and ConsumeLedger.tla model superseded designs; see formal/README.md for what each
# passing result is evidence for.
#
# Two guards keep a passing result from meaning less than it looks:
#   1. PINS. TLC prints "No error has been found" for a configuration that checks nothing, so deleting
#      an invariant from a pass configuration would not fail the gate. pin_of below fixes, for every
#      configuration, the SPECIFICATION and the exact INVARIANT and PROPERTY names it must declare;
#      any difference fails before TLC runs.
#   2. WITNESSES. A passing safety configuration is vacuous if the actions its invariants guard can
#      never fire (the TLA+ analogue of kani::cover). witnesses_of names, for every pass
#      configuration, at least one companion configuration: the same constants and specification, but
#      one W_ invariant asserting an interesting state is NEVER reached. The companion must be
#      VIOLATED, which proves the state is reachable in the very model the pass result is about.
#
# TLC_STATIC_ONLY=1 runs only the pin and witness-declaration checks (no Java, seconds).
# TLC_ONLY=<Spec>.tla runs only that spec's configurations (witnesses live in the same spec).
set -euo pipefail
cd "$(dirname "$0")"
STATIC="${TLC_STATIC_ONLY:-}"

# SPECIFICATION|sorted INVARIANT names|sorted PROPERTY names, per configuration (witness
# configurations are not listed: their single invariant is the expected violation named in the
# check line, and it must start with W_).
pin_of() {
  case "$1" in
  ConsumeLedger_safe) echo "Spec|AtMostOncePerKey InFlightRecorded TypeOK|" ;;
  ConsumeLedger_short_retention_replay) echo "Spec|AtMostOncePerKey|" ;;
  ConsumeLedger_short_retention) echo "Spec|AtMostOncePerKey InFlightRecorded TypeOK|" ;;
  ConsumeLedger_tenant_isolation) echo "TenantSpec|NoBothTenantsConsumed TenantAtMostOnce TenantTypeOK|" ;;
  ConsumeLedger_tenant_safe) echo "TenantSpec|TenantAtMostOnce TenantIsolation TenantTypeOK|" ;;
  ConsumeLedger_tenant_unsafe) echo "TenantSpec|TenantAtMostOnce TenantIsolation TenantTypeOK|" ;;
  GrantLog_current) echo "Spec|AnchoredGapless|" ;;
  GrantLog_failclosed) echo "Spec|HoleFree|" ;;
  GrantLog_fair_retry) echo "SpecFairRetry|BoundNotBinding|CheckpointRecovers" ;;
  GrantLog_fixed_live) echo "SpecFairVoid|BoundNotBinding|CheckpointRecovers" ;;
  GrantLog_fixed) echo "Spec|AnchoredGapless BoundNotBinding NoDuplicateSeq TypeOK|" ;;
  GrantLog_release_lost) echo "Spec|AnchoredGapless|" ;;
  GrantLog_reuse_release) echo "Spec|NoDuplicateSeq|" ;;
  GrantLog_void_age_only) echo "Spec|AnchoredGapless BoundNotBinding NoDuplicateSeq TypeOK|" ;;
  GrantLog_void_backstop) echo "Spec|NoVoidDuringFlight|" ;;
  GrantLog_void_index_only) echo "Spec|AnchoredGapless BoundNotBinding NoDuplicateSeq TypeOK|" ;;
  GrantLog_void_race) echo "Spec|NoDuplicateSeq|" ;;
  GrantLog_void_reachable) echo "Spec|NoVoid|" ;;
  GrantLog_void_starved) echo "SpecVoidOnly|BoundNotBinding|CheckpointRecovers" ;;
  GrantLog_wedge) echo "SpecNoRetryNoVoid|BoundNotBinding|CheckpointRecovers" ;;
  GrantRecovery_old_writer) echo "Spec|NoDuplicateSeq TypeOK|" ;;
  GrantRecovery_safe) echo "FairRecovery|AnchoredGapless NoDuplicateSeq NoLateGrant TerminalHasWinner TerminalOnceFenced TypeOK|CheckpointRecovers" ;;
  ProjectTx_checkpoint_fork) echo "CoreSpec|NoCheckpointFork|" ;;
  ProjectTx_operational_safe) echo "OperationalSpec|NoRevokedUse|" ;;
  ProjectTx_operational_unserialized) echo "OperationalSpec|NoRevokedUse|" ;;
  ProjectTx_pending_cache) echo "OperationalSpec|NoGhostFinalize|" ;;
  ProjectTx_safe) echo "CoreSpec|NoCheckpointFork NoFrontierFork NoStaleCheckpoint|" ;;
  ProjectTx_stale_cache) echo "OperationalSpec|NoRevokedUse|" ;;
  ProjectTx_unserialized) echo "CoreSpec|NoFrontierFork|" ;;
    *) echo "" ;;
  esac
}

# Reachability witness configurations of each pass configuration.
witnesses_of() {
  case "$1" in
    GrantLog_void_age_only) echo "GrantLog_void_age_only_witness_void_anchored" ;;
    GrantLog_void_index_only) echo "GrantLog_void_index_only_witness_void_anchored" ;;
    GrantLog_fixed) echo "GrantLog_fixed_witness_void_anchored" ;;
    GrantLog_fair_retry) echo "GrantLog_fair_retry_witness_gap" ;;
    GrantLog_fixed_live) echo "GrantLog_fixed_live_witness_gap GrantLog_fixed_live_witness_void_anchored" ;;
    GrantRecovery_safe) echo "GrantRecovery_safe_witness_anchored_void GrantRecovery_safe_witness_anchored_recorded" ;;
    ConsumeLedger_safe) echo "ConsumeLedger_safe_witness_all_keys_spent" ;;
    ConsumeLedger_tenant_safe) echo "ConsumeLedger_tenant_safe_witness_isolation_antecedent ConsumeLedger_tenant_safe_witness_legacy_purged" ;;
    ProjectTx_safe) echo "ProjectTx_safe_witness_both_recorded ProjectTx_safe_witness_anchor_attached" ;;
    ProjectTx_operational_safe) echo "ProjectTx_operational_safe_witness_guarded_use_done ProjectTx_operational_safe_witness_guard_held" ;;
    *) echo "" ;;
  esac
}

# Normalised configuration: one "KEY<TAB>text" line per logical line, comments and blanks dropped.
cfg_norm() {
  awk '{ sub(/\\\*.*/, ""); gsub(/[ \t\r]+/, " "); sub(/^ /, ""); sub(/ $/, "") }
    $0 == "" { next }
    { k = $1
      if (k ~ /^(CONSTANTS?|SPECIFICATION|INVARIANTS?|PROPERT(Y|IES)|CHECK_DEADLOCK|INIT|NEXT|CONSTRAINTS?|ACTION_CONSTRAINTS?|SYMMETRY|VIEW|ALIAS|POSTCONDITION)$/) {
        key = k
        if (key == "INVARIANT") key = "INVARIANTS"
        if (key == "PROPERTY") key = "PROPERTIES"
        if (key == "CONSTANT") key = "CONSTANTS"
        $1 = ""; sub(/^ /, "") }
      print key "\t" $0 }' "$1"
}
cfg_names() { # cfg key -> sorted names, space separated
  cfg_norm "$1" | awk -F'\t' -v k="$2" '$1 == k { print $2 }' | tr ' ' '\n' | grep . | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//' || true
}
cfg_pin() {
  local spec
  spec="$(cfg_norm "$1" | awk -F'\t' '$1 == "SPECIFICATION" { print $2 }')"
  echo "${spec}|$(cfg_names "$1" INVARIANTS)|$(cfg_names "$1" PROPERTIES)"
}
cfg_rest() { # everything except the checked names: constants, specification, options
  cfg_norm "$1" | awk -F'\t' '$1 != "INVARIANTS" && $1 != "PROPERTIES"'
}

TLA_VERSION="v1.7.4"  # a stable, immutable release (v1.8.0 is a rolling pre-release that is re-published)
TLA_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
if [ -z "$STATIC" ]; then
  JAR="${TLA2TOOLS_JAR:-${XDG_CACHE_HOME:-$HOME/.cache}/averin-formal/tla2tools-${TLA_VERSION}.jar}"
  if [ ! -f "$JAR" ]; then
    mkdir -p "$(dirname "$JAR")"
    curl -sSfL -o "$JAR.tmp" "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
    mv "$JAR.tmp" "$JAR"
  fi
  # sha256sum (GNU coreutils) where present, else macOS/BSD `shasum -a 256`.
  if command -v sha256sum >/dev/null 2>&1; then sha256=(sha256sum); else sha256=(shasum -a 256); fi
  echo "${TLA_SHA256}  ${JAR}" | "${sha256[@]}" -c --quiet - || { echo "tla2tools.jar checksum mismatch" >&2; exit 1; }
fi

checked=0
seen_cfgs=" "      # every configuration a check line named
seen_witness=" "   # "cfg=W_Name " for every check line that expects a W_ violation
pass_cfgs=" "      # configurations checked with expected outcome pass
die() { echo "FAIL: $*" >&2; exit 1; }

# Static checks, before TLC: the configuration declares exactly its pinned names.
verify_pin() { # config expected
  [ -f "$1" ] || die "$1 does not exist"
  if [[ "$1" == *_witness_* ]]; then
    # A witness declares exactly one invariant, named W_*, and it is the expected violation.
    local inv; inv="$(cfg_pin "$1")"
    [ "$inv" = "$(cfg_pin "$1" | cut -d'|' -f1)|$2|" ] && [[ "$2" == W_* ]] \
      || die "$1 must declare exactly the one invariant $2 (a W_ name) and no property; found: $inv"
    return 0
  fi
  local want have
  want="$(pin_of "${1%.cfg}")"
  [ -n "$want" ] || die "$1 has no entry in pin_of (every configuration's checked names must be pinned)"
  have="$(cfg_pin "$1")"
  [ "$have" = "$want" ] || die "$1 differs from its pin. pinned: $want  found: $have"
}

check() { # spec config expected: pass | <invariant or temporal property that must be violated>
  # TLC_ONLY=ProjectTx.tla runs only the configurations of that spec (used by the kit register).
  if [ -n "${TLC_ONLY:-}" ] && [ "$1" != "$TLC_ONLY" ]; then return 0; fi
  checked=$((checked + 1))
  local stem="${2%.cfg}"
  seen_cfgs="${seen_cfgs}${stem} "
  verify_pin "$2" "$3"
  if [ "$3" = pass ]; then
    pass_cfgs="${pass_cfgs}${stem} "
    [ -n "$(witnesses_of "$stem")" ] || die "$2 is a pass configuration with no reachability witness (witnesses_of)"
  elif [[ "$3" == W_* ]]; then
    seen_witness="${seen_witness}${stem}=$3 "
  fi
  if [ -n "$STATIC" ]; then echo "ok  $2 (static: ${3})"; return 0; fi
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

# Grant-transparency log (GrantLog.tla): the SUPERSEDED age-based recovery design. The current fence
# protocol is GrantRecovery.tla, below.
check GrantLog.tla GrantLog_current.cfg AnchoredGapless        # pre-fix: a gap gets anchored
check GrantLog.tla GrantLog_release_lost.cfg AnchoredGapless   # a lost release, no fail-closed checkpoint
check GrantLog.tla GrantLog_failclosed.cfg HoleFree            # release of a non-max orphan leaves a hole
check GrantLog.tla GrantLog_reuse_release.cfg NoDuplicateSeq   # release of a seq reused after an ambiguous commit
check GrantLog.tla GrantLog_void_race.cfg NoDuplicateSeq      # void age from allocation, no UNIQUE index: void races a retry
check GrantLog.tla GrantLog_void_age_only.cfg pass             # ...either guard alone closes it: age from the last attempt (one process)
check GrantLog.tla GrantLog_void_age_only_witness_void_anchored.cfg W_VoidAnchored  # witness: a void is anchored
check GrantLog.tla GrantLog_void_index_only.cfg pass           # ...or the UNIQUE record_id index
check GrantLog.tla GrantLog_void_index_only_witness_void_anchored.cfg W_VoidAnchored  # witness: a void is anchored
check GrantLog.tla GrantLog_void_backstop.cfg NoVoidDuringFlight # ...which really is exercised: the void races an in-flight retry
check GrantLog.tla GrantLog_void_reachable.cfg NoVoid           # non-vacuity: the guarded void does happen
check GrantLog.tla GrantLog_fixed.cfg pass                     # SUPERSEDED design (age-based recovery), not the shipped one: no anchored gap, no duplicate seq
check GrantLog.tla GrantLog_fixed_witness_void_anchored.cfg W_VoidAnchored   # witness: a void is anchored
check GrantLog.tla GrantLog_wedge.cfg CheckpointRecovers       # without void, a client that never retries wedges checkpoints
check GrantLog.tla GrantLog_fair_retry.cfg pass                # ...recovers only if every client retries until it commits
check GrantLog.tla GrantLog_fair_retry_witness_gap.cfg W_Gap  # witness: a gap is reachable, so CheckpointRecovers is not trivial
check GrantLog.tla GrantLog_void_starved.cfg CheckpointRecovers # a client retrying forever, every attempt failing, starves the void
check GrantLog.tla GrantLog_fixed_live.cfg pass                # superseded design, with operator void: no permanent checkpoint outage
check GrantLog.tla GrantLog_fixed_live_witness_gap.cfg W_Gap  # witness: a gap is reachable
check GrantLog.tla GrantLog_fixed_live_witness_void_anchored.cfg W_VoidAnchored  # witness: the operator void happens

# Permanent recovery fence over legacy/residual reservations. The unsafe
# counterexample demonstrates why already-running old credentials must be cut off.
check GrantRecovery.tla GrantRecovery_old_writer.cfg NoDuplicateSeq
check GrantRecovery.tla GrantRecovery_safe.cfg pass
check GrantRecovery.tla GrantRecovery_safe_witness_anchored_void.cfg W_AnchoredVoid  # witness: the void path anchors
check GrantRecovery.tla GrantRecovery_safe_witness_anchored_recorded.cfg W_AnchoredRecorded  # witness: the recorded path anchors

# Consume-before-act ledger (ConsumeLedger.tla): the SUPERSEDED pgledger consume (pgledger now only sweeps); the current consume
# (server/internal/store/ledger_postgres.go) is not modelled.
check ConsumeLedger.tla ConsumeLedger_safe.cfg pass                               # Retention >= MaxTTL: at most once per key
check ConsumeLedger.tla ConsumeLedger_safe_witness_all_keys_spent.cfg W_AllKeysSpent  # witness: every use key is spent
check ConsumeLedger.tla ConsumeLedger_short_retention_replay.cfg AtMostOncePerKey # Retention < MaxTTL: replay
check ConsumeLedger.tla ConsumeLedger_short_retention.cfg InFlightRecorded       # ...and a live in-flight key is pruned
check ConsumeLedger.tla ConsumeLedger_tenant_safe.cfg pass               # LegacyPresent = FALSE: consume is reachable (was vacuous with TRUE)
check ConsumeLedger.tla ConsumeLedger_tenant_safe_witness_isolation_antecedent.cfg W_IsolationAntecedent  # witness: TenantIsolation's antecedent holds
check ConsumeLedger.tla ConsumeLedger_tenant_safe_witness_legacy_purged.cfg W_LegacyPurged  # witness: the guarded legacy purge fires
check ConsumeLedger.tla ConsumeLedger_tenant_unsafe.cfg TenantAtMostOnce # premature legacy exclusion deletion reopens replay
check ConsumeLedger.tla ConsumeLedger_tenant_isolation.cfg NoBothTenantsConsumed # witness: both projects can consume the equal nonce

# Exact project guard and authoritative operational state across two replicas.
check ProjectTx.tla ProjectTx_unserialized.cfg NoFrontierFork        # process-local locks fork a project frontier
check ProjectTx.tla ProjectTx_checkpoint_fork.cfg NoCheckpointFork   # concurrent snapshots reuse checkpoint_seq
check ProjectTx.tla ProjectTx_stale_cache.cfg NoRevokedUse          # a stale replica admits a revoked capability
check ProjectTx.tla ProjectTx_pending_cache.cfg NoGhostFinalize    # a cached expired challenge can finalize
check ProjectTx.tla ProjectTx_safe.cfg pass                         # DB guard, ambiguity, crash and post-commit anchor
check ProjectTx.tla ProjectTx_safe_witness_both_recorded.cfg W_BothRecorded  # witness: both replicas record
check ProjectTx.tla ProjectTx_safe_witness_anchor_attached.cfg W_AnchorAttached  # witness: a checkpoint anchor attaches
check ProjectTx.tla ProjectTx_operational_unserialized.cfg NoRevokedUse  # guard off: a revoke lands between a guarded use's read and its act
check ProjectTx.tla ProjectTx_operational_safe.cfg pass             # guarded use under the project guard (NoGhostFinalize is definitional and not checked)
check ProjectTx.tla ProjectTx_operational_safe_witness_guarded_use_done.cfg W_GuardedUseDone  # witness: a guarded use completes
check ProjectTx.tla ProjectTx_operational_safe_witness_guard_held.cfg W_GuardHeld  # witness: a replica holds the guard
rm -rf states

# Pairing checks (static). Every checked pass configuration needs each declared witness to have been
# checked as an expected W_ violation, with identical constants, specification and options.
for p in $pass_cfgs; do
  for w in $(witnesses_of "$p"); do
    case "$seen_witness" in
      *" ${w}="W_*) ;;
      *) die "witness $w of $p was not checked with a W_ expectation" ;;
    esac
    [ "$(cfg_rest "$p.cfg")" = "$(cfg_rest "$w.cfg")" ] \
      || die "witness $w.cfg must differ from $p.cfg only in its INVARIANTS (same constants and specification)"
  done
done
# Every configuration file must be checked, so an orphan cannot sit unpinned and unrun.
if [ -z "${TLC_ONLY:-}" ]; then
  for f in *.cfg; do
    case "$seen_cfgs" in *" ${f%.cfg} "*) ;; *) die "$f is not named by any check line" ;; esac
  done
fi
# A TLC_ONLY that names no spec above would otherwise check nothing and still exit 0.
if [ "$checked" -eq 0 ]; then echo "FAIL: no configuration was checked (TLC_ONLY=${TLC_ONLY:-})" >&2; exit 1; fi
