#!/usr/bin/env bash
# Local resource guard for Kani runs on a shared workstation (CI relies on job timeouts instead).
#
#   bash formal/kani-watchdog.sh LOG -- COMMAND...
#
# Runs COMMAND in its own process group and kills the whole group (cargo, kani, cbmc and any
# external SAT solver, which CBMC names after its CNF file) when any member exceeds
# KANI_WD_RSS_KB (default 12 GiB), host free memory drops below KANI_WD_MIN_FREE_PCT (default
# 20%, macOS memory_pressure), or KANI_WD_WALL_S seconds pass (default: no wall limit). Killing
# the group matters: a plain `timeout` around run-kani.sh can leave CBMC running.
# Writes LOG (all output) and LOG.watchdog (one summary line). A kill is a resource failure:
# the command's nonzero exit is preserved and never counts as a proof or a counterexample.
set -u
log="$1"
shift
[ "${1:-}" = "--" ] && shift
limit_kb="${KANI_WD_RSS_KB:-12582912}"
min_free="${KANI_WD_MIN_FREE_PCT:-20}"
wall="${KANI_WD_WALL_S:-0}"
start=$(date +%s)
set -m
"$@" >"$log" 2>&1 &
pid=$!
set +m
peak=0
reason=""
cpufile="$(mktemp)"
while kill -0 "$pid" 2>/dev/null; do
  for member in $(pgrep -g "$pid"); do
    line="$(ps -o rss=,time= -p "$member" 2>/dev/null)" || continue
    [ -z "$line" ] && continue
    rss=$(awk '{print $1}' <<<"$line")
    echo "$member $(awk '{print $2}' <<<"$line")" >>"$cpufile"
    [ "$rss" -gt "$peak" ] && peak=$rss
    [ "$rss" -gt "$limit_kb" ] && reason="rss=${rss}KB"
  done
  free=$(memory_pressure -Q 2>/dev/null | awk -F': ' '/free percentage/ {gsub("%", "", $2); print $2}')
  if [ -n "$free" ] && [ "$free" -lt "$min_free" ]; then reason="host_free=${free}%"; fi
  if [ "$wall" -gt 0 ] && [ $(( $(date +%s) - start )) -gt "$wall" ]; then reason="wall>${wall}s"; fi
  if [ -n "$reason" ]; then
    kill -TERM -- -"$pid" 2>/dev/null
    sleep 2
    kill -KILL -- -"$pid" 2>/dev/null
    break
  fi
  sleep 1
done
wait "$pid"
code=$?
end=$(date +%s)
# Process-group CPU: the last sampled cumulative time of each member, summed.
cpu=$(awk '{last[$1] = $2} END {s = 0; for (p in last) {n = split(last[p], a, ":"); v = 0; for (i = 1; i <= n; i++) v = v * 60 + a[i]; s += v}; printf "%.0f", s}' "$cpufile")
rm -f "$cpufile"
summary="exit=$code wall_s=$((end - start)) group_cpu_s=$cpu peak_member_rss_mb=$((peak / 1024))"
[ -n "$reason" ] && summary="RESOURCE_KILLED($reason) $summary"
echo "$summary log=$log" | tee "$log.watchdog"
exit "$code"
