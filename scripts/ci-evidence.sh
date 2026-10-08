#!/usr/bin/env bash
# Close one CI job's evidence directory before it is uploaded as an artifact (retained 90 days; see
# "Evidence of record" in formal/README.md). Copies any Kani shard state files, then writes
# MANIFEST.txt: commit, run, job, runner, tool versions and the SHA-256 of every file in DIR.
#
#   bash scripts/ci-evidence.sh DIR
#
# The manifest records what a job ran and what it printed. It is not a signature: the evidence of
# record is the CI run itself, on the pinned toolchain.
set -uo pipefail

[ "$#" -eq 1 ] || { echo "usage: $0 DIR" >&2; exit 2; }
mkdir -p "$1"
dir="$(cd "$1" && pwd)"
cd "$(dirname "$0")/.."

if compgen -G "target/kani-shards/*.state" >/dev/null; then
  mkdir -p "$dir/kani-shards"
  cp target/kani-shards/*.state "$dir/kani-shards/"
fi

sum() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

{
  # On a pull request the checkout is a synthetic merge commit, so HEAD names a commit that exists
  # nowhere else. Record the SHA the event ran on and the pull request head separately.
  echo "checkout (git HEAD): $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "github_sha: ${GITHUB_SHA:-local}"
  echo "pr_head_sha: ${PR_HEAD_SHA:-none (not a pull request event)}"
  echo "ref: ${GITHUB_REF:-local}"
  echo "event: ${GITHUB_EVENT_NAME:-local}"
  echo "run: ${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-local} (attempt ${GITHUB_RUN_ATTEMPT:-0})"
  echo "workflow: ${GITHUB_WORKFLOW:-local}"
  echo "job: ${GITHUB_JOB:-local}"
  echo "runner: ${RUNNER_OS:-$(uname -s)} ${RUNNER_ARCH:-unknown} ($(uname -m))"
  if command -v cargo-kani >/dev/null 2>&1; then
    echo "kani: $(cargo kani --version 2>/dev/null | tr '\n' ' ')"
  fi
  if command -v lean >/dev/null 2>&1; then
    echo "lean: $(lean --version 2>/dev/null | head -n1)"
  fi
  # Production refinement toolchain pins (the versions the extraction and proofs are checked against).
  if [ -f formal/production/manifest.json ] && command -v python3 >/dev/null 2>&1; then
    python3 -I - formal/production/manifest.json <<'PY' || echo "production pins: unreadable"
import json, sys
t = json.load(open(sys.argv[1]))["toolchain"]
for key in ("lean", "charon_commit", "charon_rust_toolchain", "aeneas_commit", "mathlib_rev"):
    print(f"production {key}: {t.get(key, 'unknown')}")
PY
  fi
  echo "files (sha256):"
  (cd "$dir" && find . -type f ! -name MANIFEST.txt -print | LC_ALL=C sort | while IFS= read -r f; do sum "$f"; done)
} >"$dir/MANIFEST.txt"
cat "$dir/MANIFEST.txt"
