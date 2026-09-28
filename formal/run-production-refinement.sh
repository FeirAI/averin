#!/usr/bin/env bash
# Plan 012: regenerate the production seal core (phase A) and the verifier's claim kernel (phase B)
# from core/src with Charon + Aeneas, and prove them against the Averin model (formal/production).
# See formal/production/README.md.
#
#   bash formal/run-production-refinement.sh           # verify: regenerate into a scratch dir, require
#                                                      # it to equal the committed extraction, then
#                                                      # check glue/call paths, build every proof, audit
#   bash formal/run-production-refinement.sh --write   # after an intended source change: write the
#                                                      # regenerated files + source hashes, then build
#
# Toolchain (pinned in formal/production/manifest.json): AVERIN_AENEAS_TOOLS must name a directory with
# the pinned Charon/Aeneas/Lean install and its `with-aeneas.sh` environment wrapper (see
# plans/preflight/PROVENANCE.md for how it was built; all fetches through Socket Firewall). By default
# the script looks for `.verification-tools/aeneas-557f7a` in a parent directory. The Aeneas Lean
# backend is linked at formal/production/.aeneas; Lake packages (mathlib and friends at the manifest
# revisions) go to formal/production/.lake/packages, which may be a symlink to an existing checkout
# (AVERIN_LAKE_PACKAGES) so the mathlib build is reused, not rebuilt.
#
# Output markers (used by formal/check-mutants.sh): `production refinement: OK` or
# `production refinement: FAIL (<reason>): ...` with reason stale | call-path | cfg | glue | extract | proof | audit | toolchain.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PROD="$ROOT/formal/production"
WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

fail() { echo "production refinement: FAIL ($1): $2"; exit 1; }

# ---- toolchain ----------------------------------------------------------------------------------
TOOLS="${AVERIN_AENEAS_TOOLS:-}"
if [ -z "$TOOLS" ]; then
  d="$ROOT"
  while [ "$d" != "/" ]; do
    if [ -f "$d/.verification-tools/aeneas-557f7a/with-aeneas.sh" ]; then TOOLS="$d/.verification-tools/aeneas-557f7a"; break; fi
    d="$(dirname "$d")"
  done
fi
[ -n "$TOOLS" ] && [ -f "$TOOLS/with-aeneas.sh" ] || fail toolchain "set AVERIN_AENEAS_TOOLS to the pinned Charon/Aeneas/Lean install"
W="$TOOLS/with-aeneas.sh"
pin() { python3 -c "import json,sys;print(json.load(open('$PROD/manifest.json'))['toolchain'][sys.argv[1]])" "$1"; }
aeneas_v="$(bash "$W" aeneas -version 2>/dev/null | tr -d '[:space:]')"
# A tarball build reports the full commit; a git-checkout build (CI: setup-toolchain.sh verifies the
# checked-out HEAD equals the full pin) reports git's abbreviated id. Accept either, never a mismatch.
aeneas_pin="$(pin aeneas_commit)"
aeneas_hex="$(printf '%s' "$aeneas_v" | sed -n 's/^aeneas\([0-9a-f]\{7,40\}\)$/\1/p')"
case "$aeneas_v" in
  *"$aeneas_pin"*) ;;
  *) [ -n "$aeneas_hex" ] && [ "${aeneas_pin#"$aeneas_hex"}" != "$aeneas_pin" ] ||
       fail toolchain "aeneas -version is '$aeneas_v', pinned $aeneas_pin" ;;
esac
lean_v="$(bash "$W" lean --version 2>/dev/null)"
case "$lean_v" in *"version 4.31.0,"*) ;; *) fail toolchain "Lean is '$lean_v', pinned 4.31.0";; esac
rustc_v="$(bash "$W" rustc --version 2>/dev/null)"
[ "$rustc_v" = "$(pin charon_rustc_version)" ] || fail toolchain "Charon's rustc is '$rustc_v', pinned '$(pin charon_rustc_version)'"
grep -q "$(pin mathlib_rev)" "$PROD/lake-manifest.json" || fail toolchain "lake-manifest.json does not pin mathlib $(pin mathlib_rev)"

# Aeneas Lean backend and (optionally shared) Lake packages.
ln -sfn "$TOOLS/sources/aeneas" "$PROD/.aeneas"
if [ -n "${AVERIN_LAKE_PACKAGES:-}" ] && [ ! -e "$PROD/.lake/packages" ]; then
  mkdir -p "$PROD/.lake" && ln -sfn "$AVERIN_LAKE_PACKAGES" "$PROD/.lake/packages"
fi

# ---- 1. toolchain-free checks (call paths, cfg, glue); staleness is checked after regeneration ----
python3 "$PROD/check-production.py" --self-test && python3 "$PROD/check-production.py" --no-stale || exit 1

# ---- 2. regenerate the extraction from the checked-out source ------------------------------------
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/averin-012-extract.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT
CHARON_ARGS=()
while IFS= read -r a; do CHARON_ARGS+=("$a"); done < <(python3 -c "
import json; m = json.load(open('$PROD/manifest.json'))['charon']
for o in m['options']: print(o)
for s in m['start_from']: print('--start-from'); print(s)
for s in m['opaque']: print('--opaque'); print(s)")
AENEAS_ARGS=()
while IFS= read -r a; do AENEAS_ARGS+=("$a"); done < <(python3 -c "
import json; [print(o) for o in json.load(open('$PROD/manifest.json'))['aeneas']['options']]")
(
  cd "$ROOT/core" &&
  bash "$W" env CARGO_HOME="${AVERIN_CHARON_CARGO_HOME:-$HOME/.cargo}" \
    CARGO_TARGET_DIR="${AVERIN_CHARON_TARGET_DIR:-$SCRATCH/target}" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
    charon cargo "${CHARON_ARGS[@]}" --dest-file "$SCRATCH/production.llbc" -- --lib
) >"$SCRATCH/charon.log" 2>&1 || { tail -20 "$SCRATCH/charon.log"; fail extract "charon failed (log above)"; }
bash "$W" aeneas "${AENEAS_ARGS[@]}" -dest "$SCRATCH/lean" "$SCRATCH/production.llbc" \
  >"$SCRATCH/aeneas.log" 2>&1 || { grep -iE "error|unsupported" "$SCRATCH/aeneas.log" | head -20; fail extract "aeneas failed (partial extraction is never accepted)"; }
for f in Types.lean Funs.lean; do
  grep -q "sorry" "$SCRATCH/lean/Extracted/$f" && fail extract "generated $f contains sorry"
done
python3 "$PROD/check-production.py" --glue "$SCRATCH/lean/Extracted" --no-stale || exit 1

if [ "$WRITE" = 1 ]; then
  # Each step must succeed: a partial copy followed by a hash update would record hashes of a
  # half-written extraction.
  cp "$SCRATCH/lean/Extracted/Types.lean" "$SCRATCH/lean/Extracted/Funs.lean" "$PROD/Extracted/" ||
    fail extract "could not write the regenerated Types.lean/Funs.lean"
  python3 "$PROD/check-production.py" --update-hashes || fail stale "could not update the source hashes"
else
  for f in Types.lean Funs.lean; do
    diff -u "$PROD/Extracted/$f" "$SCRATCH/lean/Extracted/$f" >"$SCRATCH/$f.diff" ||
      { head -40 "$SCRATCH/$f.diff"; fail stale "committed Extracted/$f differs from the extraction of the checked-out source (diff above); run with --write and re-prove"; }
  done
fi
python3 "$PROD/check-production.py" || exit 1

# ---- 3. build every proof (warnings are errors) and audit ---------------------------------------
(cd "$PROD" && bash "$W" lake build --wfail Extracted Refinement ProductionAudit) >"$SCRATCH/lake.log" 2>&1 ||
  { grep -E "error|warning" "$SCRATCH/lake.log" | head -40; fail proof "lake build failed on the regenerated extraction (log above)"; }
(cd "$PROD" && bash "$W" lake env lean scripts/Audit.lean) >"$SCRATCH/audit.log" 2>&1 ||
  { tail -20 "$SCRATCH/audit.log"; fail audit "axiom/escape-hatch audit failed"; }
grep -q "production axiom audit: OK" "$SCRATCH/audit.log" || fail audit "audit did not report OK"
grep "production axiom audit: OK" "$SCRATCH/audit.log"
echo "production refinement: OK"
