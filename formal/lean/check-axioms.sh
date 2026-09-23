#!/usr/bin/env bash
# Axiom gate over the WHOLE Averin namespace, oracle glue included (not a hand-picked list): every declaration may depend
# only on propext / Classical.choice / Quot.sound. sorry and native_decide are axioms, so they fail
# here. Escape hatches that are not axioms (implemented_by / extern / an `axiom` keyword even if
# unused, `partial def`) are rejected textually, in the proofs AND the oracle.
set -euo pipefail
cd "$(dirname "$0")"
if grep -rnE '^\s*(axiom|opaque)\b|\bpartial\s+def\b|@\[(implemented_by|extern)|\bsorry\b|\badmit\b|native_decide' \
     Averin Averin.lean Oracle | grep -vE '^\S+:[0-9]+:\s*(--|/-|\*)'; then
  echo "check-axioms: FAIL (forbidden token above)" >&2
  exit 1
fi
lake build Averin oracle >/dev/null
lake env lean scripts/AxiomAudit.lean
