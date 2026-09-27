#!/usr/bin/env bash
# Axiom gate over the WHOLE Averin namespace, oracle glue included (not a hand-picked list): every declaration may depend
# only on propext / Classical.choice / Quot.sound. sorry and native_decide are axioms, so they fail
# here. Escape hatches that are not axioms are rejected twice:
#  * by attribute, in the audits (scripts/AxiomAudit.lean, scripts/VerdictAxiomAudit.lean): no declaration of
#    the Averin/Oracle modules is an `axiom` or `opaque` constant (which includes `partial def`), `@[extern]`
#    or `@[implemented_by]`, however the attribute was attached (`@[..]`, `attribute [..] x`, a list);
#  * textually, as defence in depth: `axiom`/`opaque` commands, `partial def`, `sorry`, `admit`,
#    `native_decide`, and the words `implemented_by`/`extern` anywhere outside a comment line.
# `--self-test` checks the textual scan's accepted and rejected forms.
set -euo pipefail
cd "$(dirname "$0")"
FORBIDDEN='^\s*(axiom|opaque)\b|\bpartial\s+def\b|\b(implemented_by|extern)\b|\bsorry\b|\badmit\b|native_decide'
COMMENT='^\S+:[0-9]+:\s*(--|/-|\*)'
scan() { grep -rnE "$FORBIDDEN" "$@" | grep -vE "$COMMENT"; }
if [ "${1:-}" = "--self-test" ]; then
  t="$(mktemp -d)"
  trap 'rm -rf "$t"' EXIT
  bad=('attribute [implemented_by f] X' 'attribute [simp, implemented_by f] X' '@[extern "c_f"] def f := 1'
       '@[inline, implemented_by g] def f := 1' 'axiom a : False' 'partial def f : Nat := f' 'theorem t : 1 = 1 := by sorry'
       'opaque o : Nat' 'attribute [extern "x"] X' '  local attribute [implemented_by g] f')
  ok=('-- implemented_by in a comment' 'def f := 1' 'theorem t : 1 = 1 := rfl' '/- extern in a block comment line')
  for s in "${bad[@]}"; do
    printf '%s\n' "$s" >"$t/x.lean"
    scan "$t" >/dev/null || { echo "check-axioms self-test: accepted $s" >&2; exit 1; }
  done
  for s in "${ok[@]}"; do
    printf '%s\n' "$s" >"$t/x.lean"
    if scan "$t" >/dev/null; then echo "check-axioms self-test: rejected $s" >&2; exit 1; fi
  done
  echo "check-axioms self-test: OK"
  exit 0
fi
if scan Averin Averin.lean Oracle; then
  echo "check-axioms: FAIL (forbidden token above)" >&2
  exit 1
fi
lake build Averin oracle verdict_oracle >/dev/null
lake env lean scripts/AxiomAudit.lean
lake env lean scripts/VerdictAxiomAudit.lean
