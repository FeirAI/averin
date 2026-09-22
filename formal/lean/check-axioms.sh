#!/usr/bin/env bash
# Fail unless every headline theorem depends only on Lean's three standard axioms
# (propext, Classical.choice, Quot.sound): no sorry, no custom axiom, no native_decide.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp --suffix=.lean)"
trap 'rm -f "$tmp"' EXIT
{
  echo "import Averin"
  for t in Averin.Canon.ser_injective Averin.Utf8.utf8_inj Averin.Preimage.signed_families_disjoint \
           Averin.Preimage.signed_message_long Averin.Seal.record_seal_sound \
           Averin.Seal.checkpoint_seal_sound Averin.Seal.record_ne_checkpoint_hash \
           Averin.Seal.commitment_binding Averin.Dag.bundle_eq_closure Averin.Chain.unique_history; do
    echo "#print axioms $t"
  done
} > "$tmp"
sed -i 's/Averin.Utf8.utf8_inj/Averin.utf8_inj/' "$tmp"
out="$(lake env lean "$tmp")"
echo "$out"
if echo "$out" | grep -E "depends on axioms" | grep -vE "\[(propext|Classical\.choice|Quot\.sound)(, (propext|Classical\.choice|Quot\.sound))*\]$" | grep -q .; then
  echo "check-axioms: FAIL (non-standard axiom)" >&2; exit 1
fi
if echo "$out" | grep -qi "sorry"; then echo "check-axioms: FAIL (sorry)" >&2; exit 1; fi
echo "check-axioms: OK"
