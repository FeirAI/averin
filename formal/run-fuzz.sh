#!/usr/bin/env bash
# Deterministic RCP campaign; rust-toolchain.toml, Cargo.lock and Bun 1.3.14 pin tools.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-pr}"
case "$mode" in
  pr) cases=500 ;;
  scheduled) cases=5000 ;;
  *) echo "usage: $0 [pr|scheduled]" >&2; exit 2 ;;
esac
seed="${FUZZ_SEED:-20260923}"
if [[ "$(bun --version)" != "1.3.14" ]]; then
  echo "Bun 1.3.14 required for the pinned WASM replay" >&2
  exit 2
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for run in 1 2; do
  FUZZ_SEED="$seed" FUZZ_CASES="$cases" FUZZ_OUTPUT="$tmp/corpus-$run.tsv" \
    cargo test --locked -p averin-decision-core --test rcp_fuzz -- --nocapture
done
cmp "$tmp/corpus-1.tsv" "$tmp/corpus-2.tsv"
shasum -a 256 "$tmp/corpus-1.tsv"

# Build the same C ABI core for WASM without touching the verifier's tracked supply-chain pin.
cargo build --locked --release -p averin-decision-core --target wasm32-unknown-unknown --no-default-features --lib
bun formal/fuzz/check-wasm.js "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/averin_decision_core.wasm" "$tmp/corpus-1.tsv"
