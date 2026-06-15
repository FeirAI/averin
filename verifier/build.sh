#!/usr/bin/env bash
# Build the standalone offline verifier: compile the core to wasm and copy it next to index.html.
# No bundler — the verifier is index.html + feir.js + feir_decision_core.wasm.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

( cd "$root/core" && cargo build --release --target wasm32-unknown-unknown --no-default-features )
cp "$root/target/wasm32-unknown-unknown/release/feir_decision_core.wasm" "$here/feir_decision_core.wasm"
echo "built $here/feir_decision_core.wasm ($(du -h "$here/feir_decision_core.wasm" | cut -f1))"
echo "serve with: (cd $here && python3 -m http.server 8088) then open http://localhost:8088"
