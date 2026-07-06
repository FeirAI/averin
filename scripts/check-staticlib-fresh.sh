#!/usr/bin/env bash
# Guard against a STALE cgo staticlib. The Go server links a prebuilt target/debug/libaverin_decision_core.a
# (server/internal/core/core.go #cgo LDFLAGS). If you edit core/ but forget to rebuild it, `go test` links the
# OLD core and passes GREEN against stale logic — silently hiding a just-introduced fix OR regression in the
# trust root. This script fails if the staticlib is missing or older than any core source input, so the only
# green path is one where the linked core matches the source.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
lib="$root/target/debug/libaverin_decision_core.a"

if [ ! -f "$lib" ]; then
  echo "stale-staticlib guard: $lib is MISSING — run: cargo build -p averin-decision-core" >&2
  exit 1
fi

# Newest mtime among the core's build inputs (sources, manifests, the workspace lock + toolchain pin).
newest="$(find "$root/core/src" "$root/core/Cargo.toml" "$root/Cargo.toml" "$root/Cargo.lock" \
  "$root/rust-toolchain.toml" -type f -newer "$lib" -print -quit 2>/dev/null || true)"

if [ -n "$newest" ]; then
  echo "stale-staticlib guard: the cgo staticlib is OLDER than core source ($newest)." >&2
  echo "  The Go tests would link a stale trust root. Rebuild it: cargo build -p averin-decision-core" >&2
  exit 1
fi

echo "stale-staticlib guard: OK (libaverin_decision_core.a is newer than all core inputs)"
