#!/usr/bin/env bash
# Build the standalone offline verifier: compile the core to wasm and copy it next to index.html.
# No bundler — the verifier is index.html + feir.js + feir_decision_core.wasm.
#
# Supply chain: the .wasm IS the trust root. This script regenerates its SHA-256 digest, writes it to
# feir_decision_core.wasm.sha256, and rewrites the WASM_SHA256 pin in index.html so the in-browser load
# fails CLOSED on a substituted binary. To make the digest INDEPENDENTLY reproducible, build with the
# repo-pinned toolchain (rust-toolchain.toml) — see verifier/SUPPLY-CHAIN.md.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

# Reproducibility: remap the three absolute path roots rustc would otherwise embed in panic-location strings
# (the workspace, the cargo registry, and the toolchain sysroot) to FIXED labels, so two builds with the same
# toolchain on the same OS/arch from DIFFERENT directories produce the byte-identical digest. (This does NOT
# make it identical across OS/arch — wasm32 codegen still varies by build host; see SUPPLY-CHAIN.md. The
# DEPLOYMENT self-pins what it builds, so cross-host reproduction is a transparency property, not a load gate.)
sysroot="$(rustc --print sysroot)"
export RUSTFLAGS="--remap-path-prefix=$root=/feir --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$sysroot=/rust ${RUSTFLAGS:-}"
# --locked: build the EXACT dependency versions in Cargo.lock (no silent registry drift), a prerequisite
# for a reproducible digest.
( cd "$root/core" && cargo build --release --locked --target wasm32-unknown-unknown --no-default-features )
cp "$root/target/wasm32-unknown-unknown/release/feir_decision_core.wasm" "$here/feir_decision_core.wasm"

# Digest the trust root and publish it next to the binary (the auditor's out-of-band comparison value).
digest="$(shasum -a 256 "$here/feir_decision_core.wasm" | cut -d' ' -f1)"
printf 'sha256:%s  feir_decision_core.wasm\n' "$digest" > "$here/feir_decision_core.wasm.sha256"

# Keep the in-page pin in lockstep with the freshly built binary (fail-closed load).
# Matches: const WASM_SHA256 = "sha256:<64 hex>";
perl -0pi -e 's/(const WASM_SHA256 = "sha256:)[0-9a-f]{64}(";)/${1}'"$digest"'${2}/' "$here/index.html"

echo "built $here/feir_decision_core.wasm ($(du -h "$here/feir_decision_core.wasm" | cut -f1))"
echo "pinned sha256:$digest"
echo "toolchain: $(rustc --version) / $(cargo --version)"
echo "serve with: (cd $here && python3 -m http.server 8088) then open http://localhost:8088"
