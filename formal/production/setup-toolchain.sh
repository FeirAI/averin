#!/usr/bin/env bash
# Build the pinned Charon/Aeneas/Lean toolchain for formal/run-production-refinement.sh into DIR and
# write DIR/with-aeneas.sh (the environment wrapper the run script uses).
#
#   bash formal/production/setup-toolchain.sh DIR
#
# Pins: formal/production/manifest.json; source tarball digests: plans/preflight/PROVENANCE.md.
# Needs curl, tar with zstd, make, a C toolchain, rustup and opam 2.x, or network access to fetch
# them. Every download is checked against a pinned sha256; opam packages are pinned to the versions
# the committed extraction was produced with (their transitive dependencies are resolved from the
# opam repository at install time, which is not pinned); Lean comes from the pinned release tarball
# (no elan, no install script). On developer machines run every network fetch through Socket Firewall
# (`sfw bash formal/production/setup-toolchain.sh DIR`), per the workspace supply-chain policy.
set -euo pipefail

DIR="${1:?usage: setup-toolchain.sh DIR}"
mkdir -p "$DIR/sources"
DIR="$(cd "$DIR" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
pin() { python3 -c "import json,sys;print(json.load(open('$HERE/manifest.json'))['toolchain'][sys.argv[1]])" "$1"; }
AENEAS="$(pin aeneas_commit)"
CHARON="$(pin charon_commit)"
NIGHTLY="$(pin charon_rust_toolchain)"
AENEAS_SHA=ad60d0d20eefd46773924a3f5fe96e60174c3b14bae7118f1192dc1a9b78b418
CHARON_SHA=76b6c982c00c34d9d1b7c1ba6a9f7ce5a7af5006320aec40d1e9ae3db0796ed7

fetch() { # url sha256 dest
  [ -f "$3" ] || curl -fsSL "$1" -o "$3"
  echo "$2  $3" | shasum -a 256 -c -
}
fetch "https://github.com/AeneasVerif/aeneas/archive/$AENEAS.tar.gz" "$AENEAS_SHA" "$DIR/sources/aeneas.tar.gz"
fetch "https://github.com/AeneasVerif/charon/archive/$CHARON.tar.gz" "$CHARON_SHA" "$DIR/sources/charon.tar.gz"
rm -rf "$DIR/sources/aeneas" "$DIR/sources/charon"
mkdir -p "$DIR/sources/aeneas" "$DIR/sources/charon"
tar -xzf "$DIR/sources/aeneas.tar.gz" -C "$DIR/sources/aeneas" --strip-components=1
tar -xzf "$DIR/sources/charon.tar.gz" -C "$DIR/sources/charon" --strip-components=1
grep -q "$CHARON" "$DIR/sources/aeneas/charon-pin" || { echo "aeneas charon-pin is not $CHARON" >&2; exit 1; }

# Charon (Rust, pinned nightly from its rust-toolchain file).
rustup toolchain install "$NIGHTLY" --profile minimal --component rustc-dev,llvm-tools,rust-src,miri
[ "$(RUSTUP_TOOLCHAIN="$NIGHTLY" rustc --version)" = "$(pin charon_rustc_version)" ] ||
  { echo "$NIGHTLY is not $(pin charon_rustc_version)" >&2; exit 1; }
(cd "$DIR/sources/charon/charon" && RUSTUP_TOOLCHAIN="$NIGHTLY" cargo build --release --locked)
mkdir -p "$DIR/sources/charon/bin"
cp "$DIR/sources/charon/charon/target/release/charon" "$DIR/sources/charon/charon/target/release/charon-driver" \
  "$DIR/sources/charon/bin/"
ln -sfn "$DIR/sources/charon" "$DIR/sources/aeneas/charon"

# Aeneas (OCaml 5.3.0, dependencies as in its README).
export OPAMROOT="$DIR/opam-root"
[ -d "$OPAMROOT" ] || opam init --bare --disable-sandboxing -n
opam switch list 2>/dev/null | grep -q 5.3.0 || opam switch create 5.3.0 -y
eval "$(opam env --switch 5.3.0 --set-switch)"
# Exact versions of the packages Aeneas' README lists, as installed for the committed extraction
# (plans/preflight/PROVENANCE.md; ocamlformat is not used by the build).
opam install -y calendar.3.0.0 core_unix.v0.17.1 domainslib.0.5.2 easy_logging.0.8.2 menhir.20260209 \
  ocamlformat.0.29.0 ocamlgraph.2.2.0 odoc.3.2.1 ppx_deriving.6.2.0 ppx_deriving_yojson.3.10.0 \
  progress.0.5.0 unionFind.20250818 visitors.20260520 yojson.3.0.0 zarith.1.14
(cd "$DIR/sources/aeneas" && make build-dev)

# Lean (the backend's lean-toolchain, v4.31.0) from the release tarball, sha256-checked (the GitHub
# release asset digests).
LEAN_TC="$(cat "$DIR/sources/aeneas/backends/lean/lean-toolchain")"
[ "$LEAN_TC" = "leanprover/lean4:v4.31.0" ] || { echo "aeneas lean-toolchain is $LEAN_TC, pinned v4.31.0" >&2; exit 1; }
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) LEAN_ASSET=lean-4.31.0-linux; LEAN_SHA=07a633cc8d9151cbc08825ea4cdda50d4b02a2c9cb852c0131b13046f49cad7f ;;
  Linux-aarch64) LEAN_ASSET=lean-4.31.0-linux_aarch64; LEAN_SHA=b1bf1d3c586b76cf4a86212a595d8b9edd99f438a41cce85d5780fa9347c811b ;;
  Darwin-arm64) LEAN_ASSET=lean-4.31.0-darwin_aarch64; LEAN_SHA=264105500c8abdf37b68ffe03390a783ed259807807222698da8dd92d6ce0a27 ;;
  *) echo "no pinned Lean 4.31.0 release digest for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
fetch "https://github.com/leanprover/lean4/releases/download/v4.31.0/$LEAN_ASSET.tar.zst" "$LEAN_SHA" \
  "$DIR/sources/$LEAN_ASSET.tar.zst"
rm -rf "$DIR/lean-4.31.0" && mkdir -p "$DIR/lean-4.31.0"
tar --use-compress-program=unzstd -xf "$DIR/sources/$LEAN_ASSET.tar.zst" -C "$DIR/lean-4.31.0" --strip-components=1
LEAN_BIN="$DIR/lean-4.31.0/bin"
"$LEAN_BIN/lean" --version | grep -q "version 4.31.0," || { echo "unexpected Lean version" >&2; exit 1; }

cat >"$DIR/with-aeneas.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export OPAMROOT="$DIR/opam-root"
export RUSTUP_TOOLCHAIN="$NIGHTLY"
export PATH="$LEAN_BIN:$DIR/sources/charon/bin:$DIR/sources/aeneas/bin:\$PATH"
eval "\$(opam env --switch 5.3.0 --set-switch --shell sh)"
exec "\$@"
EOF
chmod +x "$DIR/with-aeneas.sh"
echo "toolchain ready: AVERIN_AENEAS_TOOLS=$DIR"
