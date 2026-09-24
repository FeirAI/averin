#!/usr/bin/env bash
# Build the pinned Charon/Aeneas/Lean toolchain for formal/run-production-refinement.sh into DIR and
# write DIR/with-aeneas.sh (the environment wrapper the run script uses).
#
#   bash formal/production/setup-toolchain.sh DIR
#
# Pins: formal/production/manifest.json; source tarball digests: plans/preflight/PROVENANCE.md.
# Needs curl, git-free tar, make, a C toolchain, rustup, opam (OCaml 5.3.0) and elan or network access
# to fetch them. On developer machines run every network fetch through Socket Firewall
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
opam install -y calendar core_unix domainslib easy_logging menhir ocamlformat.0.27.0 ocamlgraph odoc \
  ppx_deriving ppx_deriving_yojson progress unionFind visitors yojson zarith
(cd "$DIR/sources/aeneas" && make build-dev)

# Lean (the backend's lean-toolchain, v4.31.0) through elan.
command -v elan >/dev/null || { curl -fsSL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none; }
LEAN_TC="$(cat "$DIR/sources/aeneas/backends/lean/lean-toolchain")"
"${HOME}/.elan/bin/elan" toolchain install "$LEAN_TC"
LEAN_BIN="$("${HOME}/.elan/bin/elan" which --toolchain "$LEAN_TC" lean | xargs dirname)"

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
