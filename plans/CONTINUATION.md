# Implementation continuation checkpoint

Updated 2026-09-28; evidence note corrected 2026-10-07. All twelve plans and the parser totality
track are implemented and integrated on the local branch `advisor/trust-final` (worktree
`.worktrees/averin-final`). Local runs reported every gate passing, including a full Kani mutation
run (48/48); those logs were in `/tmp` and are lost. CI never confirmed it: PR #1 was merged on a red
head, and every CI run on main was red as of 2026-10-07 (Kani and mutation jobs killed on the hosted
runner; PR #2 fixes the cause). Only CI runs count as evidence (`formal/README.md`, "Evidence of record"). Nothing is deployed. Use [README.md](README.md) for status and [EXECUTION.md](EXECUTION.md) for the evidence trail.

## Current state

- **Integration branch:** `advisor/trust-final`, head `d87d48f` (docs commits may follow). Base
  `e62cb81` (`advisor/parser-panic-freedom`: plans 001–010, 012 phases A/B, 011 through `92d615d`,
  parser totality), then hardening round 1 `07aaa30` (merge `5d3e44e`), 011 `9539e8c` (merge
  `ba70a48`), and the review fixes `ed8ca46`..`d87d48f`.
- **Contained branches:** `advisor/trust-combined` (`07aaa30`), `advisor/011-bounded-parser-proofs`
  (`9539e8c`), `advisor/parser-panic-freedom` (`e62cb81`).
- **Cross-plane producers:** Govder `advisor/003-authority-body-binding` `0a22220`, Vultrino
  `advisor/004-grant-pop-context` `85b386f`. Both are required by plans 003/004.
- **Open:**
  1. Docker images were never built (in-container crate/module fetches would bypass Socket
     Firewall). Decide a screened build path (for example vendored sources) before building them.
  2. feir-os (`deploy/compose/docker-compose.yml`, `deploy/k8s/overlays/dev/kustomization.yaml`)
     connects the Averin server as the `postgres` superuser to an empty database, which the server
     now refuses. It needs the owner/runtime split, `averin-migrate --init` and the runtime grants
     (see `deploy/postgres/` and `deploy/README.md`). Not edited here.

## Rerunning the gates

Use `CARGO_BUILD_JOBS=1 GOMAXPROCS=2 GOFLAGS=-p=1` on the shared host.

| Gate | Command | Notes |
|---|---|---|
| Rust | `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; `(cd core && cargo test --features test-tsa)` | |
| 32-bit | CI: `cargo test --target i686-unknown-linux-gnu` in `core/` | On this Mac: build with `--no-run` and a zig linker shim (`zig cc -target x86-linux-gnu.2.17`), then run the test binaries in `docker run --platform linux/386 debian:bookworm-slim` with the worktree mounted at the same path |
| Server | `make test-server` | rebuilds the rfc3161 staticlib first |
| Postgres | `make test-server-postgres`; `cd server && go test -race -count=1 ./internal/api/... ./internal/store/... ./internal/pgschema/... ./internal/resourceshim/...` | needs `AVERIN_TEST_DATABASE_URL` (task container `averin-trust-postgres`, 127.0.0.1:55432; `scratchpad/pg-env.sh` sets it without printing it) |
| Verifier | `make test-verifier` | rebuilds the WASM and rewrites the pins; commit them only from the reference environment |
| Web | `(cd web && bun run test && bun run build)` | install with `sfw bun install --frozen-lockfile` |
| Claims | `make check-claims` | textual check only |
| Lean model | `make formal-lean` | Lean 4.30.0 via elan |
| Refinement gate | `make formal-refinement` | |
| Production proofs | `bash formal/run-production-refinement.sh` | needs `.verification-tools/aeneas-557f7a` (found automatically) and `AVERIN_LAKE_PACKAGES=.verification-tools/aeneas-557f7a/smoke/proofs/.lake/packages` |
| Mutants | `SKIP_KANI=1 bash formal/check-mutants.sh` (diagnostic); `bash formal/check-mutants.sh` (full, with Kani) | about 75–85 min without Kani locally |
| Kani | `bash .verification-tools/kani-0.68/with-kani.sh bash formal/run-kani.sh [--extended]`; `run-kani-shards.sh FAMILY` | run under `formal/kani-watchdog.sh`; one solver at a time on this host |
| Kani checkers | `python3 formal/check-kani-shards.py [--self-test]`; `check-kani-domains.py`; `check-kani-success.py --self-test`; `gen-kani-string-cases.py --check`; `kani-string-slices.py --check` | no solver needed |
| Fuzz | `bash formal/run-fuzz.sh pr` | Bun 1.3.14 |
| TLC | `TLA2TOOLS_JAR=.verification-tools/tla/tla2tools-v1.7.4.jar bash formal/tla/run-tlc.sh` | 28 configs, about 6 min |

## Tool pins

- Rust 1.92.0 (`rust-toolchain.toml`, targets wasm32 and i686).
- Go 1.25.13, Bun 1.3.14, Postgres 16.
- Lean 4.30.0 (`formal/lean/lean-toolchain`) for the model.
- Production refinement (`formal/production/manifest.json`): Charon `6258597`, Aeneas `557f7a1`,
  Lean 4.31.0, mathlib `fabf563`, extraction rustc exactly `rustc 1.100.0-nightly (923c95cdf 2026-09-16)`
  (`nightly-2026-09-17`); `setup-toolchain.sh` pins source tarballs and the Lean release by sha256
  and opam packages by version.
- Kani 0.68.0 / CBMC 6.11 with bundled kissat 4.0.1 (`.verification-tools/kani-0.68`).
- TLC v1.7.4, sha256 `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
- GitHub Actions pinned by commit SHA in `.github/workflows/ci.yml`.

## Operational notes

- Dependency fetches go through Socket Firewall (`sfw ...`).
- Kani resume state (`target/kani-shards/`) is keyed by a digest that now includes `Cargo.lock`, both
  `Cargo.toml`, `rust-toolchain.toml`, the Kani version and every crate source. The recorded
  string tally (digest `fd4b0e77…`, definition as of `9539e8c`) lives in
  `.worktrees/averin-011/target/kani-shards/strings-*.state`.
- Disk headroom on the host has been 9–17 GB; prune Kani build directories (`KANI_PRUNE_BUILD=1`)
  and avoid pulling large images.
- Never borrow Rust build artifacts between worktrees; rebuild the staticlib before Go tests.
