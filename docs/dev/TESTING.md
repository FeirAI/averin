# Testing & development

averin's acceptance gates are the **golden vectors** (`spec/golden-vectors/`) and the **adversarial
fixtures** — the Rust core, the WASM verifier, and the cgo FFI must agree byte-for-byte (any
divergence is verifier skew, threat #10). The `Makefile` is the canonical local workflow; CI
(`.github/workflows/ci.yml`) mirrors it.

## The staticlib footgun (read this first)

`go test` in `server/` links a **prebuilt** Rust staticlib
(`server/internal/core` → `target/debug/libaverin_decision_core.a`). If you edit `core/` but forget to
rebuild it, the Go tests pass against a **stale trust root**. Always rebuild the staticlib before
running the Go suite — the `Makefile` does this for you:

```bash
make check-staticlib    # fails if the .a is older than core/ source
```

## Run everything

```bash
make test        # = test-core + test-server + test-verifier
```

## Run a suite individually

```bash
# Rust core: golden vectors + adversarial fixtures (the acceptance gate).
make test-core            # = cargo test --workspace
cargo test --features test-tsa   # also exercises real RFC 3161 / mini-TSA token verify

# Go server: rebuilds the staticlib FIRST, then go vet + go test.
make test-server          # = cargo build -p averin-decision-core && (cd server && go vet ./... && go test ./...)

# Offline verifier (browser trust-root tests).
make test-verifier        # = (cd verifier && bun test)
```

### Postgres store + ledger tests

The store-parity / append-only / consume-before-act-ledger tests need a real Postgres and are
**skipped** unless you point them at one:

```bash
AVERIN_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  go test -count=1 ./internal/store/... ./internal/pgledger/...
```

CI runs these against Postgres 16 under a non-owner least-privilege role (to prove the append-only
`REVOKE` actually bites).

### SDKs

```bash
cd sdk/python && python -m pytest          # Python SDK
cd sdk/typescript && bun test              # TypeScript SDK
```

## Conformance / cross-target consistency

The same Rust core is compiled to three targets; the suites that keep them honest:

- **`cargo test`** — golden vectors + the adversarial suite (`core/tests/adversarial.rs`, ~250
  cases) on native (64-bit); `cargo test --workspace` runs ~310 tests across the core crates.
- **`cargo test --target i686-unknown-linux-gnu`** — the same suite on 32-bit (`usize == u32`), the
  truncation gate standing in for `wasm32` (needs `gcc-multilib`).
- **`./verifier/build.sh` + `cd verifier && bun test`** — builds the WASM (RNG-free, no
  wasm-bindgen, the *same C ABI* as the cgo staticlib) and runs the trust-root tests
  (NUL-truncation, supply-chain pin, accountability). See `verifier/SUPPLY-CHAIN.md`.

The toolchain is pinned in `rust-toolchain.toml` (rustc **1.92.0** + the `wasm32` / `i686` targets +
`rustfmt`/`clippy`) precisely so the published WASM digest and the cgo staticlib are byte-for-byte
reproducible — bump the pin deliberately and regenerate the verifier's pinned digest in the same
commit.

## Lint & supply chain

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
make deny           # cargo-deny: RustSec advisories + licenses + sources + bans (deny.toml)
make vuln           # govulncheck over the Go module (cgo needs the staticlib built first)
make supply-chain   # = deny + vuln
```

## Four-plane end-to-end (authoritative build/run example)

The sibling repo's e2e harness (`govder/e2e`, build tag `e2e`) builds and runs averin-server exactly as
a real deployment would and is the authoritative reference for the build/config/run commands:

- builds the Rust staticlib first (`cargo build -p averin-decision-core`), then
  `go build -o averin-server ./cmd/averin-server`;
- runs it in-memory + unauthenticated with `AVERIN_SIGNING_SEED`, `AVERIN_ADDR`,
  `AVERIN_POLICY_ENGINE_PUBKEY` + `AVERIN_HUMAN_SIGNED_PUBKEY` (pinning external authority keys), and
  `AVERIN_WITNESS_DIR`;
- drives `POST /v2/records`, `GET /v2/verify`, `POST /v2/checkpoints`, and
  `GET /v2/export?record_kind=…` against the live process.

It is not part of averin's own test suite (it lives in the OS repo and is gated behind the `e2e` build
tag), but it is a useful, real, end-to-end smoke of the API.

## Contributing

- Every change to `core/` must keep the golden vectors green and the three targets byte-identical —
  add a golden/adversarial fixture for any new behavior. Codex/adversarial review of each commit is
  the project norm.
- Run `make test` (and `make supply-chain` for dependency changes) before sending a change. Keep
  `cargo fmt`/`clippy` clean — CI enforces both under the pinned toolchain.
- Package installs go through your supply-chain firewall per the repo's policy; respect the pinned
  toolchain and the `deny.toml` allowlists.
- The design *why* lives in `docs/decisions/` (ADRs) and `spec/`; these `docs/dev/` pages describe
  the shipped implementation. If you change behavior, update both the relevant ADR/spec and these
  docs, and verify the spec still matches the code.
