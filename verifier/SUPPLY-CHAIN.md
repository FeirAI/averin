# Verifier supply chain — pinning the trust root

The browser verifier is three files: `index.html`, `feir.js`, and `feir_decision_core.wasm`. The **`.wasm`
is the entire trust root** — it is the Rust integrity core that decides whether a bundle verifies. If an
attacker can serve you a *different* `.wasm`, it can report `ok:true` over a forged, tampered, or over-claimed
bundle. That is a fail-open one level above every check the core makes. `index.html` and `feir.js` are small
enough to read in full; the `.wasm` is not, so it is pinned by digest instead.

## What is pinned, and what that defends against

- `feir_decision_core.wasm.sha256` records the SHA-256 of the published binary.
- `index.html` embeds the same digest as `WASM_SHA256` and passes it to `initFeir(..., { expectedSha256 })`.
  The loader digests the fetched bytes and **refuses to instantiate on a mismatch** (fail-closed: the
  *Verify* button stays disabled). The matching digest is shown in the status line for at-a-glance confirmation.

This defends against a **partial substitution**: a CDN, cache, proxy, or MitM that swaps *only* the binary
while serving the genuine, auditable `index.html` + `feir.js`. The swap is detected and the verifier will not
run.

It does **not**, by itself, defend against an attacker who controls the whole origin and rewrites
`index.html` (they can change the pinned constant too). The defense there is **out-of-band verification**:
obtain the expected digest from a channel you trust (this repository / a signed release), and confirm the
`WASM_SHA256` you were served — shown in the page — equals it. Reproducing the build from source (below)
closes the loop: it proves the pinned digest corresponds to auditable source, not an opaque blob.

## Reproduce the digest from source

The toolchain is pinned in `rust-toolchain.toml` (exact `rustc` version + `wasm32-unknown-unknown` target),
because even a patch-level compiler bump changes codegen and therefore the digest. With that pin, the build is
deterministic:

```
./verifier/build.sh
# or, by hand:
cd core && cargo build --release --locked --target wasm32-unknown-unknown --no-default-features
shasum -a 256 ../target/wasm32-unknown-unknown/release/feir_decision_core.wasm
```

`build.sh` recomputes the digest, writes `feir_decision_core.wasm.sha256`, and rewrites the `WASM_SHA256` pin
in `index.html` so the three never drift apart. Compare the printed `sha256:…` against the value in this repo;
they must be identical. (`--locked` forbids silent dependency drift via `Cargo.lock`.)

> Bit-for-bit reproduction across machines requires the same pinned toolchain and target. A different `rustc`
> patch version, host OS, or LLVM can produce a functionally identical core with a different digest. When you
> bump the toolchain, regenerate and commit the new digest in the same change.

## When you change the core

Any edit to `core/` changes the `.wasm`. Run `./verifier/build.sh` and commit the refreshed
`feir_decision_core.wasm`, `feir_decision_core.wasm.sha256`, and the rewritten `WASM_SHA256` in `index.html`
together — a stale pin makes the page refuse to load (fail-closed), which is the intended safety property, not
a silent downgrade.
