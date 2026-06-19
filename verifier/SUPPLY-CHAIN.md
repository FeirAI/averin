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

## Two distinct properties — don't conflate them

1. **Load-time tamper detection (the fail-closed pin).** The build that PRODUCES the served `.wasm` also writes
   its digest into the served `index.html` (`build.sh` locally; `Dockerfile.web` for the deployment). So
   `served == pinned` **by construction** — it does NOT depend on the build being reproducible. A binary swapped
   *after* the build (a CDN/cache/MitM replacing only the `.wasm`) no longer matches the served pin → the loader
   refuses to run. This works on every machine.
2. **Source transparency (reproduce-from-source).** Proving the pinned digest corresponds to *auditable source*,
   not an opaque blob. This DOES require reproducing the build — but only in a **matching build environment**.

## Reproduce the digest from source

The toolchain is pinned in `rust-toolchain.toml` (exact `rustc` version + target). `build.sh` additionally
**remaps the three absolute path roots** rustc would embed in panic-location strings (workspace, cargo
registry, sysroot) to fixed labels — so the digest is identical across *directories* on the same OS/arch:

```
./verifier/build.sh           # builds, remaps paths, writes .sha256 + rewrites the WASM_SHA256 pin
```

> **Cross-machine reality:** `wasm32-unknown-unknown` codegen is **not** bit-identical across build *hosts* —
> the same pinned `rustc` on macOS-arm64 vs linux-amd64 yields different `.wasm` bytes (host-dependent codegen,
> not just paths; the remap removes only the path component). So the committed pin is a **dev-host reference**,
> and the **deployment self-pins what it builds** (it never trusts the committed pin). To verify source
> transparency, reproduce in the **same environment** as the published artifact — the canonical builder is the
> pinned Linux image:
> ```
> docker run --rm --platform linux/amd64 -v "$PWD":/src:ro rust:1.92-bookworm bash -c '
>   set -e; mkdir /w && tar -C /src --exclude=./target --exclude=./.git -cf - . | tar -C /w -xf -
>   cd /w/core && rustup target add wasm32-unknown-unknown
>   cargo build --release --locked --target wasm32-unknown-unknown --no-default-features
>   sha256sum /w/target/wasm32-unknown-unknown/release/feir_decision_core.wasm'
> ```
> and compare against the digest the deployment serves (shown in the verifier page). Bumping the toolchain
> changes the digest — regenerate in the same change.

## When you change the core

Any edit to `core/` changes the `.wasm`. Run `./verifier/build.sh` and commit the refreshed
`feir_decision_core.wasm`, `feir_decision_core.wasm.sha256`, and the rewritten `WASM_SHA256` in `index.html`
together — a stale pin makes the page refuse to load (fail-closed), which is the intended safety property, not
a silent downgrade.
