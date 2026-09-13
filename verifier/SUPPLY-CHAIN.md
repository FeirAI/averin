# Verifier supply chain — pinning the trust root

The browser verifier is three files: `index.html`, `averin.js`, and `averin_decision_core.wasm`. The **`.wasm`
is the entire trust root** — it is the Rust integrity core that decides whether a bundle verifies. If an
attacker can serve you a *different* `.wasm`, it can report `ok:true` over a forged, tampered, or over-claimed
bundle. That is a fail-open one level above every check the core makes. `index.html` and `averin.js` are small
enough to read in full; the `.wasm` is not, so it is pinned by digest instead.

## Source-only checkout

The tracked tree contains `index.html`, `averin.js` and
`averin_decision_core.wasm.sha256`, but not `averin_decision_core.wasm`.
The WASM binary is ignored by Git and must be built locally before using the
browser verifier. `./verifier/build.sh` builds and copies the binary, then
rewrites both the tracked `.wasm.sha256` file and the `WASM_SHA256` value in
`index.html` to match the local bytes. Those tracked files may therefore differ
from the checkout after a build; matching a freshly written local pin is not
independent verification of the committed reference pin.

The script requires the pinned Rust toolchain and target plus build utilities;
missing toolchain/dependency inputs may require acquisition. This source-only
alpha provides no Docker image. Both `deploy/Dockerfile.server` and
`deploy/Dockerfile.web` remain as source recipes, not certified build paths.

## What is pinned, and what that defends against

- The committed `averin_decision_core.wasm.sha256` records a dev-host reference
  digest. A local build rewrites it to match the binary that build produced;
  the source-only alpha does not supply that binary.
- `index.html` embeds the same digest as `WASM_SHA256` and passes it to `initAverin(..., { expectedSha256 })`.
  The loader digests the fetched bytes and **refuses to instantiate on a mismatch** (fail-closed: the
  *Verify* button stays disabled). The matching digest is shown in the status line for at-a-glance confirmation.

This defends against a **partial substitution**: a CDN, cache, proxy, or MitM that swaps *only* the binary
while serving the genuine, auditable `index.html` + `averin.js`. The swap is detected and the verifier will not
run.

It does **not**, by itself, defend against an attacker who controls the whole origin and rewrites
`index.html` (they can change the pinned constant too). The defense there is **out-of-band verification**:
obtain the expected digest from a channel you trust (this repository / a signed release), and confirm the
`WASM_SHA256` you were served — shown in the page — equals it. Rebuilding from
source can help establish correspondence to an independently trusted artifact
when the producing environment and inputs are recorded and matched, and its
bytes are actually compared. A newly self-generated pin alone is not that check.

## Two distinct properties — don't conflate them

1. **Load-time tamper detection (the fail-closed pin).** By design, `build.sh`
   writes a binary and a matching pin in `index.html`; `Dockerfile.web` is also
   retained as a deployment recipe, not a certified build path. The loader's
   pin check is intended to reject a later binary-only substitution when the
   genuine page and loader are retained. Self-pinning is not independent
   source-to-binary verification and makes no all-machines guarantee.
2. **Source transparency (reproduce-from-source).** Proving the pinned digest corresponds to *auditable source*,
   not an opaque blob. This DOES require reproducing the build — but only in a **matching build environment**.

## Local build and path remapping

The toolchain is pinned in `rust-toolchain.toml`. `build.sh` remaps workspace,
cargo-registry and sysroot paths that rustc could embed. Reducing build-directory
differences is the design goal, not a guarantee of identical bytes for every
host, directory or build input. Record the reference environment when comparing
against a separately trusted digest.

```
./verifier/build.sh           # builds, remaps paths, writes .sha256 + rewrites the WASM_SHA256 pin
```

> **Reference pin and build environment:** the committed pin is a dev-host
> reference, not a cross-host reproducibility guarantee. A local build writes
> its own pin. To investigate source correspondence for an independently
> obtained binary, preserve that binary and its trusted expected digest and
> record the producing toolchain, host and build inputs before comparing.
> A rebuilt binary matching its newly generated pin does not establish that
> it matches the independently obtained binary or the committed reference.
> The retained `Dockerfile.web` recipe describes a deployment build, but its
> existence does not establish successful reproduction or an approved image.
> Toolchain changes require a reviewed decision on the reference environment
> and regenerated tracked pins; do not silently substitute a new reference.

## When you change the core

When core or build inputs change, regenerate the verifier in the reviewed
reference environment and inspect the resulting binary and both tracked pins.
`./verifier/build.sh` rewrites `averin_decision_core.wasm.sha256` and the
`WASM_SHA256` value in `index.html`. Keep those two tracked references consistent
in any reviewed pin update; do not force-add the ignored `.wasm` binary to this
source-only distribution. A load-time binary/pin mismatch is meant to fail
closed, not to be bypassed by disabling the pin. A reference-pin update and a
consumer's local self-pinned build are different operations.
