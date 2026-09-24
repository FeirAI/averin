# Isolated Aeneas/Charon verification tools

All network acquisitions were run under Socket Firewall (`sfw`). These tools
live outside the Averin repositories.

| Artifact | Pin | SHA256 of downloaded artifact |
|---|---|---|
| Aeneas source tarball | `557f7a15f3b75e18ddae224fc65db0807b70acdf` | `ad60d0d20eefd46773924a3f5fe96e60174c3b14bae7118f1192dc1a9b78b418` |
| Charon source tarball | `62585970fc75f61d83c7898ff8dfdd7edaa3c073` (`aeneas/charon-pin`) | `76b6c982c00c34d9d1b7c1ba6a9f7ce5a7af5006320aec40d1e9ae3db0796ed7` |
| Lean 4.31.0 arm64 macOS | `leanprover/lean4:v4.31.0` (`aeneas/backends/lean/lean-toolchain`) | `264105500c8abdf37b68ffe03390a783ed259807807222698da8dd92d6ce0a27` (GitHub release digest) |
| opam arm64 macOS | `2.5.2` | `407e53416cfb49b41ce80e6d3c67a3df08df7f5028f407311f457f4e2a19004b` (GitHub release digest) |
| pkgconf source from official distfiles | `2.5.1` | `cd05c9589b9f86ecf044c10a2269822bc9eb001eced2582cfffd658b0a50c243` |
| Charon Rust toolchain | `nightly-2026-09-17-aarch64-apple-darwin` (`charon/charon/rust-toolchain`) | rustup verifies component manifests and checksums |

The Aeneas Lean backend has nine dependencies pinned by its
`backends/lean/lake-manifest.json`, including mathlib4 commit
`fabf563a7c95a166b8d7b6efca11c8b4dc9d911f`.
