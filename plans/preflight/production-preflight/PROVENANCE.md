# Bounded production extraction preflight

Source checkout: `5e10548485241e50b03cf6ed92430386227b3198` in
`.worktrees/averin-trust-implementation`. This wrapper imports source files by
absolute `#[path]`; it contains no copied Averin implementation.

| Source | SHA256 |
|---|---|
| `core/src/canon.rs` | `59c03bfa0f397eed9fd62853f0e4bb1ddc69c1ce954c6dc7f995bcbcf0f54382` |
| `core/src/hashx.rs` | `155ad20b9baba444e7bc3a64eb6590151e9d6f3c366f30181c17b1556681f3d4` |

The wrapper pins production Cargo.lock versions of `sha2` 0.10.9 and
`unicode-normalization` 0.1.25, with their default features, on the pinned
Charon nightly `nightly-2026-09-17-aarch64-apple-darwin`.
