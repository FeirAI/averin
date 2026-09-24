# Production proof preflight evidence

These notes preserve the toolchain compatibility results for plan 012. They are **not production proof evidence**. The actual serializer extraction remains partial and contains `sorry` and external assumptions.

- [Tool pins](PROVENANCE.md)
- [Production source pins](production-preflight/PROVENANCE.md)
- [Commands, failures and interpretation](production-preflight/RESULTS.md)

The notes were copied from `.verification-tools/aeneas-557f7a/` in the umbrella workspace. Relative command paths in the copied results refer to that original tool directory, not this documentation directory. Executables, source downloads, generated LLBC/Lean, mathlib caches, smoke project and raw logs remain in that local directory and are not included in Git. The forwarding wrapper imports the actual production files; a new machine must reconstruct it and the pinned isolated toolchain before rerunning the documented commands.

Kani 011 evidence and unresolved proof families are documented in `../CONTINUATION.md`, `../EXECUTION.md` and the separate parser checkpoint's formal documentation. Do not count a tool installation, ordinary unit tests or a timed-out solver as discharge of a production proof obligation.
