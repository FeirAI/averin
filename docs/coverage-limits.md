# Coverage limits — what feir proves, and what it does not

This document is **normative for product copy, UI, and docs** (spec §0, §14.9). The honest claim
is narrow on purpose. State it; never imply more.

## The claim we make

> We prove that a specific observed event record was **sealed by a specific tenant-controlled
> key**, **has not been altered** since sealing, is **linked into a verifiable run history**, and
> was **accompanied by declared (and where available, independently verified) authority
> evidence** — and that you can verify all of this **offline**, anchored to a third-party
> timestamp.

That is *provenance + integrity*, not *reality*. A signature proves who sealed the bytes and that
they're unchanged — not that the bytes describe what truly happened in the world.

## The three trust levels

| Level | Claim | feir today |
|-------|-------|------------|
| **1 — Record integrity** | "This record was sealed by this key and hasn't changed since, and sits in a verifiable, externally-anchored history." | **Yes.** Proven by `decision-core` (canonicalize → commit → hash → sign → DAG-link → checkpoint → anchor → verify), offline, across CLI/WASM/FFI. |
| **2 — Event observation** | "This event was observed by us." | **Partial — and we say so per event.** Every record carries `observed_via` (`proxy`/`sdk`/`otel`). We see *only* what those paths capture. |
| **3 — Complete action accountability** | "This is everything the agent did, and nothing else happened." | **Not yet.** Requires a chokepoint (credential broker / tool gateway / egress control). The schema reserves room for it; we do not claim it. |

## What each ingestion path sees (Level-2 honesty)

| Path | Captures | Does NOT capture |
|------|----------|------------------|
| OpenAI-compatible proxy | LLM request/response I/O, streaming | tool execution, DB/SaaS/shell/file/credential actions, rationale, authority |
| OTel / OpenInference | whatever the team instruments | whatever they don't |
| SDK `record()` | tool calls, rationale, authority block | anything the developer doesn't wrap; trusts caller honesty |

**The hard truth:** none of these sees an action the agent takes *outside* them — e.g. a direct DB
call the SDK didn't wrap (threat #13). That is a Level-3 gap, closed only by the credential broker
or by honestly scoping the claim. Marketing must not imply otherwise.

## What the verifier detects today (tested)

Omitted session (#1), forked history (#2), backdated checkpoints (#3), tampered records,
hash-dictionary on low-entropy fields (#6), retry duplicates (#8), key compromise with the
anchored-before rule (#9), and cross-implementation verifier skew (#10, via golden vectors across
CLI/WASM/FFI). Out-of-band key and TSA pinning gate authenticity (#4 partial).

## Stated limits (do not hide these)

- **Malicious customer / single-key self-host (#15).** A customer who holds the only signing key
  *and* controls checkpointing can fabricate a self-consistent clean trail. External anchoring
  (RFC 3161 + an object-locked, customer-controlled **witness** copy) makes a *removed, already-
  anchored* session detectable, and out-of-band key/TSA pinning lets a third party refuse the
  customer's self-asserted keys. But **suppressing a parallel chain that was never anchored is not
  detectable from a single bundle** — that needs the witness store, and ultimately Level 3.
- **Uninstrumented actions (#13).** See above — a Level-2 limit by construction.
- **Authority is *declared* by default.** `authority.source: caller_declared` is forgeable. Only
  `policy_engine_signed` / `human_signed` (with `evidence_sig` from the authority system) is
  *verified*. The UI must visibly distinguish "declared by agent" from "verified from policy
  engine." Never present declared authority as verified.
- **RFC 3161 wire format** is being finalized (the Go anchoring job + a feature-gated DER/CMS
  parser). The detection *logic* is proven today via the hermetic `test-anchor` scheme; the
  production trust anchor is a real third-party TSA.
- **Compliance exports** map sealed records to *selected* control-evidence fields with an explicit
  `gap_report`. They do **not** by themselves satisfy EU AI Act Annex IV / SOC 2. Field-level
  statutory mapping requires legal review.
