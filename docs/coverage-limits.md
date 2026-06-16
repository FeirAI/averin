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
- **No per-project authz yet (Phase-1 limit).** The app API (`/v2/sessions`, `/v2/dag`,
  `/v2/verify`, `/v2/export`) has **no authentication/authorization** — RBAC/SSO/SAML is explicitly
  Phase 2 (spec §3). Any caller who can reach the API can read any project's data. Deploy feir
  behind your own auth (or single-tenant) until the authz layer lands. (This does not affect the
  cryptographic guarantees — offline verification needs no server trust.)
- **Uninstrumented actions (#13).** See above — a Level-2 limit by construction.
- **Authority is *declared* by default.** `authority.source: caller_declared` is forgeable. Only
  `policy_engine_signed` / `human_signed` (with `evidence_sig` from the authority system) is
  *verified*. The UI must visibly distinguish "declared by agent" from "verified from policy
  engine." Never present declared authority as verified.
- **Authority signature is project-bound (v2), with a one-time pre-release cutover.** The authority
  `evidence_sig` preimage binds `project_id` (`feir.authority.v2`) so a verified triple cannot be replayed
  across tenants. This is a **hard cutover** from the pre-release `v1` (no `project_id`): the verifier
  accepts only v2. It is safe because feir has shipped no v1-signed records (nothing to migrate). **Forward
  policy:** authority evidence is append-only and cannot be re-signed in place, so any preimage change
  *after deployment* must verify the newest version first and fall back to older versions under an
  explicitly downgraded/legacy status — never a silent hard cutover that drops historical verification.
- **RFC 3161 wire format.** The DER/CMS `TimeStampToken` parser + verifier is implemented and
  feature-gated (`rfc3161`); it ships in the native verify CLI (built with the feature in CI) and is
  exercised end to end by the hermetic `test-anchor`/mini-TSA suite. It is **intentionally native-only**:
  the in-browser WASM verifier is built `--no-default-features` to stay lean and RNG-free (the P-256
  curve-arithmetic stack the RFC 3161 path needs transitively pulls `getrandom`, which has no
  `wasm32-unknown-unknown` backend), so a WASM verifier reports an `rfc3161` anchor as `Unsupported`
  — **never a silent pass** — and production-anchored bundles are verified by the native/CLI verifier.
  The remaining open item is the production Go anchoring round-trip against a real third-party TSA.
- **Best-effort secret scrubbing.** The proxy and SDK ingestion paths run captured I/O through
  regex-based credential/PII redaction (`server/internal/scrub`) before anything is stored or hashed.
  This is **best-effort defense in depth** — Go's RE2 regexes are linear-time (no ReDoS) but **cannot
  catch every secret shape**. The primary protection is that in self-host the data never leaves customer
  infra; customers should not put secrets in agent prompts. The redaction rules are not a guarantee
  against all credential or PII patterns.
- **Resource-introspection binding relocates the TCB, it does not remove it.** For native / token-exchange
  credentials (OAuth/STS/Vault) whose effective scope the verifier cannot recompute offline, the binding
  commits the resource's *signed introspection transcript* (its statement of the credential's effective
  scope). The verifier proves the resource **signed** that transcript — but the transcript's truthfulness
  is the same resource trust boundary as `resource_trust: assumed_truthful`. This moves trust from broker
  recomputation to the resource's signed statement; it does not eliminate the need to trust the resource.
- **Compliance exports** map sealed records to *selected* control-evidence fields with an explicit
  `gap_report`. They do **not** by themselves satisfy EU AI Act Annex IV / SOC 2. Field-level
  statutory mapping requires legal review.
