# Security model

averin's value is a **precise, defensible** claim. This page states the threat model, the invariants
it upholds, the trust boundaries, and — explicitly — what it does **not** do. The normative,
product-facing version lives in [`../coverage-limits.md`](../coverage-limits.md) and
[`../decisions/0001-who-is-the-evidence-for.md`](../decisions/0001-who-is-the-evidence-for.md); this
is the developer summary. **Do not overclaim past these bounds.**

## The claim, and its limit

A signed, hash-chained record proves **provenance and integrity**, not **reality**:

> a specific observed event record was sealed by a specific tenant-controlled key, has not been
> altered since sealing, is linked into a verifiable run history, and was accompanied by declared
> (and where a key was pinned, independently verified) authority evidence — all verifiable offline,
> anchored where configured to a third-party timestamp.

A signature proves *who sealed the bytes and that they're unchanged* — not that the bytes describe
what truly happened in the world.

### Three trust levels (used verbatim in product copy)

| Level | Claim | Today |
|-------|-------|-------|
| **1 — Record integrity** | sealed by this key, unchanged since, in a verifiable anchored history | **Yes.** Proven by `decision-core`, offline, across CLI/WASM/FFI. |
| **2 — Event observation** | this event was observed by us | **Partial — and stated per event** (each record carries `observed_via`). We see only what the proxy/SDK/OTel path captures. |
| **3 — Complete accountability** | this is *everything* the agent did | **Demonstrated over the brokered surface** (credential broker Tier-A + resource gateway Tier-B); full coverage still needs deployment attestations + a reduced broker TCB. Never claimed as "everything." |

## Invariants averin upholds

- **Append-only, tamper-evident.** A record's `content_hash` + `sig` make any post-seal byte change
  detectable; this cryptographic guarantee is the **primary** tamper-evidence and holds regardless of
  the storage backend. Editing a record breaks its hash; removing one from a session breaks the
  DAG/checkpoint frontier. The Postgres store *also* `REVOKE`s mutation on the history tables as
  defense-in-depth — but that `REVOKE` only bites under a non-owner, non-superuser role, and the
  default `docker compose` self-host connects as the **table-owning** role, where it is a no-op
  (owner bypass; see `deploy/docker-compose.yml` and `server/migrations/0001_init.sql`). For
  DB-enforced append-only, run the server under a dedicated least-privilege role granted only
  INSERT/SELECT (+ UPDATE on `display_seq`).
- **No DAG fork / no checkpoint fork.** The checkpoint chain rejects seq gaps, two checkpoints
  sharing a seq or prev (threat #2), a decreasing record_count, and a latest frontier that doesn't
  equal the actual heads.
- **No silent omission.** Every frontier head a checkpoint names must be present in the bundle
  (threat #1). A removed, already-anchored session is detectable via the external witness + anchor.
- **Retry-safe, no duplicate inflation.** Idempotency keys + content-hash collapse mean a retried
  record collapses rather than duplicating (threat #8).
- **Low-entropy fields are hidden, not stored.** When `input`/`output`/`rationale` are sent at the
  **top level** of a record, the server replaces each with a hiding commitment so the plaintext never
  enters the signed body (threat #6); the raw value lives in the content store and disclosure is
  checkable. **Bound:** this conversion (`commitLowEntropyFields`) covers only those three top-level
  fields. Content the SDKs and proxy place under `extensions.content_preview` is **not** committed —
  it is signed verbatim under `extensions` (the proxy regex-scrubs secrets first, but does not hide
  the body). To hide content, send it at the top level (or pre-commit it). See
  [INTEGRATION.md](INTEGRATION.md).
- **Authority is declared by default; elevation is verified.** `authority.source: caller_declared`
  is forgeable and presented as such. Elevation to `policy_engine_signed` / `human_signed` /
  `gateway_enforced` requires an `evidence_sig` that verifies under a pinned key; the preimage binds
  `project_id` (`averin.authority.v2`) so a verified triple cannot be replayed across tenants.
- **Role separation is enforced.** The signing, broker, resource, revocation, attestation, cosig,
  and taxonomy keys must be pairwise disjoint. The server fail-fasts (panics/`log.Fatal`s) on an
  overlap at startup; the offline verifier rejects an overlapping `opts.json` as a fatal config
  error. This prevents one authority signing across a role boundary (a broker self-attesting, a
  resource self-validating).
- **Consume-before-act.** A Tier-B use is recorded and its single-use/bounded capability is consumed
  in the ledger *before* the resource acts. (Durable only with the Postgres ledger — see below.)

## Authentication & authorization

- **Record authenticity** is cryptographic and offline: pin the signer's `ed25519pub:` key (logged
  at startup, or carried in the bundle's `keys`) and verify — no server trust needed.
- **API authn** (`server/internal/auth`): optional project-scoped API keys (`AVERIN_API_KEYS`). When
  configured, every `/v2/*` route requires a valid token for the `?project=`; comparison is
  constant-time over SHA-256 digests; it **fails closed** (unknown project / empty token ⇒ deny); a
  zero-key config refuses to start (no silent deny-all); tokens are never logged. The dev-only
  open-store mode is explicit and warned about.
- **API authz is Phase-1 limited.** This answers only "is this token valid for this project?" Full
  RBAC/SSO/scoped-and-expiring tokens/per-route permissions are Phase 2. With `AVERIN_API_KEYS` unset
  the app API is fully unauthenticated.

## Trust boundaries

- **The server is NOT in the cryptographic trust path.** Verification re-derives everything from the
  bundle + your pinned keys; a compromised/malicious server cannot make a forged bundle verify under
  keys it does not hold.
- **In self-host, the customer holds the signing key**, so the vendor cannot forge or alter records.
- **The resource is in the TCB for Tier-B.** Even the strongest `attested_complete_over_brokered_surface`
  capstone is always paired with `resource_trust: assumed_truthful`: it proves every resource-signed
  receipt over the brokered surface *if the resource labeled truthfully* — never "everything the agent
  did." This is irreducible (MF1).
- **External authorities hold their own private keys off-box.** averin only *verifies* their
  `evidence_sig` under the pinned public key; the policy engine / human-approval service stays out of
  averin's TCB.

## What averin deliberately does NOT do (honest non-goals / limits)

- **It does not prove reality** — only provenance + integrity of the *bytes it was given*.
- **It does not see uninstrumented actions** (threat #13). An action outside the proxy/SDK/OTel
  surface — e.g. a direct DB call the SDK didn't wrap — is a Level-2 gap, closed only by the
  credential broker / tool gateway or by honestly scoping the claim.
- **A single bundle cannot detect a suppressed parallel chain that was *never anchored*** (the
  malicious-customer / single-key case, #15). External RFC 3161 anchoring + a customer-controlled,
  object-locked **witness** copy *mitigate* this (a removed already-anchored session becomes
  detectable) — they do **not eliminate** it. Full coverage is Level 3.
- **Secret scrubbing is best-effort.** The proxy/SDK paths run captured I/O through regex redaction
  (`server/internal/scrub`, linear-time RE2, no ReDoS) before storing/hashing — but it **cannot
  catch every secret shape**. The primary protection is that self-host data never leaves customer
  infra; do not put secrets in prompts.
- **RFC 3161 verification is native-only.** The DER/CMS token parser ships under the `rfc3161`
  feature in the native CLI; the in-browser WASM verifier is built `--no-default-features` (RNG-free,
  lean) and reports an `rfc3161` anchor as **Unsupported — never a silent pass**. Production-anchored
  bundles are verified by the native/CLI verifier. The production Go anchoring round-trip against a
  real third-party TSA is the remaining open item.
- **Native/STS introspection relocates the TCB, it does not remove it.** For credentials whose
  effective scope the verifier can't recompute offline, the binding proves the resource *signed* its
  introspection transcript — the transcript's truthfulness is the same `resource_trust` boundary.
- **Compliance exports do not by themselves satisfy EU AI Act Annex IV / SOC 2.** They map sealed
  records to selected control-evidence fields with an explicit `gap_report`.
- **In-memory deployments lose evidence on restart** and are not serializable; use Postgres for any
  durability/integrity guarantee. The in-memory consume-before-act ledger reopens a single-use replay
  window on restart (warned about) — use the Postgres-backed ledger in production.

## Reporting

This is alpha software. Report security issues per the repository's policy; do not file
publicly-exploitable details in a public issue.
