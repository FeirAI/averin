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
  checkable. The durable content store (`AVERIN_CONTENT_DIR`) additionally encrypts the raw value
  **at rest** (AES-256-GCM, per-tenant key) and retention-purges it after
  `AVERIN_RAW_RETENTION_DAYS`, after which the record still verifies from its commitment. The
  reference the signed record exports (`extensions.feir_evidence.payloads[field]`) is the hiding
  **commitment**, never a plain digest — an unsalted digest of a low-entropy value in the
  always-exported body would be dictionary-reversible, undoing exactly what the commitment hides.
  **Bound:** this conversion (`commitLowEntropyFields`) covers only those three top-level
  fields. Content the SDKs and proxy place under `extensions.content_preview` is **not** committed —
  it is signed verbatim under `extensions` (the proxy regex-scrubs secrets first and hard-truncates
  each side to a bounded length, but does not hide or erase the body). To hide content, send it at the
  top level (or pre-commit it). This has a retention/erasure consequence — see
  *Data retention & erasure* below — and [INTEGRATION.md](INTEGRATION.md).
- **Authority is declared by default; elevation is verified.** `authority.source: caller_declared`
  is forgeable and presented as such. Elevation to `policy_engine_signed` / `human_signed` /
  `delegate_signed` / `gateway_enforced` requires an `evidence_sig` that verifies under a pinned key;
  the preimage binds `project_id` (`averin.authority.v2`) so a verified triple cannot be replayed
  across tenants.
- **A claimed elevation that cannot be verified fails CLOSED (default).** Authority keys are pinned per
  `(project, source)`; a record claiming an elevated source whose evidence does not verify under that
  project's pinned key — or whose source is unpinned for that project — is **rejected** at ingest
  (retryable `500`), never sealed downgraded to the forgeable `caller_declared`.
  `AVERIN_REQUIRE_PINNED_AUTHORITY=0` is an explicit, logged opt-out that restores the old silent
  downgrade. NOTE the `project_id` binding in the preimage stops a signed triple being **copied** across
  projects; it is the per-project **pin** that stops one tenant's key **minting** valid authority in
  another tenant's project.
- **Role separation is enforced.** The signing, broker, resource, revocation, attestation, cosig,
  and taxonomy keys must be pairwise disjoint. The server fail-fasts (panics/`log.Fatal`s) on an
  overlap at startup; the offline verifier rejects an overlapping `opts.json` as a fatal config
  error. This prevents one authority signing across a role boundary (a broker self-attesting, a
  resource self-validating).
- **Brokered grant requests bind the tenant and full effective request.** New online issuance uses
  the [v2 grant PoP](../../spec/grant-pop-v2.md): the agent signs the authenticated project, resolved
  idempotency key, session, scope and authorization context, TTL, and a bounded issue/expiry window.
  A committed exact retry may read the original grant after that window, but cannot mint again.
  The signed capability carries `project_id`; the resource compares it to its authenticated route
  project before revocation or replay-ledger access. Historical capabilities without that signed
  claim are denied online at the coordinated cutoff.
- **Consume-before-act.** A Tier-B use is recorded and its single-use/bounded capability is consumed
  in the ledger *before* the resource acts. (Durable only with the Postgres ledger — see below.)
  New uses verify the broker signature, signed project and sender PoP before raw
  params reach the content store. The same checks run again in the project
  transaction. Revocation, replay or expiry detected after preflight can leave
  only an unreferenced content blob subject to the configured retention purge.

## Machine-checked evidence for these invariants

[`formal/`](../../formal/README.md) proves the load-bearing parts of the list above. Lean covers:

- the seal: a body that verifies is exactly a sealed body, unless SHA-256 has a collision;
- canonical-JSON injectivity;
- domain separation of every message a signing key signs and every tagged or verifier-recomputed
  preimage (untagged server-local digests are listed as out of scope in `Catalogue.lean`);
- commitment binding;
- no omission and no injection: a verified bundle is exactly the signed closure of the latest
  frontier;
- checkpoint-chain uniqueness.

Kani checks the real encoders in CI (base64url alphabet, `sha256:<hex>` digests, LP framing,
UTF-16 key order). The parser-level harnesses exist in an extended set that does not fit a CI
runner and is not claimed as verified. TLA+ covers the gapless grant log and the
consume-before-act ledger. The same README lists what is *not* yet proved, including the verifier
verdict logic and authority-evidence binding.

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
- Without `AVERIN_API_KEYS` set, the API is unauthenticated, so keep it on loopback.

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
- **RFC 3161 verification is native-only.** The DER/CMS token parser supports the ECDSA
  P-256/SHA-256 and P-384/SHA-512 TSA profiles and ships under the `rfc3161`
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
- **Revocation and two-phase pending grants use local request caches.** In Postgres mode they persist
  and rehydrate at boot, but a live replica does not automatically see another replica's revoke or
  pending prepare. Route each project's requests to one writer; see [LIMITATIONS.md](LIMITATIONS.md).

## Data retention & erasure (append-only — no in-store deletion)

averin's record store is **append-only by design** — its integrity invariant. The Postgres migration
`REVOKE`s `UPDATE`/`DELETE`/`TRUNCATE` (enforced under a least-privilege role), and verification
re-derives the hash-chained DAG over the **closed set** of records, so a record cannot be edited or
deleted after sealing without breaking the very chain the product exists to prove. This has a hard,
deliberate consequence you must design around before recording personal data:

- **Sealed record bodies are permanently un-erasable.** There is **no in-store remedy for a GDPR
  Art. 17 (right to erasure) / CCPA deletion request** against a sealed record. The only remedy is
  physical: **cryptographically shred the whole store** (destroy the backing volume/DB) or, for the raw
  low-entropy plaintext, let the content-store retention purge run (below). averin does not, and by
  construction cannot, selectively delete one record.
- **The commitment path IS the erasure path for `input`/`output`/`rationale`.** When these are sent at
  the **top level**, only a hiding **commitment** enters the signed body; the raw value lives in the
  content store, is encrypted at rest, and is **retention-purged** after `AVERIN_RAW_RETENTION_DAYS`
  (after which the record still verifies from its commitment). This is the closest thing to erasure
  averin offers — and it works **only** for top-level committed fields.
- **`extensions.content_preview` (the flagship proxy/SDK path) is the un-erasable case.** Prompt/
  completion bodies the OpenAI-compatible proxy and the SDKs place under `extensions.content_preview`
  are signed **verbatim** — **not** committed, **not** in the encrypted content store, and **not**
  covered by the `AVERIN_RAW_RETENTION_DAYS` purge. They are therefore **permanent, always-exported,
  and un-erasable**. The proxy regex-scrubs secrets and **hard-truncates** each preview side to a
  bounded length (`maxPreview`, 16 KiB) so a large body cannot bloat the store without bound, but
  truncation is a size cap, **not** erasure or hiding. **To keep personal/regulated content erasable,
  do not rely on `content_preview` — send the content at the top level (or pre-commit it) so it lives
  in the purgeable, encrypted content store.** Full commitment-hiding of `content_preview` is a
  **deferred** design item; see [INTEGRATION.md](INTEGRATION.md).

## Reporting

This is alpha software. Report security issues privately using the channel in the root
[`SECURITY.md`](../../SECURITY.md); do not file publicly-exploitable details in a public issue.
