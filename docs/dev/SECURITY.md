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
| **1 — Record integrity** | sealed by this key, unchanged since, in a verifiable anchored history | **Yes, checked offline by `decision-core`** across CLI/WASM/FFI. Machine-checked proofs cover only part of it: the seal core (record and checkpoint hashing, the signed message; partial correctness, with SHA-256 and Ed25519 trusted) and the verifier's claim kernel, proved on code extracted from the Rust. The DAG and checkpoint-chain properties are proved on hand-written models, not on the Rust. Anchoring (RFC 3161) and the verifier passes that compute the kernel's input facts (signatures, pins, joins, Merkle paths, DAG and chain checks) are tested, not formally covered. |
| **2 — Event observation** | this event was observed by us | **Partial — and stated per event** (each record carries `observed_via`). We see only what the proxy/SDK/OTel path captures. |
| **3 — Complete accountability** | this is *everything* the agent did | **Demonstrated over the brokered surface** (credential broker Tier-A + resource gateway Tier-B); full coverage still needs deployment attestations + a reduced broker TCB. Never claimed as "everything." |

## Invariants averin upholds

- **Append-only, tamper-evident.** A record's `content_hash` + `sig` make any post-seal byte change
  detectable; this cryptographic guarantee is the **primary** tamper-evidence and holds regardless of
  the storage backend. Editing a record breaks its hash; removing one from a session breaks the
  DAG/checkpoint frontier. The Postgres store *also* `REVOKE`s mutation on the history tables as
  defense-in-depth. That `REVOKE` only bites under a non-owner, non-superuser role, so the server's
  startup readiness check (`pgschema.CheckRuntime`) refuses a runtime role that is a superuser, owns
  (or inherits ownership of) **any** table in the schema, or holds effective `UPDATE`/`DELETE`/`TRUNCATE`
  (and, where the migration forbids it, `INSERT`) on any append-only table, directly or through a role
  it inherits. Ordinary startup also refuses to bootstrap an empty database (the runtime would own it):
  initialize once with `averin-migrate --init` under the migration credential. A single-credential
  self-host that connects as the table owner (the `deploy/docker-compose.yml` default) therefore does
  not start against Postgres; see [CONFIGURATION.md](CONFIGURATION.md) for the role split.
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

The production code is connected to those proofs (plan 012, Charon/Aeneas): the seal core
(serializer, framing, digest string, record/checkpoint preimages and hashes, signature message)
is proved to compute the model's definitions, so the seal theorems apply to the production hashes
(partial correctness); the verifier's claim kernel `decide_claims` is proved to return the verdict
model's decision for every claim, for any evidence state its checked facts correspond to (standard
axioms only); and the RCP parser is proved to return for every input, without panic or overflow.

Kani checks the real code in CI within stated bounds: base64url alphabet and per-chunk
canonicality, `sha256:<hex>` digests, LP framing, UTF-16 key order and transitivity, the strict
UTF-16 decoder, the integer round trip and canonical numeric spelling on every pull request, and
the string round trip over its 17,031-case domain weekly (pull requests run a 20-case subset).
TLA+ models the current grant-recovery protocol and two-replica project transactions; its
grant-log and consume-before-act models describe superseded designs (see `formal/README.md`). The same
README lists what is *not* proved: above all, that the verifier's evidence passes (signatures,
pins, joins, Merkle paths, snapshots) compute facts meaning what the kernel's theorems assume, the
parser's functional correctness, and the trusted base (SHA-256, Ed25519, NFC, std, toolchains).

## Authentication & authorization

- **Record authenticity** is cryptographic and offline: pin the signer's `ed25519pub:` key (logged
  at startup, or carried in the bundle's `keys`) and verify — no server trust needed.
- **API authn** (`server/internal/auth`): optional project-scoped API keys (`AVERIN_API_KEYS`). When
  configured, ordinary `/v2/*` routes require a valid token for the `?project=`; comparison is
  constant-time over SHA-256 digests; it **fails closed** (unknown project / empty token ⇒ deny); a
  zero-key config refuses to start (no silent deny-all); tokens are never logged. The dev-only
  open-store mode is explicit and warned about.
- **Recovery authz:** `GET` preflight and `POST /v2/broker-seq/void` require separate `AVERIN_RECOVERY_KEYS`
  credential for the exact project. Ordinary writer possession, absent recovery config, and dev-open
  ordinary auth do not grant recovery. The credential identifies an actor signed into the tombstone
  with the required reason and operation ID for a new void. A permanent operational fence binds
  the same action before reconciliation; a legacy tombstone without original actor/operation metadata
  is never retroactively attributed. This is one narrow permission, not general RBAC.
- **Ordinary API authz is Phase-1 limited.** Full RBAC/SSO/scoped-and-expiring tokens are outside
  this implementation. With `AVERIN_API_KEYS` unset, ordinary app API routes are unauthenticated.
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
- **Historical ordering against revocation trusts averin's own serialization (plan 009, ADR 0007).**
  The optional `historical_authorized_as_of_snapshot` claim (caller-selected `db_serialized_v1`
  policy) proves that a receipt's authorization ordinal precedes a prospective revocation cutoff
  in averin's project database, as of a signed snapshot. It assumes an honest resource signer (one
  ordinal per receipt, signed in its committing transaction), an honest revocation signer (signs the
  boundary time and watermark it read) and correct PostgreSQL serialization of the project guard row.
  It does not prove physical action time or independent database membership, and it gives nothing
  against a party holding the resource and revocation keys and the database. Current revocation is
  unaffected: a revoked grant still blocks `ok`, `authorized` and the capstone. A TSA anchor never
  establishes this order: two anchors are only upper bounds on existence.

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
- **Revocation and two-phase pending state are read from the project transaction.** In Postgres mode
  an acknowledged revoke is durable and every replica's later use transaction rejects the grant; the
  in-process revoked set is a diagnostic cache only; pending grants have no in-process copy. In-memory
  mode loses this state on restart; see [LIMITATIONS.md](LIMITATIONS.md).
- **The use PoP binds the operation, not the bounded-reuse slot or the phase.** The use-time proof of
  possession signs `(grant_id, resource_id, action, params_commitment, credential_binding, nonce)`. It
  does not sign `use_sequence_number` or whether the request is recorded as `use` or `use_intent`. A
  relayer holding a captured, not-yet-submitted request can therefore choose which unused bounded-reuse
  slot it consumes, or submit it as an intent; it cannot change the operation, and the single-use nonce
  prevents a second use of the same signed request. See [LIMITATIONS.md](LIMITATIONS.md).

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
