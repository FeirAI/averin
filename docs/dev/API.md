# API / wire reference

The `averin-server` HTTP API, verified against `server/internal/api/server.go` (route table in
`Routes()`) and the core object definitions in `core/src/record.rs` / `core/src/checkpoint.rs`.

All bodies are JSON. Request bodies are bounded to **8 MiB** (`http.MaxBytesReader`). Numeric
literals are decoded with `json.Number` (no float round-trip — RCP forbids floats in signed fields).

## Authentication

- When `AVERIN_API_KEYS` is **unset**, ordinary `/v2/*` routes are unauthenticated. Dev /
  single-tenant only. The recovery route always requires `AVERIN_RECOVERY_KEYS`.
- When `AVERIN_API_KEYS` is set, ordinary `/v2/*` routes are gated by project-scoped API-key middleware;
  `/healthz` stays open. Credentials are read from `Authorization: Bearer <token>` (scheme is
  case-insensitive) **or** `X-Api-Key: <token>`; the project comes from the `?project=` query
  parameter. A token not valid for that project gets a generic `401` (`{"error":"unauthorized"}`,
  with `WWW-Authenticate: Bearer realm="averin"`). The check is constant-time and fails closed.
- With auth on, a body `project_id` that does not match the authorized `?project=` is `403`.

## Routes

| Method | Path | Purpose | Enabled by |
|--------|------|---------|------------|
| GET | `/healthz` | Liveness (`ok`). | always |
| POST | `/v2/records` | Ingest one record or a batch array. | always |
| POST | `/v2/otel/traces` | Ingest OTel/OpenInference spans, mapped to records. | always |
| POST | `/v2/checkpoints` | Seal the current frontier into the checkpoint chain. | always |
| GET | `/v2/verify` | Server-side verification report for a project. | always |
| GET | `/v2/export` | Export a verifiable bundle (proof / disclosure). | always |
| GET | `/v2/dag` | A session's sealed records (trace-waterfall view). | always |
| GET | `/v2/sessions` | List a project's session ids. | always |
| GET | `/v2/usage` | Usage / billable counts for a project. | always |
| POST | `/v2/grants` | Credential broker: issue a `gateway_enforced` grant (Tier-A). | `AVERIN_BROKER_ISSUING_SEED` |
| POST | `/v2/grants/prepare` | Two-phase grant, phase 1 (mint + reveal). | broker (+ cosig) |
| POST | `/v2/grants/finalize` | Two-phase grant, phase 2 (attach approver sigs + commit). | broker (+ cosig) |
| POST | `/v2/introspection` | Native/STS: record a resource introspection transcript. | resource gateway |
| POST | `/v2/use` | Resource gateway: one-phase use receipt (Tier-B). | `AVERIN_RESOURCE_SEED` |
| POST | `/v2/use-intent` | Two-phase use, phase 1 (before the side effect). | resource gateway |
| POST | `/v2/use-outcome` | Two-phase use, phase 2 (after the side effect). | resource gateway |
| POST | `/v2/revoke` | Mark a `grant_id` revoked. | `AVERIN_REVOCATION_SEED` |
| GET | `/v2/broker-seq/void` | Recovery-authenticated, read-only reservation and fence preflight. | broker |
| POST | `/v2/broker-seq/void` | Fence a stranded `broker_seq`, then reconcile a landed grant or signed `grant_void`. | broker |

Routes whose feature is not enabled return **`501 Not Implemented`** with an `{"error":...}` telling
you which env var to set.

---

## POST `/v2/records`

Ingest. Accepts a single record **object** or a JSON **array** (batch). The server stamps every
server-controlled field, defaults missing semantic fields, replaces low-entropy `input`/`output`/
`rationale` with hiding commitments, links the record into the session DAG, signs it, and stores it.

Required (per item): `project_id`, `session_id`, and an idempotency key — `idempotency_key` field
or the `Idempotency-Key` header. The caller may also supply any of the allowed top-level fields
(see [Record object](#record-object)); server-controlled fields are overwritten.

Batch semantics: the **whole batch** is validated up front (decodability, project binding,
idempotency, reserved-field checks, and an RCP-canonicalization dry-run). A malformed item rejects
the entire batch with a deterministic `400` before any item is sealed. The pinned-authority decision
(`AVERIN_REQUIRE_PINNED_AUTHORITY`, below) and `record_id` uniqueness are also dry-run up front: an
item whose authority elevation would be rejected fails the whole batch with the documented `500`, and a
`record_id` collision with the `409`, in both cases with nothing sealed.

**Every item in a multi-item batch needs its OWN `idempotency_key`.** Two items resolving to the same
`(project_id, idempotency_key)` would collapse in the append-only store — the second would return the
FIRST item's record with `created:false` and its own evidence would be silently discarded — so the
whole batch is rejected with a `400`. Note this means an `Idempotency-Key` **header** cannot key a
multi-item batch (it applies to every item); the header remains the supported way to key a **single**
record. The same key under two different `project_id`s does not collide and is accepted.

**Response `201`:**

```json
{ "results": [ { "created": true, "record": { /* the sealed record */ } } ] }
```

`created` is `false` for an idempotent collapse (a retry under the same key). Errors: `400`
(invalid body, missing required field, reserved field/prefix, non-canonical field), `403`
(project_id mismatch with auth), `409` (the `record_id` is already held by a different record in the
project — see below).

**`record_id` is unique per project.** A caller may choose its own `record_id`, but a second, different
record under an id the project already holds is rejected with `409` and nothing is stored (a duplicate
would fail offline verification forever and lose its disclosure secret). An exact idempotent replay (same
`idempotency_key`) still collapses onto the stored record. In a batch, a collision — with a stored record
or between two items — rejects the whole batch before any item is sealed.

**`record_id` is at most 256 bytes** (UTF-8). A longer caller-supplied id is a `400` (the whole batch,
before anything is sealed), identically on the in-memory and Postgres stores. Server-derived ids are well
under the cap. The Postgres uniqueness backstop indexes `md5(record_id)` rather than the raw id, so a
longer id stored before the cap existed never exceeds the index row limit (migration `0002` cannot fail
on it).

### Reserved fields (rejected on a generic record)

- `idempotency_key` prefix `denial:` — reserved for the broker denied-grant log.
- `record_id` prefix `use-`, `outcome-`, `denial-`, `introspection-`, or `revocation-`, and any
  lowercase UUIDv5-shaped `record_id` (the form of the broker's deterministic grant and introspection
  ids) — reserved for the broker/resource endpoints.
- `event_type == "credential_grant_denied"` — reserved for the broker denied-grant log.
- `extensions.broker` and `extensions.broker_denial` — reserved for the broker/resource lifecycle.
- `record_kind` (optional) must be one of `budget-exhausted`, `chargeback-posted`.

**No NUL in identifiers (every route).** A `project_id`, `idempotency_key`, `record_id` (and the
`/v2/revoke` `grant_id`) containing U+0000 (for example an escaped `\u0000` in the JSON body), a `?project=`
query parameter containing `%00`, or an `Idempotency-Key` header containing NUL is a `400`. The server
derives deterministic ids and keys by joining these values with a NUL separator, so a NUL inside one would
let two different `(project_id, idempotency_key)` pairs derive the same grant, use or outcome id.

---

## POST `/v2/otel/traces`

Maps OTel/OpenInference spans (request body) to records and ingests each, content-addressed for
idempotency. Requires `?project=`.

Prompt/completion/tool payloads are extracted from the span attributes — both the exact semconv keys
(`gen_ai.input.messages`, `gen_ai.completion`, `tool.arguments`, `input.value`, …) and the indexed
forms (`llm.input_messages.*`, `gen_ai.prompt.*`, `gen_ai.completion.*`, `llm.output_messages.*`,
`llm.prompts.*`, `llm.completions.*`) — and folded into the record's `input`/`output`/`rationale` so
they follow the commitment/encryption path, never left in plaintext under `extensions.otel_attrs`.
Attribute keys whose name contains a credential marker (`authorization`, `api_key`/`api-key`,
`api_token`/`api-token`, `access_token`, `refresh_token`, `password`, `secret`, `cookie`,
`credential`) are redacted; other string attributes still pass through the scrubber.

**Response `201`** (or `400` if all spans failed):
`{ "ingested": <n>, "failed": <n>, "errors": [ ... ] }`

---

## POST `/v2/checkpoints?project=<id>`

Seals the project's current frontier (the set of session heads) into the hash-chained checkpoint
chain, and best-effort appends it to the configured witness. Empty JSON body.

**Response `201`:** `{ "checkpoint": { /* sealed checkpoint */ } }`, with an optional
`"warning"` if the checkpoint stored but witnessing is pending. Requires `?project=` (`400`
otherwise).

A checkpoint is **refused** (`500`, `checkpoint refused: ...`) while the project's grant log is not a
gapless `[1..N]` prefix: a `broker_seq` is reserved but no grant (or tombstone) records it. This happens
when a grant's commit was ambiguous (or its seq release failed) and its client never retried. Inspect the reservation with the authenticated
[`GET /v2/broker-seq/void`](#get-v2broker-seqvoidprojectidbroker_seqn), then retry the
original grant if it can still finish or run the bounded operator
[`POST /v2/broker-seq/void`](#post-v2broker-seqvoidprojectid) action.

---

## GET `/v2/verify?project=<id>`

Returns the **server's self-view** verification report (built from the project's full bundle,
self-pinning only the roles meaningful without an externally-held TSA key — broker/federation,
resource, revocation, cosig; **not** attestation, which needs a pinned TSA). For an authoritative,
independent verdict, export and verify offline with your own pinned keys.

**Response `200`:** the [verification report](#verification-report) JSON.

---

## GET `/v2/export?project=<id>`

Returns a verifiable [bundle](#bundle-object) for offline verification.

Query parameters:

- `mode` (default `proof_only`) — one of `proof_only`, `selective_disclosure`, `full_evidence`.
  Disclosing modes attach a `disclosures` array (`{record_id, field, value_b64, nonce_hex}`) so an
  offline verifier can open each committed field against its record's commitment. A field whose raw
  payload has been purged by retention is simply omitted from `disclosures` (the sealed record still
  verifies from its commitment); `gap_report.raw_content_available` reflects whether any raw value was
  disclosable.
- `record_kind` (optional) — filter to a typed view. Must be a valid `record_kind`; an unknown value
  is `400`. Adds a `filtered_records` array + a `record_kind_filter` echo. The canonical `records`/
  `checkpoints` arrays are left intact (so the bundle still verifies); the filter is a typed *view*.

---

## GET `/v2/dag?project=<id>&session=<id>`

A session's sealed records, in causal/display order, for the trace-waterfall view.

**Response `200`:** `{ "records": [ /* sealed records */ ] }`. Both query params required (`400`).

> Phase-1 authz limit: with `AVERIN_API_KEYS` unset, any caller who can reach this endpoint can read
> any project's data. Run single-tenant or behind your own auth until you configure project keys.

---

## GET `/v2/sessions?project=<id>`

`{ "sessions": [ "<session-id>", ... ] }`.

## GET `/v2/usage?project=<id>`

`{ "usage": {...}, "free_tier": <n>, "billable_records": <n>, "billable_exports": <n> }`.

---

## POST `/v2/grants` (credential broker, Tier-A)

Issues a grant: it **records** a signed `gateway_enforced` grant into the agent's session DAG
**before** returning the minted, sender-constrained, single-use capability (record-before-issue).
Idempotency key required (so a lost-response retry never double-issues).

Request (`grantRequest`):

| Field | Type | Notes |
|-------|------|-------|
| `idempotency_key` | string | Required (or `Idempotency-Key` header). Deterministically fixes `grant_id`. |
| `pop_version` | int | `2` for new brokered issuance; native `token_exchange` has its separate proof contract. |
| `issued_at`, `request_expires_at` | int64 Unix seconds | Agent-signed freshness window. Maximum 15 minutes; 30 seconds of clock skew accepted. |
| `project_id`, `session_id` | string | Required. |
| `agent_id`, `action`, `resource`, `scope` | string | The operation being authorized. |
| `scope_class` | string | Scope classification input (see broker `ScopeClass`). |
| `use_limit` | int | `bounded_reuse` only (≥1): the cap N. |
| `agent_pubkey`, `agent_sig` | string | Proof-of-possession (the cnf key + signature over the challenge). |
| `authorizing_principal`, `delegation_chain` | string / []string | Authorization provenance. |
| `justification` | string | |
| `ttl_seconds` | int | Capability TTL. |
| `mode` | string | `token_exchange` ⇒ a native/STS grant (no broker PoP; accountable only via a later introspection transcript). |
| `lease_id` | string | Native mode only: the external credential reference a transcript must match. |

**Response `201`:**

```json
{
  "grant_id": "<uuid>",
  "capability": "<minted sender-constrained token>",
  "expires_at": "2026-...Z",
  "scope_class": "single_operation"
}
```

Errors: `400` (validation, failed PoP, forbidden scope, malformed), `409` (idempotency key reused
for a *different* grant request, or the grant's reserved `broker_seq` was voided by the operator —
re-issue under a new `idempotency_key`), `500` (store/seal failure), `501` (broker not enabled). When an
M-of-N cosig policy is pinned, single-phase issuance is refused (`400`) — use prepare/finalize.
An invalid signature, stale proof, or conflicting project/idempotency representation is rejected
without allocating a grant sequence or sealing authorization or denial evidence. An authenticated
fresh request that fails broker policy may produce a signed denied-grant record when denial logging
is enabled.

**What `agent_sig` binds.** For `pop_version: 2`, the agent signs a SHA-256 digest of the
length-prefixed effective request, including authenticated `project_id`, resolved `idempotency_key`,
`session_id`, operation and sender key, effective scope class/use limit, TTL, authorizing principal,
delegation chain, justification, and the signed issue/expiry envelope. The exact field order and
encoding are specified in [grant-pop-v2.md](../../spec/grant-pop-v2.md). A captured proof cannot be
moved to another project or idempotency key, and it cannot mint after the signed freshness window.
An exact v2 committed retry can return the original capability after that window; it does not re-mint or
extend the capability. Historical v1 signatures remain inspectable under their original format but
are not accepted by online brokered grant routes after the cutoff, including committed retries.

### POST `/v2/grants/prepare` and `/v2/grants/finalize` (two-phase)

`prepare` takes the same `grantRequest` body (PoP-validated first), mints the credential without
committing, and returns the challenge inputs (`grant_id`, `credential_binding`, `cnf_kid`, `exp`,
`cosig_threshold`). `finalize` takes **the same `grantRequest` body again** (including `agent_pubkey` /
`agent_sig`) plus `cosignatures` and/or `delegation_hops`, re-validates the proof-of-possession, and
commits. Both phases answer only the request that prepared the grant: an already-pending or committed
grant under the same `idempotency_key` is returned only when the request matches it (the same rule as a
`/v2/grants` retry), else `409`; a body without a valid `agent_sig` is a `400`. `finalize` with no
prior `prepare` is a `409`.

With `AVERIN_DATABASE_URL`, pending challenges persist and rehydrate after restart. They are still
served from a local cache: a different live replica may answer `409` until it is restarted or the
request is routed to the original issuer. Route both phases to the same writer.

---

## POST `/v2/use` (resource gateway, Tier-B)

The resource validates a presented capability + proof-of-possession at use time (capability sig,
validity window, audience/action, PoP, consume-before-act ledger), then seals a resource-signed use
receipt the offline verifier joins back to its grant.

Request (`useRequest`): `idempotency_key`, `project_id`, `session_id`, `capability`, `use_sig`
(base64url Ed25519 PoP), `action`, `params`, `nonce`, `params_nonce`, and `use_sequence_number`
(bounded_reuse only). For other capability classes, the server currently ignores a supplied
`use_sequence_number` and records the effective value `0`; committed retry matching uses that
effective value as well.

A bounded project read returns an exact committed retry, including after capability
expiry, without another content write or ledger claim; a changed request under
the same key is `409`. That retry still verifies the presented capability under
the configured broker issuer key; an issuer key rotation without a compatible
keyring cannot recover the old receipt through this endpoint. For a new use,
the resource verifies the capability,
signed project, and use PoP before storing raw params. It repeats that preflight
inside the project transaction, then checks revocation and consumes the ledger
with receipt insertion. A request that passes the first preflight but later
fails revocation, replay, or time revalidation can leave an immutable,
unreferenced content blob until normal content retention purges it; it leaves
no receipt or committed ledger claim.

**Response `201`:**
`{ "use_id": "use-<uuid>", "grant_id": "<uuid>", "record": { /* sealed receipt */ }, "idempotent": false }`

`/v2/use-intent` and `/v2/use-outcome` are the two-phase variant (intent recorded *before* the side
effect, outcome *after*, linked by a forced causal edge). An intent is completed **exactly once**: a
second `/v2/use-outcome` for an intent that already has one (under a different `idempotency_key`) is a
`409`; a retry of the original outcome under its own key returns it with `"idempotent": true`.

---

## POST `/v2/revoke`

Marks a `grant_id` revoked (permissive by id — the id need not already exist locally, so a
compromised/federated id can be revoked preemptively). From the moment it returns `201`, `/v2/use` and
`/v2/use-intent` reject (`400`, before consuming the credential) any capability of that grant. The next
`/v2/export` carries a signed, time-bounded `revocation_list`; the offline verifier then blocks any use
of a revoked grant. Whenever revocation is enabled, every export carries a signed `revocation_list`, an
**empty** one (`"revoked_grant_ids": []`) when nothing is revoked. A verifier that pins `revocation_keys`
reads a bundle with no list as `revocation_status: missing` (which blocks the capstone), so "nothing is
revoked" is an affirmative, signed statement rather than an absent field. (Known limit: the verifier evaluates a use against the list *as of the export*, so a
use recorded **before** the revoke is also reported blocked; distinguishing pre-revocation uses needs a
verifier-side change.)

In Postgres mode, the revoke is durable before `201`. Later use transactions on
any live replica check the same durable project state. An already admitted use
may complete; a failed revocation lookup rejects rather than trusting a cache.

Request: `{ "project_id": "...", "grant_id": "..." }` (both required).

**Response `201`:**
`{ "revoked": "<grant_id>", "project_id": "...", "revoked_total": <n>, "note": "..." }`.
Errors: `400`, `403`, `429` (the per-project revoked-set cap is reached — explicit, never a silent
fail-open), `501` (revocation not enabled).

---

## GET `/v2/broker-seq/void?project=<id>&broker_seq=<n>`

Recovery-authenticated, read-only preflight for an allocated sequence. It reports the
reservation and database allocation time, pending grant and liveness, winning record and
hash, void marker, immutable fence, terminal result, and actual required `record_id`
uniqueness status. `diagnostic_only: true` means it cannot reserve or promise an outcome;
POST revalidates under the project guard. Unlike a write, it remains available when the
historical non-unique index fallback blocks mutations. Requires the separate exact-project
`broker_seq:recover` credential; ordinary writer keys receive `403`.

## POST `/v2/broker-seq/void?project=<id>`

Authenticated operator recovery for a legacy or residual reserved sequence without a
recorded grant. Request:

```json
{"project_id":"p1","broker_seq":1,"session_id":"broker-seq-void","operation_id":"incident-123","reason":"abandoned grant transaction"}
```

`session_id` defaults to `broker-seq-void`; `operation_id` is 1–128 printable
non-whitespace ASCII bytes and `reason` is nonblank, at most 512 bytes, and normalized to
NFC by the Rust RCP canonicalizer. The authenticated actor comes from
`AVERIN_RECOVERY_KEYS`, never the request body. The same actor, operation ID, session and
normalized reason must be used for every retry. The token grants only recovery for its
configured project.

The first exact project transaction drains earlier supported writes and commits a
permanent immutable fence for the reserved grant ID and sequence, bound to actor, action,
reason, request digest, generation 1, and database time. Every supported grant path checks
that fence; allocation and record insertion enforce it inside their final project
transaction. A second guarded transaction observes the winner. If the grant landed first,
it commits a `recorded` terminal result, leaves the grant and its revocation state
unchanged, and returns `409` with `outcome: recorded` and `winning_record_hash`. Exact
readback of that prior issuance remains available. Otherwise, it commits the signed
`grant_void` tombstone, reservation void marker, optional durable revocation, and
`voided` terminal result atomically. No sequence or grant ID is reissued. A live pending
grant is not a landed grant; the fence prevents it finalizing. Existing pre-protocol
partial tombstones are reconciled without resealing.

The `grant_void` binds project, sequence, and grant ID in signed
`extensions.broker.void_evidence` (domain `averin.broker.grant_void.v1`), with the actor,
operation ID, and reason. Its `record_id` equals the grant ID. It fills the gap in
`broker_grant_head` for the next checkpoint but is never counted as a grant or matched to
a use. `/v2/use` rejects that ID because of the terminal void even without a revocation
signing key. With revocation enabled, the durable revoke commits in the same transaction;
offline publication requires the next signed revocation list.

A completed new void returns `201` with `operation_id`, `outcome: voided`,
`winning_record_hash`, `grant_id`, `broker_seq`, `created: true`, and the sealed `record`.
Exact replay returns `200` and `created: false`. A different operation or actor returns
`409` `action_conflict`. A missing reservation returns `404`; broker disabled returns
`501`. A `503` `retryable: true` may follow a bounded lock wait, failed reconciliation,
cancellation, or ambiguous commit. Query preflight and repeat the **same** operation;
never treat a timeout as proof of rollback. Other projects do not wait on this project's
guard. A client retrying a failing grant cannot extend the fence, and process restarts do
not reset it. There is no minimum reservation age.

For a tombstone from before authenticated attribution, repair is allowed only when both
`actor_id` and `operation_id` fields are absent and the complete project, grant ID,
sequence, domain, and broker role match. Its original signed JSON and hash remain
unchanged. `legacy_tombstone: true` and `original_void_actor_unattributed: true` explicitly
distinguish original void evidence from the current `reconciliation_actor_id` on the
operational fence. These rows are local diagnostics, not new offline proof. A present
empty, null, partial, mismatched, or malformed attribution fails closed; a legacy marker
alone is not evidence of revocation.

The project write guard and the exact valid per-project `record_id` UNIQUE index decide
grant-versus-void races across replicas. Every project write is refused when the index is
absent, non-unique, invalid, partial, or has the wrong expression. Preflight reports the
condition; preserve duplicate signed history and follow the
[operator runbook](../operator-verification.md) rather than deleting evidence. Existing
sessions of pre-fence writer binaries can ignore the fence. Deploy only after the runbook's
traffic drain, prepared-transaction resolution, old runtime credential revocation and
session termination, and explicit old-credential write refusal test.

Verifier builds from before `grant_void` existed do not recognize its role and fail the
bundle; auditors need a verifier with ADR 0004 amendment A1. The historical
`GrantLog_void_starved.cfg` models the replaced age-based protocol; current liveness also
assumes database transactions resolve and authorized recovery is eventually scheduled.

---

## Record object (schema v2)

The signed Decision Record. Closed top-level key set (`ALLOWED_TOP_KEYS` in `core/src/record.rs`);
unknown top-level keys are **rejected** — only `extensions` may hold arbitrary keys.

Required keys (`REQUIRED_TOP_KEYS`): `schema_version`, `canon_version`, `domain`, `record_id`,
`project_id`, `agent_id`, `agent_version`, `session_id`, `span_id`, `parent_span_id`,
`causal_prev_hashes`, `display_seq`, `agent_ts`, `received_ts`, `event_type`, `action`,
`observed_via`, `status`, `content_hash`, `sig`, `key`.

Server-stamped constants: `schema_version = "2"`, `canon_version = "rcp-1"`,
`domain = "flightrecorder.record.v2"`. Server-controlled: `received_ts`, `display_seq`,
`causal_prev_hashes` (the session's current heads), `content_hash`, `sig`, `key`, plus defaults for
absent semantic fields (`agent_id`/`agent_version` → `unknown`, `event_type` → `decision`,
`observed_via` → `sdk`, `status` → `ok`).

Other allowed keys: `anchored_ts`, `record_kind`, `input_commit`, `output_commit`,
`rationale_commit`, `credential_commit`, `tokens`, `cost_micros_usd`, `authority`, `content`,
`framework`.

- `content_hash`: `sha256:<hex>` over `SHA-256( LP(domain) ‖ LP(canon_version) ‖ RCP-serialize(body \ {content_hash, sig}) )`.
- `sig`: `ed25519:<base64url-no-pad>` over the domain-tagged content hash (tag `averin.record.sig.v1`).
- `key`: `{signing_key_id, key_epoch, key_valid_from, key_status}`.
- `input_commit` / `output_commit` / `rationale_commit`:
  `{alg: "sha256", commitment: "sha256:<hex>", low_entropy: bool}` — a hiding commitment; the raw
  value lives in the content store (encrypted at rest) and is revealed only via a disclosing export.
- When a low-entropy field is committed, the server also stamps `extensions.feir_evidence`:
  `payloads[field] = {commitment, payload_reference: "averin-commit:<commitment>", retention_class}`,
  plus `capture_authority` (= the record's `observed_via`) and a `lineage`
  (`{session_id, span_id, parent_span_id}`). The exported reference is the **hiding commitment**, never
  a plain digest of the raw value — an unsalted `sha256` of a low-entropy value in the always-exported
  signed body would be dictionary-reversible (threat #6). The plain content digest lives **only** in the
  server-private disclosure store.

### Enums

- `observed_via`: `proxy`, `sdk`, `otel`, `broker` (Level-2 honesty — what each path captures;
  `broker` is stamped by the server on every grant / use receipt / intent / outcome record).
- `record_kind` (optional): `budget-exhausted`, `chargeback-posted`.
- `authority.source`: `caller_declared` (the forgeable default), `policy_engine_signed`,
  `human_signed`, `delegate_signed`, `gateway_enforced` (the broker's own source). An evidence triple
  verifying under the key pinned for the record's `(project_id, source)` elevates from
  `caller_declared` to the matching source. A claim that does **not** verify — or whose source is
  unpinned for that project — is **rejected with a retryable `500`** by default
  (`AVERIN_REQUIRE_PINNED_AUTHORITY`); set it to `0` to restore the legacy silent downgrade.
- `key.key_status`: `active`, `retired`, `revoked`, `compromised` (the record's own signing-key
  lifecycle; echoed verbatim into the verify report). Not to be confused with the `opts.json`
  pinned-authority role-key rotation status (`active`/`rotated`/`compromised`/`revoked`, ADR 0006),
  which is a separate mechanism that governs PINNED authority keys, not a record's `key` block.

## Checkpoint object

Domain `flightrecorder.checkpoint.v2`, canon `rcp-1`. Hash-chained via `prev_checkpoint_hash`; the
`checkpoint_hash` strips `{anchor, checkpoint_hash, sig}` from the preimage (so a later anchor does
not change the hash). Carries `checkpoint_id`, `checkpoint_seq`, `frontier` (the head content
hashes), `record_count`, `created_ts`, `broker_grant_head` (the grant-transparency cumulative root),
and an optional `anchor` (an RFC 3161 token, attached at export). The chain enforces: first seq is
`0` with null prev; no seq gaps; no two distinct checkpoints sharing a seq or a prev (fork, threat
#2); record_count non-decreasing; every frontier head present in the bundle (omission, threat #1);
the latest frontier equals the actual DAG heads.

## Bundle object

`GET /v2/export` returns: `bundle_version`, `project_id`, `keys` (`[{signing_key_id, key_epoch,
public_key, key_status}]`), `records[]`, `checkpoints[]`, `mode`, `gap_report`, and (when
configured/applicable) `coverage_manifest`, `revocation_list`, `deployment_attestation`,
`disclosures`, `filtered_records` + `record_kind_filter`.

## Verification report

Returned by `GET /v2/verify` and by the offline verifier (`VerifyReport` in `core/src/verify.rs`).
Key fields:

| Field | Type | Meaning |
|-------|------|---------|
| `ok` | bool | The integrity verdict: every record sealed + linked + checkpoint-consistent, no hard violation. **Not** the accountability capstone. |
| `keys_externally_pinned` | bool | `true` only when record `signing_keys` were pinned out of band; merely passing other options does not authenticate record provenance. |
| `body_bound_role_evidence` | bool | Every contributing committed broker/resource/void role record has a verified body-bound authority proof; historical v2 role signatures remain useful for forensic joins but cannot satisfy this stronger prerequisite. |
| `claims_version`, `claims` | string/object | Version `1` typed decisions for `integrity`, `authenticated`, `authorized`, `temporal`, `complete_brokered`, and `complete_introspected`. Each is `satisfied`, `insufficient`, or `refuted`; `requested` and `requested_decision` identify the caller's required claim. Only `satisfied` accepts a required claim. |
| `records_total`, `records_proven` | int | |
| `dag_ok`, `dag_heads`, `collapsed_duplicates` | bool/int | DAG validity, head count, deduped retries (#8). |
| `checkpoints_total`, `checkpoints_verified`, `chain_ok` | int/bool | |
| `checkpoints_anchored` | int | Checkpoints whose anchor **verified** under a pinned TSA (`tsa_keys` / `tsa_spki_b64`) on a verified checkpoint. `0` whenever no TSA trust is pinned. (Changed: it used to count every checkpoint carrying an `anchor` field, verified or not.) |
| `checkpoints_anchors_attached` | int | Checkpoints that merely **carry** an `anchor` field. Unverified: anyone can attach one, so never read it as timestamp evidence. |
| `grant_accountability` | string | `not_applicable` / `incomplete` / `complete` (Tier-A). |
| `broker_trust` | string | `assumed` / `sequence_verified`. |
| `uses_matched`, `uses_pop_reverified`, `unmatched_violation`, `unmatched_pending`, `grants_unused` | int | Tier-B join. |
| `action_completeness` | string | `not_claimed` / `claimed_over_manifest` / `attested_complete_over_brokered_surface` / `attested_complete_over_introspected_surface`. |
| `resource_trust` | string | Always `assumed_truthful` (the irreducible resource-TCB conditional, MF1). |
| `cosig_status`, `delegation_status`, `taxonomy_status`, `attestation_status`, `revocation_status`, `revocation_merkle_status`, `introspection_status`, `federation_status` | string | Mode gates: `absent` / `unevaluated` (no key pinned) → an evaluated verdict when the role's key set is pinned. |
| `issues` | []string | Human-readable violations (omission/fork/tamper/role-overlap/…). |

`ok` retains the legacy bundle diagnostic meaning. It is not an authorization acceptance
predicate. An optional malformed disclosure can make `ok` false; removing it may remove that
parsing issue without proving any stronger claim. The CLI exits successfully only when `ok` is
true **and** the explicitly requested claim is `satisfied`. The default request is `integrity`.
Even a complete claim remains bounded by `resource_trust: assumed_truthful`.

Set `claim_policy` in verifier options, for example
`{"requested":"authorized","revocation":"disclosed","require_disclosure":true}`.
`requested` is `integrity`, `authenticated`, `authorized`, `complete_brokered`, or
`complete_introspected`. `revocation` is `pinned` (default: a disclosed list required whenever
`revocation_keys` are pinned), `disclosed`, `merkle`, or `both`; Merkle mode must be selected by
the caller, not by the bundle. A pinned revocation issuer always requires current evidence for
authorization and completeness. `require_disclosure` and `require_attestation` are optional
booleans. `require_disclosure` demands a valid matching credential opening for every accepted
committed broker grant, including unused grants; counting only supplied openings is insufficient.
Explicit `merkle` and `both` modes require both a fresh signed root and valid non-membership
paths for every brokered use and indexed native credential. Root freshness alone does not prove
non-revocation. Present malformed policy fields are fatal configuration errors. Missing required
evidence gives `insufficient`; a committed contradiction or authenticated revocation gives
`refuted`. Neither accepts the claim.
