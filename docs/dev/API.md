# API / wire reference

The `averin-server` HTTP API, verified against `server/internal/api/server.go` (route table in
`Routes()`) and the core object definitions in `core/src/record.rs` / `core/src/checkpoint.rs`.

All bodies are JSON. Request bodies are bounded to **8 MiB** (`http.MaxBytesReader`). Numeric
literals are decoded with `json.Number` (no float round-trip — RCP forbids floats in signed fields).

## Authentication

- Every `/v2/*` route needs a token. A server with **no token configured refuses every `/v2/*` request**
  (`401`), and `averin-server` refuses to start without `AVERIN_API_KEYS` unless `AVERIN_DEV_MODE=1`
  selects the explicit, warned-about open store (local development only). `/healthz`, `/readyz` and
  `/metrics` stay outside the gate.
- Credentials are read from `Authorization: Bearer <token>` (scheme is case-insensitive) **or**
  `X-Api-Key: <token>`; the project comes from the `?project=` query parameter. An unknown, wrong-project
  or **expired** token gets a generic `401` (`{"error":"unauthorized"}`, with
  `WWW-Authenticate: Bearer realm="averin"`). The check is constant-time and fails closed.
- **Roles.** A token has a role: `read` (every `GET`), `write` (read, plus the evidence-adding `POST`s:
  `/v2/records`, `/v2/refusals`, `/v2/grants`, `/v2/grants/prepare`, `/v2/grants/finalize`, `/v2/introspection`,
  `/v2/use`, `/v2/use-intent`, `/v2/use-outcome`, `/v2/otel/traces`) or `admin` (everything, including
  `POST /v2/revoke` and `POST /v2/checkpoints`). Any other method or path, and any route added later, needs
  `admin` until it is classified. A valid token whose role is too low gets a generic `403`
  (`{"error":"forbidden"}`). Tokens written in the legacy `proj:token` form are `admin` with no expiry.
- With auth on, a body `project_id` that does not match the authorized `?project=` is `403`.
- **Quota.** With `AVERIN_PROJECT_MAX_RECORDS` set, a write that would take the project past the cap is
  refused with `507` (`{"error":"project record quota exceeded"}`) and stores nothing; an idempotent
  replay of a stored record still succeeds. With `AVERIN_INGEST_BUDGET` set, `POST /v2/*` past the
  per-project or global rate is `429` with `Retry-After`.

## Routes

| Method | Path | Purpose | Enabled by |
|--------|------|---------|------------|
| GET | `/healthz` | Liveness (`ok`). | always |
| POST | `/v2/records` | Ingest one record or a batch array. | always |
| POST | `/v2/otel/traces` | Ingest OTel/OpenInference spans, mapped to records. | always |
| POST | `/v2/checkpoints` | Seal the current frontier into the checkpoint chain. | always |
| GET | `/v2/records` | List records newest first, or (with `after` and `order=asc`) read oldest first from an ordinal. | always |
| GET | `/v2/verify` | Server-side verification report for a project. | always |
| GET | `/v2/export` | Export a verifiable bundle (proof / disclosure), whole history or one month. | always |
| GET | `/v2/segments` | List the project's month segments (AVE-01). | always |
| GET | `/v2/dag` | A session's sealed records (trace-waterfall view). | always |
| GET | `/v2/sessions` | List a project's session ids. | always |
| GET | `/v2/usage` | Stored record count and the configured record quota for a project. | always |
| GET | `/v2/posture` | Read-only startup-guard report for the deploy-time verifier. | always |
| POST | `/v2/grants` | Credential broker: issue a `gateway_enforced` grant (Tier-A). | `AVERIN_BROKER_ISSUING_SEED` |
| POST | `/v2/grants/prepare` | Two-phase grant, phase 1 (mint + reveal). | broker (+ cosig) |
| POST | `/v2/grants/finalize` | Two-phase grant, phase 2 (attach approver sigs + commit). | broker (+ cosig) |
| POST | `/v2/introspection` | Native/STS: record a resource introspection transcript. | resource gateway |
| POST | `/v2/refusals` | Seal one gateway refusal record (`record_kind` `gateway-refusal`). Role `write`. | always |
| POST | `/v2/use` | Resource gateway: one-phase use receipt (Tier-B). | `AVERIN_RESOURCE_SEED` |
| POST | `/v2/use-intent` | Two-phase use, phase 1 (before the side effect). | resource gateway |
| POST | `/v2/use-outcome` | Two-phase use, phase 2 (after the side effect). | resource gateway |
| POST | `/v2/revoke` | Record a total or prospective revocation of a `grant_id`. | `AVERIN_REVOCATION_SEED` |
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
idempotency, reserved-field checks, and an RCP-canonicalization dry-run). A malformed item (including, in the default `AVERIN_SEAL_SHAPE=enforce` mode, an unknown top-level key or an unknown member inside `authority`, `authority.policy_snapshot_ref`, `content`, `tokens` or a `*_commit` block; only `extensions` may hold custom fields) rejects
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
(invalid body, missing required field, reserved field/prefix, non-canonical field, a malformed or
incomplete v3 authority claim, or, with `AVERIN_REQUIRE_BODY_BOUND_AUTHORITY` on (the default outside dev
mode), an elevated external authority claim that is not v3), `403`
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
- `record_kind` (optional) must be one of `budget-exhausted`, `chargeback-posted`. The third kind,
  `gateway-refusal`, is reserved for `POST /v2/refusals`.
- `event_type == "gateway_refusal"`, `record_kind == "gateway-refusal"`, `observed_via == "gateway"`,
  `extensions.gateway_refusal`, a `record_id` with the prefix `refusal-` and an `idempotency_key` with the
  prefix `refusal:` are reserved for the gateway refusal endpoint. A refusal is signed by the server key like
  any record, so the verifier cannot tell a server-built one from a forged one by its signature; reserving
  every marker at ingest is the only defence against inflating a blocked-attempts count.

**No NUL in identifiers (every route).** A `project_id`, `idempotency_key`, `record_id` (and the
`/v2/revoke` `grant_id`) containing U+0000 (for example an escaped `\u0000` in the JSON body), a `?project=`
query parameter containing `%00`, or an `Idempotency-Key` header containing NUL is a `400`. The server
derives deterministic ids and keys by joining these values with a NUL separator, so a NUL inside one would
let two different `(project_id, idempotency_key)` pairs derive the same grant, use or outcome id.

---

## POST `/v2/refusals`

Seals one gateway refusal record: the gateway refused an agent's attempt and reports it. Role `write`. The
server builds the record itself from a closed set of fields (the B11 denied-grant pattern), so a caller
cannot choose the record id, a free-text reason, params or a URL. It is chained into the `session_id` the
caller names (vultrino uses its `[averin]` session), checkpointed and anchored like any record.
A replay is keyed on `idempotency_key`: a key already stored returns that record with `created: false`
whatever the other fields say, so use keys that a peer writer cannot predict (see LIMITATIONS).

Body (an unknown field is a `400`):

| Field | Meaning |
|---|---|
| `project_id`, `session_id`, `idempotency_key` | Required. The key may also come in the `Idempotency-Key` header. A replay returns the same record with `200` and `created: false`. |
| `agent_id` | Required, `[A-Za-z0-9._:-]{1,128}`. |
| `action` | The refused action. A name outside that pattern is stored as the literal `invalid_name`. `*` only on a summary. A name inside the pattern is stored verbatim in a permanent record, including a string shaped like a secret: the caller must not pass one. |
| `entry_point` | `mcp`, `execute`, `llm` or `approval_resume` (required unless `summary`). |
| `reason_class` | One of the 14 classes in `vectors/refusal-classes.v1.json` (required unless `summary`). Never free text. |
| `credential` | Optional resolved alias, same name rule, stored verbatim (never pass a secret value). |
| `attempts` | 1 to 10^9: the number of coalesced refusals this record stands for. |
| `first_at`, `last_at` | RFC3339, `first_at <= last_at <= now + 5 minutes`. |
| `summary`, `by_class` | A summary merges refusals a producer could not seal one by one: `by_class` counts per class, no `reason_class`, and `attempts` equals the sum. |

The sealed record has `event_type` `gateway_refusal`, `record_kind` `gateway-refusal`, `observed_via`
`gateway`, `status` `refused`, **no** `authority` and **no** `extensions.broker`. It is never a grant or a
use, so it cannot enter the coverage closure, the deployment attestation or the operation taxonomy: no
taxonomy rotation is needed to record a refusal. The verifier counts it as `gateway_refusals` (see the
report fields). Response `201 {"record_id","created":true}`.

`GET /v2/records` also takes `record_kind=<kind>` (only that kind) and `exclude_record_kind=<kind>`; the page
is the newest `limit` matching records. The scan is bounded: it reads and decodes up to 50000 records
newest-first inside a read transaction, so a filtered call costs a scan even when few records match.
`truncated` is `true` when the bound stops it or the page is full. `total` is the unfiltered record count of
the project, not the number of matches. The scan over Postgres is untested.

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

A cut that runs the shadow check (the first incremental cut of a project after a start, every cut after a mismatch,
and the scheduled one; see [LIMITATIONS](LIMITATIONS.md)) seals the state at a snapshot taken after the request
arrived. It covers every record committed before the request, and records committed while the shadow ran go into the
next checkpoint, so a verify run right after such a cut can report the newest records as not yet checkpointed when
writes are concurrent. Such a cut can take up to the shadow budget (20 s by default), plus any wait for another cut
of the same project in the same process. If another writer process cuts a checkpoint of the project in the
meantime, the response is `500` (`checkpoint cut abandoned: ... nothing was signed, retry the cut`); nothing was
stored, and retrying the cut is safe.

A checkpoint is **refused** (`500`, `checkpoint refused: ...`) while the project's grant log is not a
gapless `[1..N]` prefix: a `broker_seq` is reserved but no grant (or tombstone) records it. This happens
when a grant's commit was ambiguous (or its seq release failed) and its client never retried. Inspect the reservation with the authenticated
[`GET /v2/broker-seq/void`](#get-v2broker-seqvoidprojectidbroker_seqn), then retry the
original grant if it can still finish or run the bounded operator
[`POST /v2/broker-seq/void`](#post-v2broker-seqvoidprojectid) action.

---

## GET `/v2/verify?project=<id>[&month=YYYY-MM]`

Returns the **server's self-view** verification report (built from the project's full bundle, or, with `month`, from
that month's [segment](SEGMENTS.md); `404` if no checkpoint was created in that month, `400` for a malformed
month, `413` when the whole history or the month exceeds the 256 MiB single-bundle limit,
self-pinning the broker/federation, resource, revocation and cosig roles and the project's pinned
authority keys; attestation and the signed taxonomy are evaluated only when the operator has configured
their out-of-band roots, `AVERIN_VERIFY_ATTESTATION_PUBKEY` with `AVERIN_VERIFY_TSA_SPKI_B64` and the
`AVERIN_VERIFY_TAXONOMY_*` set). For an authoritative,
independent verdict, export and verify offline with your own pinned keys.

**Response `200`:** the [verification report](#verification-report) JSON. When verification is
overloaded the request is refused with a retryable `503`. A caller that has waited `AVERIN_EXPORT_TIMEOUT` for the
build gets `504` (the shared build keeps running for other waiters).

---

## GET `/v2/segments?project=<id>`

Lists the project's month segments, oldest first: `{project_id, format: "averin.segment.v1", segments: [{month,
records, first_seq, last_seq, head_hash, base_seq, base_hash, records_before}]}`. `base_seq` and `base_hash` are
`null` for the first month. Reads checkpoints only. See [SEGMENTS.md](SEGMENTS.md).

---

## GET `/v2/export?project=<id>`

Returns a verifiable [bundle](#bundle-object) for offline verification. A whole-history export larger than the
256 MiB the verifier accepts is refused with `413` and a pointer to the month segments. At most 4 bundle
builds run at once; a request past that is refused with a retryable `503`. `/v2/export` and `/v2/verify` also run under a build deadline, `AVERIN_EXPORT_TIMEOUT` (default 10 minutes, range 1 to 60 minutes; see [CONFIGURATION.md](CONFIGURATION.md)). A build still running at the deadline is refused with `504` and `{"error":"export did not finish within <duration> (AVERIN_EXPORT_TIMEOUT); export by month: GET /v2/segments, GET /v2/export?month=YYYY-MM"}` (`verify` in place of `export` on `/v2/verify`) before any body byte. Once the body has started, a write that passes its own deadline is still cut. On one measured host a whole-history export of about 110 MiB took 521 s to build before the verifier change described in [LIMITATIONS.md](LIMITATIONS.md), so the deadline can be reached below the 256 MiB cap.

Query parameters:

- `month` (optional, `YYYY-MM`) - export that month's [segment](SEGMENTS.md) instead of the whole history: the
  base checkpoint, the month's checkpoints and records, and a `segment` block. `404` if no checkpoint was created
  in that month, `400` for a malformed month, `413` if the month alone exceeds the limit.
- `mode` (default `proof_only`): `proof_only`, `selective_disclosure` or `full_evidence`. The two
  disclosing modes currently behave the same: each opens every committed field that still has raw
  content (narrowed only by `record_kind`), with no per-field selection. Any other value is not
  rejected: it is echoed in the bundle's `mode` and exports commitments only, like `proof_only`.
  Disclosing modes attach a `disclosures` array (`{record_id, field, value_b64, nonce_hex}`) so an
  offline verifier can open each committed field against its record's commitment. A field whose raw
  payload has been purged by retention is simply omitted from `disclosures` (the sealed record still
  verifies from its commitment); `gap_report.raw_content_available` reflects whether any raw value was
  disclosable.
- `record_kind` (optional) — filter to a typed view. Must be a valid `record_kind`; an unknown value
  is `400`. Adds a `filtered_records` array + a `record_kind_filter` echo. The canonical `records`/
  `checkpoints` arrays are left intact (so the bundle still verifies); the filter is a typed *view*.

---

## GET `/v2/records?project=<id>&after=<n>&order=asc[&limit=<L>][&at_seq=<k>]`

The incremental read. Without `after`, `order` and `at_seq` this route is the newest-first list
(`limit`, `offset`, `total`, `truncated`). With `after=<n>&order=asc` it returns the records with
insertion ordinal `n+1` onward, oldest first, at most `limit` (default 100, capped at 1000), in
`records`. The ordinal is the position a checkpoint's `record_count` refers to, so
`after=<record_count of checkpoint k>` reads the records that checkpoint does not cover. `after=0`
reads from the first record.

From the same repeatable-read snapshot the response also carries `total` (the store's record count),
`after`, `next_after` (`after` plus the page length), `more` (records remain past `next_after`),
`latest_checkpoint` (`seq`, `hash`, `record_count`; absent when the project has no checkpoint) and,
when `at_seq=<k>` is given, `at_seq` (the checkpoint with that seq; absent when there is none). A
reader compares these on every page: the hash at the seq it holds, the latest seq and count not
below what it held, and `total` not below the latest count. The read costs the page plus two
checkpoint rows, whatever the history size.

If the store's ordinals have a gap (a page that is not exactly the ordinals `after+1` onward, or a short page
that does not end at `total`), the read is a 500 (the error starts `record ordinal gap`), never a page that
repeats one record and hides another. The page check is the same one the checkpoint cut and the segment read
use. An empty page with `after` at or past `total` is not a gap: it is a reader that is ahead of the store, and
the response is `200` with no records and `more` false.

It verifies nothing and builds no bundle. A reader that follows it holds a read frontier bound to a
signed checkpoint, not a verified one; the records are as authentic as the store they came from. A
rewrite below the reader's frontier is for the reader's own re-read to find. Each page is its own
snapshot. `order` other than `asc`, a missing, negative or non-numeric `after` or `at_seq`,
`at_seq` without `after` and `offset` with `after` are `400`; a store error, or a checkpoint whose
`record_count` cannot be read, is `500`.

---

## GET `/v2/dag?project=<id>&session=<id>`

A session's sealed records, in causal/display order, for the trace-waterfall view.

**Response `200`:** `{ "records": [ /* sealed records */ ] }`. Both query params required (`400`).

> Reads need a token valid for the project (any role). Only the explicit dev mode serves this unauthenticated.

---

## GET `/v2/sessions?project=<id>`

`{ "sessions": [ "<session-id>", ... ] }`.

## GET `/v2/usage?project=<id>`

`{ "records": <n>, "quota_records": <n> }`: the project's stored record count, read from the store (it
survives restarts), and the configured cap (`0` = none). A store read error is `500`, never a zero.

---

## GET `/v2/posture?project=<id>`

A read-only report of the guards this process was started with, for the posture verifier in feir-os
(`deploy/vps/deploy.sh verify-posture`). It is under the same project API-key auth as every other `/v2` route:
on a keyed deployment it needs the project's bearer. Booleans, one integer (`schema_version`), a short region label and build identifiers only, never a key, a seed or
a DSN: `schema`, `plane`, `build` (`go_version`, `vcs_revision`, `vcs_modified`, `core_rustc` when the build
stamped it with `-ldflags "-X main.coreRustc=..."`), `require_prod_secrets`, `api_keys_configured` (false when the
app API is unauthenticated), `durable_store` (Postgres wired), `signing_seed_is_dev`, `require_pinned_authority`,
`require_body_bound_authority`, `region` (`AVERIN_REGION`, empty when not declared), `schema_version` (the Postgres schema version this binary understands, 0 with in-memory storage), `runtime_role_verified` (true when startup verified the Postgres credential is a least-privilege runtime role), `dev_mode` (true only for a process started with `AVERIN_DEV_MODE=1`; the feir-os posture verifier fails it), `require_approver_binding` (whether the server's own verify requires a govder approval to name who approved), `approver_binding_since` (the canonical cutover string, or `null` when none is set; a far-future cutover turns the requirement off as surely as `require_approver_binding=false`, so the verifier reads both), and `secret_fingerprints` (an object; on a keyed deployment `averin-api-key` is a
list with one keyed fingerprint per distinct API key averin accepts across all projects: the first 16 bytes of
HMAC-SHA256 keyed by the token over `feir-secret-alignment/v1:averin-api-key`, vectors in
`vectors/secret-fingerprint.v1.json`; empty on an open deployment). feir-os's verifier checks that the key
govder, vultrino and the broker send is on that list, so a wrong key fails the launch instead of surfacing as
401s later. A fingerprint is not the key, but someone who holds it can test guesses for a weak key offline,
which is why the report sits behind a project key. The list is one set across all projects, so a key
holder can read the fingerprints of other projects' keys, and the verifier cannot tell that a key was sent for
the wrong project; fine for a single-project host, to be split per project before a shared multi-tenant
deployment. `authority_pins` (a list, empty when nothing is pinned) names every pinned authority verifying key as
`{project, source, pubkey}`: `project` is empty for the global default pin, `pubkey` is the hex public key (public,
so reported as it is). feir-os's verifier compares it with the keys govder derives from its authority seed. It
says what was configured, not that the database is
reachable. On an unauthenticated deployment it answers anyone and reports `api_keys_configured: false`.

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
  "scope_class": "single_operation",
  "created": true,
  "record": { /* the sealed grant record */ }
}
```

`created` is `false` (still `201`) for an idempotent retry that returns the original grant.

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
committing, and returns `200` with the challenge inputs (`grant_id`, `credential_binding`, `cnf_kid`, `exp`,
`cosig_threshold` when a cosig policy is set) and `finalized: false`. `finalize` takes **the same `grantRequest` body again** (including `agent_pubkey` /
`agent_sig`) plus `cosignatures` and/or `delegation_hops`, re-validates the proof-of-possession, and
commits. Both phases answer only the request that prepared the grant: an already-pending or committed
grant under the same `idempotency_key` is returned only when the request matches it (the same rule as a
`/v2/grants` retry), else `409`; a body without a valid `agent_sig` is a `400`. `finalize` with no
prior `prepare` is a `409`. A store failure while preparing, looking up the pending grant or committing
the finalize answers `503`.

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

**Errors.** A forged, expired, revoked, replayed (nonce already consumed) or double-spent use is a `400`
deny (`averin_use_requests_total{outcome="deny"}`). A consume-ledger store failure (timeout,
cancellation, lost connection) is `503`: the transaction rolls back, nothing is consumed, and it is not
counted as a deny; retry the same request. A failed revocation lookup or receipt write is `500`.

`/v2/use-intent` and `/v2/use-outcome` are the two-phase variant (intent recorded *before* the side
effect, outcome *after*, linked by a forced causal edge). An intent is completed **exactly once**: a
second `/v2/use-outcome` for an intent that already has one (under a different `idempotency_key`) is a
`409`; a retry of the original outcome under its own key returns it with `"idempotent": true`.

**Authorization order (plan 009, schema v7).** Every admitted `/v2/use` and `/v2/use-intent` receipt
carries `use_evidence.authorization_order =
{"format":"averin.authorization_order.v1","project_id":…,"ordinal":n}`, allocated from the project's
monotonic order inside the transaction that stores the receipt and covered by the resource's
body-bound signature. An exact retry returns the stored receipt and its original ordinal. A
`/v2/use-outcome` allocates nothing: it copies its intent's signed ordinal into the `use_outcome`
payload, so an outcome recorded after a revocation still describes an intent admitted before it.
Ordinals are unique and increasing per project, not gapless.

---

## POST `/v2/introspection`

Records a resource-signed introspection transcript for a native (`token_exchange`) grant. Request:
`{project_id, session_id, idempotency_key, grant_id, credential_ref, effective_scope, effective_exp,
introspected_at?, transcript_hash?}`; `introspected_at` 0 or absent means the server's time.

Inside one project transaction the server first returns an exact committed retry (`201`,
`"created":false`), even after the grant later expired or was revoked. Every immutable field must
match the stored receipt; an omitted time reuses the committed time, and a different explicit time or
any other different field is `409`. Otherwise it validates the actual committed grant: a native grant
for this resource, `credential_ref` equal to its `lease_id`, `effective_scope` within its scope,
`effective_exp` not after its expiry, `issued_at ≤ introspected_at < min(effective_exp, exp)`, `introspected_at` not in
the future beyond the accepted clock skew, the grant not expired now, not revoked (either mode) and
not voided. A failure is `400` and nothing is signed or stored. Only then does it allocate an
authorization ordinal (carried in `introspection_evidence.authorization_order`) and sign the
transcript. `record_id` and `grant_id` in the response come from the stored receipt.

---

## POST `/v2/revoke`

Records an immutable revocation event for a `grant_id` (permissive by id — the id need not already
exist locally, so a compromised/federated id can be revoked preemptively). `mode` is `total` (the
default: compromise, every use invalid) or `prospective` (cancellation: effective from the next
authorization ordinal). From the moment it returns `201`, `/v2/use`, `/v2/use-intent` and
`/v2/introspection` reject (`400`, before consuming the credential) any use of that grant, in either
mode. The next `/v2/export` carries a signed, time-bounded `revocation_list`; the offline verifier then
blocks any use of a revoked grant, including one ordered before a prospective cutoff (the separate
historical result is described under the verification report). Whenever revocation is enabled, every
export carries a signed `revocation_list`, an **empty** one when nothing is revoked. A verifier that
pins `revocation_keys` reads a bundle with no list as `revocation_status: missing` (which blocks the
capstone), so "nothing is revoked" is an affirmative, signed statement rather than an absent field.

A prospective cutoff is allocated in the same serialization domain as receipt ordinals, so a receipt
admitted before the revoke has a smaller ordinal. A retried prospective revoke returns the original
event and cutoff (`"created":false`); the cutoff never moves later. A later `total` revoke of the same
grant is always recorded and makes it total. `prospective` is refused (`400`) unless the server
exports v2 lists (`AVERIN_REVOCATION_EXPORT_FORMAT=v2`), because a v1 list can state only total
revocations. With v1, an export over a project that already has a prospective event fails rather
than emitting it as total or omitting it.

**Export formats.** v1 (default): `{issuer_kid, issued_at, not_after, revoked_grant_ids, sig}` in
domain `averin.revocation.v1`; every listed grant is total. v2 (`AVERIN_REVOCATION_EXPORT_FORMAT=v2`):
`{format:"averin.revocation.list.v2", issuer_kid, issued_at, not_after, project_id,
snapshot:{boundary_time, authorization_high_watermark}, revocations:[{grant_id, mode,
cutoff_order?}], sig}` in domain `averin.revocation.v2`. The boundary time and watermark are read
inside the same repeatable-read snapshot as the records and revocation state and signed as read.
Legacy verifiers reject a v2 list (fail closed), so upgrade verifiers first. See ADR 0007.

In Postgres mode, the revoke is durable before `201`. Later use transactions on
any live replica check the same durable project state. An already admitted use
may complete; a failed revocation lookup rejects rather than trusting a cache.

Request: `{ "project_id": "...", "grant_id": "...", "mode": "total"|"prospective", "reason": "..." }`
(`project_id`, `grant_id` required; `reason` is stored with the event, at most 512 bytes).

**Response `201`:**
`{ "revoked": "<grant_id>", "project_id": "...", "mode": "<effective mode>", "cutoff_order": <n>
(prospective only), "created": <bool>, "revoked_total": <n>, "note": "..." }`.
Errors: `400`, `403`, `429` (the per-project revoked-set cap is reached: explicit, never a silent
fail-open), `501` (revocation not enabled), `503` (the revocation could not be durably persisted and did
not take effect; retry).

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
unknown top-level keys are **rejected** (only `extensions` may hold arbitrary keys). The nested
objects `authority`, `authority.policy_snapshot_ref`, `key`, `content`, `tokens` and the four
`*_commit` blocks are closed to the members their JSON Schema lists, and the verifier rejects a
record with any other member (the `/v2/records` ingest returns a `400` naming it first). Value types
and required members inside those objects are not checked. `causal_prev_hashes` must be sorted
ascending by bytes without duplicates; the server always seals it that way.

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
- `key`: `{signing_key_id, key_epoch, key_valid_from, key_status}`. `key_epoch` is `AVERIN_SIGNING_KEY_EPOCH`.
  `key_valid_from` is a fixed placeholder (`2026-01-01T00:00:00.000Z`) for every key and epoch; the verifier
  does not read it, and averin never writes `key_valid_until`, `key_attestation_ref` or `rotation_prev_key_sig`.
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
- `record_kind` (optional): `budget-exhausted`, `chargeback-posted`, `gateway-refusal`.
- `observed_via` also admits `gateway` on a gateway refusal record only (reserved, see above).
- `authority.source`: `caller_declared` (the forgeable default), `policy_engine_signed`,
  `human_signed`, `delegate_signed`, `gateway_enforced` (the broker's own source). An evidence triple
  verifying under the key pinned for the record's `(project_id, source)` elevates from
  `caller_declared` to the matching source. A claim that does **not** verify — or whose source is
  unpinned for that project — is **rejected with a retryable `500`** by default
  (`AVERIN_REQUIRE_PINNED_AUTHORITY`); set it to `0` to restore the legacy silent downgrade for v2 claims
  (a v3 claim that fails verification is rejected either way).
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
the latest frontier equals the actual DAG heads. A [month segment](SEGMENTS.md) starts the chain at its
carried base checkpoint instead of seq `0`, and the latest `record_count` equals the base's count plus the
records carried.

## Bundle object

`GET /v2/export` returns: `bundle_version`, `project_id`, `keys` (`[{signing_key_id, key_epoch,
public_key, key_status}]`: the current key first, then each retired key with `status_changed_at`),
`key_rotations` (signed rotation statements, only after a rotation; see [KEY-ROTATION.md](KEY-ROTATION.md)), `records[]`, `checkpoints[]`, `mode`, `gap_report`, and (when
configured/applicable) `coverage_manifest`, `revocation_list`, `deployment_attestation`,
`disclosures`, `filtered_records` + `record_kind_filter`. A month export also carries `segment`
(`{format: "averin.segment.v1", month, base_seq, base_checkpoint_hash, base_record_count}`, see
[SEGMENTS.md](SEGMENTS.md)) and its `checkpoints[]` starts with the base checkpoint.

## Verification report

Returned by `GET /v2/verify` and by the offline verifier (`VerifyReport` in `core/src/verify.rs`).
Key fields:

| Field | Type | Meaning |
|-------|------|---------|
| `ok` | bool | The integrity verdict: every record sealed + linked + checkpoint-consistent, no hard violation. **Not** the accountability capstone. |
| `keys_externally_pinned` | bool | `true` only when record `signing_keys` were pinned out of band; merely passing other options does not authenticate record provenance. |
| `body_bound_role_evidence` | bool | Every contributing committed broker/resource/void role record has a verified body-bound authority proof; historical v2 role signatures remain useful for forensic joins but cannot satisfy this stronger prerequisite. |
| `claims_version`, `claims` | string/object | Version `2` typed decisions for `integrity`, `authenticated`, `authorized`, `historical_authorized_as_of_snapshot`, `temporal`, `complete_brokered`, and `complete_introspected`. Each is `satisfied`, `insufficient`, or `refuted`; `requested` and `requested_decision` identify the caller's required claim. Only `satisfied` accepts a required claim. Version 2 added the historical claim; consumers of version `1` must reject version `2` rather than guess. |
| `revocation_temporal` | object | Plan 009. `policy` (`strict`/`db_serialized_v1`) and, for the latter, the caller's `evaluation_time`, `max_snapshot_age_seconds`, `min_authorization_watermark` and the named `trust_basis`; `snapshot` (`status`, `reason`, signed `project_id`, `boundary_time`, `authorization_high_watermark`); `grant_revocations[]` (`grant_id`, `current_revocation`, `cutoff_order`); `receipt_ordering[]` (`record_id`, `kind`, `grant_id`, `authorization_order`, `historical_ordering`); counts `proven_before`, `at_or_after`, `indeterminate`. |
| `records_total`, `records_proven` | int | |
| `dag_ok`, `dag_heads`, `collapsed_duplicates` | bool/int | DAG validity, head count, deduped retries (#8). |
| `checkpoints_total`, `checkpoints_verified`, `chain_ok` | int/bool | |
| `latest_checkpoint_seq`, `latest_checkpoint_record_count` | int/null | `checkpoint_seq` and signed `record_count` of the highest-seq checkpoint whose seal verified; `null` when none verified. Context for `oldest_uncovered_received_at`, which is the field to use for tail age (a count cannot tell a young tail from an omitted session). Never an input to any verdict. |
| `oldest_uncovered_received_at` | string/null | RFC 3339 `received_ts` of the oldest record the latest **verified** checkpoint does not cover (not in the causal closure of its frontier); with no verified checkpoint, the oldest record of all; `null` when every record is covered. An uncovered record without a canonical `received_ts` reports `1970-01-01T00:00:00.000Z`. A consumer decides how old an unsealed tail may be from this, not from record counts: a checkpoint that omits a live session leaves that session's oldest record here while another session grows. Display only; never an input to any verdict. |
| `checkpoints_anchored` | int | Checkpoints whose anchor **verified** under a pinned TSA (`tsa_keys` / `tsa_spki_b64`) on a verified checkpoint. `0` whenever no TSA trust is pinned. (Changed: it used to count every checkpoint carrying an `anchor` field, verified or not.) |
| `checkpoints_anchors_attached` | int | Checkpoints that merely **carry** an `anchor` field. Unverified: anyone can attach one, so never read it as timestamp evidence. |
| `key_rotations_total`, `key_rotations_verified`, `key_rotations_chain_trusted` | int | Signed recording-key rotation statements in `bundle.key_rotations`, how many verified, and how many keys are trusted only because a verified `scheduled` statement links them to a pinned key that is neither revoked nor compromised. A statement that does not verify is also an `issues` entry. |
| `cleartext_content_records` | int | Records whose signed body carries `extensions.content_preview`: prompt or answer text in the clear that no retention purge can erase (sealed before the server began committing it). A count for the reader, not an input to any verdict. |
| `segment` | object | Only on a month segment: `month`, `base_seq`, `base_checkpoint_hash`, `head_seq`, `head_checkpoint_hash`, `head_record_count`, `link` (`genesis` / `base_pinned` / `base_unpinned`), `base_anchored`, `earlier_parent_refs`, `unresolved_cross_month` (uses and outcomes whose grant or intent is in an earlier month) and `not_evaluated` (the grant-log chain and federation heads; `record_completeness` when the month has parents before its base; `cross_month_uses` for every month with a base, which caps its headline at INSUFFICIENT). Absent on a whole-history report. |
| `gateway_refusals` | int | Sealed gateway refusal records (`record_kind` `gateway-refusal`), counted only when the record is integrity-proven and its shape is valid, deduplicated by `content_hash`. Keyed on `record_kind`, never on `event_type` alone, so a history that predates the kind keeps its verdict. Always present (zero when none). |
| `gateway_refusal_attempts` | int | Sum of `attempts` over the counted refusal records. A floor: an attempt without an authenticated agent is not recorded, a refusal the producer could not seal is a receipt gap, and a producer crash can lose a short window. |
| `gateway_refusals_by_class` | object | `gateway_refusal_attempts` by reason class (closed vocabulary). A malformed refusal (unknown class or entry point, authority or broker evidence carried, an unknown key, a divergent `event_type`, attempts not equal to the sum of `by_class`) is a hard `issues` entry and is not counted. |
| `grant_accountability` | string | `not_applicable` / `incomplete` / `complete` (Tier-A). |
| `broker_trust` | string | `assumed` / `sequence_verified`. |
| `uses_matched`, `uses_pop_reverified`, `unmatched_violation`, `unmatched_pending`, `grants_unused` | int | Tier-B join. |
| `action_completeness` | string | `not_claimed` / `claimed_over_manifest` / `attested_complete_over_brokered_surface` / `attested_complete_over_introspected_surface`. A capstone label is never stronger than the claim kernel: it additionally needs `claims.complete_brokered` (or `claims.complete_introspected`) to be `satisfied`, otherwise it is `claimed_over_manifest`. Read `claims.*` for the authoritative decision. |
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

**Historical ordering (plan 009, ADR 0007).** `requested` may also be
`historical_authorized_as_of_snapshot`. It is decided only when the caller also sets
`revocation_temporal`, for example
`{"policy":"db_serialized_v1","evaluation_time":"2026-09-24T12:00:00.000Z","max_snapshot_age_seconds":3600,"min_authorization_watermark":0}`.
Absent (or `{"policy":"strict"}`) the claim is always `insufficient`. Any malformed, unknown or
partial value is a fatal configuration error. The claim is `satisfied` only if an authenticated,
fresh v2 revocation snapshot for this project shows every receipt ordered strictly before any
prospective cutoff of its grant (or its grant not revoked) and at or below the snapshot watermark,
with every other obligation of `authorized`, and only if the `claim_policy.revocation` mode holds
for the v2 evidence (a pinned issuer; `disclosed` needs a usable v2 list, `merkle` a usable v2 root
with a valid proof for every receipt's grant, `both` all of these). A use of a totally revoked grant, a receipt at or after
its cutoff, or an outcome signing another ordinal than its intent refutes it. Current revocation is
reported separately and still blocks `ok`, `revoked_uses_blocked`, `authorized` and the capstone, so
a bundle can be `ok:false` with the historical claim satisfied; the CLI and viewers show both. The
claim proves order within Averin's database under an honest resource signer, revocation signer and
database serialization; it does not prove physical action time.

A consumer that requests `historical_authorized_as_of_snapshot` must read
`claims.historical_authorized_as_of_snapshot` (and `claims.requested_decision`), never the legacy
`ok`: `ok` stays false while any revoked grant was used, including a use proven before that
grant's own prospective cutoff, so it can never stand in for the historical claim. The offline CLI
(`averin-verify bundle`) and both viewers (the static HTML verifier and the Svelte app) print this
claim's own decision as a prominent line next to the legacy verdict whenever it was the requested
claim (the requested decision under a valid claims contract, else `insufficient`; the same rule in
all three), so the historical decision is never left to be inferred from a FAIL line. In the receipt
detail, a `proven_before` receipt is only labeled "proven before revocation" when its grant's
`current_revocation` is `revoked_prospective`; a receipt proven before the snapshot against a
grant that is `not_revoked` is labeled "authorized as of snapshot (grant not revoked)" instead
(that grant was never headed toward a cutoff), and any other or unknown grant state is shown as
"indeterminate" rather than claiming either outcome.
