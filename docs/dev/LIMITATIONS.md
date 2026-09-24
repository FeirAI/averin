# averin — limitations & bounds

Honest, shipped-behavior bounds for the averin server. These are deliberate scoping decisions, not
bugs; each names the constraint, why it holds, and (where relevant) the deferred design item that
would lift it. See [`../coverage-limits.md`](../coverage-limits.md) for the trust-model coverage
limits and [SECURITY.md](SECURITY.md) for what averin deliberately does not do.

## Export / verify build the whole project bundle in memory

`GET /v2/export` and `GET /v2/verify` build the bundle by reading the project's **entire** record and
checkpoint history into memory (`buildBundle` → `store.AllRecords` + `store.Checkpoints`), materializing
every sealed record as a `json.RawMessage`, then serializing the whole bundle in one response. The
offline verifier re-derives the DAG, frontier, and checkpoint chain over the **closed set**, so the
bundle is intentionally whole-history — records cannot be pruned without breaking causal-parent /
frontier resolution.

Consequences and the bounds that contain them:

- **Peak memory ≈ O(project history).** A very large project's export/verify holds its full sealed
  history in RAM for the duration of the build. Size the process (or shard tenants) accordingly.
- **Concurrency cap.** Concurrent export/verify builds are bounded by a semaphore
  (`maxConcurrentBundleReads`, currently **4**). A request that would exceed the cap gets a retryable
  `503` rather than piling on memory pressure.
- **Write-timeout exemption.** The server's global 60s `WriteTimeout` (Slowloris / slow-body defense
  for every other route) would hard-kill a large-but-legitimate export mid-write. Export/verify
  therefore run under a **per-handler write deadline** (`bundleWriteTimeout`, currently **10m**) set via
  `http.ResponseController`; every other route keeps the finite `WriteTimeout`.
- **Not retroactive.** These bounds only shape *how* the current whole-history bundle is served.

**Deferred:** a **cursor-streaming export** — open the JSON envelope, stream sealed records from a
store cursor with an `http.Flusher`, and close it — would make export memory **constant** (independent
of history size) and remove the need for both the concurrency cap and the extended deadline. It
requires a paged/cursor store method and an incremental bundle writer that emits **byte-identical**
bytes to today's build (the offline verifier re-derives over the whole set, so the framing must not
change). That is a design item, not yet built.

## App list endpoint pages in the store (not in RAM)

`GET /v2/records` pages via `store.RecordsPage` (SQL `LIMIT`/`OFFSET` on Postgres) plus a cheap
`RecordCount`, so a list call no longer materializes the whole history in memory the way the prior
`AllRecords`-then-slice did. `limit` defaults to 100 (capped at 1000); `offset` (default 0) pages
deeper. This is the paged read path; the export/verify bound above is separate.

## Checkpoint grant-head read is filtered, not indexed

Checkpoint creation folds the D6 grant-transparency head from `store.GrantRecords` (the grant-tuple
records) instead of a full-history scan, under the project write transaction — so it no longer materializes the whole
project history per checkpoint, and the single-snapshot D6 consistency (no grant insert can interleave
between the frontier read and the grant-log read) is preserved. The filter is a **superset** of the
transparency-log membership set (it matches the necessary marker `extensions.broker.kind == "grant"`;
`grantLog` re-applies the exact rule, so a real grant can never be omitted → no suppression).

This is a **RAM/parse** reduction, not a scan-latency one: `json` is a `text` column, so the Postgres
read still scans `O(records)` (a per-row `::jsonb` cast), holding the project guard for the query. A truly
`O(grants)` **indexed** grant head — a durable incremental head keyed off `broker_seq` with a
`content_hash` column — is a **deferred** rearchitecture: it needs a schema migration/backfill and is
not worth reopening a grant-suppression race for here.

## OTel secret scrubbing only protects newly-sealed records

`scrubAttributes` recursively redacts secret-shaped keys and values (including inside nested
maps/arrays) before a span is sealed into a record body. Because records are **append-only and
signed**, this only affects records sealed **after** the fix — any secret already sealed in an
existing record's plaintext `otel_attrs` **cannot be retroactively scrubbed**. Scrubbing is also
best-effort pattern/keyword matching, not a guarantee that every possible secret shape is caught;
treat the raw OTel attribute bridge as a lower-trust ingest path (Level-2 observation).

## Project writes wait on a database guard

Postgres serializes each project's authoritative writes with a persisted guard
row. Frontier reads, broker sequence allocation, grant/use receipts, ledger
claims, voids, revocations, pending transitions and checkpoints use one
transaction and connection. Another project can proceed while a guard is held.
The project session has finite pool, lock and statement waits; a canceled
request may leave a COMMIT result unknown. Retry only the same idempotency or
operation identity and reconcile the durable result. A database outage fails
closed; it does not promise write availability.

The in-memory implementation mirrors transactional rollback and project
isolation but is volatile across process restart. A multi-replica deployment
claim still needs authenticated capability-project binding, scoped nonce
claims and bounded sequence recovery tested together. Until then, keep the
single-writer-per-project deployment policy even though frontier and checkpoint
writes now serialize across replicas.

## Storage growth is unbounded and append-only (monitoring is a hard deploy requirement)

The record store is **append-only by design** (the migration `REVOKE`s UPDATE/DELETE/TRUNCATE) and the
app API is **Phase-1** — it has no per-project authentication/authorization or storage quota of its own
(see [SECURITY.md](SECURITY.md) and `docs/coverage-limits.md`). Every accepted ingest therefore grows
the database **permanently**; nothing in averin caps total per-project record count or bytes, and
records cannot be deleted (that is the integrity invariant). **Two operator controls are HARD deploy
requirements, not options:**

- **A reverse-proxy / API-gateway rate limit in front of averin** is the PRIMARY control against a
  leaked token (or an unauthenticated dev-posture deploy) driving unbounded billable, append-only
  growth. averin ships an **opt-in** in-process backstop (`WithIngestBudget`, a coarse per-project +
  global token bucket that answers `429` on `POST /v2/*` ingest — see
  [CONFIGURATION.md](CONFIGURATION.md)); it is **defense-in-depth**, not a substitute for the gateway
  limit, and is **off by default** (so no existing deployment is throttled).
- **Database-growth monitoring + capacity alerting.** Because storage only ever grows, operators MUST
  monitor DB size / per-project record counts and alert well before exhaustion. There is no in-store
  eviction to fall back on.

**Deferred:** a first-class configurable per-project record/byte quota (a `429`/`507` at ingest) and
per-project authz are Phase-2 items.

## Usage metering is best-effort and volatile (bounded revenue loss)

The billing meter's base counter is **in-memory** (`meter.Mem`); the Stripe reporter forwards billable
events best-effort over a bounded async queue. This bounds metering accuracy — see
[CONFIGURATION.md](CONFIGURATION.md) *Metering loss bounds* for the exact failure modes (restart
re-grants the free tier; a full queue or a non-2xx/transport delivery failure drops the event with no
retry) and the `/metrics` counters that make the loss observable
(`averin_meter_queue_drops_total`, `averin_meter_post_failures_total`). **Deferred:** a durable
per-project counter (a Postgres table beside the store, surviving restart) plus **idempotent, retried**
Stripe delivery (meter-event ids) would close the loss; it is documented, not built.

## Consume-ledger retention is a correctness parameter

The Postgres consume-before-act ledger is swept on an hourly ticker
(`AVERIN_LEDGER_RETENTION`, default 30 days). The retention window MUST exceed the longest credential
validity (`broker.MaxTTL` = 1h) — pruning a nonce/jti that is still inside a live credential's window
would reopen the single-use replay the ledger exists to close. A configured value below the 24h safe
floor is fatal at startup. A sweep failure is logged, never fatal: it only defers reclaiming space, it
can never reopen a replay window.

## Revocation and pending-grant visibility

When revocation is enabled, an acknowledged revoke is durable before `201` and
all later project transactions on any live replica reject a new use for that
grant. A use already admitted before the revoke's linearization point may
complete. Query failure rejects or retries; no replica treats a boot cache as
authority. Export signs the revoked set at its repeatable-read cutoff. The
offline verifier still evaluates earlier uses against the current export list,
so a pre-revocation use can be reported blocked.

Two-phase prepare/finalize and void read the same durable pending row on every
replica. A restart or route to another live replica does not lose the challenge
in Postgres mode; a missing or expired row fails closed. In-memory mode loses
pending and revocation state on process restart.

