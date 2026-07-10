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
records) instead of a full-history scan, under `ingestMu` — so it no longer materializes the whole
project history per checkpoint, and the single-snapshot D6 consistency (no grant insert can interleave
between the frontier read and the grant-log read) is preserved. The filter is a **superset** of the
transparency-log membership set (it matches the necessary marker `extensions.broker.kind == "grant"`;
`grantLog` re-applies the exact rule, so a real grant can never be omitted → no suppression).

This is a **RAM/parse** reduction, not a scan-latency one: `json` is a `text` column, so the Postgres
read still scans `O(records)` (a per-row `::jsonb` cast), holding `ingestMu` for the query. A truly
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

## Consume-ledger retention is a correctness parameter

The Postgres consume-before-act ledger is swept on an hourly ticker
(`AVERIN_LEDGER_RETENTION`, default 30 days). The retention window MUST exceed the longest credential
validity (`broker.MaxTTL` = 1h) — pruning a nonce/jti that is still inside a live credential's window
would reopen the single-use replay the ledger exists to close. A configured value below the 24h safe
floor is fatal at startup. A sweep failure is logged, never fatal: it only defers reclaiming space, it
can never reopen a replay window.
