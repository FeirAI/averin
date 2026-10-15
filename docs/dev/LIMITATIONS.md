# averin — limitations & bounds

Honest, shipped-behavior bounds for the averin server. These are deliberate scoping decisions, not
bugs; each names the constraint, why it holds, and (where relevant) the deferred design item that
would lift it. See [`../coverage-limits.md`](../coverage-limits.md) for the trust-model coverage
limits and [SECURITY.md](SECURITY.md) for what averin deliberately does not do.

## Export / verify of a whole history are bounded; long histories go by month

`GET /v2/export` and `GET /v2/verify` without `month` still build the project's **entire** record and
checkpoint history in memory (`buildBundleView` reads `store.AllRecords` + `store.Checkpoints` in one repeatable-read
snapshot, materializing every sealed record as a `json.RawMessage`) and serialize it in one response. The
offline verifier re-derives the DAG, frontier and checkpoint chain over that closed set, and **refuses any file
over 256 MiB** (CLI, browser and `/v2/verify` alike).

What contains this:

- **Month segments** ([SEGMENTS.md](SEGMENTS.md)). `GET /v2/export?month=YYYY-MM` and
  `GET /v2/verify?month=YYYY-MM` serve one month, chained to the previous month's last checkpoint, reading only that
  month's records from the store. `averin-verify chain` checks all the months. No single export or verification
  has to hold the history.
- **A refusal, not an unverifiable file.** A whole-history build whose records exceed 256 MiB fails with `413` and a
  pointer to `/v2/segments`; a single month that does is refused with its own `413`.
- **Concurrency cap.** Concurrent export/verify builds are bounded by a semaphore (`maxConcurrentBundleReads`,
  currently **4**). A request over the cap gets a retryable `503`.
- **Write-timeout exemption.** The global 60s `WriteTimeout` would kill a large-but-legitimate export mid-write, so
  export/verify run under a per-handler deadline (`bundleWriteTimeout`, **10m**).

What it does not do:

- **A month cannot evaluate the grant-log transparency chain or the federation heads.** They chain every grant
  since the project began, so a month that starts after a base reports `broker_trust: assumed` and the capstone
  claims stay unsatisfied for it (`segment.not_evaluated`). Only the first month and a whole-history bundle
  evaluate them, so a project past the 256 MiB limit has no single check of its whole grant log.
- **A month with parents before its base cannot show its record set is complete.** When `earlier_parent_refs` is
  above 0, a record dropped from the month can be replaced by an earlier month's record without changing the
  record count, the heads or any signature. The month then lists `record_completeness` in `segment.not_evaluated`
  and reports the hashes (`earlier_parent_ref_hashes`); `averin-verify chain` over every month catches the swap. A
  month with no such parents is exact. A signed per-checkpoint delta commitment would close this for a single
  month; it is not built.
- **A month's record range is read by position.** On Postgres the order is `(inserted_at, ctid)` and the checkpoint
  `record_count` is a position in it, so a wall clock stepped back can make a month carry the wrong records. That
  fails closed (the month and its neighbour do not verify), it never verifies a wrong set. The month export is
  covered on real Postgres in CI.
- **A use or outcome whose grant or intent is in an earlier month** is listed (`unresolved_cross_month`), never
  matched. The chain checks the named record exists in an earlier month, not the full use-to-grant match.
- **A month is bounded by its own size.** A project that records more than 256 MiB in a month cannot be verified
  month by month; cutting finer than a month is not built.
- **Peak memory of a whole-history build is O(history)** for projects under the limit, and the in-memory store holds
  everything regardless.

**Deferred:** a **cursor-streaming export** (constant memory, byte-identical framing) and **checkpoint
accumulators** that would let a bundle start from a pinned checkpoint and prove earlier parents by membership
(removing the two month-boundary gaps above) are not built. The segment design needs neither.

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

## Text signed before prompt commitment stays in the clear

Since ADR 0008 the server commits prompt and answer text instead of signing it, so it can be erased. Records
sealed **before** that change carry their text in `extensions.content_preview`, inside a signed, hash-chained
body, and cannot be edited or erased selectively without breaking the chain. An export reports the number of
such records as `cleartext_content_records`. For them the only remedy is the whole-store one (SECURITY.md,
*Data retention & erasure*): start a new project and destroy the old store.

## Key rotation does not prove when the old key stopped signing

A signed rotation statement links the retiring recording key to its successor and lets a verifier that pinned
only the old key follow the chain. It does not prove the old key signed nothing after `rotated_at`: for a
scheduled rotation that rests on destroying the old seed, for a compromise on a verified timestamp anchor
taken before `status_changed_at` (KEY-ROTATION.md). The statements live in the export, not in the project
chain.

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

Within one process, at most one writer per project is in flight: queued writers
of the same project wait in-process (context-cancellable, bounded by the 45 s
project session) before taking a pool connection, so one hot project cannot
exhaust the pool and starve other projects' writes or any reads. Across
replicas there is no such gate: each replica's writer for the same project
holds its own connection while it waits in Postgres on the guard row, bounded
by the 10 s `lock_timeout`. Size each replica's pool for its concurrent
distinct-project writers plus reads.

Recovery of older stranded broker sequences uses a permanent project fence. It
requires a coordinated rollout that removes all pre-fence writer credentials,
sessions, and prepared transactions before new writers or recovery run. A
schema startup check cannot stop an already-running old writer. See the
[operator cutoff](../operator-verification.md). Recovery liveness assumes the
database resolves in-flight transactions and an authorized operator is
eventually scheduled; permanent database failure has no liveness promise.

The in-memory implementation mirrors transactional rollback and project
isolation but is volatile across process restart. It is a development store:
every project write copies that project's entire state (O(n) in its records,
disclosures and index maps) to make the transaction private, and it never prunes
expired pending grants. Online capability use now
checks its signed project against the authenticated project. Scoped nonce
claims and bounded sequence recovery are built, and a failure matrix in CI
(`multiwriter`: two or three real `averin-server` processes on one Postgres, a
capability used concurrently, a revoke against a use, `kill -9` during prepare
and finalize, stranded sequence recovery while the other process writes, a lost
COMMIT acknowledgment cut before and after the server commits, each checked by
a trace monitor against the `ProjectTx` invariants) found no violation. That is
not yet a multi-replica deployment claim: each replica still reads its own
content directory, so a record disclosed through another replica needs the
content in Postgres first; the ingest budget is per process; the optional
witness is not in object storage; and Postgres failover and more than two
concurrent writers are not exercised. Until those are done, keep the
single-writer-per-project deployment policy even though frontier and checkpoint
writes serialize across replicas.

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
authority. Export signs the revocation state at its repeatable-read cutoff.

Current revocation is total for verification: a use of any listed grant, even one
admitted before the revoke, is reported blocked (`ok:false`, `revoked_uses_blocked`,
`authorized` refuted, no capstone), under every verifier policy. Plan 009 adds a
separate, caller-selected historical result (`db_serialized_v1`, ADR 0007) for
prospective (cancellation) revocations exported in the v2 list format. Its limits:

- It orders receipts against cutoffs inside averin's project database only, under an
  honest resource signer, revocation signer and database. It does not prove when the
  physical action happened (the Vultrino one-phase path records after the side effect).
- A snapshot is "as of" its boundary: an older snapshot within the caller's maximum age
  can predate a later compromise (total) revocation. Callers bound this with
  `max_snapshot_age_seconds`, `min_authorization_watermark` or a required attestation.
- Total revocations (compromise, every recovery void and every pre-v7 revocation) and
  every v1 list or v1 Merkle membership never yield a historical positive.
- Only receipts with a body-bound (v3) resource signature and an ordinal (produced at
  schema v7 or later) can be `proven_before`; older receipts stay `indeterminate`.
- The server exports only the disclosed list (v1, or v2 with the v2 export). Merkle roots,
  v1 and v2, are builder-only: the Go builders exist but the server does not export them.
- An unusable signed v2 artifact still blocks current use of the grants it names, but is not
  historical evidence: it never proves or refutes on its own, and a grant it names is never
  `proven_before`. An authenticated prospective cutoff from a usable v2 source for the same grant
  still decides `at_or_after` (and so a `refuted` claim); without one the claim is `insufficient`.
- There is no external (TSA-based) temporal mode.

Two-phase prepare/finalize and void read the same durable pending row on every
replica. A restart or route to another live replica does not lose the challenge
in Postgres mode; a missing or expired row fails closed. In-memory mode loses
pending and revocation state on process restart.

An abandoned prepare leaves its pending row behind. Each server with a Postgres
store sweeps `pending_grants` every 5 minutes, deleting rows older than the
15-minute pending TTL plus a 1-minute grace by database time, one project at a
time under that project's write transaction. The grace exceeds the 45 s bound of
any project transaction, so the sweep never removes a row an in-flight prepare
or finalize still judges live. A failed sweep is logged and retried; it never
authorizes anything, because finalize requires a live row.

## Use proof of possession does not bind the slot or phase

The use-time PoP signs `(grant_id, resource_id, action, params_commitment,
credential_binding, nonce)`. It does not sign `use_sequence_number` or the phase
(`use` or `use_intent`). Whoever relays a captured request that has not yet been
submitted can choose which unused bounded-reuse slot it consumes (any
`use_sequence_number` in `[1, use_limit]` not yet spent) or record it as a
`use_intent` instead of a `use`. It cannot change the grant, resource, action,
parameters or nonce, and the scoped nonce claim prevents the same signed request
from being used a second time. Binding the slot and phase needs a new PoP
version; it is not changed on the wire now.

## Consume-ledger failures are not denies

A consume-ledger store error (timeout, cancellation, lost connection) on
`POST /v2/use` rolls the use transaction back, consumes nothing and answers
`503`; it is not reported as a replay and is not counted as a deny in
`averin_use_requests_total`. Only an already-consumed nonce or double-spend key is
a `400` deny.

## Maintenance operations

- `averin-migrate --purge-legacy` briefly takes an `ACCESS EXCLUSIVE` lock on
  `legacy_consume_exclusions` (it disables the immutability trigger, deletes the
  aged rows, re-enables it, all in one transaction). Every online nonce/JTI claim
  reads that table, so uses wait for the purge to commit. Run it in a quiet window.
- Migration `0007` backfills every stored `grant_void` tombstone record as a total
  revocation event, without the runtime's binding check (at runtime a tombstone
  retires a grant only when it is bound to that grant's reserved `broker_seq`,
  see `terminalGrantVoided`). This is deliberately
  broader: it only affects history written before the v7 cutover (pre-reservation
  history), and a total revocation is the conservative outcome (it blocks current
  use and never yields a historical positive).
- `averin-migrate` bounds each run by `--timeout` (or `AVERIN_MIGRATE_TIMEOUT`),
  default 90 s. A cutover rewrites migrated history in one transaction; raise the
  timeout for large histories rather than retrying a run that times out.

## Formal evidence bounds (phase 2 close-out)

The claims registers (`docs/dev/FORMAL.md`, `formal/README.md`) state each claim's own limits.
These are the cross-cutting residuals accepted at the phase 2 close-out, with the condition under
which each one matters.

- **Seal shape is top-level only.** `record::seal` refuses a body that `verify_sealed` would reject
  on top-level shape, `domain` or `canon_version`, and `checkpoint::seal_checkpoint` refuses a body
  that `verify_checkpoint_sealed` would reject on `domain` or `canon_version`. Unknown keys inside
  nested objects are not checked by either, and a checkpoint's chain fields (sequence, previous
  hash, frontier, record count) are checked only when a bundle is verified. Records and
  checkpoints stored before these checks shipped are not re-checked.
- **The generic records path mirrors the core key list.** In `enforce` mode `/v2/records` refuses
  an unknown top-level key before sealing, from a Go copy of the core's key list held equal by a
  parity test. If the copy lags the core, the parity test fails; at runtime the seal still refuses
  the key, so the failure mode is the old partial batch commit, not an unverifiable seal.
- **`AVERIN_SEAL_SHAPE=shadow`** seals records and checkpoints that every verifier rejects, on
  purpose, as a rollback switch. `averin_seal_shape_violations_total` counts them.
- **Kani mutants run nightly only.** The kit's Kani mutants (m2 to m4, m9 to m12) run in
  `formal-nightly`, not on pull requests. In the kit a Kani detector that fails for a tool error
  counts as a kill; the legacy `formal-mutants-full` job tells a completed counterexample from a
  tool error.
- **Scheduled evidence lags.** GitHub has started this repository's scheduled `ci` runs about
  6.5 hours after their cron time, so nightly and weekly evidence (`formal-nightly`,
  `formal-mutants-full`, the Kani string family) can be most of a day old.
- **Filtered test detectors.** The kit's vacuity guard fails a cargo test detector whose name
  filter matches no test, but it proves only that at least one test ran, not that every test the
  filter was meant to select ran.
- **TLA+ models are designs.** No model has a trace link to the Go or Postgres code;
  `NoGhostFinalize` holds by definition and is not checked in any passing `ProjectTx`
  configuration; reachability witnesses are states a person chose as interesting.
- **Aeneas production proofs stay in the legacy register.** m50, m54 to m58, m60 to m64 as proof
  mutants run in `formal-production` (every pull request), not in the kit register.
- **Verifier headline surfaces.** `averin-verify bundle` exits 2 for CONSISTENT and also for usage
  or unreadable-file errors, so a caller must read the RESULT line. INSUFFICIENT exits 1, like FAIL.
  The web app's TypeScript `claimVerdict` is covered by its own unit tests, not by the Rust to JS
  differential. The kernel cap on the introspected Level-3 label is exercised only by a unit test
  (no corpus case shows an introspected overclaim). `averin-verify record` uses the same words
  and exit codes (no key: CONSISTENT, exit 2), so the same rule applies: read its RESULT line, as
  a usage error also exits 2. A PASS there means the signature verified under the key given on
  the command line; the CLI cannot tell whether that key is the right one to trust.
