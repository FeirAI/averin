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
  month's records from the store. `averin-verify chain` checks all the months. A month export and a month check are bounded by
  the month. The chain's cross-month verdict is not: it needs the concatenation in memory and under the 256 MiB
  cap, and over the cap it is INSUFFICIENT.
- **A refusal, not an unverifiable file.** A whole-history build whose records exceed 256 MiB fails with `413` and a
  pointer to `/v2/segments`; a single month that does is refused with its own `413`.
- **Size check before load (whole history).** Before anything is loaded, the server sums the stored record and
  checkpoint JSON lengths in SQL (`Store.BundleSizeParts`; Postgres `octet_length`, no row is read into memory) and adds
  the bundle's fixed skeleton. When that estimate alone is over 256 MiB it answers the same `413` without loading the
  history. The estimate is a lower bound of the serialized bundle, so it never refuses a history that would have been
  served; a history whose estimate is under the cap is loaded and checked exactly as before, which means a history
  just over the cap can still be loaded in full before it is refused. The SQL sum reads every row of the project,
  though it keeps none. Month requests are not prechecked.
- **Concurrency cap.** Concurrent export/verify builds are bounded by a semaphore (`maxConcurrentBundleReads`,
  currently **4**). A request over the cap gets a retryable `503`.
- **Write-timeout exemption.** The global 60s `WriteTimeout` would kill a large-but-legitimate export mid-write, so
  export/verify run under a per-handler build deadline, `AVERIN_EXPORT_TIMEOUT` (default **10m**, accepted range 1m to
  60m; a value outside it, or not a Go duration, stops startup). A build (load, self-verify, disclosures, marshal for
  export; load and verify for a verify waiter) that has not finished by the deadline is answered `504` with a generic
  body (the duration and a pointer to the month segments) before any body byte, and is counted in
  `averin_bundle_deadline_exceeded_total{route}`. The abandoned export build is not stopped if it is already inside
  the Rust verifier: it runs on and keeps its concurrency slot until it ends, so a retry meanwhile can get `503`.
  Once the body has started, a write that passes its own deadline (the same duration plus 30s; on `/v2/export` it is reset when the build
  finishes, on `/v2/verify` it is set once at handler start and never reset) is still cut, because the status can no longer change; that only reaches a client that reads more slowly
  than the body size over that duration. The other ceilings are unchanged and unmeasured at 256 MiB: the 45s project
  read session, the 30s store statement timeout, and any limit in a caller or proxy in front of averin. Before the
  `504` existed, a build past 10 minutes ended as a cut connection (HTTP 000). Measured 2026-10-28 on one soak host
  at 0.5 metered calls/s with a fresh history: a 28.5 MiB `proof_only` export plus verify took 86 s; 41.7 MiB took 177 s;
  a 110.6 MiB export took averin 521 s to build (first byte) and `averin-verify` 687 s to verify (PASS, integrity). The
  8 h end-of-run export of the same harness was cut at 610 s. The cost per MiB grows with the size, so on that host the
  whole-history export reaches the deadline at about 110 to 130 MiB (about 9 h of history at 0.5 calls/s, later at
  lighter load), well below the 256 MiB cap. Other hardware was not measured (feir-ops#26).
  Most of the verifier's time was its grant-log check (ADR 0004 D6), which rebuilt every checkpoint's grant
  log from the whole history, so the work grew with checkpoints times records. Only `averin-verify` was profiled; that
  the same check dominates the export's 521 s (the self-verify before the first byte) is inferred from the code, not
  measured. The verifier now derives each
  checkpoint's log from the previous checkpoint's when it can show the new checkpoint commits the previous one, and
  recomputes in full otherwise; every checkpoint is still checked against its own frontier and the report is
  byte-identical. Measured after the change (2026-10-28, same host and build profile, user CPU of `averin-verify`
  alone on prefixes of the soak export, not an end-to-end export): 5,000 records 13.1 s before and 4.7 s after;
  10,000 records 46.2 s and 8.6 s; 19,999 records 232.4 s and 18.8 s; the full 42,749 records 1,270.8 s and 49.5 s (loaded host, so the ratios matter more than the absolute times). The time
  per doubling is now 1.8x to 2.4x instead of 3.5x to 5x (the last step, 19,999 to 42,749 records, took 2.63x for 2.14x the size). The end-to-end export time (time to first byte of `/v2/export`) was not measured after the change, and the new deadline and `504` are covered by unit tests with a slowed store, not by a timing run at these sizes. The linear behavior was measured only on histories in which each checkpoint commits the previous one (every history
  averin itself produces). A crafted bundle whose checkpoints do not extend each other can still cost the old quadratic
  time, and one whose checkpoints do extend each other can still cost more than linear time in ways that were not
  measured (for example frontiers that list many already-committed records); all of it is bounded by the 256 MiB cap.
  Tests count the slow-path entries on an honest history but do not time the verifier.

What it does not do:

- **A month cannot evaluate the grant-log transparency chain or the federation heads.** They chain every grant
  since the project began, so a month that starts after a base reports `broker_trust: assumed` and the capstone
  claims stay unsatisfied for it (`segment.not_evaluated`). Only the first month, a whole-history bundle and
  `averin-verify chain` (which rebuilds the whole history) evaluate them, so a project whose whole history is past the
  256 MiB limit has no single check of its whole grant log.
- **A month with parents before its base cannot show its record set is complete.** When `earlier_parent_refs` is
  above 0, a record dropped from the month can be replaced by an earlier month's record without changing the
  record count, the heads or any signature. The month then lists `record_completeness` in `segment.not_evaluated`
  and reports the hashes (`earlier_parent_ref_hashes`); `averin-verify chain` over every month catches the swap. A
  month with no such parents is exact. A signed per-checkpoint delta commitment would close this for a single
  month; it is not built.
- **A month's record range is read by position, and the position is a per-project insertion ordinal only from
  schema version 8.** Each Postgres record carries `records.ord`, 1, 2, 3, ... per project in insertion order
  (migration 0008), assigned while the writer holds the project's write-guard row lock, so two replicas cannot
  commit in an order that differs from their ordinals and a wall clock step cannot reorder them. A checkpoint's
  `record_count` is a position in that order, a month's range and "the records after checkpoint N" are index
  range reads, and the record count and the newest record are one index entry each, whatever the history. Records
  that were stored before the migration were numbered by it in `(inserted_at, ctid)` order, the order they had
  been read in until then and the one every earlier checkpoint was cut against, so for those rows the old hazard
  stays: a wall clock stepped back, or two replicas whose transactions committed in the opposite order to their
  start times, before the migration can still leave a checkpoint cut between such records, which makes that month
  and the next unverifiable. That fails closed (the months do not verify), it never verifies a wrong set. The
  heads (frontier) query `ProjectHeads` still reads the whole project; the checkpoint cut no longer calls it
  (see "Checkpoint cut is incremental, with a sampled shadow check" below), but the first cut of a project and
  the cut's fallback still do.
  Separately, the server refuses to plan months (409) for a project whose checkpoint `created_ts` months go
  backwards, for example after a clock step at a month boundary. The month export is covered on real Postgres
  in CI. The in-memory store numbers records by their position in its insertion-ordered list.
- **A use or outcome whose grant or intent is in an earlier month** is listed (`unresolved_cross_month`), never
  matched, so a month with one reports `authorized` as insufficient. `averin-verify chain` checks that the named record
  exists in an earlier month, refuses a record two months both carry, and then verifies the concatenated history as
  one bundle, so the match, scope, expiry, key binding and single use are decided there, as in a whole-history export.
  That needs the whole history in memory and under the 256 MiB verifier cap; over it the chain word is capped at
  INSUFFICIENT and says the cross-month rules were not run (so a history over the cap never gets PASS from the chain,
  and a cross-month double use in it is not reported as FAIL; carrying that state month by month is not built; accepted as a written limit and tracked in
  FeirAI/feir-ops#9). The
  concatenation carries the latest month's `revocation_list` and `deployment_attestation` (a server re-issues them for
  every month; `averin-verify split` copies them into the last month) and every month's disclosures.
- **A month with a base never passes alone.** Its headline is capped at INSUFFICIENT (exit 1) in the CLI, the browser
  verifier and the web app, because one month cannot close the rules that span months (a second use of a single-use
  grant, a replayed nonce or ledger commitment, a use of a grant no month holds, a revocation across months;
  `segment.not_evaluated` lists `cross_month_uses`). The same cap applies to a month with parents before its base
  (record completeness) and to an unpinned base. Only the first month, which has no base, can pass alone.
- **A month is bounded by its own size.** A project that records more than 256 MiB in a month cannot be verified
  month by month; cutting finer than a month is not built.
- **Peak memory of a whole-history build is O(history)**, including for a project over the limit: the whole history
  is loaded before the size check answers 413. The in-memory store holds everything regardless.
- **The C heap is trimmed after each whole-bundle verification, on glibc only.** Without it glibc keeps freed
  pages below each malloc arena's top resident until malloc_trim is called (arenas are capped and shared, and the
  top is trimmed automatically). On a non-glibc libc nothing is returned, and the
  transient peak while a verification runs is still O(history).

**Deferred:** a **cursor-streaming export** (constant memory, byte-identical framing) and **checkpoint
accumulators** that would let a bundle start from a pinned checkpoint and prove earlier parents by membership
(removing the two month-boundary gaps above) are not built. The segment design needs neither.

## Durable records need a durable content store; the dev store is capped

The raw `input`/`output`/`rationale` values behind selective disclosure (and each grant's credential descriptor and
each use's parameters) go to the content store, not into the records. With the in-memory content store they are
lost on every restart while the records stay durable in Postgres, so disclosures silently stop working.

- **Startup refusal.** With `AVERIN_DATABASE_URL` set, `AVERIN_CONTENT_DIR` unset and `AVERIN_DEV_MODE` off,
  averin-server refuses to start and names `AVERIN_CONTENT_DIR`. Set `AVERIN_CONTENT_DIR` and
  `AVERIN_CONTENT_MASTER_KEY` on every such deployment before upgrading. A deployment with no database is unaffected
  here (the production gate already refuses it outside dev mode).
- **Dev mode keeps the in-memory store, capped.** Past `AVERIN_CONTENT_MEM_MAX_BYTES` (default 64 MiB) the oldest
  blobs are evicted first and a WARNING is logged (at most one line per 10 seconds). Evicted values can no longer be
  disclosed, and a blob larger than the whole cap is not retained. The cap counts blob bytes, not the map and
  bookkeeping around them. Tests and library users who build the server without setting a store also get this capped
  store.
- **What is not covered.** The guard checks that the variable is set, not that the directory is healthy or backed
  up. The content directory is per replica, and a replica that does not hold a record's content cannot disclose it.
- **Memory gauges on `/metrics`.** `averin_content_store_durable` (1 for a filesystem store, 0 for the in-memory one),
  `averin_content_store_entries` and `averin_content_store_bytes` (the in-memory store only; a filesystem store would
  need a directory walk, so it reports 0 for both), and `averin_go_heap_inuse_bytes`, `averin_go_heap_alloc_bytes`,
  `averin_go_heap_objects` and `averin_go_goroutines`.

## App list endpoint pages in the store (not in RAM)

`GET /v2/records` pages via `store.RecordsPage` (SQL `LIMIT`/`OFFSET` on Postgres) plus a cheap
`RecordCount`, so a list call no longer materializes the whole history in memory the way the prior
`AllRecords`-then-slice did. `limit` defaults to 100 (capped at 1000); `offset` (default 0) pages
deeper. This is the paged read path; the export/verify bound above is separate.

## Checkpoint cut is incremental, with a sampled shadow check

A checkpoint is cut from the latest checkpoint plus the records after it: the new frontier, the record count
and the grant-transparency head are derived from the previous checkpoint's signed values and only the new
records, so the work and the rows read per cut do not grow with the project's history (the argument that this
equals the full computation is a comment on `cutBodyIncremental`). The full computation (all records,
all grants, all checkpoints) is still used for a project's first checkpoint, for a latest checkpoint that has no
grant head (written before the D6 head), for a federated broker with no entry in the latest checkpoint yet, and
when the stored checkpoint count disagrees with the latest sequence number.

What this does not give:

- **The incremental cut trusts the latest stored checkpoint** as the base. It is signed, but the cut does not
  re-verify the signature or the chain below it. A latest checkpoint that was corrupted in the store (not by the
  signing key) is carried forward by every unshadowed cut.
- **The check against the full computation is sampled, per project, and rate-limited.** The cut of checkpoint seq
  100, 200, ... of a project also computes the full body, but only if the project's last shadow attempt (whatever its
  outcome) is at least one hour old (`DefaultCheckpointShadowMinInterval`), so the scheduled cadence is
  max(every 100th cut, once per hour per project). This is weaker than a plain 1-in-100 sample: an incorrect
  incremental cut can stay signed for at least an hour of cuts: until the first cut whose seq is a multiple of 100
  after the hour has passed, and longer while a backoff after a shadow that could not run is in force. The
  limit exists because the shadow is O(history) and costs database CPU, memory and a pool connection; at 1-in-100 and a cut every 3 s it would run every
  ~5 minutes. (It used to run under the project write lock and stall writes for up to its budget; it no longer does, see below.) The first cut after a start and every cut after a
  mismatch are not rate-limited. A checked cut refuses to sign unless the full body is byte-identical
  (`averin_checkpoint_shadow_checks_total`); the sample is chosen from the checkpoint being cut, so it does not
  depend on how cuts of different projects interleave. The first incremental cut of each project after the process
  starts is also checked once, which covers a base changed while the process was down and the first cut after an
  upgrade. A divergence on any other cut is signed, because checkpoints are append-only; the next shadowed cut of
  that project, or the offline verifier, finds it. A refusal is not stored: it recurs because the refused seq is
  cut again as the same seq and checked again, also after a restart. After one mismatch
  (`averin_checkpoint_shadow_mismatch_total`, a log line starting `ALERT`) every cut is checked until the process
  restarts. The shadow computation is O(history). A checked cut runs in three steps: the write lock is held only for the incremental cut and the decision (as for every cut);
  the full and incremental bodies are then computed and compared on one repeatable-read snapshot OUTSIDE the write lock; the lock is taken again for a constant-time check that the
  latest checkpoint is unchanged, and the exact bytes that were compared are signed. The shadow holds no write lock, so writes to the project do not wait for it; they can still wait for a pool connection when concurrent shadows fill the pool (see below). A mismatch returns before any lock or
  signature, so a divergent checkpoint of a checked cut is never stored, witnessed or anchored. The costs: the shadow still uses database CPU, memory and one pool connection for up to its budget
  (20 s by default, at most 20 s), and a checked cut's HTTP response takes up to that long; other cuts of the same project in the same process wait for it (writes do not). There is no process-wide limit on
  concurrent shadows of different projects (after a restart every project's first cut is checked at once, and while the mismatch latch is set every cut of every project is shadowed, each holding a pool connection and database CPU for up to its budget). The pool's default size is small (the larger of 4 and the CPU count), so such shadows can occupy it and writes then wait for a connection. A checked checkpoint covers the records committed when its snapshot was taken: records committed during the shadow go into the next checkpoint
  (it still covers everything committed before the cut request arrived). If another writer process cuts a checkpoint of the project while the shadow runs, this cut returns an error and signs nothing
  (`averin_checkpoint_shadow_raced_total`); the supported setup is one writer per project. When that happens after the comparison matched, the project's first-cut check is not counted as done, so its next cut is shadowed again. The rate limit, the backoff and the latch are unchanged. Unshadowed cuts are signed unchecked, as before.
- **The shadow stops being effective as history grows.** A shadow that cannot run (the full computation errors,
  hits the statement timeout, or runs out of that budget before producing a body) does not refuse: the incremental body is signed,
  `averin_checkpoint_shadow_failed_total` is incremented, an `ALERT` line is logged, and that project's next
  shadow waits for a backoff (not the next cut). A mismatch still refuses, and so does one found in a full body that came back over budget (a computed body is always compared; a match is signed and counted as late). The budget covers the whole shadow, not each statement. Once the full computation no longer
  fits its budget the counter rises on every attempt and the sampled check is effectively off for that project.
  The default budget was lowered from 5 s to 1 s after the release-1 soak (about 0.5 calls/s, fresh history), because the
  full computation stopped fitting 5 s reliably from about 5 h of history and each attempt was a 3.5 to 5 s write stall (metered calls of 3.3 to 5.1 s).
  The shadow no longer runs under the write lock, so the default is now 20 s (the ceiling). As an estimate scaled from that measurement (about 1 s of full computation per hour of
  history at 0.5 calls/s, not measured), the cross-check then stops fitting after roughly 20 h of history, and later at lighter load; making the full computation cheaper is a separate follow-up.
  The differential tests are the primary assurance of the equality, not the shadow.
  What still holds the equality then is the differential tests (incremental equals full on random histories,
  in memory and on Postgres) and the guards every cut applies itself: the record count must equal the base count
  plus the records after it, every page of those records must hold exactly the next ordinals, and the new grants
  must carry exactly the next `broker_seq` values.
- **Grant membership is exact-case.** Both cuts count a record as a grant or void tombstone only when
  `extensions.broker.kind` and `authority.enforcement_point` are strings under exactly those keys, as the offline
  verifier does; a record with a differently cased key or a value of another type is not counted and does not fail
  the cut.
- A cut refuses (as the full computation does) when the new grants do not carry exactly the next `broker_seq`
  values, when the store's record count is not the base count plus the records after it, and when a page of the
  records after the base does not hold exactly the next ordinals in order (a record deleted from the middle of
  the range, which would otherwise shift the next page by one row). The same page check guards the head fold
  `ProjectHeadsSince` and the month-segment record read. A delete needs a database role that can delete from
  `records`; the application role cannot.
- `ProjectHeads` (the full anti-join) is unchanged and still O(history); only the cut stopped using it.

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

## A seal reads the session frontier from a table (Postgres) or by scanning (in-memory)

Postgres keeps each session's heads in `session_heads` (migration 0009), updated in the same
transaction as the record insert, so a seal's frontier read does not grow with the session's history.
The in-memory (dev) store derives session heads by scanning the session on every seal, so it slows
linearly with history and is not for production. `ProjectHeads` still reads the whole project (the
checkpoint cut's first cut and fallback only). `session_heads` is derived state, not evidence: a
writer that inserts into `records` without going through `PutRecord` leaves it stale, and it can be
rebuilt from `records` with the backfill statement in the migration.
A record that names a parent not yet in the store, when that parent is later inserted into the same
session, leaves the parent listed as a head although a record names it (the full scan would not list
it). The seal path never produces that and the verifier rejects a missing parent; the migration's
backfill is the full definition.

## A use-outcome finds its intent and prior outcome by index (Postgres) or by scanning (in-memory)

`/v2/use-outcome` resolves the `use_intent` it completes with `Store.IntentRecord` (Postgres: the
`(project_id, record_id)` index of migration 0002) and any outcome already completing it with
`Store.UseOutcomeFor` (Postgres: `records_use_outcome_intent_idx`, migration 0010), so its cost does not
grow with the session's history. The in-memory (dev) store answers both by scanning the session. Both
lookups reproduce what the former whole-session scan accepted: same session, `extensions.broker.kind`
non-empty for an intent, kind `use_outcome` for an outcome, the first match in insertion order (the
per-project ordinal `records.ord`). Two differences from the scan, both outside operation: (1) the
Postgres lookups read the stored JSON with exact key names, while the scan's Go decoder also accepts
keys that differ only in letter case (`Record_ID`); a sealed record never has such keys, and a generic
record cannot set `extensions.broker`, so the lookups are at most stricter. (2) An empty
`intent_record_id` (the API rejects it) is answered from the session by the intent lookup, since an
absent `record_id` reads as the empty string. If a database holds a historical duplicate `record_id`
(migration 0002 then built a non-unique index), the lookup still takes the first row in insertion order
that satisfies the scan's conditions.

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

## Storage only grows, and the cap is by record count (a deploy requirement is still monitoring)

The record store is **append-only by design** (the migration `REVOKE`s UPDATE/DELETE/TRUNCATE), so every
accepted ingest grows the database **permanently** and records cannot be deleted (that is the integrity
invariant). averin bounds the growth with admission control, all configured by environment variable (see
[CONFIGURATION.md](CONFIGURATION.md)):

- `AVERIN_PROJECT_MAX_RECORDS` caps stored records per project, enforced inside the project write
  transaction (exact across replicas); a write past the cap is `507` and stores nothing.
- `AVERIN_INGEST_BUDGET` is a per-project and global rate limit (`429`); `AVERIN_DENIED_GRANT_LOG` is
  always paired with its own budget.

What remains:

- **The cap counts records, not bytes.** The storage bound is the cap times the per-record body limit.
  There is no per-project byte quota.
- **Both controls are off until configured**; set them. A reverse-proxy or gateway rate limit stays the
  primary control against a leaked token, because the in-process limiter's per-project state is bounded
  and a flood of distinct project ids falls back to the global bucket.
- **Monitor database size and `averin_quota_rejections_total`.** There is no in-store eviction, and a
  project at its cap refuses all new evidence (fail closed) until the operator raises the cap.
- **Pending two-phase grants are briefly uncounted.** `POST /v2/grants/prepare` (a write-role route) stores
  a pending row without a record, so the cap does not count it. On Postgres the sweeper removes rows older
  than the 15-minute pending TTL plus a 1-minute grace, so a flood of distinct keys is uncounted for roughly
  16 to 21 minutes before it is swept. The in-memory dev store has no sweep. Bound a burst with the ingest
  budget and the reverse-proxy limit.
- **Counting cost.** With the cap on, each write transaction counts the project's stored records, which is
  linear in the project size, so ingest slows as a project nears a large cap. Keep the cap modest.
- A batch `POST /v2/records` is item by item, so the items that fit before the cap stay stored.

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

## Gateway refusal records are a reported floor

`POST /v2/refusals` seals what the gateway reports (feir-ops#1). The verifier counts integrity-proven
refusal records (`gateway_refusals`, `gateway_refusal_attempts`); it cannot know about an attempt that was
never reported.

- **Level 1 and Level 2 only.** A refusal record proves the report was sealed unchanged and is in the
  checked history. It does not prove the gateway reported every refusal, and a gateway that suppressed a
  report before sealing is undetectable. Level 3 is not claimed for refusals.
- **Any project writer can submit one.** The route needs the `write` role, and a deployment that shares one
  averin token across planes lets any holder add a refusal record. The generic ingest path rejects every
  refusal marker, but it cannot tell two writers apart. A gateway-only key needs a producer-labelled
  `AVERIN_API_KEYS` entry.
- **The count is a floor.** An attempt with no authenticated agent is not recorded, and a producer crash can
  lose its pending window. A producer may coalesce repeats into one record with an `attempts` count, or merge
  a storm into a per-class summary; whether and how a given producer does so is that producer's behaviour
  (vultrino, when its default-off `[averin]` seal client is enabled, coalesces repeats per window and merges refusals past its record budget into a per-class summary; see vultrino's configuration docs), and averin only counts what is sealed. The count is a lower bound, never
  an exact total of refusals.
- **A prior submission can suppress a refusal.** A replay is keyed on the caller's `idempotency_key`
  (stored as `refusal:<key>`), not on the record id, whose salt does not hide it from a caller who can
  predict the gateway's key. A project writer who posts that key first through `/v2/refusals` makes the
  gateway's real refusal return `200 created:false` and never be sealed, and a replay whose fields differ
  from the stored record is not rejected, only answered with the stored id. Compare the returned
  `record_id` and `created` flag with what you sent, and give each producer keys a peer writer cannot
  predict (random per record, not a counter or a hash of public fields).
- **Names are stored verbatim.** An agent-chosen tool or credential name that matches
  `[A-Za-z0-9._:-]{1,128}` is written into a permanent signed record that no purge can erase. A
  token-shaped string (an `sk-` key, a `vut_` token) fits that pattern, so an agent that has seen a secret can
  push it into the record by naming an unknown tool after it. The producer must redact or refuse names that
  look like secrets before calling the endpoint; averin does not.
- **A filtered record list is a bounded scan.** `GET /v2/records?record_kind=` and `exclude_record_kind=`
  page the store newest-first and decode every record, up to 50000 per request, inside a read transaction.
  On a large project with few matching records each call pays that scan, and past 50000 records it reports
  `truncated: true` with an incomplete answer. `total` stays the unfiltered record count. The Postgres path
  of this scan has no test yet.
- **Volume is the producer's to bound.** Each record is a normal record, and `attempts` is capped at 10^9 per
  record, but nothing in averin limits how many refusal records a writer submits; the per-month 256 MiB
  segment cap still applies. Use `AVERIN_INGEST_BUDGET` and the producer's own budget.
- **No taxonomy or manifest entry.** A refusal never touches the operation taxonomy, the coverage manifest or
  the deployment attestation. Signing a new Solo taxonomy version (FEI-36) is a separate release step with the
  owner's key; the vectors committed with this kind are signed by TEST-ONLY keys listed in
  `spec/test-keys.json`, which no deployment may pin.
