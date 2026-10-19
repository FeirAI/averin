# Configuration reference

Every environment variable / flag each averin binary reads, its default, whether it is required, and
the fail-closed behavior on a missing/invalid value. Verified against `server/cmd/*/main.go` and
the wiring in `server/internal/api/server.go`.

All keys are configured via **environment variables** (the `averin-taxonomy` tool is the exception —
it takes CLI flags). A general rule across the server: a **malformed** value for a security-relevant
key is **fatal at startup** (the process `log.Fatal`s) rather than silently disabling the feature —
e.g. a typo'd authority pubkey must not silently drop you back to forgeable `caller_declared`.

---

## `averin-server` (`server/cmd/averin-server`)

The ingestion + app API. Started with `./averin-server`.

> Every Ed25519 root seed below (`AVERIN_SIGNING_SEED`, `AVERIN_BROKER_ISSUING_SEED`,
> `AVERIN_RESOURCE_SEED`, `AVERIN_REVOCATION_SEED` — plus the AES master key
> `AVERIN_CONTENT_MASTER_KEY`) also accepts a `<NAME>_FILE` form pointing at a mounted secret
> file (e.g. a CSI/Kubernetes secret volume), keeping the seed off the env block. **Setting
> both the inline and `_FILE` form for the same name is fatal** ("set exactly one"); the
> `_FILE` target must be a regular, size-bounded file (a FIFO/device/dir/oversized file is
> fatal — symlinks are followed, so k8s/CSI secret files work); file contents are trimmed
> (mounted secrets carry a trailing newline).

### Core

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_SIGNING_SEED` (or `_FILE`) | — | **Yes** | 64 hex chars = 32-byte Ed25519 seed; the key all records/checkpoints are signed with. **Missing ⇒ fatal** (`log.Fatal`). Invalid (bad hex / wrong length) ⇒ fatal. There is no KMS or HSM signer integration in this release: the server always signs with this raw seed, so protect it with your secrets store and file permissions. |
| `AVERIN_SIGNING_KEY_ID` | `k0` | No | The `signing_key_id` stamped into each record's `key` block and the export key descriptor. |
| `AVERIN_SIGNING_KEY_EPOCH` | `0` | No | The `key_epoch` stamped on new records and checkpoints; raise it with each rotation. Non-integer or negative ⇒ fatal. |
| `AVERIN_RETIRED_SIGNING_KEYS_FILE` | unset | No | JSON array of retired recording keys `{signing_key_id, key_epoch, public_key, key_status: retired\|compromised, status_changed_at}`. Written by `averin-keyrotate`. Published in every export. An entry with no signed rotation statement, a duplicate of the current key, or a non-canonical time ⇒ fatal. |
| `AVERIN_KEY_ROTATIONS_FILE` | unset | No | JSON array of signed rotation statements from `averin-keyrotate`. Every statement must verify and the chain must end at the current key, else fatal. Published in every export as `key_rotations`. See [KEY-ROTATION.md](KEY-ROTATION.md). |
| `AVERIN_ADDR` | `:8080` | No | Listen address (`host:port`). |

### Storage & durability

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_DATABASE_URL` | unset ⇒ **in-memory** | No (but see note) | Postgres DSN for a separate, least-privilege runtime role. Existing databases must first use the explicit maintenance cutover below; ordinary startup refuses an older schema. Connection failure, a missing nonce cutover marker, or a newer schema is fatal. Unset ⇒ in-memory store (NOT durable; logs a WARNING). The project transaction owns consume-before-act claims and the signed use receipt. |
| `AVERIN_REGION` | unset ⇒ not declared | No | The cell's region label (lower-case letters, digits and hyphens, starting with a letter, at most 64 bytes, for example `eu-central-1`). averin does not interpret it; `GET /v2/posture` reports it as `region` so the deploy-time verifier can require every plane of a cell to name the same region. An invalid value is a **startup error**. |
| `AVERIN_CONTENT_DIR` | unset ⇒ in-memory | No | Filesystem directory for the durable content store (the raw low-entropy `input`/`output`/`rationale` values committed at ingest, revealed on selective disclosure). Blobs are stored **AES-256-GCM encrypted at rest**, under a per-tenant subdirectory (`<dir>/tenant-<hash>/sha256-<hex>`); the per-tenant key is derived from `AVERIN_CONTENT_MASTER_KEY` via HMAC, with tenant+plaintext-digest as GCM additional-authenticated-data. Encryption is **at-rest only** — a disclosing export still ships the plaintext value, so offline verification is unchanged. A bad/uncreatable dir is fatal. Unset ⇒ in-memory (disclosures don't survive a restart; logs a WARNING). |
| `AVERIN_CONTENT_MASTER_KEY` (or `_FILE`) | — | **Yes** when `AVERIN_CONTENT_DIR` is set | 64 hex chars = 32-byte master key from which each tenant's content-encryption key is derived. **Missing/invalid with the dir set ⇒ fatal** (`log.Fatal`) — the content store never runs unencrypted. The `_FILE` form reads the value from a mounted secret file (setting both the inline and `_FILE` form is fatal). No effect when the content store is in-memory. |
| `AVERIN_RAW_RETENTION_DAYS` | `30` | No | Retention window for the encrypted raw payloads: a daily purge deletes blobs older than N days (by file mtime). Must be a positive integer (else fatal). Re-committing identical content refreshes its mtime, restarting the window. Purging removes only the raw opening material — the sealed record keeps its hiding commitment, so a post-purge export reports `raw_content_available:false` while the proofs stay verifiable. Only applies when `AVERIN_CONTENT_DIR` is set. |
| `AVERIN_WITNESS_DIR` | unset ⇒ no witness | No | Filesystem directory for a customer-controlled append-only checkpoint witness (`<dir>/<project>/checkpoint-<seq>.json`). Best-effort: a witness write failure is a warning, not fatal. Defends omission/rewrite (threats #1/#15). |
| `AVERIN_TSA_PRESET` | unset ⇒ no anchoring | No | `freetsa` stamps at https://freetsa.org/tsr (free, no service level) and logs the signing key to pin. An unknown name is fatal; setting it together with `AVERIN_TSA_URL` is fatal. See [TIMESTAMPS.md](TIMESTAMPS.md). |
| `AVERIN_TSA_AUTH_HEADER` | unset ⇒ none sent | No | The `Authorization` header value a paid TSA needs (for example `Basic ...`), sent with every stamp request to `AVERIN_TSA_URL` or the preset. Start-up is refused when it is set with a URL that is not https. |
| `AVERIN_TSA_URL` | unset ⇒ no anchoring | No | URL of a third-party RFC 3161 timestamp authority. When set, sealed checkpoints are anchored with an RFC 3161 token (attached at export), defending backdating (threat #3). The verifier must pin this TSA's signing-certificate public key out of band (`tsa_spki_b64` in `opts.json`, or `AVERIN_VERIFY_TSA_SPKI_B64` for `/v2/verify`) to trust the anchor; `tsa_keys` is only for the hermetic `test-anchor` scheme. See [TIMESTAMPS.md](TIMESTAMPS.md). |
| `AVERIN_ATTESTATION_SEED` (or `_FILE`) | unset ⇒ no deployment attestation | No | 64 hex chars = role-separated Ed25519 issuer seed (a bad value is fatal, and a key equal to the signing, broker, resource or revocation key aborts startup). When set, exports carry a signed `deployment_attestation` bound to the latest checkpoint. This alone does not make `/v2/verify` attested; the verifier roots below must also be independently pinned. |
| `AVERIN_VERIFY_ATTESTATION_PUBKEY` | unset ⇒ D7 unevaluated | No | Comma-separated `ed25519pub:` issuer keys pinned out of band by the operator/auditor. Must be configured together with `AVERIN_VERIFY_TSA_SPKI_B64`; partial configuration is fatal. |
| `AVERIN_VERIFY_TSA_SPKI_B64` | unset ⇒ D7 unevaluated | No | Comma-separated base64url-no-pad DER SubjectPublicKeyInfo values from the chosen RFC 3161 TSA signing certificate. These public roots make the product-facing `/v2/verify` endpoint evaluate the timestamp and attestation instead of trusting producer-supplied cert material. |
| `AVERIN_VERIFY_TAXONOMY_FILE` | unset ⇒ D4 absent | No | Path to the signed operation-taxonomy JSON artifact. Must be configured with the issuer key, digest, and version below; a partial tuple is fatal. |
| `AVERIN_VERIFY_TAXONOMY_PUBKEY` | unset ⇒ D4 absent | No | Comma-separated role-separated Ed25519 taxonomy issuer keys pinned out of band. |
| `AVERIN_VERIFY_TAXONOMY_DIGEST` | unset ⇒ D4 absent | No | Canonical `sha256:` digest emitted by `averin-taxonomy`, pinning the exact signed artifact. |
| `AVERIN_VERIFY_TAXONOMY_VERSION` | unset ⇒ D4 absent | No | Positive taxonomy version emitted by `averin-taxonomy`; the verifier requires it to match the artifact. |
| `AVERIN_COVERAGE_MANIFEST` | unset | No | Valid JSON operator declaration emitted in exports and cryptographically bound into the attestation. Required for the D8 completeness-over-declared-brokered-surface capstone; it does not turn a declaration into observed runtime fact. |

#### Schema versioning & upgrades

averin's three Postgres-backed stores — the append-only evidence store, the consume-before-act ledger,
and the durable revocation / two-phase grant state — share the one `AVERIN_DATABASE_URL`. At startup a
single **versioned migration runner** (`server/internal/pgschema`) checks the schema at ordinary
startup. Only a truly empty DB can bootstrap automatically. Existing databases need a selected
maintenance cutover before new writers start. The runner uses `pg_advisory_xact_lock` and writes one
`schema_migrations(version int PRIMARY KEY, applied_at
timestamptz)` ledger for the whole averin DB, so an operator sees **one** version, not three. (It is
named `schema_migrations`, distinct from the flight-recorder record's own `schema_version` field.)

The runner reads the stored version (an existing **unstamped** DB reads as `0`) and:

- **stored < binary** ⇒ existing DB startup fails closed, even when its version table is empty.
  Run the explicit cutover command below after retiring every old writer. A truly empty DB is
  **refused** by ordinary startup (its runtime credential would own every table it created and then
  fail the least-privilege readiness check forever): initialize it once with `averin-migrate --init`
  using the migration credential, grant the runtime role, then start the server.
- **stored == binary** ⇒ no-op; a steady-state boot issues **zero DDL**. This is what lets the runtime
  role drop `CREATE`/`ALTER` (run migrations as a privileged role, the server as a least-privilege one;
  see the append-only role split in `migrations/0001_init.sql`).
- **stored > binary** ⇒ **fatal, fail-closed refusal to start.** averin's evidence is immutable, so a
  binary older than the DB never re-migrates it backward or risks misreading it. **Downgrades are not
  supported**: to roll back a schema change, roll the DB back from a backup taken before the upgrade,
  then start the older binary against it.

**To add a migration:** bump `CurrentSchemaVersion` and append one ordered DDL step in
`server/internal/pgschema` — it is a version stamp, not a framework.

**Hook mode (`averin-migrate --hook`), for a pre-upgrade Job or any automation.** One idempotent
invocation with the migration credential: an **empty** database is initialized, a database **at the
current version is left unchanged** (a rerun, a retried Job and a concurrent run all print `noop`), an
**older** database (or an unstamped legacy schema) is advanced **only** when `--old-runtime` and
`--new-runtime` are given together, through the same validated cutover barrier as the manual command,
and a database **newer** than the binary is refused. Without the roles an older database is left
untouched, the command prints `cutover_required` and exits **3**, so a Job can surface "a maintenance
window is needed" distinctly from a failure. Every state change runs under the same advisory-lock
transaction as server startup, so concurrent runs serialize: exactly one reports `initialized` or
`cutover`, the others report `noop`. On success, and for `cutover_required`, it prints one JSON line on stdout (`plane`, `action`,
`schema_before`, `schema_after`, `schema_current`); a refusal or failure (a database newer than the binary, an unreachable database) prints a message on stderr and no JSON line, so read the exit status, not stdout, to tell failure from success; exit status 0 success, 1 refused or failed,
2 usage or configuration, 3 cutover required. It does not grant the runtime role anything: run the
grants step after it, then verify the runtime credential with `averin-migrate --check-runtime`
(reads `AVERIN_DATABASE_URL`, the runtime DSN; runs the same check the server runs at startup, so an
owning, superuser or over-privileged runtime role fails the Job instead of the first pod; prints
`{"action":"runtime_checked","ok":...}` and exits 1 when it refuses). `--hook` cannot take the
rollback path: **downgrades are not supported**, as above.

For a fresh empty database, run `cd server && AVERIN_MIGRATION_DATABASE_URL='<migration DSN>' go run ./cmd/averin-migrate --init`, then grant a distinct runtime role its application privileges and set `AVERIN_DATABASE_URL` to that role's DSN. For an existing database, stop old servers/workers and producers, drain sessions and prepared transactions, revoke/rotate every old runtime identity, and run `cd server && AVERIN_MIGRATION_DATABASE_URL='<migration DSN>' go run ./cmd/averin-migrate --old-runtime old_role[,other_old_role] --new-runtime new_role`. The command verifies each named old identity is `NOLOGIN`, has no live sessions or prepared transactions, and has no effective write privilege on Averin tables (including inherited grants); it applies pending migrations (v6 nonce ledger, v7 temporal revocation, v8 record ordinal) and stamps them in one transaction. The operator must supply a complete retired-identity inventory and distribute the new secret only to new binaries; a database role cannot identify a binary version. The new runtime must be non-owner, non-superuser, and unable to inherit ownership. A later migration needs a fresh barrier for its own version; the v6 marker is not a reusable authorization, and the command re-validates the barrier for v7 and again for v8 even on a database already cut over to v6. An advancing cutover also refuses while the new runtime role has any session or the database has any prepared transaction: start new runtimes only after it commits. It further refuses while any other client backend is connected to the database (the migration identity must be a superuser or have the privileges of `pg_read_all_stats`, `GRANT pg_read_all_stats TO <migration role>`, or the advancing cutover refuses: without it PostgreSQL hides other roles' sessions from `pg_stat_activity`, and a session whose type is hidden counts as a client), and while any LOGIN, non-superuser role other than the migration identity, the new runtime and the table owner has effective `INSERT`/`UPDATE`/`DELETE` on a schema table directly, by inheritance or through a `SET ROLE`-reachable membership (a LOGIN member of a retired role is otherwise not named by `--old-runtime`). `averin-migrate --timeout <duration>` (or `AVERIN_MIGRATE_TIMEOUT`) sets the run's deadline, default `90s`; raise it for large histories. Server readiness (`CheckRuntime`) refuses a runtime role that owns any schema table or holds a mutation privilege on an append-only table, at table or column level, directly, inherited or through any role it can `SET ROLE` to (see [the runbook](../operator-verification.md#required-deployment-cutoff) for the exact list). See [the operator cutover runbook](../operator-verification.md#required-deployment-cutoff).

Migration `0006` keeps unknown-owner old nonce/JTI rows as immutable global exclusions. Scoped `(authenticated project, configured resource, nonce)` claims are checked against these exclusions within the receipt transaction; JTI claims remain global. Ordinary sweep never removes legacy exclusions. The explicit `--purge-legacy` maintenance command requires the same retired-role barrier and waits for the DB-time v6 cutoff plus the 24-hour retention floor. This floor must exceed the maximum accepted capability TTL (one hour) plus the worst old/new application-to-DB clock disagreement; the accepted issuance skew is 30 seconds. The finite hold assumes clocks remain within that bound, not arbitrary clock jumps. New online uses reject malformed or overlong capability lifetimes before claiming; this does not alter historical offline bytes. Increasing TTL, skew, accepted credential modes, or clock-disagreement bounds requires a new retention review.

Migration `0007` (plan 009, ADR 0007) adds the per-project authorization order on the project guard row (it can only advance; guard rows cannot be deleted), the `authorization_receipts` ordinal backstop and immutable `revocation_events`. Every earlier boolean revocation, recovery void marker and signed `grant_void` tombstone becomes a total event, and `revocations` is renamed to the immutable `legacy_boolean_revocations` with no compatibility bridge, so an old writer or prepared statement fails instead of recording an untyped revocation. 0006's legacy-exclusion time is unchanged. The v7 runtime role additionally needs `SELECT, INSERT` on `authorization_receipts` and `revocation_events` (`UPDATE` on `project_write_guard` was already required); `averin-server` readiness checks these.

Migration `0008` (history-scaling PR1) adds `records.ord`, the per-project insertion ordinal (1, 2, 3, ... with no gaps), a unique index on `(project_id, ord)` and a `BEFORE INSERT` trigger that numbers a row without an ordinal as the project's largest ordinal plus one (the write path holds the project's write-guard row lock, so inserts of one project are serialized; a racing insert that bypassed it fails on the unique index). Existing records are backfilled per project in `(inserted_at, ctid)` order, the order the store read them in before, which is the order every existing checkpoint's `record_count` was cut against. The step needs `UPDATE` on `records`, which the append-only revoke removed from the migrating role: it grants it back for the one backfill statement and revokes it again inside the same transaction, writes only the new column and changes no signed bytes. It rewrites the records table once, so size the maintenance window to the table and expect it to roughly double on disk until vacuum. The runtime role needs no new privilege (the trigger only reads `records`). Run it inside the usual cutover; an older binary refuses a v8 database.

Versions: **1** is the baseline above; **2** (`migrations/0002_record_id_unique.sql`) adds a per-project
`record_id` uniqueness index (an expression index over the sealed JSON — no new column, no row rewrite).
If the DB already holds a historical duplicate `record_id`, v2 still applies but builds a non-unique index
and logs a `WARNING`; new duplicates are still rejected by the application.

### Authentication (project-scoped API keys)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_DEV_MODE` | unset (off) | No | `1`/`true` selects local development: with no `AVERIN_API_KEYS` the API is **open** (warned), the in-memory store and the dev signing seed are allowed, and `AVERIN_REQUIRE_PROD_SECRETS`, `AVERIN_REQUIRE_BODY_BOUND_AUTHORITY` and `AVERIN_REQUIRE_APPROVER_BINDING` default **off**. It is the only way to turn the production gate off. Any other value is fatal. Never set it in production. |
| `AVERIN_API_KEYS` | **required** (unset ⇒ refuses to start, unless `AVERIN_DEV_MODE=1`) | Yes | Project API keys, in one of two forms. **Legacy** `proj-a:tok1,tok2;proj-b:tok3`: every token is an `admin` token with no expiry. **JSON** (value starts with `[`): `[{"project":"p","token":"<secret>","role":"read","not_after":"2027-01-01T00:00:00Z"}]`. `role` is required and is `read`, `write` or `admin` (see [API.md](API.md) for the routes each allows). Roles are ordered `admin` > `write` > `read`, so `write` includes everything `read` can do, including `GET /v2/export` with its full evidence: a write-only plane token can still read the project's evidence. Give `token_sha256` (64 hex chars) instead of `token` to keep the secret out of the config. `not_after` is optional (RFC 3339; a token is invalid at and after it, so omitting it means it never expires). Unknown fields, an unknown role, a bad date, a duplicate project+token and an empty array are fatal; error messages never echo a token. Rotate by adding the new token, moving clients, then removing the old one (or let `not_after` retire it). Without keys, and outside dev mode, the server does not start; a server built without an auth store refuses every `/v2/*` request. The recovery route always has separate auth. See [SECURITY.md](SECURITY.md). |
| `AVERIN_RECOVERY_KEYS` | unset ⇒ recovery denied | No | JSON array of `{ "project_id": "p1", "actor_id": "operator-1", "token": "<secret>" }` objects. Grants only `broker_seq:recover` for the named project, not ordinary write access. Actor ID is a stable non-secret identity of 1–128 printable non-whitespace ASCII bytes, signed byte-exact into recovery evidence. Absent or `[]` denies even in dev-open mode. Invalid entries, duplicate tokens, or a token shared with an ordinary API key fail startup; token values are never logged. For rotation, temporarily configure two distinct tokens with the same actor ID, then remove the old token. |

### Authority elevation (external authority keys, T7)

These pin **external** authorities' published verifying keys so a generic record carrying a matching
`authority.source` + a verifying `evidence_sig` is **elevated** to that verified source at ingest
(else it is forced to the forgeable `caller_declared`, threat #4). Each key may be hex (64 chars) or
base64url-no-pad (optionally with the `ed25519pub:` prefix). The private half stays out of this
server — averin only **verifies**. **A bad pubkey or a duplicate-pinned (project, source) is fatal.**
The three valid sources are `policy_engine_signed`, `human_signed`, and `delegate_signed`.

Pins are keyed by **(project, source)**. An un-prefixed pin is the **global default** for that source
(the historical single-key behavior); a `project:`-prefixed pin applies to that averin project only and
**wins** over the global default. This matters because govder derives its authority signing key per
**(tenant, role)** and a govder tenant *is* an averin project: a deployment recording more than one
tenant MUST pin each tenant's key against its project, or every tenant but one has its
kill/approval/policy evidence rejected (or, under the explicit fail-open opt-out, silently sealed at
`caller_declared`). Derive a tenant's three pubkeys with
`GOVDER_AUTHORITY_SEED=... go run ./cmd/govder-derive-pubkeys <tenant>` in govder.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_POLICY_ENGINE_PUBKEY` | unset | No | Pins one **global** key for the source named by `AVERIN_POLICY_ENGINE_SOURCE`. Bad value ⇒ fatal. |
| `AVERIN_POLICY_ENGINE_SOURCE` | `policy_engine_signed` | No | The source the above key vouches for. |
| `AVERIN_HUMAN_SIGNED_PUBKEY` | unset | No | Pins one **global** key for the `human_signed` source (e.g. a separate human-approval service, signing with a different key than the policy engine). Bad value ⇒ fatal. |
| `AVERIN_DELEGATE_SIGNED_PUBKEY` | unset | No | Pins one **global** key for the `delegate_signed` source (govder's delegate-agent approval records). This is the third value `govder-derive-pubkeys` prints. Bad value ⇒ fatal. |
| `AVERIN_AUTHORITY_KEYS` | unset | No | General `[project:]source=pubkey,...` list (sources: `policy_engine_signed`, `human_signed`, `delegate_signed`). Without a `project:` prefix the key is the global default for that source; with one it is pinned for that project only. A malformed entry, an unknown source, an empty project, or a duplicate `(project, source)` is fatal. Pinning the **same** `(project, source)` twice across any of these forms is a fatal config error. |
| `AVERIN_REQUIRE_PINNED_AUTHORITY` | **`1` (on)** | No | **Fail-closed authority posture (the default).** A record that CLAIMS an elevated source (`policy_engine_signed`/`human_signed`/`delegate_signed`) whose `evidence_sig` fails to verify under the key pinned for its `(project, source)` — or whose source is **unpinned for that project** — is **REJECTED** with a retryable `500` instead of silently sealed downgraded to the forgeable `caller_declared`. `0`/`false` is the **explicit fail-OPEN opt-out** (restores the Phase-1 silent downgrade + a rate-limited WARNING + the `averin_authority_downgrades_total` counter) and logs a loud WARNING naming what that means; any other value is **fatal** (a typo must not select a security posture). Ordinary `caller_declared` traffic is never affected either way. |
| `AVERIN_REQUIRE_BODY_BOUND_AUTHORITY` | **`1` (on)**, off in dev mode | No | New generic ingest rejects elevated external authority claims without a complete v3 subject proof. Historical v2 exports remain readable as `legacy_unbound`. Local broker/resource builders always emit v3, and govder emits only v3. An explicit `0`/`false` is the migration opt-out for an old producer and logs a WARNING; feir-os sets `1` explicitly. Unknown values are fatal. |
| `AVERIN_REQUIRE_APPROVER_BINDING` | **`1` (on)**, off in dev mode | No | The server's own `/v2/verify` treats a govder approval whose signed evidence leaves out who approved (`decided_by` and the sign-off set) as a verification failure, not a note. The server pins the project's authority keys (the ones ingest elevates under) in that verification, so a govder record is read as verified and the policy can fire; with no authority key pinned the record is unverifiable and the policy has nothing to check. Export reuses the verdict only for its completeness wording and does not refuse on it. `AVERIN_APPROVER_BINDING_SINCE` (canonical `YYYY-MM-DDTHH:MM:SS.mmmZ`) keeps records received before it as history with a note, for a deployment that holds approvals sealed before approver binding. The offline CLI applies the same rule by default (`--allow-unbound-approvers` accepts history), but only for a record its `opts.json` pins the authority key for (`authority_keys`); without that key the record is unverifiable and no note or count is printed. opts.json can set `require_approver_binding` and `approver_binding_since`. |
| `AVERIN_SEAL_SHAPE` | `enforce` | No | `enforce` makes the core refuse to seal a record body that `verify_sealed` would reject on top-level shape (unknown or missing key), `domain` or `canon_version`, so every record averin seals in this mode passes those verifier checks (records stored before this change are not re-checked). It also makes the core refuse to seal a checkpoint body that `verify_checkpoint_sealed` would reject on `domain` or `canon_version` (checkpoints stored before that change are not re-checked; the chain checks of the bundle verifier still run only at verify time). `shadow` seals such a body anyway and counts it in `averin_seal_shape_violations_total` (records and checkpoints share the count); it is a rollback switch only, because every verifier rejects the records and checkpoints it writes, and the server logs a warning at startup. Values other than `enforce` or `shadow` are fatal. In `enforce` mode the generic `/v2/records` path also refuses an unknown top-level key with a `400` before anything is sealed (the key list is a Go mirror of the core's, pinned by a parity test); in `shadow` mode that early refusal is off. Applies to the signing core and the resource core. Does not check nested object shape. |

Every pinned authority key must be role-separated (it is rejected if it equals the server signing
key or the resource key, or if one key is reused across two **sources**; the same key across two
**projects** for the same source is allowed — the preimage binds `project_id`).

#### Migration: the fail-closed default (was off before)

`AVERIN_REQUIRE_PINNED_AUTHORITY` used to default to `0`, and no shipped config set it. Upgrading a
running deployment therefore **changes behavior** wherever a producer claims an authority averin cannot
verify: what was a silent downgrade-and-seal is now a `500` and no record. Before upgrading:

1. **Inventory the producers.** Only records whose `authority.source` is `policy_engine_signed`,
   `human_signed`, or `delegate_signed` are affected. Plain `caller_declared` traffic (SDKs, OTel spans)
   is not. `averin_authority_downgrades_total` on the running server counts exactly the records that
   would now be rejected — **if it is 0, the flip is a no-op for you.**
2. **Pin every producing (project, source).** For govder: run `govder-derive-pubkeys` **per tenant** and
   pin the three pubkeys with the `project:` prefix. `delegate_signed` in particular had no configuration
   path at all before this release, so any deployment recording delegate-agent approvals must add it.
3. **Only if you cannot align the pins immediately**, set `AVERIN_REQUIRE_PINNED_AUTHORITY=0` as a
   temporary, explicit step — and understand that kill/approval/policy evidence recorded in that mode is
   not cryptographically distinguishable from a forgery.

Whether or not the fail-closed toggle is on, a **failed** elevation increments
`averin_authority_downgrades_total` and emits a rate-limited `WARNING` naming the claimed source and
the pinned-key id — so a govder/averin key misalignment is visible in both metrics and logs.

### Checkpoint cut shadow check (no setting)

Checkpoints are cut incrementally (see LIMITATIONS, "Checkpoint cut is incremental, with a sampled shadow check").
The cut of checkpoint seq 100, 200, ... of each project, and the first incremental cut of each project after the
process starts, are also computed in full and refused if they differ. There is no environment variable
to turn this off. Alert on `averin_checkpoint_shadow_mismatch_total > 0`: a mismatch refuses that checkpoint
(`POST /v2/checkpoints` returns 500, "the incremental cut disagrees with the full computation"), logs a line
starting `ALERT`, and makes every later cut a checked cut until the process restarts, except while a project waits out the backoff after a shadow that could not run (below): that project's incremental body is then signed unchecked. The refused seq is retried as
the same seq and checked again, so a restart does not let it through.
`averin_checkpoint_shadow_checks_total` counts the checks that ran.

A shadow that cannot run does not refuse the checkpoint: if the full computation fails to read, hits the
statement timeout or runs out of the shadow's own time budget before it has produced a body, the incremental body (which passed its own count and
contiguity guards) is signed, `averin_checkpoint_shadow_failed_total` is incremented, a line starting `ALERT` is
logged, and that project's next shadow attempt waits for a backoff (10 minutes, doubling per consecutive failure
up to 64 times that, reset when a shadow runs). A full body that was computed but came back over budget is still compared: a mismatch refuses, a match is
signed and counted as failed (late) with the same backoff. The shadow's budget is 5 s by default and covers the
WHOLE shadow: on Postgres the statement timeout is re-issued with the time that remains before every statement,
so a checked cut never holds the project write guard for much longer than the budget (the ceiling is 20 s, below
the 30 s statement timeout). Neither value has an environment variable; they are the `WithCheckpointShadowBudget`
(ceiling 20 s) and `WithCheckpointShadowBackoff` options on the server. Alert on any non-zero rate of
`averin_checkpoint_shadow_failed_total`: it means the shadow has stopped being effective for that history size.

### Credential broker (Level 3 Tier-A — `POST /v2/grants`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_BROKER_ISSUING_SEED` (or `_FILE`) | unset ⇒ broker disabled | No | 64-hex (32-byte) Ed25519 seed; the key that signs the minted capabilities. Bad value ⇒ fatal. Unset ⇒ `POST /v2/grants` returns `501 Not Implemented`. The recording key for the grant's `gateway_enforced` evidence is the server's own signing key (Tier-A `broker_trust: assumed`). |
| `AVERIN_BROKER_ID` | unset | No | This broker's federation identity (ADR 0005 M4). When set, grants carry `grant_evidence.broker_id` and checkpoints carry a per-broker `broker_grant_heads` map (verify under `federated_broker_keys[<id>]`). Requires the broker. |

Broker sequence recovery uses an authenticated permanent database fence and has no age
setting. `AVERIN_BROKER_SEQ_VOID_MIN_AGE` is no longer read by the server. Deploy the
new writer credential only after the old-runtime session and credential cutoff in the
[operator runbook](../operator-verification.md).

### Online M-of-N cosign policy (`POST /v2/grants/prepare` + `/finalize`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_COSIG_APPROVER_KEYS` | unset ⇒ cosig off | No | Comma-separated base64url-no-pad Ed25519 approver pubkeys (optional `ed25519pub:` prefix). Requires the broker (fatal otherwise). Parsing to zero keys, or a malformed key, is fatal. When set, single-phase `POST /v2/grants` is refused (would bypass cosig) — issuance must use the two-phase prepare/finalize flow. |
| `AVERIN_COSIG_THRESHOLD` | = number of approvers | No | The M in M-of-N. Must be an integer in `[1, len(approvers)]`; otherwise fatal. |

### Resource gateway (Level 3 Tier-B — `POST /v2/use`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_RESOURCE_SEED` (or `_FILE`) | unset ⇒ `/v2/use` disabled | No | 64-hex (32-byte) Ed25519 seed for the resource recording key, which signs use-receipt evidence. **Must be role-separated**: distinct from `AVERIN_SIGNING_SEED` and `AVERIN_BROKER_ISSUING_SEED` (checked by derived pubkey — fatal on overlap). Requires the broker (fatal otherwise). Also enables `POST /v2/introspection` (native/STS, M3) with the raw resource key. |
| `AVERIN_RESOURCE_ID` | — | **Yes** when `AVERIN_RESOURCE_SEED` is set | This resource's audience id. Missing (with the seed set) ⇒ fatal. |

When the resource gateway is on, replay claims and the receipt use the configured
project Store transaction. PostgreSQL makes both durable; in-memory mode is
volatile and reopens a replay window on restart. `pgledger` runs the retention
sweeper and its own readiness probe, not a separate request-time claim path.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_LEDGER_RETENTION` | `720h` (30 days) | No | TTL for new Postgres nonce/JTI claims only. The hourly sweep never deletes unknown-owner legacy exclusions. This correctness floor must exceed the maximum accepted capability lifetime (one hour); below 24h or malformed is fatal. Legacy deletion is a separate, DB-time-gated maintenance operation. |

### Revocation authority (`POST /v2/revoke`)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_REVOCATION_SEED` (or `_FILE`) | unset ⇒ revocation off | No | 64-hex (32-byte) Ed25519 seed for the revocation issuer. Bad value ⇒ fatal. **Must differ from the signing/broker/resource seeds** (role separation) ⇒ fatal otherwise. When set, `POST /v2/revoke` marks a `grant_id` revoked and every `/v2/export` carries a signed, time-bounded `revocation_list`. The revoked set (and, when the M6/M2 online two-phase grant flow is used, the pending prepare→finalize mint state) is **durable Postgres-backed** if `AVERIN_DATABASE_URL` is set — a revoke or an in-flight cosig/delegation approval survives a pod restart or `SIGTERM` — else in-memory only (a revoke issued or a mint prepared just before restart is forgotten). |
| `AVERIN_REVOCATION_EXPORT_FORMAT` | `v1` | No | Plan 009. `v1` exports the legacy total-only `revocation_list` and refuses prospective revocations. `v2` exports `averin.revocation.list.v2` (per-grant mode and cutoff plus the signed database snapshot) and lets `POST /v2/revoke` accept `"mode":"prospective"`. Requires `AVERIN_REVOCATION_SEED`. Pre-plan-009 verifiers reject v2 lists, so switch only after upgrading every relying verifier (reader-first). Any other value is fatal. |

### Operational hardening (prod secret gate, egress scrubbing, graceful shutdown)

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_REQUIRE_PROD_SECRETS` | **`1` (on)**, off in dev mode | No | **Fail-closed prod gate, on by default.** Refuses to start unless `AVERIN_API_KEYS` is set (else the app API would be refused or open), `AVERIN_DATABASE_URL` is set (else the store would be volatile in-memory, reopening a `/v2/use` replay window), and `AVERIN_SIGNING_SEED` is **not** the well-known committed dev seed (a globally-known, forgeable integrity root). Any of the three missing/failing is fatal (`log.Fatal`, names each missing one). The gate is turned off only by `AVERIN_DEV_MODE=1` (then `AVERIN_REQUIRE_PROD_SECRETS=0` is also accepted); `AVERIN_REQUIRE_PROD_SECRETS=0` outside dev mode is refused at startup. Mirrors govder's `GOVDER_REQUIRE_AUTHORITY_SEED` and leria's `LERIA_REQUIRE_PROD_SECRETS`. feir-os sets `1` explicitly. |
| `AVERIN_SECRET_PATTERNS` | unset ⇒ built-in patterns only | No | JSON string array of extra RE2 regexes, atomically appended to the built-in credential-scrubbing rules (`server/internal/scrub`) that redact provider API keys, PEM private keys, JWTs, `Bearer`/`Basic` auth, generic `key: value` secrets, and high-entropy hex. In `averin-server` the scrubber runs only on the OTel ingest path (`POST /v2/otel/traces`), before the record is stored or hashed; records sent to `POST /v2/records` (the SDK and raw HTTP path) are not scrubbed. `averin-proxy` scrubs what it captures with the built-in rules only: it does not read this variable. Each match is replaced with `[REDACTED:configured]`. **A malformed pattern (bad regex) is fatal at startup** — a typo must not silently create a secret-capture gap. Scrubbing is defense-in-depth (RE2 is linear-time / no ReDoS, but cannot catch every secret shape); the primary protection is that self-hosted data never leaves customer infra. |
| `AVERIN_SHUTDOWN_TIMEOUT` | `25s` | No | Graceful-drain deadline on SIGINT/SIGTERM: `http.Server.Shutdown` lets in-flight requests (and, with `AVERIN_DATABASE_URL` set, the cross-request prepare→finalize window) finish before exit, then closes the store pool, all within this deadline. An unparseable or non-positive value logs a warning and keeps the default. **Must stay under the orchestrator's stop grace** (no Kubernetes manifest ships with averin, so set `terminationGracePeriodSeconds` above this yourself; the shipped docker-compose file sets `stop_grace_period: 30s` for the server) or the process is SIGKILLed mid-drain. `averin-proxy` reads the same variable with a different default (`60s`, below, it streams long completions and needs more room to drain). |

### Storage and rate controls (quota, ingest limiter, denied-grant log)

The record store is append-only (nothing can be deleted), so growth is bounded by admission control:

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_PROJECT_MAX_RECORDS` | unset (no cap) | No | Per-project cap on stored records of every kind (evidence, grants, receipts, denials). The count is read inside the project write transaction, so the cap is exact even with several replicas; a write that would pass it is refused with `507` and stores nothing, an idempotent replay still succeeds, reads are unaffected. A batch `POST /v2/records` is processed item by item, so the items that fit stay stored. Counted in `averin_quota_rejections_total`. `GET /v2/usage?project=` shows the count and the cap. The cap is on record **count**, not bytes: the bound is the cap times the per-record body limit. A negative or non-numeric value is fatal. |
| `AVERIN_INGEST_BUDGET` | unset (off) | No | Coarse token-bucket rate limit on state-mutating `POST /v2/*`: `1` turns it on with the defaults, or a JSON object `{"per_project_per_sec":50,"per_project_burst":200,"global_per_sec":500,"global_burst":2000,"max_projects":4096}` (omitted fields take those defaults). A saturated bucket answers `429` with `Retry-After`; reads pass. Unknown fields and negative values are fatal. |
| `AVERIN_DENIED_GRANT_LOG` | `0` (off) | No | `1` seals a tamper-evident record for every policy-refused grant request. It always runs with a rate budget so a varying-scope probe cannot inflate storage. |
| `AVERIN_DENIED_GRANT_BUDGET` | defaults | No | The denial-seal budget: `1`/unset for the defaults, or a JSON object with the same fields as `AVERIN_INGEST_BUDGET` (defaults 5/s and 50 per project, 50/s and 500 global). Setting it without `AVERIN_DENIED_GRANT_LOG` is fatal. |

Still operator work: a reverse-proxy or gateway rate limit in front of averin remains the primary control
against a leaked token, and database size and the quota rejection counter should be monitored. See
[LIMITATIONS.md](LIMITATIONS.md).

> Note: the server library options `WithAttestation` (deployment-attestation export) and
> `WithCoverageManifest` (the operator-declared `side_effect_closure`, required for the
> `attested_complete_over_brokered_surface` capstone) are both set by `averin-server` env vars,
> `AVERIN_ATTESTATION_SEED` and `AVERIN_COVERAGE_MANIFEST` (see the storage table above).

---

## `averin-proxy` (`server/cmd/averin-proxy`)

OpenAI-compatible reverse proxy that records `llm_call` evidence to a averin server.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_UPSTREAM` | `https://api.openai.com` | No | Upstream LLM base URL. |
| `AVERIN_SERVER_URL` | `http://localhost:8080` | No | The averin server to record evidence to. |
| `AVERIN_PROJECT_ID` | `default` | No | Project the proxied calls are recorded under. |
| `AVERIN_PROXY_ADDR` | `:8081` | No | Inbound listen address. |
| `AVERIN_PROXY_AVERIN_TOKEN` | unset | No | API token used when recording to the averin server (needed if the server has `AVERIN_API_KEYS` set). |
| `AVERIN_PROXY_INBOUND_TOKEN` | unset | No | If set, inbound auth is REQUIRED (`X-Averin-Proxy-Token` or `Authorization: Bearer`). **Unset ⇒ OPEN RELAY + evidence-injection surface** (logs a WARNING — bind to loopback or place behind your own auth). |
| `AVERIN_SHUTDOWN_TIMEOUT` | `60s` | No | Graceful-drain deadline on SIGINT/SIGTERM: `http.Server.Shutdown` lets active streamed completions finish before exit (an instant kill would cut an agent's in-flight response). Longer than `averin-server`'s default (25s) since completions stream. An unparseable or non-positive value logs a warning and keeps the default. Must stay under the orchestrator's stop grace. |

---

## `averin-mcp` (`server/cmd/averin-mcp`)

Experimental MCP server over stdio, exposing averin to agents as tools.

| Variable | Default | Required | Behavior |
|----------|---------|----------|----------|
| `AVERIN_SERVER_URL` | `http://localhost:8080` | No | The averin server the MCP tools call. |
| `AVERIN_API_TOKEN` | unset | Outside dev mode | Sent as a Bearer token on every call. A server outside `AVERIN_DEV_MODE=1` refuses requests without one; the token needs the `write` role for `record_decision`. |

---

## `averin-taxonomy` (`server/cmd/averin-taxonomy`)

CLI tool that mints a **signed operation taxonomy** artifact (D4). Flags (`flag` package):

| Flag | Default | Meaning |
|------|---------|---------|
| `-key` | — | Taxonomy issuer signing key: 64 hex chars (a 32-byte Ed25519 seed). |
| `-key-file` | — | Owner-only regular file (mode `0600`) containing the 64-hex seed. Exactly one of `-key` or `-key-file` is required; deployments should use the file form so the seed never enters argv. |
| `-version` | `1` | Taxonomy version (bump to rotate; pinned as `taxonomy_version`). |
| `-from` | `0` | `effective_from`, unix seconds. |
| `-until` | `0` | `effective_until`, unix seconds (must be `>= from`). |
| `-out` | stdout | Write the signed taxonomy JSON here. |
| `-single` | — | A `single_operation` entry `resource_id=action` (repeatable). |
| `-escalating` | — | An escalating entry `resource_id=action` (repeatable). |
| `-verify` | off | Verify mode: no key is used and nothing is signed. Checks `-file` against `-pubkey`, `-digest` and `-version` and exits 0 only when the RCP digest, the version and the `averin.taxonomy.v1` signature all match; any mismatch (or an unsigned, malformed or tampered artifact; the raw bytes are parsed as the runtime verifier parses them, so a duplicate key, trailing data, a lone surrogate or a malformed action list is refused) exits 1. Prints `taxonomy verify: OK (version, digest)`, never key material. The verifier's own check downgrades the same mismatch to a quiet `taxonomy_status: untrusted`; this mode makes it an error. It does not judge the effective window. |
| `-file` | none | With `-verify`: the signed taxonomy artifact. |
| `-pubkey` | none | With `-verify`: the pinned issuer key `ed25519pub:...` (a comma list is accepted). |
| `-digest` | none | With `-verify`: the pinned `taxonomy_digest` (`sha256:...`). |

Build note: the tool is cgo and links the Rust staticlib, so build `cargo build -p averin-decision-core` first. On a
glibc older than 2.34 add `CGO_LDFLAGS='-ldl -lm'`.

---

## `averin-verify` CLI (`core/src/bin/averin_verify.rs`)

Not env-configured; arguments only:

```
averin-verify bundle <bundle.json> [opts.json] [--allow-unbound-approvers]    # full offline verification
averin-verify record <record.json> [ed25519pub:<key>]   # single record (CONSISTENT, or PASS with the signer's key)
```

`bundle` fails a govder approval whose signed evidence does not commit who approved (an issue, so FAIL),
prints the reason and a count of such approvals under the issues, and exits 1. `--allow-unbound-approvers`
accepts approvals sealed before approver binding as history (they are still counted and noted). `opts.json` may set
`require_approver_binding` (boolean) and `approver_binding_since` (a canonical timestamp: records received before
it stay history), which then override the flag.

With `opts.json`, the role-disjoint authority key sets are pinned (authentic verification + the
mode gates). The `opts.json` keys are documented in [`../operator-verification.md`](../operator-verification.md):
`broker_authority_keys`, `resource_authority_keys`, `tsa_keys`, `taxonomy`/`taxonomy_keys`/
`taxonomy_digest`/`taxonomy_version`, `attestation_keys`, `cosig_approver_keys`, `revocation_keys`,
`federated_broker_keys` (a `{broker_id: [keys]}` map), and `authority_keys`. For `bundle`, the `RESULT:` word
is the same `claimVerdict` rule as the browser verifier and web app. `bundle` exit codes: `0` PASS (requested
claim satisfied AND signing keys externally pinned), `2` CONSISTENT (requested claim satisfied only
under the bundle's own unpinned keys: internal consistency, not authenticity), `1` FAIL (legacy `ok`
false or requested claim refuted) or INSUFFICIENT (requested claim not satisfied, or the claims
contract is missing or invalid). Usage and unreadable-file errors also exit `2` and print no
`RESULT:` line, so read the `RESULT:` line, not only the exit code, to tell CONSISTENT from a usage
error. Without `opts.json`, a bundle that is not valid JSON or RCP exits `1` and prints no `RESULT:`
line (with `opts.json` it reads `RESULT: FAIL`, as does an invalid `opts.json`). Before this change
the CLI printed PASS and exited 0 for unpinned bundles.

`record` prints a `RESULT:` line with the same words and exit codes: `0` PASS only when a key was
passed on the command line and shape, content hash and signature verify under it (`PASS
(authentic)`); `2` CONSISTENT when no key was passed and shape and content hash check out
(`CONSISTENT (integrity only)`: nothing authenticated the record); `1` FAIL when a check fails or the
file is not valid JSON or RCP. A usage error, an unreadable file or a malformed key also exits `2`
with no `RESULT:` line, so read the `RESULT:` line here too. Before this change a keyless record
printed `PASS (integrity only)` and exited `0`.

---

## Docker Compose extras (`deploy/docker-compose.yml`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `AVERIN_DB_SUPERUSER_PASSWORD`, `AVERIN_DB_OWNER_PASSWORD`, `AVERIN_DB_RUNTIME_PASSWORD` | **none, set all three** | Three Postgres passwords, passed to the `db` service as compose secrets: the bootstrap superuser (first-boot init only, never used by averin), `averin_owner` (the migration identity used by the one-shot `migrate` and `grants` services) and `averin_app` (the least-privilege runtime identity in the server's `AVERIN_DATABASE_URL`). Compose uses `:?` for the owner and runtime passwords, so `docker compose up` refuses to start without them. |
| `AVERIN_SIGNING_SEED` | **none — required** | Server signing seed. Compose uses `${AVERIN_SIGNING_SEED:?...}`, so `docker compose up` refuses to start without it; generate a fresh one with `openssl rand -hex 32`. |
| `AVERIN_API_KEYS` | **none, required** | The server's project API keys (compose uses `${AVERIN_API_KEYS:?...}`); the server refuses to start without them. |
| `AVERIN_PROXY_AVERIN_TOKEN` | **none, required** | The write (or admin) token for `AVERIN_PROJECT_ID` that the proxy records with. Must be one of the tokens in `AVERIN_API_KEYS`. |
| `AVERIN_PROXY_INBOUND_TOKEN` | **none — required** | Inbound auth token for `averin-proxy`. Compose uses `${AVERIN_PROXY_INBOUND_TOKEN:?...}`, so the stack refuses to start without it (without it the proxy would be an open relay); generate one with `openssl rand -hex 24`. |
| `AVERIN_UPSTREAM` | `https://api.openai.com` | Overrides the proxy's upstream LLM base URL. |
| `AVERIN_PROJECT_ID` | `default` | Overrides the project the proxied calls are recorded under. |

`stop_grace_period` is set per service to exceed `AVERIN_SHUTDOWN_TIMEOUT`'s default for that
binary (`server`: 30s > the 25s default; `proxy`: 65s > the 60s default) — raise both together if
you override `AVERIN_SHUTDOWN_TIMEOUT`.
