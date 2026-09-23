# Architecture, core concepts & algorithms

averin is a tamper-evident evidence service. Agents (or a proxy/SDK) submit observed event records;
averin canonicalizes, hash-chains, and signs them into a per-session causal DAG, periodically commits
the frontier into a hash-chained checkpoint chain, and exports a bundle that anyone can verify
**offline** — re-deriving every hash, signature, and link with no trust in the server.

## Components

```
                    ┌─────────────────────────────────────────────┐
   agent / SDK ───▶ │  averin-server (Go, internal/api)             │
   proxy / OTel     │   ingest · DAG-link · seal · checkpoint     │
                    │   broker · resource gateway · export        │
                    └──────────────┬──────────────────────────────┘
                                   │ cgo
                    ┌──────────────▼──────────────────────────────┐
                    │  averin-decision-core (Rust)                  │   ← single source of truth
                    │  canon · commit · record · sign · dag ·     │     for ALL crypto
                    │  checkpoint · verify · rfc3161 · ffi        │
                    └──────────────┬───────────────┬──────────────┘
                          staticlib │               │ wasm32
                              (FFI) │               │
                    ┌──────────────▼──┐    ┌────────▼──────────────┐
                    │  averin-verify CLI │    │  /verifier/ (browser) │
                    └──────────────────┘    └───────────────────────┘
```

The **Rust core is the single source of truth**: the Go server, the CLI, and the browser verifier
all execute the *same* canonicalization, hashing, signing, and verification code. The Go server
never re-implements crypto — it calls the core via cgo (the `server/internal/core` cgo bridge links
`target/debug/libaverin_decision_core.a`). This is what makes "verify offline, in your browser, on CI,
and on the server" produce byte-identical results, and why the toolchain is pinned (`rust-toolchain.toml`).

Core modules (`core/src/`):

| Module | Owns |
|--------|------|
| `canon.rs` | RCP v1 — the byte-for-byte JSON canonicalization engine. |
| `commit.rs` | Hiding commitments for low-entropy fields. |
| `record.rs` | Record content-hash preimage, schema-v2 shape, seal/verify. |
| `sign.rs` | Domain-tagged Ed25519 sign/verify; key encoding. |
| `dag.rs` | Causal DAG build, duplicate collapse, head/frontier derivation. |
| `checkpoint.rs` | Checkpoint hash + chain verification (fork/omission/gap). |
| `verify.rs` | The full bundle verifier + the typed report + the mode gates. |
| `rfc3161.rs` | RFC 3161 (DER/CMS) timestamp-token parsing (feature `rfc3161`). |
| `anchor.rs` | Anchor join helpers. |
| `ffi.rs` / `b64.rs` / `hashx.rs` | the C ABI, base64url, length-prefix hashing. |

## Core algorithms

### 1. RCP canonicalization (`canon.rs`)

averin defines and implements its own canonical JSON profile (Record Canonical Profile v1; see
`spec/rcp-v1.md`) rather than reusing a lenient library, because the integrity guarantee requires
behaviors general-purpose JSON does not give:

- post-NFC **duplicate-key rejection** and **lone-surrogate rejection**,
- **integers only** (`i64`; floats and out-of-range integers are hard-rejected),
- byte-exact escaping and **UTF-16 code-unit key ordering**,
- interior-NUL rejection (so untrusted input can't be silently truncated into a prefix-only "ok").

Any divergence here is verifier skew (threat #10); the golden vectors in `spec/golden-vectors/` are
the contract that the Rust, WASM, and FFI builds agree byte-for-byte.

### 2. Content hash (`record.rs`)

A record's `content_hash` is a domain-separated digest of its canonical body minus the
`content_hash`/`sig` fields:

```
content_hash = "sha256:" + hex( SHA-256( LP(domain) ‖ LP(canon_version) ‖ RCP-serialize(body \ {content_hash, sig}) ) )
```

where `LP(s)` is a 4-byte big-endian length prefix of the UTF-8 string. Binding `domain` +
`canon_version` into the preimage means a body cannot be reinterpreted under a different profile.

### 3. Signature (`sign.rs`)

```
sig = "ed25519:" + base64url-no-pad( Ed25519( sk, LP(tag) ‖ utf8(content_hash) ) )
```

The domain tag (`averin.record.sig.v1` for records, `averin.checkpoint.sig.v1` for checkpoints) prevents
cross-context signature reuse. Public keys are encoded `ed25519pub:<base64url-no-pad>`. Authority and
attestation evidence use their own tags (`averin.attestation.v1`, etc.).

### 4. Hiding commitments (`commit.rs`)

Low-entropy fields (`input`/`output`/`rationale`) are never stored in the signed body — a short
plaintext would otherwise be recoverable by a hash dictionary (threat #6). Instead the server mints a
32-byte nonce and commits:

```
commitment = "sha256:" + hex( SHA-256( LP("averin.commit.v1") ‖ LP(field_domain) ‖ LB(nonce) ‖ LB(value) ) )
```

The signed record carries `{alg, commitment, low_entropy}`; the plaintext goes to the content store
(encrypted at rest — see [Storage model](#storage-model)). A disclosing export reveals `(value,
nonce)`, which the offline verifier recomputes and compares (constant-time) against the record's
commitment. The record's own exported reference to the payload
(`extensions.feir_evidence.payloads[field]`) is the hiding commitment, never a plain content digest,
so nothing in the always-exported body is dictionary-reversible.

### 5. Causal DAG (`dag.rs`)

Records form a per-session DAG keyed by `content_hash`. On ingest the server reads the session's
current **heads** (records referenced by no other record's `causal_prev_hashes`) and links the new
record to them — server-derived, never client-trusted. Building the DAG:

1. index records by `content_hash`, **collapsing exact duplicates** (identical bytes ⇒ identical
   hash ⇒ one node; the count is reported as `collapsed_duplicates`, defending retry-duplication,
   threat #8);
2. validate each parent reference resolves;
3. derive **heads** = nodes nobody references, de-duplicated and byte-sorted (the RCP §10 frontier).

The frontier is the input to checkpointing.

### 6. Checkpoint chain (`checkpoint.rs`)

A checkpoint seals the current frontier into a hash-chained chain (`prev_checkpoint_hash`). The
`checkpoint_hash` preimage strips `{anchor, checkpoint_hash, sig}`, so an anchor attached *later* (at
export) does not change the hash. The verifier enforces, over the whole bundle:

- first seq is `0` with a null prev; **no seq gaps**;
- **no fork** — two distinct checkpoints sharing a seq, or a prev, is threat #2;
- `record_count` never decreases;
- every frontier head named by a checkpoint is **present** in the bundle (omission, threat #1);
- the **latest** checkpoint's frontier equals the actual DAG heads (no uncommitted/omitted session).

This is why a fresh record reports `ok:false` until you cut a checkpoint over it — the latest
frontier is uncommitted.

### 7. Offline bundle verification (`verify.rs`)

`averin-verify bundle <bundle.json> [opts.json]` (and the WASM/FFI entrypoints) re-derive everything
from the bundle alone. **Two postures:**

- **Internal consistency** (no `opts`): every hash recomputes, every signature checks against the
  bundle's *own* key claims, the DAG and checkpoint chain are consistent. Proves integrity +
  omission/fork/tamper, **not** authenticity against an out-of-band root.
- **Pinned (authentic)** (`opts.json`): the above plus every role's evidence verifies under the
  role-disjoint keys *you* pinned out-of-band — which unlocks the Tier-A/Tier-B and ADR-0005 mode
  gates (cosig, revocation, federation, native introspection, attestation, taxonomy) and the
  `attested_complete_*` capstone. The role key sets MUST be pairwise disjoint (a shared key is a
  fatal config error). See [`../operator-verification.md`](../operator-verification.md).

The verdict is a typed report (see [API.md → Verification report](API.md#verification-report)). PASS
is integrity-level; the capstone is the higher, separately-stated claim.

### Formal model

Algorithms 1–6 have a Lean 4 counterpart in [`formal/lean/Averin/`](../../formal/lean/Averin):

| Algorithm | Model | Proof |
|---|---|---|
| 1 | `Canon.lean` | `ser_injective` |
| 2, 3 | `Preimage.lean`, `Seal.lean` | `record_seal_sound`, `checkpoint_seal_sound`, `signed_families_disjoint` |
| 4 | `Seal.lean` | `commitment_binding` |
| 5 | `Dag.lean` | `bundle_eq_closure` |
| 6 | `Chain.lean` | `unique_history` |

The executable Lean oracle (`formal/lean/Oracle`, checked by `core/tests/oracle.rs`) and the tag
inventory in `formal/check-refinement.py` keep the models in step with this code; `formal/check-mutants.sh`
checks that those gates catch known drifts. Algorithm 7's verdict logic
is covered by the adversarial suite; it is not formally modelled yet.

## Domain model

- **Record** — one observed event (schema v2, closed top-level key set). Carries identity
  (`record_id`, `agent_id`, `session_id`, `span_id`), causal links (`causal_prev_hashes`), the
  `authority` block, optional hiding-committed fields, and the seal (`content_hash`, `sig`, `key`).
- **Authority** — *under whose declared (and, where a key is pinned, verified) authority* an action
  happened. `source` defaults to the forgeable `caller_declared`; an evidence triple
  (`evidence_hash`/`evidence_sig`) that verifies under the key pinned for the record's
  `(project_id, source)` elevates to `policy_engine_signed` / `human_signed` / `delegate_signed` /
  `gateway_enforced`. The triple is project- and record-id-bound so it can't be replayed. A claimed
  elevation that fails verification is **rejected at ingest** by default, not sealed downgraded.
- **Session DAG** — the causal history for one `(project, session)`.
- **Checkpoint** — a signed, hash-chained commitment to a frontier at a point in time; the "as-of"
  line, optionally RFC 3161-anchored.
- **Grant / Capability / Use receipt** — the credential broker (Tier-A) records a `gateway_enforced`
  grant before issuing a sender-constrained, single-use (or bounded-reuse) capability; the resource
  gateway (Tier-B) validates the capability + proof-of-possession at use time, consumes it before
  acting, and seals a resource-signed use receipt the verifier joins back to its grant.
- **Bundle** — the export: records + checkpoint history + public keys (+ anchors/disclosures/
  attestation/revocation as configured).

## Storage model

The `store.Store` interface (`server/internal/store/store.go`) has two implementations:

- **In-memory** (`store.NewMem`) — default. Correct within one process but **NOT durable** (lost on
  restart) and the `heads → seal → put` ingest path is not a single atomic transaction. Dev /
  single-process only.
- **Postgres** (`store.NewPostgres`, selected when `AVERIN_DATABASE_URL` is set) — **append-only at the
  database** (the migration `REVOKE`s UPDATE/DELETE/TRUNCATE, verified under a least-privilege role),
  with idempotency + content-hash collapse + a DAG-derived frontier computed in SQL. A single versioned
  migration (`server/internal/pgschema`, advisory-lock-guarded, folding the store + ledger + durable
  schemas under one `schema_migrations` version) auto-applies on first startup (`docker compose up` is
  turnkey); a steady-state boot issues zero DDL, and a DB newer than the binary is a fail-closed refusal
  to start. See CONFIGURATION.md → "Schema versioning & upgrades".

  **Single-writer-per-project, in-process only (NOT a DB serializable transaction).** The `heads → seal
  → put` ingest critical section is serialized by a **process-local mutex** (`ingestMu` in
  `server/internal/api/server.go`), so concurrent ingests within ONE server process cannot read a stale
  frontier and fork the DAG. `PutRecord` itself runs at Postgres's default (read-committed) isolation —
  it is NOT a `SERIALIZABLE` transaction. The only DB-level advisory lock (`pg_advisory_xact_lock`,
  `store/postgres.go` `AllocateBrokerSeq`) covers **broker_seq allocation**, not the record frontier.
  **Consequence (deploy-critical):** running **two averin replicas against the same
  `AVERIN_DATABASE_URL` can silently fork a project's DAG** — the in-process mutex does not span
  processes. Run averin as a **single writer per project** (one replica, or shard projects across
  replicas so no project is written by more than one). A real cross-replica frontier lock is a DEFERRED
  item; see `docs/dev/LIMITATIONS.md`.

Append-only is the integrity invariant: records are written once, keyed by `(project, idempotency
key)`; a retry collapses onto the existing row rather than duplicating. Disclosure secrets are
written **atomically** with the record they open. The Rust core never touches storage — it only
canonicalizes/seals/verifies the bytes the store persists.

The raw low-entropy payloads (`input`/`output`/`rationale`) live in a **separate content store**
(`content.Store`), not in `store.Store`. Its durable implementation (`content.EncryptedFSStore`,
selected by `AVERIN_CONTENT_DIR`) is content-addressed by the plaintext SHA-256 but stores each blob
**AES-256-GCM encrypted at rest** under a per-tenant subdirectory; the per-tenant key is HMAC-derived
from `AVERIN_CONTENT_MASTER_KEY` with tenant+digest bound as GCM AAD. A daily retention purge
(`AVERIN_RAW_RETENTION_DAYS`, mtime-based; re-committing identical content restarts the window)
deletes the raw opening material while the sealed record keeps its commitment — so a purged field
just drops out of `disclosures` and the export reports `raw_content_available:false`, proofs
unaffected. Unset ⇒ an in-memory content store (volatile).
