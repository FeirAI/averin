# Operator guide: offline verification + role-disjoint key pinning

averin's guarantees are enforced **offline**, by a verifier that needs no server. A bundle
(`GET /v2/export`) carries the records, the checkpoint history, and the public keys; the verifier
re-derives every hash, signature, DAG edge, checkpoint chain, anchor, and the Tier-B / ADR-0005 mode
gates from the bundle alone. The server is never in the trust path.

There are two verification postures:

| Posture | How | Proves |
|---|---|---|
| **Internal consistency** | `averin-verify bundle b.json` (no opts) | the bundle is self-consistent under **its own** key claims — integrity, DAG, checkpoint chain, omission/fork/tamper. It does **not** authenticate against an out-of-band trust root. |
| **Pinned (authentic)** | `averin-verify bundle b.json opts.json` | the above **plus** every role's evidence verifies under the keys **you** pinned out-of-band, which is what unlocks the Tier-B / mode gates (cosig, revocation, federation, native, attestation, taxonomy) and the `attested_complete_*` capstone. |

Browser (`/verifier/`) and FFI (`core.VerifyBundleWith`) take the same `opts` object.

## The role-disjoint key sets (`opts.json`)

Each set authorizes exactly **one** role. They **MUST be pairwise disjoint** — a key shared across
two roles is a **fatal configuration error** (the verifier aborts), because it would let one authority
sign across a role boundary (e.g. a broker self-attesting, or a resource self-validating a taxonomy).
Pin only the sets you want to enforce; an omitted set leaves that mode `unevaluated`/`absent`
(fail-closed — it never silently passes).

```jsonc
{
  // AUTHENTICITY: the record-signing key(s). Omitted => internal consistency only (keys from the bundle);
  // an EMPTY [] is a config error. Each entry is a string or an RCP §10.2 object carrying the authoritative
  // compromise time: {"key": "ed25519pub:…", "status": "compromised", "status_changed_at": "…"}
  // (status: active | retired | revoked | compromised). A record OR checkpoint signed by a revoked/compromised
  // key is trusted only if a verified anchor at or before status_changed_at commits it. MAY equal the
  // broker/authority keys (ADR 0002); must be disjoint from every other role.
  "signing_keys": ["ed25519pub:<record-signing-key>"],

  // Tier-A grant accountability (ADR 0002/0003): the credential broker's recording key(s).
  "broker_authority_keys": ["ed25519pub:<broker-recording-key>"],

  // Tier-B use receipts (ADR 0003 R2): the resource gateway's recording key(s). Also the M3
  // native introspection-transcript signer (averin.resource.introspection.v1).
  "resource_authority_keys": ["ed25519pub:<resource-recording-key>"],

  // D3/D7 time anchoring: the TSA key(s) (or "tsa_spki_b64" for an RFC 3161 TSA's DER SPKI).
  "tsa_keys": ["ed25519pub:<tsa-key>"],

  // D4 operation taxonomy (MF5): the SIGNED taxonomy artifact + its issuer key(s) + the pinned
  // content digest + version it must match to reach `validated` (a signed-but-unpinned taxonomy stays untrusted).
  "taxonomy": { /* the signed taxonomy doc */ },
  "taxonomy_keys": ["ed25519pub:<taxonomy-issuer-key>"],
  "taxonomy_digest": "sha256:<digest of the taxonomy minus sig>",
  "taxonomy_version": 1,

  // D7 deployment attestation: the attestation issuer key(s) (role-separated, so a broker/resource cannot self-attest).
  "attestation_keys": ["ed25519pub:<attestation-issuer-key>"],

  // M6 Cosig: the M-of-N grant-approval GOVERNANCE keys. A grant declaring cosig_threshold is
  // Tier-B-eligible only if >= M distinct keys here cosigned it.
  "cosig_approver_keys": ["ed25519pub:<approver-1>", "ed25519pub:<approver-2>"],

  // M5 Revocation: the revocation issuer key(s) (role-separated, so a broker cannot sign its own
  // revocation). Covers BOTH the disclosed `revocation_list` AND the Merkle-non-disclosure
  // `revocation_merkle_root` (each verified under this same role). For the Merkle variant the bundle ALSO
  // carries `revocation_merkle_root` + a `revocation_proofs` map (see "Producing the optional artifacts").
  "revocation_keys": ["ed25519pub:<revocation-issuer-key>"],

  // M4 Federation (per-broker_id authority): a MAP of broker_id -> its authority key set. When set,
  // a grant carrying that broker_id elevates ONLY under its own broker's keys. Every set above must be
  // disjoint from the UNION of all per-broker sets too.
  "federated_broker_keys": { "broker-A": ["ed25519pub:<A>"], "broker-B": ["ed25519pub:<B>"] },

  // Generic non-broker authority (policy engine / approval service) for BrokerRole::None records. MAY
  // equal broker_authority_keys (self-host), but must be disjoint from every other role.
  "authority_keys": ["ed25519pub:<policy-engine-key>"]
}
```

All keys are base64url-no-pad ed25519 public keys with an `ed25519pub:` prefix (the form
`averin-server` logs at startup, and the form `core.PubKey()` returns).

## Rotating / retiring a compromised role key (ADR 0006 §1)

If you learn (out of band — a key-transparency record, an incident) that one of your pinned **authority** keys
was **compromised** or **rotated** at a point in time, pin its lifecycle so grants/uses that key elevated
*after* that point stop counting — without throwing away the legitimate ones it signed *before*. Replace the
bare `"ed25519pub:…"` string with an object:

```jsonc
{
  "broker_authority_keys": [
    { "key": "ed25519pub:<broker-key>",
      "status": "compromised",                       // active | rotated | compromised | revoked
      "status_changed_at": "2026-06-15T10:05:00.000Z" } // RCP timestamp (fixed-ms UTC)
  ]
}
```

Semantics: a grant/use whose authority verified under a non-`active` key keeps `gateway_enforced` **only if it
was transitively committed by a verified anchor at or before `status_changed_at`** (it predates the
compromise). Otherwise its elevation is **withdrawn** — a *use* of a withdrawn grant then fails to match (a
violation, `ok:false`); an unused grant simply drops to unaccountable. The status is **authoritative**: it
comes from *your* opts, never the bundle, so a forger cannot self-assert it. A non-active status with **no**
`status_changed_at` (or an unanchored record) withdraws **unconditionally** (fail-closed — an undatable
compromise cannot be proven to predate anything).

The object form works for **every** role key (`signing_keys` uses the RCP §10.2 `key_status` vocabulary —
`active|retired|revoked|compromised` — see the options block above). The exact rule differs by what the role signs:

- **Authority-elevation** (`broker_authority_keys`, `resource_authority_keys`, `authority_keys`, each
  `federated_broker_keys` set) and **`cosig_approver_keys`** — the signed artifact is committed by an anchor, so
  a `compromised`/`rotated`/`revoked` key is honored for anything anchored **at or before** `status_changed_at`
  (the anchor proves it predates the compromise). A `federated_broker_keys` rotation also gates a transitive
  `cross_broker_cert` grant by the **issuer** key's lifecycle. A non-honored approver's approval stops counting
  toward the M-of-N threshold.
- **`attestation_keys`, `revocation_keys`, `tsa_keys`** — the signed artifact carries a SELF-asserted time a
  stolen key could forge, so `compromised`/`revoked` is **never** honored; only `rotated`, and only for an
  artifact whose own time is `≤ status_changed_at`. Effects: a non-honored **attestation** issuer →
  `attestation_status:failed`; a non-honored **revocation** issuer → `revocation_status:stale` (the listed
  revocations still block — they are never un-honored), `ok:false`; a non-honored **TSA** key → its anchors are
  distrusted, so the checkpoint is treated as un-anchored (this is what stops a stolen TSA key from backdating).
- **`taxonomy_keys`** — your `taxonomy_digest` pin already binds the exact artifact, so rotation is
  defense-in-depth: `compromised`/`revoked` → the taxonomy is `untrusted`; `rotated` keeps the digest-pinned
  taxonomy valid.

> **Fail-closed, not silent.** An UNKNOWN status, a misspelled field name, or an empty `signing_keys` array
> is a **parse error** (never silently read as `active`) — you can never get false comfort that a rotation took
> effect when it didn't.

## What each mode means in the report

- `grant_accountability` — every credential grant verified under `broker_authority_keys` (Tier-A).
- `broker_trust: sequence_verified` — the grant-transparency log is a gapless, anchored prefix (D6); no suppression.
  A `grant_void` tombstone (see below) fills its seq in that prefix but is never counted as a grant; a malformed,
  unbound or (under pinned `broker_authority_keys`) unsigned tombstone, or a grant claiming a voided seq, is a hard
  failure.
- `cosig_status: satisfied` — every cosigned grant met its M-of-N (M6).
- `delegation_status: verified` — every per-hop delegation chain re-walked + monotone (M2).
- `revocation_status` — disclosed-list mode (M5): `fresh`/`absent` pass; `stale`/`revoked_present` block the capstone, as does `missing` (revocation_keys pinned but the bundle carries neither a `revocation_list` nor a `revocation_merkle_root`).
- `attestation_status` with `revocation_keys` pinned (behaviour change) — the deployment attestation's signed
  subject must carry a `revocation_digest` equal to the digest of the bundle's `revocation_list` (`""` when the
  bundle has none), so stripping or swapping the list cannot keep the attestation valid. An attestation signed
  before its producer bound that field has none, so on a bundle that **carries** a `revocation_list` it now fails
  as `deployment_attestation: subject does not match the bundle under review — substitution/replay (D7):
  revocation_digest`, which is a hard failure (`ok: false`), not merely `attestation_status` short of
  `attested_claims`. Without `revocation_keys` pinned, a subject with no `revocation_digest` is still accepted.
  Remedy: re-export from a current server (it signs a fresh attestation per export, binding the list it emits), or
  verify an archived pre-upgrade bundle without `revocation_keys` and record why.
- `revocation_merkle_status` — Merkle-non-disclosure mode (M5): when `fresh`, EVERY Tier-B use **and** every native credential must carry a per-grant proof in the bundle's `revocation_proofs` map — a non-membership proof to proceed, a membership/missing/forged proof blocks it (fail-closed; the revoked set is never disclosed). `stale` blocks the capstone; `absent` is the baseline. `revocation_nonmembership_verified` counts grants proven NOT revoked.
- `introspection_status: attested` — every native (token_exchange) credential's resource-signed transcript verified (M3); the native surface reaches `attested_complete_over_introspected_surface`. A native credential that a fresh revocation list/root marks revoked is blocked here too (it can never be `attested`).
- `federation_status: sequence_verified` — every broker's per-`broker_id` log verified, no `cross_broker_suppression` (M4).
- `transitive_grants` — grants from an UNPINNED subject broker that elevated to `transitive` trust via a `cross_broker_cert` signed by a PINNED issuer broker (M4 optional). The cert binds the subject's KEY (not just its id), and the subject key is rejected if it collides with any non-broker role.
- `action_completeness` — the D8 capstone (`attested_complete_over_brokered_surface` / `..._introspected_surface` / `claimed_over_manifest` / `not_claimed`), **always** bounded by `resource_trust: assumed_truthful` (MF1 — the irreducible resource TCB).

## Unwedging a refused checkpoint: `grant_void` tombstones (D6)

The server refuses to sign a checkpoint while a `broker_seq` is reserved but no grant records it
(`checkpoint refused: allocated broker_seq max M != N recorded grants`), because an anchored gap would fail
verification forever. The usual cause is a grant whose commit was ambiguous (or whose seq release failed) and
whose client never retried. **Upgrade hazard:** before this release any post-allocation failure left the seq
reserved, so a project that ever hit a transient grant error can start refusing checkpoints as soon as this
build is deployed (no new anchoring; after the revocation validity window its exported `revocation_list` reads
`stale`).

Remediation, per unrecorded seq `k` in `[1..M]`:

1. If the grant's client is still around, have it retry under its original `idempotency_key`: the retry
   reclaims seq `k` and the gap closes.
2. Otherwise, once the reservation, its grant's latest attempt **and the server's start** are all older
   than `AVERIN_BROKER_SEQ_VOID_MIN_AGE` (default `1h`), call `POST /v2/broker-seq/void?project=<id>` with
   `{"project_id":"<id>","broker_seq":k,"reason":"..."}`. The server confirms from the store that nothing
   records seq `k` (a seq whose ambiguous commit actually landed is refused), retires the reserved `grant_id`
   (a later retry of it is a `409`; re-issue under a new key), and seals a broker-signed `grant_void`
   tombstone binding the project, `k` and that `grant_id`. The tombstone is sealed before the reservation is
   marked voided. A `409` "grant landed; nothing to void" means the grant's own commit won: seq `k` is
   recorded and nothing was voided. A `500` means either nothing was voided or the tombstone is sealed and
   only the mark is missing. In both cases repeat the call; it finishes the void without re-sealing. When revocation is enabled, it also **revokes**
   that `grant_id`, so a capability minted for it stops working at `/v2/use`. Without revocation, such a
   capability stays usable until it expires. In that case, enable `AVERIN_REVOCATION_SEED` and
   `POST /v2/revoke` the `grant_id`, or wait out its TTL.
3. `POST /v2/checkpoints` now signs. The offline verifier accepts the tombstone as filling seq `k`
   (`broker_trust: sequence_verified`), does not count it in `grant_total`, and never matches a use to it.

What makes a void safe against a commit that is still in flight:

- **Latest-attempt age.** The age is measured from the later of the seq's `allocated_at` and the last time
  its grant attempted the seq on this server (every retry refreshes that time, although a retry never
  refreshes `allocated_at`). A client that keeps retrying a persistently failing grant therefore keeps the
  void refused; stop that client first (the TLA+ model's `GrantLog_void_starved.cfg` shows the outage).
  Attempt times are kept in memory, so after a restart the age also counts from the server's start: no void
  passes until the minimum age has elapsed since the restart.
- **Ingest lock.** Within one process the void and every grant commit are serialized. The void holds that lock
  while its tombstone insert waits on any in-flight row with the same `record_id`, up to the 30 s Postgres
  statement timeout, so ingest on that server can stall for that long.
- **UNIQUE `record_id` index.** On Postgres, the void requires the UNIQUE index `records_project_record_id_uniq`
  from migration `0002`. The tombstone's `record_id` is the voided `grant_id`, so at most one of the two can
  land. If `0002` logged its WARNING and built a non-unique index (historical duplicate `record_id`s), every
  void is refused with `409` until you resolve the duplicate and rebuild the index as UNIQUE. Check with
  `SELECT indisunique FROM pg_index WHERE indexrelid = 'records_project_record_id_uniq'::regclass;`.

The first two guards are process-local. On a multi-instance deployment only the UNIQUE index closes the race
between a retry on one instance and a void on another. The age compares the database clock (`allocated_at`
is Postgres `now()`) with the server clock. If the database clock runs behind, reservations look older by
that difference, so keep the minimum age far above any plausible clock skew. The route has no separate
operator privilege: any holder of the project's write key can call it.

A tombstone is the broker's signed statement that seq `k` was never issued. An auditor who holds a credential
carrying seq `k`, or finds a grant record claiming it, has evidence of equivocation: the verifier reports a
bundle carrying both as a duplicate `broker_seq`.

## Producing the optional M4/M5 artifacts

Most modes are produced automatically by the broker/resource on the recording path (and via the online
`/v2/grants/*`, `/v2/use*`, `/v2/introspection` flows). Two OPTIONAL tiers are assembled at bundle/checkpoint
time from a role-separated key:

- **Disclosed revocation (M5) — server-native.** Set `AVERIN_REVOCATION_SEED` (a key disjoint from the broker,
  resource, attestation, and cosig keys). `POST /v2/revoke {project_id, grant_id}` marks a grant revoked; every
  `/v2/export` carries a signed, time-bounded `revocation_list` (its freshness window anchored to the latest
  checkpoint) — an empty one while nothing is revoked, so a verifier pinning `revocation_keys` reads `fresh`
  rather than `missing`. Verify with `revocation_keys` pinned → a revoked grant's use (brokered OR native) is blocked.
  A successful revoke also blocks later uses on the serving process. Postgres mode restores the revoked set
  after restart, but does not synchronize other live replicas; route each project's uses and revokes together.
- **Federation (M4) — server-native.** Set `AVERIN_BROKER_ID`; the server tags its grants with `broker_id` and
  emits a per-broker_id `broker_grant_heads` map in each checkpoint. Verify with `federated_broker_keys[<id>]`
  pinned → `federation_status: sequence_verified`. (One server = one broker_id; combine bundles from multiple
  brokers to verify a multi-broker federation.)
- **Merkle-non-disclosure revocation (M5).** The library producer (no server endpoint) — a revocation authority
  builds a sorted Merkle tree over the revoked grant_ids, signs the root, and attaches `revocation_merkle_root` +
  a per-grant `revocation_proofs` map — committing to the revoked set **without disclosing it**:
  - Go: `broker.BuildRevocationTree(revokedIDs)` → `api.BuildRevocationMerkleRoot(core, revKey, issuedAt, notAfter, tree)`
    for the signed root; `tree.NonMembershipProof(gid)` / `tree.MembershipProof(gid)` for each grant in the bundle.
  - Verify with `revocation_keys` pinned; under a fresh root **every** use and native credential needs a proof
    (a missing proof is fail-closed → blocked).
- **Cross-broker cert (M4 transitive trust).** The library producer (no server endpoint) — a PINNED issuer
  broker A vouches for an UNPINNED subject broker B's authority key over a `(scope, resource)`:
  - Go: `broker.CrossBrokerCert(issuerID, subjectID, subjectPub, scope, resource, notAfter, issuerKey)`, embedded
    in B's `grant_evidence.cross_broker_cert`.
  - Verify with only A pinned in `federated_broker_keys`; B's grant elevates to `transitive` and is counted in
    `transitive_grants`.

## Running it

```bash
# build the CLI once
cargo build --release --bin averin-verify

# internal consistency
target/release/averin-verify bundle bundle.json

# authentic + mode gates (pin the keys you printed from averin-server's startup log / your KMS)
target/release/averin-verify bundle bundle.json opts.json
```

A non-zero exit = FAIL. The keys you pin here are the out-of-band trust root — distribute them through a
channel independent of the server (the server can produce a bundle, but it can never make the verifier
accept one its pinned keys don't authenticate).
