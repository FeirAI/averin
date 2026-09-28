# ADR 0007 — Historical ordering against revocation, separate from current revocation

**Status:** Accepted and implemented (plan 009).
**Date:** 2026-09-24
**Builds on:** ADR 0005 M5 (signed revocation list and Merkle root), ADR 0006 (role-key rotation),
plan 002 (typed claims and support-erasure monotonicity), plan 003 (body-bound v3 authority),
plan 005 (maintenance writer barrier), plan 007 (per-project transactions and repeatable-read
export), plan 008 (recovery voids).

## 1. Problem

A signed revocation blocks every use of the grant it names, including uses made before the
revocation. That is safe, and it stays the default. It cannot answer a different question: was
this receipt authorized before the grant was cancelled? Answering it from a self-reported time
(`used_at`, `agent_ts`, a revocation timestamp) would let a producer backdate a receipt. Two TSA
anchors do not answer it either: each is only an upper bound on when its object existed, so
`anchor(receipt) < anchor(revocation)` does not order the events.

## 2. Decision

### 2.1 Two policies, chosen by the verifier caller

`revocation_temporal` is a verify option, never a bundle field.

| policy | meaning |
|---|---|
| `strict` (default, also when absent) | Exactly the pre-009 behavior. No historical positive is ever produced. |
| `db_serialized_v1` | The caller supplies `evaluation_time` (canonical `YYYY-MM-DDTHH:MM:SS.mmmZ`, a real calendar date), `max_snapshot_age_seconds` (1 to 31622400) and optionally `min_authorization_watermark` (default 0). |

An unknown policy, unknown field, missing field, malformed time or out-of-range bound is a
configuration error (`{"ok":false,"error":…}`), never a fallback to a weaker policy.

### 2.2 The ordering domain

Averin keeps one monotonic **authorization order** per project on the plan 007 guard row
(`project_write_guard.authorization_order`, migration 0007). A transaction allocates from it only
while it holds that row lock, so allocation is serialized per project across replicas and pools and
rolls back with its transaction. Ordinals are unique and increasing, not gapless.

- `/v2/use` and `/v2/use-intent` allocate the next ordinal after the capability validated, in the
  transaction that stores the receipt. `/v2/introspection` does the same after validating the
  actual native grant (§2.6).
- The ordinal is written into the resource-signed payload before the body-bound v3 signature:
  `authorization_order: {"format":"averin.authorization_order.v1","project_id":…,"ordinal":n}`
  inside `use_evidence` or `introspection_evidence`. Averin's resource key signs it inside the same
  transaction (no external party signs the receipt body; Vultrino posts to `/v2/use`).
- `/v2/use-outcome` is completion evidence, not an authorization. It copies the intent's signed
  ordinal into its `use_outcome` payload and allocates nothing, so an outcome recorded after a
  revocation still describes an intent admitted before it.
- An exact retry returns the stored receipt, so it never allocates a second ordinal.
- `authorization_receipts` is an operational backstop (one receipt per ordinal, one ordinal per
  record). It is not a proof surface; the signed receipt is.

### 2.3 Revocation events

`revocation_events` rows are immutable: `{project, grant_id, format averin.revocation.event.v1,
mode total|prospective, cutoff_order (prospective only), issuer, reason, created_at}`, at most one
per `(project, grant, mode)`.

- **Total** (default for `POST /v2/revoke`, every recovery void, every pre-v7 revocation): every use
  of the grant is invalid. This is the compromise case.
- **Prospective** (`"mode":"prospective"`, cancellation): its cutoff is the next ordinal, allocated
  in the same serialization domain as receipts. A receipt is `proven_before` iff its authenticated
  ordinal is strictly less than the cutoff; equality is at/after.
- A retried prospective revoke returns the original event, so the cutoff never moves later. A later
  total revoke is always recordable and wins.
- Readers combine conservatively: any total event makes the grant total; otherwise the earliest
  cutoff applies.
- Current validity is unchanged: any event (either mode) or a signed `grant_void` tombstone makes
  `IsRevoked` true, so every later use and introspection is rejected immediately.

### 2.4 Export: a signed snapshot

With `AVERIN_REVOCATION_EXPORT_FORMAT=v2`, `/v2/export` carries an `averin.revocation.list.v2`
under the existing `revocation_list` key, signed in the separate `averin.revocation.v2` domain:

```json
{"format":"averin.revocation.list.v2","issuer_kid":"…","issued_at":"…","not_after":"…",
 "project_id":"p1",
 "snapshot":{"boundary_time":"2026-09-24T10:00:00.123Z","authorization_high_watermark":42},
 "revocations":[{"grant_id":"g1","mode":"prospective","cutoff_order":17},
                {"grant_id":"g2","mode":"total"}],
 "sig":"…"}
```

The boundary time and watermark are read first inside the same repeatable-read transaction as the
records and revocation events. The boundary is PostgreSQL `now()` (transaction start), which is
never later than the snapshot, so every commit before the boundary is in the snapshot. Allocation
under the guard lock means a visible watermark `W` implies every ordinal `≤ W` is committed or
was rolled back. The signed values are exactly the captured ones; no later wall-clock time
substitutes for the boundary. `issued_at`/`not_after` keep their legacy meaning (the freshness
window dated against the latest anchored checkpoint).

The versioned Merkle root `averin.revocation.merkleroot.v2` (domain
`averin.broker.revocation.merkleroot.v2`) carries the same project and snapshot. Its leaves are
sorted by `key = sha256(LP4("averin.broker.revocation.key.v2") ‖ LP4(grant_id))` and commit
`state = sha256(LP4("averin.broker.revocation.state.v2") ‖ LP4(mode) ‖ BE8(cutoff))` through
`entry = sha256(LP4("averin.broker.revocation.entry.v2") ‖ key ‖ state)`, sentinel-bracketed with
keys `0x00…` and `0xff…` and mode `sentinel`. A membership proof carries the mode and cutoff in
clear and the verifier re-derives `state`, so a stripped or altered cutoff does not authenticate.
A non-membership proof reveals only the neighbours' keys and opaque state digests. The Go producer
(`broker.BuildRevocationTreeV2`, `api.BuildRevocationMerkleRootV2`) and the Rust verifier share
`spec/golden-vectors/revocation-v2.json`; the server does not yet export a Merkle root itself.

The legacy formats are unchanged and remain total: any v1 list membership or v1 Merkle membership
blocks every use for every verifier, including a temporal one. A producer never emits a
prospective revocation in a v1 list; the v1 export refuses (fails the export) rather than emit it
as total or omit it. `POST /v2/revoke` refuses `prospective` unless the v2 export is enabled.

**Rollout is reader-first.** A pre-009 verifier rejects a v2 list (its signature does not verify in
the v1 domain, which is an issue and `ok:false`) instead of misreading it. Enable the v2 export
only after every relying verifier is upgraded.

### 2.5 Verifier: current revocation unchanged, history separate

Legacy fields are identical under every policy: `ok`, `revoked_uses_blocked`, `revocation_status`,
the issues, `authorized`, `complete_*` and the D8 capstone. A use of a revoked grant still blocks
them even when it is `proven_before`. The new information is separate:

- `revocation_temporal.grant_revocations[]`: per grant, `current_revocation` ∈ `not_evaluated`,
  `not_revoked`, `revoked_prospective` (with `cutoff_order`), `revoked_total`,
  `revoked_unverified` (named only by an unusable v2 artifact), `unproven`.
- `revocation_temporal.receipt_ordering[]`: per committed use/intent/transcript, the authenticated
  `authorization_order` and `historical_ordering` ∈ `proven_before`, `at_or_after`,
  `indeterminate`.
- `revocation_temporal.snapshot`: `status` (`absent`, `not_evaluated`, `verified`, `stale`,
  `unverified`), a reason, and the signed identity (project, boundary time, watermark) the
  judgment is bound to; the policy, the caller's bounds and the named `trust_basis`.
- The claim `historical_authorized_as_of_snapshot` (claims version 2). It is distinct from
  plan 002's `temporal` claim, which concerns anchor and attestation freshness.

Classification of one receipt:

1. `indeterminate` unless the receipt passed every validation and carries a well-formed ordinal
   from a body-bound (v3) resource signature. A v2 (legacy-unbound) receipt never carries a trusted
   ordinal. For an intent, its outcome must sign the same ordinal (a different signed ordinal is an
   adverse contradiction; a missing one leaves the pair indeterminate).
2. `at_or_after` if a usable v2 artifact commits a prospective cutoff `c` for the grant and the
   ordinal is `≥ c`. Cutoffs never move later, so this needs no snapshot, and an unproven Merkle
   path for the same grant does not suppress it (a positive still requires every path).
3. `proven_before` only if, additionally, the caller selected `db_serialized_v1`, the snapshot is
   `verified` (below), the ordinal's project is the snapshot's project, the ordinal is `≤` the
   signed watermark, and every present v2 source states "not revoked" or a prospective cutoff above
   the ordinal. A v1 artifact can only add a total revocation or an unproven proof.
4. `indeterminate` otherwise, including every total revocation, every unproven Merkle path and
   every mixed or malformed state.

The snapshot is `verified` iff there is a usable signed v2 artifact (well formed, parseable
snapshot, issuer honored at the boundary time under ADR 0006 rotation rules), a v2 list and a v2
root (if both present) sign the identical snapshot, its project is the bundle's, `boundary_time ≤
evaluation_time`, `evaluation_time − boundary_time ≤ max_snapshot_age_seconds`, and the watermark
is at least the caller's minimum. An unusable v2 artifact is an issue. Every grant it names under
its signature (including any legacy `revoked_grant_ids` it carries) still blocks current use, but
it is not authenticated evidence for history: such a grant is `revoked_unverified`, its receipts
stay `indeterminate`, and it never refutes the claim (plan 002: `refuted` needs authenticated
adverse facts). An authenticated total revocation (a usable v2 total entry, or any v1 membership)
does refute it.

`historical_authorized_as_of_snapshot` is `insufficient` under `strict`. Under `db_serialized_v1`
it is `refuted` on an immutable-record contradiction, a checked Tier-B contradiction (counting
violations found among revocation-blocked receipts), an adverse opening or anchor, a validated
receipt at/after its cutoff or of an authenticated totally revoked grant, or an outcome/intent
ordinal conflict. It is `satisfied` when `authenticated` is satisfied, role authority is pinned, the
snapshot is verified, the caller's `claim_policy.revocation` mode holds for the v2 evidence (a
pinned revocation issuer, and: `pinned` any verified snapshot; `disclosed` a usable v2 list; `merkle`
a usable v2 root and a valid v2 proof for every receipt's grant; `both` all of these), the
disclosure and attestation requirements of the claim policy hold, and every receipt (brokered and
native) is `proven_before` with the same use obligations as
`authorized` (every use matched and PoP re-verified, no violation or pending use, validated
taxonomy with every action verified; for the native surface, every transcript verified and every
native grant covered). Otherwise it is `insufficient`.

**One validation path.** The legacy branch for a revocation-blocked use still counts it, raises its
violation and consumes nothing. The remaining grant, single-use/bounded-reuse, two-phase outcome,
offline PoP and closure checks then run through the same `check_use` on a shadow consumption ledger.
Only its result can mark the receipt validated, so a historical positive is never a relabeled,
unvalidated candidate. The legacy orphan-outcome count still includes outcomes whose intent was
blocked; the historical view replaces it with the outcomes neither path consumed.

### 2.6 Native introspection

`POST /v2/introspection` now signs inside the project transaction. It first returns an exact
committed retry (even after the grant later expired or was revoked); every immutable field must
match, an omitted (zero) `introspected_at` reuses the committed server-selected time, and a
conflicting explicit time or any other difference is `409`. Otherwise it validates the actual
committed native grant: a `token_exchange` grant for this resource, `credential_ref == lease_id`,
`effective_scope ⊆ scope`, `effective_exp ≤ exp`, `issued_at ≤ introspected_at < exp`, not in the
future beyond the accepted clock skew, not expired now, not revoked in any mode and not voided.
Only then does it allocate an ordinal and sign. Identifiers in the response come from the stored
receipt.

### 2.7 Migration 0007

Maintenance cutover only, behind the plan 005 barrier, which is re-validated for this step even if
0006 was already cut over (retired identities NOLOGIN, no sessions or prepared transactions, no
effective write privilege). It adds the guard column with a trigger that only lets the order
advance and forbids deleting guard rows; creates the receipt backstop and event tables with
immutability triggers; migrates every boolean revocation, void marker and signed `grant_void`
tombstone as a total event; and renames `revocations` to `legacy_boolean_revocations` with
immutability triggers. There is no compatibility trigger mapping a boolean insert into an event, so
nothing can hide a later total upgrade; old prepared statements naming `revocations` fail. 0006's
nonce cutover row, including its legacy-exclusion time, is not touched. An advancing cutover also
requires the new runtime identity to have no session and the database to have no prepared
transaction, so a still-running old binary reusing the new identity cannot straddle the step.

## 3. Trust assumptions of `db_serialized_v1`

A positive historical judgment names this basis in the report. It holds only if:

1. The resource signer is honest: it signs each ordinal once, in the transaction that commits it.
2. The revocation signer is honest: it signs the snapshot it read, with the boundary and watermark
   it captured.
3. The database serializes the project guard row as PostgreSQL documents.

It proves an order inside Averin's project database. It does not prove physical action time (the
Vultrino one-phase path records its receipt after the side effect), independent membership of a
receipt in the database, or anything against a party that holds both the resource and revocation
keys and the database. A separate signed receipt-order log was considered and excluded: in the
current single-process architecture the order signer and the database writer are not independently
protected, so it would add a proof surface without removing assumption 1.

A snapshot is an "as of" statement. Substituting an earlier honest snapshot cannot turn an
at/after receipt into a proven one (its cutoff is either in that snapshot or above its watermark,
and then the receipt's ordinal is above the watermark too). It can predate a later total
(compromise) revocation; `max_snapshot_age_seconds`, `min_authorization_watermark` and a required
deployment attestation that binds the list digest bound that window.

## 4. Not implemented

- An external (TSA) temporal mode. It needs an independently trusted no-earlier-than bound on when a
  revocation takes effect, or a revocation defined to take effect after a receipt witness. Bare
  anchor ordering is insufficient.
- Server export of a Merkle root, v1 or v2 (both are builder-only; the server exports the disclosed
  list).

## 5. Evidence

- `core/tests/adversarial.rs` `temporal_*`: the decision table (integrity, current validity,
  historical status and capstone eligibility per row, and strict-policy legacy equality), snapshot
  identity and clocks, malformed/mixed/downgraded evidence, v2 Merkle commitments, shadow
  validation of blocked uses, rotated keys, native transcripts and the JSON policy path.
- `formal/lean/Averin/Verdict.lean`: the claim model, support erasure including the snapshot,
  `historical_requires_policy`, `historical_requires_order`, `historical_requires_snapshot`,
  `at_or_after_refutes`, `total_revocation_refutes`, `earlier_snapshot_cannot_flip` and
  `historical_requires_pinned_issuer`; the verdict oracle rows `hist_*` (including the revocation
  modes); mutants m40–m47. The model does not encode the implementation's rule that every present
  v2 artifact signs the identical snapshot (it is not a monotone attachment condition); Rust tests
  cover it, so the model is weaker than the implementation there.
- Server: `temporal_revocation_test.go` (ordinals, revoke modes, v2 export, introspection,
  producer-to-verifier), `temporal_revocation_pg_test.go` (races across pools, causal schedules,
  repeated revokes, snapshot consistency, child-process crash cuts), `temporal_cutover_test.go`
  (v7 barrier, rollback and retry, live new-runtime session) , `temporal_conflict_test.go` (no
  ordinal survives a conflict or collapse; store errors are 5xx) and `store/temporal_test.go`.
