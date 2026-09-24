# Plan 009: Distinguish proven historical authorization from current revocation

## Status and execution contract

- Priority: P2; effort: L; implementation risk: HIGH; confidence: HIGH about current behavior, design requires explicit temporal trust policy.
- Category: correctness / protocol migration. Depends on: 001, 002, 005, 007, 008; coordinate versioned body/receipt formats with 003/004.
- Planned at `e81aa90adaf7ca90bb78f397839b51935e81c699`, 2026-09-23.
- Use `advisor/009-temporal-revocation` on a PR descendant. Run `git diff --stat e81aa90..HEAD -- core/src/verify.rs server/internal/api/revocation.go server/internal/api/revocation_server.go server/internal/pgdurable spec formal docs` and reconcile drift. No publishing; update index after review.

## Why this matters

Current revocation deliberately blocks every use of a listed grant, including earlier uses. That is conservative and safe, but it cannot answer whether a historical receipt had authority before cancellation. Add that distinction without trusting an attacker-controlled event timestamp or rewriting the meaning of old revocations.

## Current state

`server/internal/api/revocation.go` signs a set of `revoked_grant_ids`. `core/src/verify.rs:5649` checks membership with no per-use cutoff:

```rust
if revocation.revoked.contains(&gid) {
    revoked_uses_blocked += 1;
    violation(&mut issues, /* revoked grant */);
    continue;
}
```

The same policy applies to native introspection later in that file. Signed stale revocations continue blocking: staleness is not permission to un-revoke. Merkle mode proves membership/nonmembership of a set, without a temporal value. Live rejection is implemented in `revocation_server.go`/`resourceshim`; it is not an unimplemented feature.

## Scope

Revocation schemas/signing/export in `server/internal/api/`, durable revocation state/migrations, consumption/receipt ordering through 007, Rust disclosed/Merkle/native verification and report states, schemas/vectors/Lean models/oracle, browser report presentation and operator/API/security docs. No redesign of Govder/Vultrino kill-switch semantics, external time authority service, or weakening of legacy total revocation.

## Target contract

Execution design reconciliation (2026-09-24): implement `strict` (default) and explicit caller-selected `db_serialized_v1`. Migration 0007 adds a monotonic authorization-order counter under 007's exact project guard and immutable revocation events. Assign an ordinal to each successful brokered use authorization and native introspection inside the same transaction as its receipt; place it in the semantic evidence before 003's body-bound v3 resource signature. Allocate revoke cutoff in that same serialization domain. This proves the stated order only under the honest resource signer, revocation signer and database transaction assumptions; it does not independently prove database membership or physical action time.

The authorization points are `/v2/use`, `/v2/use-intent`, and native introspection. `/v2/use-outcome` is completion evidence, not another authorization: join its exact resource-signed intent reference, grant ID, intent hash and causal edge to the intent's ordinal. A later outcome may describe an intent admitted before revocation. Exact receipt retries do not allocate another ordinal.

Read-only preflight found that native introspection currently signs before the transaction and accepts any row under a reused idempotency key. Move its signing inside the project transaction, validate the actual native grant, lease/reference, resource, effective scope, expiry and durable revoke/void state before a new ordinal, and require exact immutable request matching on retry. Preserve an exact committed receipt after later expiry/revocation. An omitted/default-zero introspection time must reuse the original committed server-selected time on exact retry; a new explicit conflicting time or different request field must not return that receipt. Return record/grant identifiers from the matched stored receipt, never from conflicting new input.

Migration 0007 must use a newly validated maintenance writer barrier from 005, even when 0006 was previously cut over: an already-running v6 writer could still append unordered receipts or old boolean revocations. Recheck retired identities, sessions, prepared transactions and effective write access on every advancing maintenance migration. Preserve 0006's original legacy-exclusion timestamp. Existing boolean revocations and 008 void revocations remain total; do not replace them with a compatibility trigger that loses a later compromise/total upgrade.

A separate receipt-order table/root is excluded from this implementation: it adds another state/proof surface and only strengthens the distinct resource-key-compromise threat if the order signer and database writer are independently protected. The present common-process architecture does not establish that independence. Record the assumption instead of claiming extra Merkle structure removes it. The revocation state itself still needs versioned disclosed and Merkle temporal values as below.

Preserve legacy `ok`, `revoked_uses_blocked` and existing capstone blocking. Add a distinct `historical_authorized_as_of_snapshot` decision and per-receipt `historical_ordering`; do not overload 002's existing anchor/attestation `temporal` field. Bind the result to its signed snapshot identity, DB read-boundary time and high-watermark. A snapshot begun before a revoke cannot acquire a later signing timestamp that makes its old state look newly current. Caller supplies evaluation time/max age and may require a minimum known watermark. Existing revocations migrate as total. A producer must not emit a v1 list containing prospective IDs, since any authenticated v1 membership remains total even for new verifiers.

The current verifier's revoked-use branches skip subsequent grant, PoP and outcome checks. A positive historical result must execute all of those checks through a shared validation path; relabeling an otherwise unvalidated revoked candidate is unsound. Export must capture database boundary time and high watermark inside the same repeatable-read snapshot as records and revocation state, then sign those captured values without substituting a later wall-clock timestamp.

External temporal mode is intentionally not introduced without a sound lower bound on revocation effect. Two TSA anchors ordered by timestamp provide upper bounds on existence, not event order. A future external mode needs an independently trusted no-earlier-than cutoff or a revocation event cryptographically defined to take effect after a receipt witness. Bare `anchor(receipt) < anchor(revoke)` is insufficient. This excludes unsupported claims and unnecessary protocol surface, not the selected database-order implementation.

Keep legacy/compromise revocation as total invalidation. Add an explicit versioned prospective revocation event with immutable project/grant identity, issuer, effective ordering/cutoff and reason/mode. Persist the earliest applicable cutoff; retries cannot move it later. A separate history judgment reports `proven_before`, `at_or_after`, or `indeterminate`. Current capability validity remains revoked regardless of historical classification.

Represent these as separate typed report fields (for example `current_revocation` and `historical_ordering`), not just UI text. Define compatibility of `ok` and `revoked_uses_blocked` explicitly: under the strict legacy policy or indeterminate ordering they must not silently become successful/zero. A legacy total-revoke artifact remains total even when evaluated by a temporal-capable verifier; add a dedicated compatibility regression.

Choose and document the trusted basis for a positive historical claim:

- Prefer a signed receipt/authorization ordering boundary serialized with revoke in the authoritative project transaction, within the explicitly trusted recorder/resource model.
- For stronger external temporal evidence, an anchor can establish that a committed receipt existed before a trusted cutoff. It does **not** prove when the physical action occurred. Describe that narrower claim.
- Comparing `agent_ts`, `used_at` or `received_ts` to a self-asserted cutoff alone is insufficient against backdating. Without adequate evidence return indeterminate/conservatively blocked, never retrospectively authorized.

The policy/required temporal basis is supplied out of band by the verifier caller. Absence, stripping, an unsupported version or an untrusted clock cannot select a weaker policy. If multiple authenticated revocations apply, combine conservatively; a later prospective event cannot override total invalidation.

## Steps and verification

1. Specify the temporal subject, order semantics and exact claims in an ADR/schema with decision-table vectors. Do not implement a naked `used_at < revoked_at` exception. Include ordinary cancellation versus compromise and signed receipt existence versus physical event time.
   **Verify:** add executable Rust table tests in the adversarial/temporal suite; every row has expected integrity, current validity, historical status and capstone eligibility.
2. Persist revocation events and ordering boundaries atomically with authoritative use authorization. Export authenticated complete history/snapshots with stable cutoff identity and freshness. Treat cache/replica delay according to 007; offline artifacts must not claim current state they did not observe.
   **Verify:** `make test-server` with disposable Postgres. Tests race revoke against use, crash/restart before/after commit, repeated revoke and multiple instances. Successful revoke precedes rejection of later authorized uses on every replica.
3. Add explicitly versioned disclosed-list and Merkle value/proof formats that commit mode and cutoff, including native introspection. Keep legacy roots/lists total-blocking. Verify complete proof paths, authority status/freshness, and matching project/cutoff; stripped cutoff/proof must never yield `proven_before`.
   **Verify:** `cargo test --workspace`, `make formal-lean formal-refinement`, `python3 formal/check-refinement.py`; vectors cover old/new formats, malformed and mixed evidence, equality-at-cutoff and rotated keys.
4. Extend 002's monotonicity proof/oracle and mutation suite for temporal decisions. Update displays to separate current revocation from proven historical receipt status. Roll out reader-first; only producers with the required durable ordering can emit prospective artifacts.
   **Verify:** `make test`, `(cd web && bun run test)`, and `bash formal/check-mutants.sh`; deleting time/order evidence, substituting earlier roots or using an untrusted timestamp cannot strengthen the historical verdict.

## Done criteria

- Valid pre-cutoff evidence may be recognized under an explicit trustworthy ordering policy; uncertain evidence remains indeterminate/blocked.
- Current revocation is always enforced; legacy and compromise revocations remain conservative.
- Disclosed and Merkle modes, native and brokered paths, key rotation and missing evidence share one documented policy.
- Every new positive historical claim names its temporal trust assumption; no UI claims TSA proves physical action time.

## STOP conditions and maintenance

Stop if a proposed positive judgment depends only on a record's self-reported timestamp, if history completeness cannot be authenticated, or if missing fields silently fall back to prospective semantics. Document the unresolved trust boundary and keep strict behavior until the design is sound. Work size is not a reason to omit this plan; its additional semantics must earn their correctness through the proof/tests.
