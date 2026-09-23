# Plan 004: Bind issuance proof to the complete request and tenant

## Status and execution contract

- Priority: P1; effort: L; implementation risk: HIGH; confidence: HIGH.
- Category: security / wire-format migration. Depends on: 001.
- Planned at `e81aa90adaf7ca90bb78f397839b51935e81c699`, 2026-09-23.
- Use a PR descendant, branch `advisor/004-grant-pop-context`. First run `git diff --stat e81aa90..HEAD -- server/internal/broker server/internal/resourceshim server/internal/api sdk spec core/src/verify.rs formal` and reconcile drift. Do not publish. Update the index after review.

## Why this matters

The current proof demonstrates possession for an operation but can be reused to request another grant under a different project/idempotency tuple. Other unsigned issuance inputs can also change the resulting authorization. Bind the effective security request once, and ensure the tenant identity remains authenticated when the capability is used. The latter is a prerequisite to safely scoping the nonce ledger in plan 005.

## Current state

`server/internal/broker/broker.go:170`, `Request.Challenge()`, serializes only:

```go
"tag": popTag, // averin.broker.pop.v1
"agent_id": r.AgentID, "action": r.Action,
"resource": r.Resource, "scope": r.Scope,
"agent_pubkey": r.AgentPubKey,
```

`docs/dev/API.md:238` documents omitted project, idempotency, session, TTL, scope class and use limit. `server/internal/api/server.go:1683` derives grant ID from project/idempotency separately. `broker.go:297` creates a signed capability descriptor without an explicit project claim; `Claims` at line 397 also lacks one. `handleUsePhase:2336` creates a shim with resource identity, and selects revocation state from the request's project. Avoid making a ledger namespace an unauthenticated caller-controlled selector.

## Scope

`server/internal/{broker,resourceshim}/`, grant/use and two-phase handlers in `server/internal/api/`, relevant tests, actual client signing helpers under `sdk/` and integration fixtures, capability descriptor checks in `core/src/verify.rs`, `spec/` vectors/schemas, Lean catalogue and oracle, API/operator docs. Native token-exchange proof formats and Vultrino's separate token protocol are out of scope.

## Target contract

Introduce explicit PoP v2 bytes covering authenticated project, resolved idempotency key, session, existing five fields, effective scope class, use limit, TTL, principal and delegation/approval context that affects authorization. Encode with one specified framing/canonicalization. Idempotency is a signed retry identity, not proof of freshness. Add agent-signed request issue/expiry fields with a server-enforced maximum request age and documented clock-skew allowance. Fresh single-phase issuance and prepare require a current request; finalize also requires the persisted request/prepare expiry to remain valid. An already committed exact result may be returned after request expiry without reminting, extending capability validity or re-consuming. Resolve defaults/header-vs-body precedence before verification and reject conflicting representations. Do not let a retry renew TTL or change the approved operation.

Carry the server-authorized project in a versioned signed capability descriptor at mint. Pass the authenticated route's project context into the resource shim, then compare the signed claim to it before revocation lookup or consumption; offline verification cross-checks descriptor/evidence/record project. The existing credential binding commits the whole descriptor, so update its schema and vectors consistently. Legacy online capabilities remain on the conservative old ledger behavior until expiry or require an authoritative grant→project lookup; never assign them a fresh namespace from request text alone. Test the same legacy token under two project contexts. Native token-exchange paths stay on their separately authenticated tenant/credential contract and must not inherit the new namespace by accident.

## Steps and verification

1. Add the v2 request and capability schemas plus shared vectors for defaults, expiry and conflict handling. Inventory real producers using `rg -n 'averin.broker.pop.v1|Challenge\(' server sdk ../govder ../feir-os` and identify protocol-specific matches before changes.
   **Verify:** from `server/`, `go test ./internal/broker/... ./internal/resourceshim/...`; existing cases pass and new tests demonstrate substitutions fail under v2.
2. Verify the finalized request before any grant allocation, preparation, denial evidence or credential mint. Prepare/finalize must bind to exactly the same stored subject; do not allow lookup/idempotency shortcuts to bypass authentication. Require project binding at use time before ledger operations.
   **Verify:** `make test-server` with disposable Postgres, including two-phase and idempotency tests; no rejected request allocates/consumes or persists authority.
3. Update actual SDK/caller helpers, core descriptor checking and formal catalogue/oracle. Add strict explicit version negotiation; no automatic v2→v1 fallback. Use staged reader-first, producer-second, online-cutoff rollout; historical signatures remain inspectable under their original rules.
   **Verify:** `make formal-lean formal-refinement`, `cargo test --workspace`, `(cd sdk/typescript && bun test && bun run typecheck)`, `(cd sdk/python && python3 -m pytest)` all pass. Python tests are pytest-style functions; unittest discovery would misleadingly run zero tests. If a script has drifted, inspect its package manifest and update the plan before proceeding.
4. Test mixed-version deployment and cutoff, including maximum capability TTL and request expiry. Update API examples and reject v1 for new online issuance after configured cutover.
   **Verify:** `make test` plus the protocol migration tests pass, with unchanged legacy historical verification fixtures.

## Tests and done criteria

Test changing each signed field independently, same proof in another project/new idempotency key, same key with a changed request, prepare/finalize mismatch, expired fresh request, valid identical retry, header/body conflict, same token routed to another project, and missing project on a new capability. Assert rejection precedes consumption. Version/tag mutations must be caught by oracle or negative tests. A replay of an old valid proof must never create an additional v2 grant.

## STOP conditions and maintenance

Stop if normalized request bytes differ between SDK and server, if tenant identity comes only from request routing, or if legacy compatibility would reopen issuance after cutoff. Do not normalize opaque secrets or rewrite historical grant IDs. Future authorization inputs must enter the signed request schema. Socket Firewall applies to dependency acquisition.
