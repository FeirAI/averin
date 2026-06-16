# ADR 0002 — The credential broker (Level 3: complete action accountability)

**Status:** Accepted — the **Tier-A grant-verification prototype is built** (the `broker` package,
`POST /v2/grants` record-before-issue issuance, `feir_sign_evidence`, and the verifier's
`grant_accountability` under a pinned broker key); the **Tier-B (Level 3) demonstrator** — resource
use-receipts, attestation evaluation, and the broker-TCB reduction — remains gated on a design-partner
pull (ADR 0001 / spec §12).
**Date:** 2026-06-15
**Builds on:** ADR 0001 (who the evidence is for), P2.3 (authority `evidence_sig` verification),
the append-only witness + RFC 3161 anchoring spine.
**Revision:** rev 4 — restructured (rev 2) after adversarial review around the **grant ≠ action**
gap into Tier A (cryptographic, grant accountability) vs Tier B (Level 3, action accountability);
rev 3 added the semantic match predicate, closed-interval watermark, taxonomy-validated scope
classes, prepare/commit recovery, and sender-key non-exportability; rev 4 made the scope taxonomy a
surfaced, freshness-checked, pinned artifact (its semantic correctness a stated resource-owner TCB
residual). Hardened across three adversarial-review rounds.

## Context — the gap Level 3 closes

feir today proves **Level 1** (record integrity) and **partial Level 2** (event observation: we see
only what `observed_via` ∈ {proxy, sdk, otel} captures). The honest hole, stated in
[`coverage-limits.md`](../coverage-limits.md) and threat **#13** (uninstrumented action):

> none of the ingestion paths sees an action the agent takes *outside* them — a direct DB call the
> SDK didn't wrap, a raw HTTP request, a shell exec, a cloud API call with a standing key.

No amount of *observation* fixes this, because observation is opt-in and the agent can always act
outside it. Level 3 — **"this is everything the agent did, and nothing else happened"** — requires a
**chokepoint**: the agent must be structurally *unable* to act without producing a record. The
credential broker is that chokepoint. The schema already reserves the slots and we have never claimed
it (ADR 0001 §consequences): `authority.source = gateway_enforced`,
`enforcement_point = credential_broker | tool_gateway`, `grant_type ∈ {id-jag, oauth-scope, role}`,
plus `grant_id`, `authorizing_principal`, `delegation_chain[]`, `evidence_hash`, `evidence_sig`.

## The core idea, and the trap in it

**The agent holds no standing credentials.** Every credential that can touch an external resource is
held **only by the broker**. To act, the agent performs a *token exchange*: it presents its agent
identity, the broker evaluates policy, **records a signed grant**, mints a credential, and returns it.

The seductive (and **wrong**) reduction is: *recorded grants ⊇ credentials the agent could use ⊇
brokered actions, therefore every action is recorded.* The adversarial review demolished the second
"⊇": **a grant proves a credential was issued, not that exactly one action followed it.** A credential
can be reused within its TTL, exchanged for longer-lived native access, used for multiple operations
inside one scope, transferred to a collaborator, or grant a scope where action A and action B are
indistinguishable. And a grant can be recorded but never used. **Grants are authorizations; actions
are executions; the two are not equal.** This ADR is organized around that distinction.

## Two tiers of accountability (the central honesty)

| Tier | Claim | How it is established | Trust basis |
|------|-------|------------------------|-------------|
| **A — Grant accountability** | "Every credential the broker issued has a recorded, signed, checkpoint-committed, anchored grant; the grant log is tamper-evident and non-backdatable." | Reuse the Phase 1/2 spine: seal → DAG → checkpoint → anchor; grants verify to `gateway_enforced` under a pinned broker key (P2.3). | **Cryptographic, from the bundle** — *plus* the broker-integrity TCB (below). |
| **B — Action accountability (Level 3)** | "Every action the agent took on a brokered resource produced a record, and the granted authority maps 1:1 to the executed action." | Tier A **+** sender-bound single-use credentials **+** resource-side *use* records (execution receipts) **+** the three deployment attestations below. | Tier A **+ out-of-band attestations + resource cooperation.** Not provable from the bundle alone. |

**Level 3 is Tier B.** Tier A alone is "complete credential-grant accountability" and must never be
rendered as Level 3. The verifier emits them as distinct, separately-qualified results.

### What Tier B additionally requires (each closes a specific review finding)

1. **Sender-constrained, single-use credentials.** Bearer tokens are transferable and reusable — an
   agent (or a thief) can use one credential for many actions or hand it to a collaborator while both
   isolation and egress attestations stay true. Tier B credentials MUST be (a) **sender-constrained**
   (mTLS client-cert / DPoP / workload-bound `cnf` confirmation) so only the granted agent can use
   them, and (b) **single-use or per-operation** (one credential = one operation, consumed on use)
   so issuance count ≈ action count. Caching/coarsening is a *Tier-A-only* relaxation that must be
   labeled as such in the manifest.
2. **Resource-side use records (execution receipts).** Because a grant ≠ an action, the **resource
   (or its gateway shim) must emit an `observed_via: broker` use record** referencing `grant_id` when
   the credential is actually exercised. Tier B requires every brokered resource to be at a declared
   **conformance level**: `L2_use_receipts` (emits use records) or `L1_grant_only` (cannot, so only
   Tier A holds for it). The verifier surfaces each resource's conformance level; a resource at
   `L1_grant_only` contributes to Tier A but explicitly **not** to Tier B.
3. **Forbidden scopes — and `scope_class` must be verifier-validatable, not just broker-asserted
   (New Finding 2).** A grant's scope must map to a single semantic action. For Level 3 a grant MUST
   NOT carry a scope that can mint or delegate further credentials, start unbounded asynchronous work
   (jobs, webhooks, workflows), or cover multiple distinct operations — unless the record is
   *explicitly* typed `session_grant`/`batch_grant` (a labeled Tier-A-only coarsening). The broker
   refuses such scopes for Tier B. But a `scope_class: single_operation` **asserted by the broker** is
   not trustworthy on its own — a mislabeled broad scope would let Tier B overclaim with no
   verifier-side catch. So `scope_class` is Tier-B-eligible **only** when the verifier can validate it
   against a **signed resource operation taxonomy** (the resource owner publishes a pinned mapping
   from concrete scope strings → `scope_class`; the verifier recomputes the class from the grant's
   actual scope and the taxonomy). Absent a pinned taxonomy for a resource, its grants are
   `scope_class: unvalidated` and contribute to **Tier A only** — never to Tier B.

   **The taxonomy is itself a surfaced, freshness-checked, pinned artifact — not an invisible new
   trust root (rev-4 fix).** Validating `scope_class` against a taxonomy only moves the trust to the
   taxonomy, so the taxonomy must be as auditable as the broker key or TSA cert. The coverage manifest
   carries, per resource: `taxonomy_ref`, `taxonomy_digest`, `taxonomy_publisher_key`,
   `taxonomy_version`, and `effective_interval`; the verifier resolves a `taxonomy_status ∈
   {absent, untrusted, stale, validated}` (`validated` = signed by a pinned publisher key, digest
   matches, and the grant's `evaluated_at` falls in `effective_interval`). Tier B counts a grant's
   scope **only** under `taxonomy_status: validated`; `absent|untrusted|stale` demote it to Tier A.
   **Residual (stated, not hidden):** the verifier proves the taxonomy's *authenticity and freshness*,
   not its *semantic correctness* — that the published mapping truly captures each scope's real blast
   radius is a **resource-owner TCB** assumption, alongside broker integrity and resource cooperation.

## What "completeness" can honestly mean (read this before any product copy)

Level 3 (Tier B) is **complete with respect to an enumerated set of `L2_use_receipts` brokered
resources, conditional on three deployment attestations**:

- **(i) credential isolation** — the agent holds no out-of-band credential to those resources;
- **(ii) egress control** — the agent has no network path to those resources except via a broker-
  issued credential;
- **(iii) credential non-transferability** — issued credentials are sender-constrained (`cnf` = agent
  key) so the *token* cannot be exfiltrated-and-reused by another workload (the gap that survived
  (i)+(ii) alone). **Caveat (New Finding 5):** `cnf` binding defeats *token-only* theft but not
  *token-plus-key* theft or an agent-key signing oracle — a workload that obtains the agent's
  sender-key satisfies proof-of-possession. So (iii) is only as strong as **agent-key
  non-exportability**: the full Tier-B claim requires the sender-key to be hardware/enclave-bound
  (HSM, TPM, measured-boot-attested), and the demonstrator's negative bypass tests MUST include a
  token+key transfer attempt. Where the sender-key is software-resident, (iii) covers token theft
  only and key-exfiltration is a **stated residual**, not a defended threat.

What feir proves **cryptographically from the bundle** (Tier A): every issued credential has a
recorded, signed, checkpoint-committed, anchored grant, and the grant log is tamper-evident and
non-backdatable. What feir **cannot** prove from the bundle (and must surface, never assume):

- That (i)/(ii)/(iii) hold — **out-of-band attestations** (a signed deployment manifest digest at
  minimum; a TEE/measured-boot quote at best). The bundle carries a **coverage manifest** enumerating
  the brokered resources, their conformance levels, the credential-transfer model, and the attestation
  references. The verifier echoes these and reports `attestation_status: unevaluated` unless an
  attestation evaluator is wired; it never silently treats them as satisfied.
- **Side-effect closure** — a granted action on resource X may trigger effects on resource Y. The
  manifest declares transitive side-effect assumptions as `side_effect_closure`. **[T6, IMPLEMENTED —
  actionable half]:** the verifier now proves that declaration is COMPLETE over the observed brokered
  surface (every resource a grant/use names must be within the declared closure, else an
  `unclosed_side_effects` violation; the D8 capstone requires `side_effect_closure_status == "closed"`).
  This proves the manifest *declares* a complete closure; it does NOT prove the runtime *obeyed* it nor that
  the closure is semantically complete — the irreducible resource TCB (`resource_trust: assumed_truthful`),
  closable only by D7-style runtime/TEE enforcement.
- That a grant **never anchored** wasn't suppressed — inherits the **#15** residual (ADR 0001): a
  malicious customer holding the only key can suppress a never-anchored parallel chain. The witness
  store makes *already-anchored* omission detectable; the residual is stated.
- **Intent / correctness** — a grant+use proves an action was *authorized and recorded*, never that
  it was wise, in-policy-for-the-business, or non-malicious.

The product claim is **"complete accountability over the attested, use-receipting brokered surface"**,
with the manifest, conformance levels, and attestation status rendered verbatim next to it.

## Broker trust is part of the TCB — stated, not hidden

The broker holds all resource credentials **and** records grants. Splitting "issuing key" from
"recording key" is **not** a cryptographic guarantee if the same process can call both: a compromised
or buggy broker can mint without recording, and "every issued credential has a recorded grant" is then
true only by the broker's own correctness. We therefore state plainly: **the broker is in the trusted
computing base for Tier A.** To *reduce* that trust (optional, design-partner dependent), the
record-before-issue invariant can be enforced **outside the broker process**:

- **HSM/KMS issuance gate:** the issuing key lives in an HSM whose policy releases a signature only
  when presented a *grant receipt* (a broker-recording-key signature over the grant) — so the HSM
  mechanically refuses to mint a credential for an unrecorded grant.
- **Resource-side introspection:** the resource validates a presented credential by introspecting it
  against the *committed* grant log (online or via the bundle), refusing credentials with no anchored
  grant — moving enforcement to the relying party.
- **Separate issuer/recorder services** with an independently auditable barrier between them.

Absent one of these, broker integrity is an assumption; the verifier labels Tier A
`broker_trust: assumed` vs `broker_trust: hsm_gated` / `resource_introspected`.

## Architecture

```
agent (no standing creds, sender identity = mTLS/workload key)
   │  1. POST /v2/grants  { agent_identity, action, resource, scope, justification, idempotency_key }
   ▼
┌──────────────────────── feir-broker ─────────────────────────┐
│  a. authenticate agent_identity (mTLS / signed workload JWT)  │
│  b. policy decision; REJECT scopes broader than               │
│     single_operation for Tier B (forbidden-scope check)       │
│  c. issuance state machine (durable, idempotent):             │
│       requested → RECORDED → checkpointed → minted →          │  ◄── record-before-issue (B2),
│       delivered → used|expired   (or → mint_failed)           │      transactional (Finding 6)
│     the grant Decision Record is sealed+committed at RECORDED  │
│     BEFORE any mint; mint is gated on a durable grant receipt  │
│  d. mint a SENDER-CONSTRAINED, SINGLE-USE credential bound to  │
│     grant_id (cnf = agent key), short TTL                      │
│  e. deliver credential; mark delivered                        │
└───────────────────────────────────────────────────────────────┘
   │  2. agent presents credential to the RESOURCE (proves possession of the cnf key)
   ▼
resource / gateway shim — validates broker signature + sender constraint + scope, consumes the
   single-use credential, EMITS an `observed_via: broker` USE record referencing grant_id (L2), and
   rejects out-of-scope/expired/replayed use (B3/B4/B8/B10).
```

`feir-broker` is a new service (or a mode of `feir-server`) that is **both** a token-exchange
authorization server **and** a feir ingestion client; every issuance is an ingest reusing the
seal → DAG → checkpoint → anchor spine.

**Failure-atomic issuance recovery (New Finding 3).** Naming the states is not enough; every crash
point needs a defined recovery, keyed idempotently by `grant_id` (the request carries an
`idempotency_key` → deterministic `grant_id`). The protocol is **prepare/commit**:
- crash after `requested`, before `recorded` → no durable grant; the agent's idempotent retry
  re-derives the same `grant_id` and starts clean. **Safe** (nothing issued).
- crash after `recorded`/`checkpointed`, before `minted` → a durable grant exists with
  `issuance_status = recorded`; recovery either mints (resuming) or marks `mint_failed` via an
  append-only follow-on record. The grant stands as an **unused authorization** (safe over-record;
  the verifier counts it in `grants_unused`, never as an action). **Safe.**
- crash after `minted`, before `delivered` → a credential exists but the agent never received it;
  because it is **single-use and sender-constrained**, an undelivered credential is unusable by anyone
  and expires. Recovery marks `delivered` if the channel confirms, else lets it expire. **Safe.**
- the dangerous inverse — *credential delivered but grant not durable* — is **structurally excluded**:
  mint is gated on a durable grant receipt (a recording-key signature over the committed grant), so a
  credential cannot exist before its grant is durable.

**Native credentials are excluded from Tier B until a deterministic mint protocol exists.** For
capability mode the credential descriptor (and thus `credential_binding`) is known *before* mint, so
record-before-issue binds the exact credential. For native token-exchange (STS/Vault) the `lease_id` /
effective scope is only known *after* mint — a pre-mint binding gap. Until a two-phase mint (reserve a
deterministic lease id, record, then materialize) or a post-mint introspection-transcript record
bound back into the grant by a second append-only record is specified, **native-credential grants are
Tier A only.**

### The grant Decision Record + exact credential binding

A grant is an ordinary sealed Decision Record (so the *same verifier* validates it under the
**unchanged** record schema — only the two enum values are added) with `event_type:
"credential_grant"`, `observed_via: "broker"`, `action` = stable operation id, and:

- `authority`: `source=gateway_enforced`, `enforcement_point=credential_broker`,
  `grant_type=id-jag` (default), `grant_id` (also the credential `jti`), `authorizing_principal`,
  `delegation_chain=[caller,…,agent]` (scope **monotonically non-increasing** along the chain),
  `evidence_hash`, `evidence_sig` (broker `ed25519`, **record_id-bound** per P2.3 — confirmed
  sufficient to stop grant-evidence replay across records),
  `evaluated_at`, `expires_at`.
- `input_commit` (RCP §9.3): a hiding commitment to the **full canonical credential artifact** (not a
  live secret in the body); selective disclosure reveals it to an auditor to prove the binding.
- `extensions.broker` (the schema's open `extensions` object — broker-only fields do **not** become
  new top-level keys, which the closed record schema / `ALLOWED_TOP_KEYS` would reject): the grant
  lifecycle and Tier-B inputs the verifier reads — `issuance_status`
  (`recorded|minted|delivered|mint_failed`, advanced **append-only** via a follow-on grant record
  that cites the same `grant_id`, never an in-place mutation), `scope_class`, `conformance_level`,
  and the `credential_binding` value. (The first review iteration mistakenly placed `issuance_status`
  at the top level; routing broker metadata through `extensions` keeps the core record schema stable.)

**Exact credential binding (Finding 5).** `evidence_hash` covers
`{ grant_id, grant_type, principal, delegation_chain, resource, scope, scope_class, conformance_level,
evaluated_at, expires_at, credential_binding }` where `credential_binding` is the hash of the **full
canonical credential descriptor**, not four fields:
`sha256(canon({ typ, alg, kid (issuing key), iss, sub, aud=resource, jti=grant_id, scope, nbf, iat,
exp, cnf (sender constraint), mode (capability|token_exchange), lease_id (for native creds),
effective_restrictions }))`. For **token-exchange / native credentials** (STS, Vault) whose effective
scope the verifier cannot recompute, the binding instead commits a **resource introspection
transcript** (the resource's signed statement of the credential's effective scope). This prevents one
grant from covering credentials that differ in any security-relevant field, and prevents post-hoc
re-scoping after the commitment.

### Use record (execution receipt)

Emitted by the resource/shim on actual use: a Decision Record, `event_type` = the real operation,
`observed_via: broker`, carrying `grant_id`, the resource's identity, the operation parameters
(hiding-committed where sensitive), and a resource signature.

**The join is a full semantic predicate, not a key lookup (New Finding 1).** A use record that merely
cites a valid `grant_id` is not enough — a buggy or malicious `L2` shim could otherwise "match" an
unauthorized action to an unrelated grant. The verifier confirms a use ↔ grant pair **only when every
field agrees**: `grant_id`, resource/`aud`, operation/`action` id, `scope_class`, the grant's
`effective_restrictions`, the `credential_binding` (the use must present the same credential the grant
committed), `issuance_status = delivered`, the use timestamp within `[evaluated_at, expires_at]`, a
valid resource signature, and **single-use consumption** (no second use cites the same single-use
`grant_id`). A pair that matches the id but mismatches any other field is a **violation**, not a match.

**Match outcomes against a finalized interval (New Finding 4).** "Unmatched" is sound as *not
verifiable* but not always as *unauthorized* — an honest export race (a use exported before its grant,
or a grant not yet checkpointed) produces a transient mismatch in a correct deployment. The bundle
therefore carries a **watermark**: a finalized `verification_interval` (closed under the checkpoint
chain — every grant/use with `received_ts ≤ watermark` is included). The verifier classifies:
- use with a fully-matching grant → **matched** (a Tier-B executed action);
- grant with no use, both ≤ watermark → **grants_unused** (safe over-record, not an action);
- use with no/partial grant, both ≤ watermark → **`unmatched_violation`** (action without valid
  authorization — the strongest alarm, a hard Tier-B failure);
- either side `> watermark` (in-flight) → **`unmatched_pending`** (reported, NOT a failure).

Hard-fail only on `unmatched_violation` inside the closed interval; `unmatched_pending` is expected
churn at the tail.

## Verification — what the offline verifier adds

Reusing P2.3 (elevate to `verified` when `evidence_sig` checks under a pinned key; here the pinned key
is the broker recording key), additive outputs:

- `grant_total` / `grant_verified` — grants whose broker signature verified (Tier A).
- `verification_interval` / watermark — the closed interval the verdict applies to.
- `uses_matched` — uses satisfying the **full match predicate** (Tier-B executed actions).
- `unmatched_violation` — uses inside the interval with no fully-matching grant (**hard failure**).
- `unmatched_pending` — uses/grants past the watermark (in-flight; reported, not a failure).
- `grants_unused` — recorded grants with no use inside the interval (not counted as actions).
- `scope_class_unvalidated` — grants whose `scope_class` lacks a `validated` taxonomy (Tier A only).
- `native_credential_grants` — token-exchange grants (Tier A only until deterministic mint).
- per-resource `taxonomy_status ∈ {absent, untrusted, stale, validated}` with the resolved
  `taxonomy_ref`/`digest`/`publisher_key`/`version`/`effective_interval` echoed, so an auditor can
  independently re-validate or challenge the scope classification behind any Tier-B upgrade.
- `coverage_manifest` (echoed): brokered resources, per-resource `conformance_level`,
  `credential_transfer_model`, `attestation_refs`, `side_effect_closure`, `taxonomy_*`.
- `attestation_status`: `unevaluated` (default) | `evaluated:pass|fail` (only if an evaluator is
  wired). The verifier does **not** trust the manifest/attestations; it surfaces them.
- `broker_trust`: `assumed | hsm_gated | resource_introspected`.

**Verdict rules (Finding 8 — do not over-render):**
- Tier A: `grant_accountability: complete` iff every grant verifies ∧ DAG/chain sound ∧ no
  `unmatched_violation` inside the interval.
- Tier B: the verifier emits **`action_completeness: claimed_over_manifest`** with
  `attestation_status` and the per-resource conformance breakdown — and only upgrades to
  `attested_complete_over_brokered_surface` when, **for the closed `verification_interval`**: (a)
  every in-scope resource is `L2_use_receipts`, (b) every counted grant is `scope_class:
  single_operation` under `taxonomy_status: validated` and is **not** native-credential mode, (c)
  `unmatched_violation = 0`, (d) `attestation_status = evaluated:pass` (incl. sender-key
  non-exportability), and (e) `broker_trust ≠ assumed`. Absent any of these it is **never** rendered
  as unconditional completeness. A bundle with no manifest → `action_completeness: not_claimed`.

## Threat model

| # | Threat | Defense |
|---|--------|---------|
| B1 | Agent acts directly (bypasses broker) | Credential isolation + egress control (attested); manifest scopes the claim to brokered resources |
| B2 | Broker issues without recording | **Transactional record-before-issue**: grant sealed+committed before mint; mint gated on a durable grant receipt; optional HSM/resource enforcement outside the broker |
| B3 | Credential used for a different action than granted | Forbidden-scope rules (`single_operation`), single-use credentials, resource enforces scope **and emits a use record** so substitution within scope is at least *recorded* |
| B4 | Replayed grant / credential | Unique `grant_id`; single-use + short-TTL credential; record_id-bound `evidence_sig` (P2.3) |
| B5 | Forged `gateway_enforced` (agent lies) | Elevated only under the pinned broker key; an agent-claimed `gateway_enforced` stays `caller_declared` |
| B6 | Broker compromise | **Stated TCB.** Mitigated by HSM-gated issuance / resource introspection / issuer-recorder split; a fully compromised broker breaks Tier A and confidentiality and is outside the cryptographic guarantee |
| B7 | Grant omission (never-anchored suppression) | Inherits #15: anchored-before omission detectable via witness; never-anchored residual stated |
| B8 | Time-of-check/use skew | Short TTL; `evaluated_at`/`expires_at`; resource rejects expired |
| B9 | Confused-deputy / delegation laundering | `delegation_chain[]`; scope monotonically non-increasing per hop; broker refuses widening |
| **B10** | **Resource non-cooperation / grant-use ambiguity** | Per-resource `conformance_level`; `L1_grant_only` resources contribute to Tier A only and are excluded from Tier B; `L2` resources MUST emit use records; an unmatched use is a hard failure |
| **B11** | **Broker as a metadata/policy oracle** (probing resources, scopes, principals via allow/deny + timing) | Denied requests are themselves recorded; rate-limit + least-informative errors; minimize policy-query surface; the denied-grant log is part of the evidence |
| **B12** | **Credential exfiltration-and-reuse** (survives B1 isolation+egress) | Sender-constrained credentials (cnf=agent key) defeat **token-only** transfer (resource verifies proof-of-possession). **Token+key** transfer / agent-key signing oracle is defended only when the sender-key is non-exportable (HSM/TPM/measured-boot, attestation iii); otherwise key-exfiltration is a **stated residual** |

## Build scope (when pulled)

**Tier-A prototype (grant-verification — honestly labeled, NOT Level 3) — ☑ BUILT:**
1. ☑ `event_type: "credential_grant"` + `observed_via: "broker"` schema additions (additive; SDK
   allowlists updated in lockstep). Broker-only fields live under `extensions.broker`.
2. ☑ `POST /v2/grants`: **proof-of-possession** of the `cnf` key (agent signs a domain-separated
   challenge) → forbidden-scope check → **idempotent** (deterministic `grant_id`) record-before-issue
   (reuse seal/DAG/store) → broker-signed **sender-constrained, single-use** capability (`cnf` = agent
   key, `jti = grant_id`, max-TTL-capped) → `issuance_status` under `extensions.broker`. (Agent auth
   is the PoP; mTLS/agent-JWT transport is a deployment concern.)
3. ☑ Broker recording key pinned by the verifier (`feir_verify_bundle_with`); grants verify to
   `gateway_enforced` only when the record is ALSO integrity-proven.
4. ☑ Verifier `grant_total`/`grant_verified`, `grant_accountability`, `coverage_manifest` echo,
   `attestation_status: unevaluated`, `broker_trust: assumed`, and the **Tier-A** verdict only.

*Built-but-noted Tier-A residuals (honest, documented in code):* the evidence preimage is not
disclosed (so `evidence_hash` is the broker-TCB-assumed opaque value, not auditor-re-derivable); the
`credential_binding`/`evidence_hash` use Go-`json.Marshal` canonicalization, not the Rust RCP
canonicalizer; the forbidden-scope filter is a coarse pre-filter (the signed taxonomy is
authoritative); the descriptor reuses the `input` commit domain.

**Tier-B (Level 3) demonstrator — the real claim, fail-closed:**
5. A locked-down runtime: no standing credentials, enforced egress policy, sender-bound credentials —
   with **negative bypass tests** (the agent *tries* to act directly and to reuse/transfer a
   credential, and the attempts fail and/or surface as violations).
6. A reference resource shim at `L2_use_receipts` that validates the capability + proof-of-possession,
   consumes the single-use credential, and **emits a use record**.
7. Verifier join of use↔grant, the unmatched-use hard failure, per-resource conformance, and the
   bounded `action_completeness` verdict that **fails closed** without use records + attestation.

**Deferred past the demonstrator:** token-exchange/native-credential mode with introspection
transcripts, full delegation-policy engine, TEE/measured-boot attestation ingestion + evaluator,
revocation lists, multi-broker federation.

## Honest non-goals (state, don't hide)

- Not a proof the agent did nothing on **un-brokered** or `L1_grant_only` resources.
- Not a proof of **intent or correctness** of an action.
- Not resilient to a **compromised broker** (B6, TCB) unless issuance is enforced outside it.
- Not resilient to an **authentic-but-semantically-wrong scope taxonomy** — the verifier proves the
  taxonomy is signed, current, and digest-matched, not that it correctly captures each scope's real
  blast radius (a resource-owner TCB assumption).
- Tier A proves **grants**, not **actions**; Tier B's action claim is **conditional** on
  attestations (i)/(ii)/(iii), resource use-receipts, and side-effect closure.
- Inherits the **#15 never-anchored-suppression** residual until the witness store is in the trust
  path.

## Resolved review findings (rev 3 → rev 4)

Round-3 review: 5 RESOLVED, 2 PARTIAL collapsing to one MUST-FIX (now fixed); all other residuals
explicitly accepted by the reviewer ("do not re-raise"):
- *Taxonomy was a new unauditable trust boundary* → the signed scope taxonomy is now a **surfaced,
  freshness-checked, pinned artifact**: per-resource `taxonomy_ref`/`digest`/`publisher_key`/
  `version`/`effective_interval` + `taxonomy_status ∈ {absent, untrusted, stale, validated}` in the
  manifest and verifier output; Tier B counts a scope only under `validated`. The taxonomy's
  *semantic correctness* (vs authenticity/freshness) is stated as a resource-owner TCB residual.

## Resolved review findings (rev 2 → rev 3)

Round-2 review: 7/9 rev-1 findings RESOLVED; 2 PARTIAL + 5 new, all incorporated here:
- *Partial #2 / new #2 — `scope_class` was broker-asserted* → now Tier-B-eligible only when validated
  against a **pinned signed resource operation taxonomy**; unvalidated → Tier A only.
- *Partial #6 / new #3 — record-before-issue recovery unspecified* → **prepare/commit recovery** with
  a defined safe state at every crash point; the dangerous inverse structurally excluded; **native
  credentials demoted to Tier A** until a deterministic mint protocol exists.
- *New #1 — use↔grant was a key join* → now a **full semantic match predicate** (all security-
  relevant fields, single-use consumption, resource signature).
- *New #4 — unmatched-use hard failure tripped by honest races* → **watermark / closed
  `verification_interval`**; `unmatched_pending` (in-flight) vs `unmatched_violation` (hard fail).
- *New #5 — `cnf` stops token theft, not key theft* → B12 narrowed to token-only; full claim requires
  **sender-key non-exportability** (HSM/TPM/measured-boot); software-key key-exfil is a stated
  residual with a mandatory token+key negative bypass test.

## Resolved review findings (rev 1 → rev 2)

1. *Grants ≠ actions* → Tier A / Tier B split; Tier B requires use receipts + single-use creds.
2. *Scope does too much* → forbidden-scope rules + `scope_class`; verifier surfaces granularity.
3. *Attestations too narrow* → added (iii) non-transferability + side-effect closure to the manifest.
4. *Broker trust too cryptographic* → explicit TCB; `broker_trust` label; HSM/introspection options.
5. *Binding not exact* → full canonical credential descriptor (or introspection transcript) in
   `credential_binding`; confirmed P2.3 record_id-binding stops cross-record replay.
6. *Record-before-issue under-specified* → transactional issuance state machine + `issuance_status` +
   idempotency keys.
7. *Missing threats* → B10 (resource non-cooperation), B11 (metadata oracle), B12 (exfil-reuse).
8. *Verifier read too strongly* → tiered verdicts; `claimed_over_manifest` + `attestation_status`;
   upgrade gated on evaluated attestation + L2 + non-assumed broker trust.
9. *MVP wasn't Level 3* → renamed Tier-A prototype; defined the fail-closed Tier-B demonstrator with
   negative bypass tests.

## Open questions (for the next review round)

1. **Side-effect closure** is declarative (the manifest *asserts* what a granted action can touch).
   Is there any way to make it *verifiable* rather than asserted, or is it irreducibly an attestation?
   *[T6, PARTIALLY RESOLVED — see ADR 0004 D9 floor 2.]* The **declaration-completeness** half is now
   verifiable: the verifier checks that every resource any granted/used surface names is *affirmatively
   declared* in the D7-digest-bound `side_effect_closure` (else `unclosed_side_effects` → `ok=false`), and
   the D8 capstone requires `side_effect_closure_status=="closed"`. What stays irreducibly attested is
   **runtime obedience** — that the resource actually confined the action to the declared closure
   (bounded by `resource_trust: assumed_truthful`, the resource TCB). So: the *manifest is asserted*, but
   the surface staying *within* what it asserts is verified; the resource *honoring* it is not.
2. **Single-use vs. throughput.** Per-operation credentials maximize action↔grant tightness but cap
   agent throughput at broker round-trip latency. Is a bounded short-TTL multi-use credential (N uses
   within Δ, each emitting a use record) an acceptable Tier-B point, or does it reopen B3?
3. **Resource introspection trust.** Token-exchange binding relies on the resource's signed
   introspection transcript — does that just move the TCB to the resource, and is that better or worse
   than trusting the broker?
4. **Denied-grant volume.** Recording every denied request (B11) is good evidence but a DoS/cost
   vector. Sampling vs. full capture?
