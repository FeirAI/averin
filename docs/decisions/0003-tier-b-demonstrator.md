# ADR 0003 — Tier-B (Level 3) demonstrator: implementation design

**Status:** Implemented (rev 4; Codex review READY TO BUILD — all four rev-2 MUST-FIXES resolved + the
rev-3 R5 per-`grant_id` blocker closed). Built across five adversarially-reviewed commits `tierb[1..5]`:
R1 RCP-canonical re-derivable evidence_hash; R2 role-separated broker/resource authority keys;
`resourceshim` (PoP-at-use + consume-before-act ledger, R4/R5); `POST /v2/use` resource-signed receipts;
verifier use↔grant join over the closed set (R3) + `action_completeness` + the full match predicate.
**Date:** 2026-06-15
**Builds on:** ADR 0002 (the credential-broker architecture, hardened across 3 review rounds) and the
shipped Tier-A prototype (`broker` pkg, `POST /v2/grants`, `feir_sign_evidence`, verifier
`grant_accountability`).
**Revision:** rev 4 — the four rev-2 MUST-FIXES are RESOLVED (below); rev 4 fixes one new blocker the
rev-3 review surfaced: the single-use invariant is **per-`grant_id`**, not per-`jti`. The verifier now
fails on >1 matched closed use per `single_operation` `grant_id` regardless of `jti`, and requires
`use_evidence.jti == grant_id` for single-use uses as the canonical binding (R5) so the shim's per-jti
ledger and the verifier's per-grant_id rule provably coincide.

rev 3 — addresses the four MUST-FIXES from the second adversarial review round.
(rev 2 corrected the headline claim to **resource-attested** action accountability — the resource is
an explicit TCB member, F7 — and promoted evidence re-derivability (F1), broker/resource key
role-separation (F2), and a checkpoint-frontier closed boundary (F3) to load-bearing requirements.)
rev 3 pins down the four under-specified mechanisms the review flagged:
- **MUST-FIX 1 (R1):** canonical **grant_evidence** and **use_evidence** schemas are now defined
  field-by-field; the verifier reads *every* match input ONLY from the re-derived evidence payload,
  and any divergence between the evidence payload and a duplicated record field is a hard failure.
- **MUST-FIX 2 (R3):** the closed-frontier wording is narrowed to "the **watermark-specific**
  suppression path is closed"; Tier-B is explicitly scoped to visible, checkpoint-committed receipts,
  and suppression of a never-anchored use is named an accepted residual (not a closed gap).
- **MUST-FIX 3 (R2):** role classification is fully fail-closed — broker/resource key-set
  intersection is a fatal config error; exactly one recognized role per record; enforcement_point
  must align with the signer role; any missing/unrecognized role discriminator is a verification
  failure, never a silent drop.
- **MUST-FIX 4 (R4/R5):** the receipt now CARRIES `pop_challenge_hash`, the agent `cnf_kid`, and a
  `ledger_commitment` under the re-derived `evidence_hash` (tamper-evident, offline-inspectable), AND
  the claim section states plainly that the resource shim — which validated capability, PoP, nonce,
  and consume-before-act before signing — is TCB; the verifier checks the signature, the
  `evidence_hash` re-derivation, and the presence/integrity of these audit fields, not the PoP
  semantics themselves.

The record-after-action gap (F4), single-use suppression residual (F5), and taxonomy dependence (F8)
remain bounded honestly below.

## What Tier-B claims — and the precise, honest line it does NOT cross

Tier A proved **grant accountability**: every credential the broker issued has a recorded, signed,
anchored grant. Tier B's claim is narrower than "everything the agent did" — it is:

> **Resource-attested action accountability over the closed interval:** every USE RECEIPT a resource
> emitted has a verifiable, integrity-proven, gateway-enforced grant it maps to (and a single-use
> grant is exercised at most once) — **conditional on the resource being honest** (it actually
> performed the attested action, labeled it truthfully, and emitted a receipt for everything it did).

The resource is therefore a **TCB member** alongside the broker (F7). What Tier B proves
cryptographically: a resource-signed receipt is bound to a real grant, and there is no receipt
without a grant (an unmatched receipt is a hard failure). What it CANNOT prove from the bundle, stated
plainly next to the claim:

- **(F4) Actions the resource performed but never recorded** — a use is recorded AFTER the action, so
  a resource that acts then crashes/suppresses before the receipt is durable leaves an INVISIBLE
  action. This is the real residual Level-3 gap. The verifier catches receipt-without-grant, never
  action-without-receipt. Hardening (future): a two-phase resource gateway that records a `use_intent`
  BEFORE the side effect and a `use_outcome` after (so a missing outcome is itself a recorded,
  detectable anomaly). The demonstrator builds the one-phase receipt and bounds this explicitly.
- **(F7) Resource forgery/mislabeling** — a malicious resource can sign a matched receipt without
  acting, or perform op X while labeling it the granted action. Surfaced as the resource TCB.
- **(F5) Suppression of a second single-use receipt** — inherits #15: double-spend is detected only
  when BOTH receipts are visible; a never-anchored second receipt is suppressible. This is the
  PRIMARY attack on single-use, not a tail edge case.
- **Deployment attestations** (isolation/egress/non-transferability) — NOT built; `attestation_status:
  unevaluated`. The runtime properties are demonstrated via negative bypass tests, not claimed.

**The resource shim is TCB for use-time validation (MUST-FIX 4).** Tier-B trusts the shim to have
validated the capability (signature, expiry, scope), the PoP-at-use (`use_sig` under the `cnf` key
with the fully-bound challenge, R4), the nonce freshness, and consume-before-act on the jti/nonce
ledger (R5) **before it signs the receipt**. The offline verifier's role is narrower: it checks the
resource's signature over the receipt, re-derives `evidence_hash` from `use_evidence` (R1), confirms
role separation (R2) and closure (R3), and confirms the receipt *carries* well-formed
`pop_challenge_hash`, `cnf_kid`, `nonce`, `jti`, and `ledger_commitment` consistent with the grant —
but it does **not** re-run the Ed25519 PoP check or verify ledger ordering. Those checks live in the
shim, inside the TCB. Carrying the audit fields (R4/R5) makes them tamper-evident and cross-checkable;
full offline re-verification of PoP (bundling the agent `cnf` pubkey + `use_sig` so the verifier
re-runs the signature check) is the named next step that would shrink this TCB.

The verifier keeps emitting `action_completeness: claimed_over_manifest` (never
`attested_complete_over_brokered_surface`) until attestations are evaluated and broker_trust is
reduced. We build the *evidence machinery*, honestly bounded.

## Canonical evidence schemas (MUST-FIX 1 — the only inputs the match predicate may read)

The match predicate's inputs come from **exactly two** canonical payloads, each carried inside the
record and bound by `evidence_hash = sha256(RCP-canonicalize(payload))`. RCP forbids floats and sorts
keys, so the canonical form is byte-deterministic. Both payloads are integer-/string-only.

**`grant_evidence`** (carried at `extensions.broker.grant_evidence`, signed by a **broker** key):

| field | type | role in matching |
|-------|------|------------------|
| `kind` | `"grant"` (literal) | role/shape discriminator |
| `grant_id` | string | join key |
| `action` | string | action-equality input |
| `resource_id` | string | resource-equality input |
| `scope_class` | string | selects single-use (`single_operation`) vs reusable |
| `agent_id` | string | provenance (not matched, audited) |
| `cnf_kid` | string | key id the use's PoP must verify under |
| `issued_at` | int (unix s) | lower bound of the temporal window |
| `exp` | int (unix s) | upper bound of the temporal window |

**`use_evidence`** (carried at `extensions.broker.use_evidence`, signed by a **resource** key):

| field | type | role in matching |
|-------|------|------------------|
| `kind` | `"use"` (literal) | role/shape discriminator |
| `grant_id` | string | join key (→ `grant_evidence.grant_id`) |
| `action` | string | must equal `grant_evidence.action` |
| `resource_id` | string | must equal `grant_evidence.resource_id` |
| `jti` | string | single-use consumption id; for `single_operation` grants MUST equal `grant_id` (R5) |
| `nonce` | string | PoP freshness nonce (R4) |
| `pop_challenge_hash` | hex (sha256) | offline-inspectable PoP binding (R4/MUST-FIX 4) |
| `cnf_kid` | string | must equal `grant_evidence.cnf_kid` |
| `ledger_commitment` | hex (sha256) | resource consume-before-act ledger evidence (R5/MUST-FIX 4) |
| `used_at` | int (unix s) | must lie in `[issued_at, exp]` |

**The verifier reads each match input ONLY from these payloads** — never from a sibling/top-level
record field. Top-level conveniences (e.g. a record's top-level `action`) are permitted ONLY as a
human-readable echo and are **not** consulted for matching. To make that non-bypassable:

- If a match-relevant field appears both in the canonical payload and in a duplicated record field
  and the two **diverge**, the record is a **hard verification failure** (fail-closed), not a
  silently-ignored mismatch. (Identical duplicates are allowed.)
- A record missing its expected canonical payload, or whose payload omits a required field, is **not
  verified** and, if closed and Tier-B-relevant, is surfaced as an error.

## Load-bearing requirements the review surfaced (must-build, not deferred)

### R1 — The verifier re-derives `evidence_hash` from the canonical payload (F1, MUST-FIX 1)

`verify_authority` only checks a signature over `(source, record_id, evidence_hash)` — it treats
`evidence_hash` as opaque. So `AuthorityTrust::Verified` alone does NOT prove the resource signed the
semantic fields the match predicate reads. **The match would otherwise fire on unverified field
values.** Therefore, for a grant or use to count:

1. The record carries its canonical payload (`grant_evidence` / `use_evidence` above) and, for uses,
   the params via `input_commit` (disclosable).
2. The verifier **recomputes** `evidence_hash' = sha256(RCP-canonicalize(payload))` using the
   **Rust RCP canonicalizer** (the single source of truth) and requires `evidence_hash' ==
   authority.evidence_hash` before the record is `verified`. A mismatch ⇒ not verified.
3. **All** match inputs are then read from that proven payload (per the schemas above); divergence
   from any duplicated record field is fatal.
4. Consequently the broker/resource MUST compute `evidence_hash` the same way — via the core's RCP
   canonicalizer (a new `feir_rcp_evidence_hash` helper, or `feir_rcp_canonicalize` + sha256), NOT Go
   `json.Marshal`. (The shipped Tier-A grants use Go-json `evidence_hash`; Tier-B re-derivation is
   added for BOTH grants and uses — step 1 retires the Tier-A "evidence opaque" residual for any
   record that participates in a Tier-B match, since the carrier `grant_evidence` is now re-derivable.)

### R2 — Broker/resource keys are role-separated, fail-closed (F2, MUST-FIX 3)

Pinning broker + resource keys together in one `authority_keys` set lets a resource key sign a
`credential_grant`, or the broker key sign a `kind:"use"`, and both pass. The verify options therefore
take **two disjoint sets** — `broker_authority_keys` and `resource_authority_keys` — and role
classification is fully fail-closed:

1. **Disjointness is a fatal configuration error.** If `broker_authority_keys ∩
   resource_authority_keys ≠ ∅` (compared by key id AND by raw key bytes), the verifier aborts with a
   config error before evaluating any record — it never proceeds on an ambiguous key universe.
2. **Exactly one role per record.** Each Tier-B-relevant record carries a role discriminator =
   `(extensions.broker.kind, authority.enforcement_point)`. The two recognized tuples are
   `("grant", "credential_broker")` → **broker role** and `("use", "tool_gateway")` → **resource
   role**. A record whose tuple is neither, or whose `kind` and `enforcement_point` point at
   different roles (ambiguous), classifies to **no role**.
3. **Enforcement_point alignment is fail-closed.** A broker-role record must verify under a
   `broker_authority_keys` key AND carry `enforcement_point: credential_broker`; a resource-role
   record under a `resource_authority_keys` key AND `enforcement_point: tool_gateway`. Any
   cross-signing (resource key on a grant, broker key on a use) or mismatched enforcement_point ⇒ not
   verified.
4. **A missing or unrecognized role discriminator is a verification failure, not a silent drop.** A
   closed Tier-B-relevant record that classifies to no role is surfaced as an error (it cannot be
   quietly excluded from the count, which would let a mislabeled use escape the `unmatched_violation`
   check).
5. The per-record report carries which role/key id verified it, so an auditor sees broker-signed vs
   resource-signed provenance.

### R3 — The "closed" boundary is the verified checkpoint frontier, NOT an exporter watermark (F3, MUST-FIX 2)

An exporter-asserted watermark is a suppression surface: a too-early watermark pushes a closed
violating/second-spend use into `pending`, and if the Tier-B verdict gates only on
`unmatched_violation == 0`, a known-bad bundle reads clean. So there is no exporter watermark. Instead:

- A record (grant or use) is **CLOSED** iff its `content_hash` is transitively committed by a
  **verified, anchored** checkpoint (reuse the existing `committed_set` / frontier machinery). The
  closed boundary is therefore cryptographic, not asserted.
- Tier-B outcomes are computed over the CLOSED set: a closed use with no matching closed grant ⇒
  `unmatched_violation` (hard fail); a use NOT yet committed by a verified checkpoint ⇒
  `unmatched_pending` (in-flight, not a failure). A clean Tier-B result is NEVER issued while closed
  records have unexplained pending peers — `action_completeness` cannot exceed `claimed_over_manifest`
  unless every in-scope record is closed.

**What this closes, and what it does NOT (MUST-FIX 2).** Replacing the exporter watermark with the
verified frontier closes the **watermark-specific** suppression path: an exporter can no longer move a
boundary to hide a use that *was* committed, because "closed" is now derived from the checkpoint DAG,
not asserted. Tier-B's guarantees are therefore scoped to **visible, checkpoint-committed receipts** —
the closed set. It does **not** close suppression of a use the resource simply **never anchored**:
because a use is recorded AFTER the action (F4) and a malicious/crashed resource can decline to emit
or seal a receipt, an action with no anchored receipt is invisible to the frontier too. **All
never-anchored use suppression is an accepted residual** (the F4 record-after-action gap and the F5
never-anchored second single-use receipt), not something the frontier eliminates. The frontier only
guarantees that *anchored* receipts cannot be retroactively hidden behind a watermark.

### R4 — PoP-at-use is mandatory, fully bound, and the binding is carried in the receipt (F6, MUST-FIX 4)

`use_sig` is REQUIRED (no optional). The agent signs a `pop_challenge` with the `cnf` private key,
where `pop_challenge = sha256(LP("feir.broker.use.pop.v1") ‖ grant_id ‖ resource_id ‖ action ‖
params_commitment ‖ credential_binding ‖ nonce)`. The **resource generates a one-time `nonce`** and
records it in a durable, auditable resource-side nonce ledger (R5) so a captured `use_sig` cannot be
replayed for a different operation or a second time. A use with a missing/invalid `use_sig`, or a
reused `nonce`, is rejected by the shim and does not become a Tier-B-countable use.

**Carried for offline inspection (MUST-FIX 4).** So that the PoP binding is not invisible to an
offline auditor, `use_evidence` carries `pop_challenge_hash = sha256(pop_challenge preimage)`, the
agent `cnf_kid` (which must equal the grant's `cnf_kid`), the `nonce`, and the `jti` — all under the
re-derived `evidence_hash`, so they are tamper-evident. The verifier checks these fields are present,
well-formed, and consistent across grant/use (`cnf_kid` equality), and that the resource signed the
whole evidence. **It does NOT re-execute the Ed25519 PoP verification** (it has no `use_sig` or agent
public key in the bundle) — see the TCB statement under the claim. The honest delta vs full offline
PoP re-verification is documented as the resource-shim TCB and a named next step.

### R5 — Single-use is a per-`grant_id` invariant; the ledger and the receipt enforce it (F5, rev-4 fix)

The single-use claim is **"a single-use grant is exercised at most once"** — a **per-`grant_id`**
invariant. The resource ledger is the runtime enforcer, but the verifier's authoritative rule must be
stated as the true invariant, not a `jti` proxy that can diverge from it. So:

1. **Verifier rule (authoritative).** For a grant with `scope_class == "single_operation"`, the
   verifier fails (`unmatched_violation`, double-spend) on **more than one matched closed use per
   `grant_id`** — **regardless of the `jti` values**. Keying detection on duplicate `jti` alone is
   insufficient: two closed receipts for the same single-use `grant_id` with *different* `jti` are
   still a double-spend, and this rule catches them.
2. **Canonical binding.** For single-use grants the broker mints the capability with `jti == grant_id`
   (one single-use grant ⇒ one jti). The verifier requires `use_evidence.jti == grant_id` for any use
   matched to a `single_operation` grant and treats divergence as a hard verification failure (R1/
   MUST-FIX 1 fail-closed). This makes the shim's per-`jti` ledger and the verifier's per-`grant_id`
   rule provably coincide. (Reusable grants legitimately have many uses with distinct `jti ≠
   grant_id`; the per-`grant_id` cap does not apply to them.)
3. **Runtime ledger (shim).** The shim maintains a durable ledger keyed by `jti` (single-use
   consumption) AND `nonce` (PoP freshness), with **consume-before-act** semantics: the jti/nonce is
   marked consumed BEFORE the side effect, so a crash cannot leave a consumable credential. Each
   consumption contributes a `ledger_commitment` (sha256 over the consumed `(jti, nonce, used_at)`
   entry) into `use_evidence`, so an auditor sees the use claims to have been ledger-consumed.

**What the verifier can prove offline:** two visible closed matched uses for one single-use `grant_id`
⇒ double-spend `unmatched_violation` (per rule 1). **What it cannot prove offline:** that the consume
happened *before* the act (ordering is internal to the shim — TCB), and that a never-anchored second
receipt does not exist — that suppression remains the #15 residual, stated.

### R6 — Taxonomy-unvalidated grants are NOT counted as Tier-B actions (F8)

`U.action == G.action` only proves one-grant-one-operation when `scope_class == single_operation` is
**validated against a signed resource operation taxonomy** (ADR 0002 rev 3/4). The demonstrator has no
taxonomy, so matched uses against taxonomy-unvalidated grants are shown as a **demonstrator artifact**
(`action_unverified`) and do NOT count toward `uses_matched` for any `attested_complete` upgrade.

## Components

### Use record (execution receipt) — schema

A sealed Decision Record (the SAME verifier validates it):
- `event_type`: the real operation type (`tool_call` etc.); `observed_via`: `"broker"`.
- `action`: the operation id — MUST equal the grant's `action`.
- `authority`: `source = gateway_enforced`, `enforcement_point = "tool_gateway"`, `grant_id`,
  `evidence_hash` + `evidence_sig` **signed by the RESOURCE key** (record_id-bound; evidence re-
  derivable per R1), `evaluated_at`.
- `input_commit`: hiding commitment over the operation params (disclosable).
- `extensions.broker`: `{ kind: "use", grant_id, resource_id, use_evidence: {…} }` where
  `use_evidence` is the exact canonical payload defined in *Canonical evidence schemas* above
  (`kind, grant_id, action, resource_id, jti, nonce, pop_challenge_hash, cnf_kid, ledger_commitment,
  used_at`) and is the **only** source the verifier reads match inputs from (R1/MUST-FIX 1).

### Resource shim — `resourceshim` package (pure logic) + negative bypass tests

Configured with the broker **issuing** pubkey + the durable jti/nonce ledger (R5).
`ValidateUse(token, useSig, op, nonce, now)`: VerifyCapability → expiry (B8) → single-use via ledger
(R5) → PoP-at-use under `cnf` with the fully-bound challenge (R4) → scope/action coverage. On success
the resource recording side produces the re-derivable use evidence and a sealed receipt; on any
rejection it errors (a real deployment also records the denied attempt, B11).

### `POST /v2/use` — submit a use receipt

Enabled by `WithResource(recordingKey, resourceID)`. Validates + signs the use evidence with the
**resource** key (R1/R2), commits params, seals+stores the receipt in the grant's session DAG.
Idempotent on a caller-supplied key. An **empty** `project_id`/`session_id` is a 400 (the agent must
pass a session). The use↔grant join is keyed by `grant_id`, NOT by session, so a use may legitimately
land in any session branch — a novel session id starts a fresh DAG branch rather than being rejected.

### Verifier — use↔grant join, closed-set, `action_completeness`

Pin `broker_authority_keys` + `resource_authority_keys` (R2). New report fields: `uses_total`,
`uses_matched`, `uses_action_unverified` (R6), `unmatched_violation`, `unmatched_pending`,
`grants_unused`, per-resource `conformance`, and `action_completeness`
(`not_claimed`|`claimed_over_manifest`|`attested_complete_over_brokered_surface`). The full match
predicate (R1 evidence-re-derived on both sides; R2 role-checked; R3 closed-set; action/resource/
window equality; for `single_operation` grants ≤1 matched closed use **per `grant_id`** regardless of
`jti`, with `use_evidence.jti == grant_id` required, R5) gates every count, with `attested_complete`
reachable only
when all-L2 ∧ taxonomy-validated ∧ attestation evaluated ∧ broker_trust≠assumed ∧
unmatched_violation==0 ∧ no unexplained pending in the closed set.

## Negative bypass tests (the demonstrator's teeth)

- **action without a credential / forged use without a grant** → `unmatched_violation` (hard fail).
- **credential reuse (same jti)** → shim rejects the 2nd use (ledger); if two receipts are
  nonetheless visible and closed, the verifier flags the 2nd as a double-spend `unmatched_violation`.
- **single-use double-spend (same jti == grant_id)** → two closed matched uses for the SAME
  `single_operation` `grant_id` → the 2nd is flagged a double-spend `unmatched_violation` by the
  per-`grant_id` rule (R5, regardless of jti) — the invariant a `jti`-only check would miss.
- **single-use jti rebinding** (a `single_operation` use with `jti ≠ grant_id`) → hard verification
  failure (R5 canonical binding). *Implementation note:* because `jti == grant_id` is REQUIRED for
  single-use, a second receipt carrying a *distinct* jti is caught here (jti-rebinding) BEFORE the
  per-`grant_id` cap — so the demonstrator catches the distinct-jti double-spend too, just via the
  binding rather than the cap. Both same-jti (cap) and distinct-jti (binding) are violations; tests
  cover both.
- **expired credential** → shim rejects after `exp`.
- **token theft (use without the cnf key)** → PoP-at-use fails.
- **replayed use_sig** → rejected (nonce ledger; challenge bound to nonce+op).
- **action substitution** (use.action ≠ grant.action) → no match → `unmatched_violation`.
- **tampered use evidence** (evidence_hash ≠ sha256(RCP-canon(use_evidence))) → not verified (R1).
- **field divergence** (top-level `action` ≠ `use_evidence.action`, or `cnf_kid` use≠grant) → hard
  verification failure, NOT a silent non-match (R1/MUST-FIX 1).
- **role confusion** (use signed by the broker key, or grant by a resource key) → not verified (R2).
- **role-less / mislabeled record** (closed Tier-B record with a missing or unrecognized
  `(kind, enforcement_point)` discriminator) → verification failure surfaced as an error, never a
  silent drop (R2/MUST-FIX 3).
- **key-set intersection** (a key configured in both `broker_authority_keys` and
  `resource_authority_keys`) → fatal verifier config error before any record is evaluated (R2/MUST-FIX 3).

## Build order (each commit adversarially reviewed)

1. RCP evidence-hash helper (FFI `feir_rcp_evidence_hash` or canonicalize+sha256) + Go wrapper;
   make Tier-A grant evidence_hash RCP-canonical and have the verifier re-derive it (R1 for grants).
2. Verifier: role-separated `broker_authority_keys`/`resource_authority_keys` + re-derivation gate
   (R1/R2), no Tier-B counting yet.
3. `resourceshim` pkg (ValidateUse + ledger) + negative bypass tests (R4/R5).
4. `POST /v2/use` + use-receipt sealing (R1 evidence, resource-signed).
5. Verifier use↔grant join over the closed set (R3) + `action_completeness` + the full match
   predicate + report fields + golden adversarial tests (all negative cases above).

## Resolved open questions (rev 1 → rev 2)

1. Watermark → replaced by the verified checkpoint frontier (R3); the **watermark-specific**
   suppression path is closed (anchored receipts can't be hidden behind a moved boundary). Suppression
   of a never-anchored use stays an accepted residual (F4/F5), not a closed gap.
2. Use without a session → an empty project/session is a 400; the join is by `grant_id`, so a novel
   session id is accepted (a fresh DAG branch), not rejected.
3. Single-use double-spend → resource nonce/jti ledger (R5) + the stated #15 suppression residual.
4. Resource key conflation → role-separated key sets + per-record signer-role report (R2).

## Remaining honest residuals (accept-and-document)

- The resource is a TCB member (forgery/mislabeling/unrecorded-action) — bounded, not eliminated (F4,
  F7); the two-phase intent/outcome gateway is the future hardening.
- Single-use suppression of a never-anchored second receipt — #15 residual.
- The signed operation taxonomy is not built — taxonomy-unvalidated matches are `action_unverified`,
  excluded from any `attested_complete` upgrade (F8).
- Deployment attestations unevaluated; broker_trust assumed.
