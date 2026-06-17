# ADR 0005 — Deferred Producer Modes (design-only + staging map)

**Status:** Accepted (DESIGN ONLY — no production code). Stages the six credential-broker producer modes
ADR 0002 deferred (line 362) and resolves ADR 0002 open Q2 (N-use) + Q3 (introspection).
**Date:** 2026-06-17
**Builds on:** ADR 0002 (broker, tiers, B-threats), ADR 0003 (Tier-B demonstrator: R1–R5, role separation),
ADR 0004 (D1–D9 residual reduction, MF1–MF5, the D8 capstone + per-conjunct discipline, the build-order
and honesty-about-floors voice this ADR mirrors).

## 0. What this ADR is — and the honesty bar it holds

This is a **staging map, not an implementation**: for each of six deferred modes it fixes the mechanism,
the schema/evidence deltas, the verifier semantics, the D8-capstone interaction, the new signature domains,
and the residual floors — plus a table of exactly where each mode hooks into the code. **No code, no schema
files, and no behavior change ship with this ADR.** Following ADR 0004's rule, every mode states plainly what
it proves *cryptographically* versus what stays *TCB* (`resource_trust: assumed_truthful`), and the D8
conjunction only ever gets MORE restrictive (or gains an explicit, weaker, labeled tier) — never looser.

> **Implementation status (updated):** **M1 (`bounded_reuse`/N-Use) has since been built end-to-end** —
> see its §M1 status note. M2–M6 remain design-only staging maps. The ADR 0002 amendments §9 prescribes
> "to apply alongside the first implementation" are now applied (M1 was that first implementation).

The design was pressure-tested against the live verifier (`core/src/verify.rs`) and producer
(`server/internal/broker`, `server/internal/api`, `server/internal/resourceshim`). Where a mode stresses or
breaks an existing invariant, the exact reconciliation is given.

## 1. Context — the six deferred modes (ADR 0002:361) + the open questions

ADR 0002 deferred: token-exchange/native credentials, a full delegation-policy engine, revocation lists, and
multi-broker federation; and left open **Q2** (single-use vs. throughput — is a bounded multi-use credential
an acceptable Tier-B point?) and **Q3** (resource-introspection trust). M-of-N co-signature is added here as a
seventh concern (today it exists only as the ADR 0001 evidence-custody pattern, not a broker mode).

The broker is already **credential-production-complete for `single_operation`**: PoP sender-constraint (D2),
gapless `broker_seq` transparency (D6), role-separated grant/use evidence (R2), the credential descriptor +
`credential_binding` commitment, two-phase intent/outcome (D5). Every mode below **extends** these primitives
rather than rewriting them; the reuse inventory is called out per mode.

## 2. Locked decisions (design within these — not re-litigated here)

- **N-Use** = a `bounded_reuse` scope_class: N uses of the *identical* `(action, resource_id)`, fixed at the
  grant; each use emits a receipt; replay dedup per `(grant_id, use_sequence_number)`; window = the grant's
  `[issued_at, exp]`. Capstone-reachable **iff** every use is two-phase + PoP-reverified.
- **Delegation** = **per-hop signed** assertions: each delegator signs the next hop's identity + scope + cnf;
  the verifier proves every hop and re-checks monotonic non-increase — without trusting the broker's chain.
- **Native/STS** = **post-mint introspection transcript**: record the grant, then bind the resource's signed
  effective-scope statement via a second append-only record. Offline verifies the bundled transcript (resource
  TCB); opt-in online re-introspect.
- **Federation** = **tiered**: pinned per-broker authority keys (offline baseline) + optional cross-broker
  delegation certs; each broker's `broker_seq` log verified independently; cross-broker suppression surfaced.
- **Revocation** = **tiered**: a bundled, signed, time-bounded list (offline default; stale status blocks the
  capstone) + opt-in online CRL.
- **Cosig** = **M-of-N grant approval**: N approver keys disjoint from broker/resource keys (a new role key
  set ADDED to the R2 disjointness machinery — see the note below); the verifier counts ≥ M cosignatures.
- Opt-in **online checks are allowed** (clearly labeled non-offline). The ADR **classifies each mode's D8
  interaction**.

All new signature preimages follow the existing LP4-length-prefix / BE8-big-endian / domain-tag convention of
`authority.rs` (`feir.authority.v2`), `resourceshim` (`feir.broker.use.pop.v1`, `feir.broker.use.ledger.v1`),
and the grant-head root — `sha256(LP4(tag) ‖ …)`, signed by the noted key.

## 3. Per-mode design

Each subsection mirrors the ADR 0004 D-series shape: *Mechanism → Schema delta → Verifier semantics →
Capstone → Signature domain → Residual*.

### M1 — N-Use (`bounded_reuse`) — resolves ADR 0002 Q2

> **Status: IMPLEMENTED end-to-end** (verifier semantics `fbab33c`, Go producer + D6.4 `use_limit`
> cross-check `a5877c6`). This is the first ADR-0005 mode to ship; the design below is live. The other
> five modes (M2–M6) remain design-only staging maps. Live surface: `POST /v2/grants` accepts
> `scope_class:"bounded_reuse"` + `use_limit:N`; `POST /v2/use[-intent]` accepts `use_sequence_number`;
> the verifier enforces the per-class branch + `(grant_id, usn)` dedup + the two capstone conjuncts; the
> resource shim keys its consume-before-act ledger on `(grant_id, usn)`. Tested: Rust adversarial
> (within-cap / overspend / seq-replay / no-`use_limit`-fail-closed) + Go e2e (incl. the capstone over an
> N-Use credential). One honest residual, documented in `verify.rs`: the descriptor↔grant_evidence
> `use_limit` equality is verified only under credential-descriptor disclosure (the standard D6.4
> broker-TCB residual), but the evidence-plane cap is `grant_evidence.use_limit`, enforced fail-closed.

- **Mechanism.** A fourth `ScopeClass` `bounded_reuse` (alongside `single_operation`/`session_grant`/
  `batch_grant`). The grant fixes `(action, resource_id)` and a cap `N`; the credential is `single_use:false`
  but bounded — each use carries a 1-based `use_sequence_number ≤ N` and emits a receipt. Window = the grant's
  `[issued_at, exp]`.
- **Schema delta.** `grant_evidence.use_limit:int`; `use_evidence.use_sequence_number:int`; `Descriptor`
  carries `use_limit`. Reuses the `single_use:false` path and the existing `[nbf,exp]` enforcement.
- **Verifier semantics.** The single-use check (verify.rs ~2466) becomes per-class. `single_operation` keeps
  `jti==grant_id` + `used==0`. `bounded_reuse` **keeps `jti==grant_id` too** (so the D6.4 descriptor
  cross-check `descriptor.jti == grant_id` at verify.rs ~2267 is UNCHANGED — the resource sources
  `use_evidence.jti` straight from the descriptor jti, so it must NOT diverge); the per-exercise identity is
  the SEPARATE `use_sequence_number` field. The verifier requires `1≤usn≤use_limit`, dedups `(grant_id, usn)`
  across closed receipts, and caps `used ≤ use_limit`. On the producer side the shim's single-use ledger
  consumes `(grant_id, usn)` for `bounded_reuse` instead of the bare jti (resourceshim ConsumeJTI key
  generalizes; the nonce ledger is unchanged). New report fields: `bounded_reuse_grants`,
  `bounded_reuse_overspent`, `bounded_reuse_seq_replays`.
- **Capstone.** **Reachable.** The existing `!one_phase_use_present` + `uses_pop_reverified==uses_matched`
  conjuncts already enforce "two-phase + PoP-reverified"; add `bounded_reuse_overspent==0 &&
  bounded_reuse_seq_replays==0` (surfacing-redundant with `unmatched_violation` but self-documenting).
- **Signature domain.** None required (fields ride inside the signed `grant_evidence`/`use_evidence`).
  *Recommended* defense-in-depth: `feir.broker.use.pop.v2` appends `BE8(use_sequence_number)` so a captured
  PoP for use #2 can't be replayed as #3 before the ledger dedup fires.
- **Residual.** Reopens a *bounded* slice of B3 (a credential reused N times within one window); stated as a
  Tier-A-style coarsening that is nonetheless Tier-B-eligible because action↔grant tightness is preserved
  (identical `(action, resource_id)`).

### M2 — Delegation (per-hop signed)

- **Mechanism.** The grant carries an ordered list of signed hop-assertions. Each hop `H_k` is signed by hop
  k's cnf key (the delegator) over the *next* hop's identity + narrowed scope + cnf + exp. The verifier
  re-walks the chain from the broker-signed root `cnf_kid`, proving each signature and re-checking monotonic
  non-increase itself — it never trusts the broker's flattened `delegation_chain[]` claim.
- **Schema delta.** Activates the already-present-but-unused `Request.{Principal,DelegationChain}`; adds
  `grant_evidence.delegation_assertions[]` of `{delegator_cnf, delegate_cnf, scope, action, resource_id, exp,
  sig}`. The minted credential's scope is the *leaf* (narrowest) scope.
- **Verifier semantics.** New report fields `delegation_chains_total/_verified`,
  `delegation_monotonicity_violations`, `delegation_status`. The use-side binds to the **leaf** cnf/exp
  (computed from the verified chain), not the root — so PoP re-verification (D2) runs under `effective_cnf_kid`
  and the window is `min(root_exp, leaf_exp)`. Hop keys are per-grant cnf keys, orthogonal to R2 (no
  disjointness extension).
- **Capstone.** **Reachable**, gated by `(delegation_chains_total==0 || delegation_chains_verified ==
  delegation_chains_total) && delegation_monotonicity_violations==0` — every *present* chain must be fully
  chain-proven.
- **Signature domain.** `feir.broker.delegation.hop.v1` = `sha256(LP4(tag) ‖ LP4(grant_id) ‖ BE8(hop_index) ‖
  LP4(delegator_cnf_kid) ‖ LP4(delegate_cnf_kid) ‖ LP4(scope) ‖ LP4(action) ‖ LP4(resource_id) ‖ BE8(exp))`.
- **Residual.** Strengthens B9 (confused-deputy) from broker-attested labels to cryptographic hops. The
  monotonicity subset relation over scope strings remains a TCB on the scope vocabulary (D4 taxonomy).

### M3 — Native/STS (post-mint introspection transcript) — resolves ADR 0002 Q3

- **Mechanism.** For credentials minted by an external IdP/STS whose effective scope the verifier cannot
  recompute, record the grant (`mode:"token_exchange"`, `lease_id`), then bind the *resource's signed
  introspection transcript* (its statement of the credential's effective scope) via a **second append-only
  record** that references the grant. Offline verifies the bundled signed transcript; with
  `online_introspect_url` configured the verifier re-introspects (labeled non-offline).
- **Schema delta.** Reuses `Descriptor.mode` (value `token_exchange`) + `grant_type:"oauth-scope"` (already a
  legal enum); adds `Descriptor.lease_id` and a new record kind `extensions.broker.kind ==
  "introspection_transcript"` carrying `introspection_evidence{grant_id, lease_id, effective_scope,
  resource_id, transcript_hash, observed_at}`, resource-signed.
- **Verifier semantics.** New `classify_role` tuple `(introspection, tool_gateway) → Resource`. A pre-pass
  binds each transcript to its grant and checks `effective_scope ⊆ grant.scope` (a resource broadening past the
  grant is a violation); the *effective* scope then governs use action-verification. New fields
  `introspection_transcripts_total/_verified`, `introspection_scope_narrowed`, `native_credential_present`.
- **Capstone.** **NOT** the standard label — native credentials have no broker `credential_binding` and no
  cnf-key PoP, so they can never satisfy `uses_pop_reverified==uses_matched`. Add the explicit exclusion
  `!native_credential_present`, and introduce a **parallel, strictly-weaker label**
  `attested_complete_over_introspected_surface` (every other conjunct PLUS
  `introspection_transcripts_verified==introspection_transcripts_total>0`). A *mixed* native+PoP bundle reaches
  neither full label (≤ `claimed_over_manifest`) — keeping each label's MF1 meaning crisp.
- **Signature domain.** `feir.resource.introspection.v1` = `sha256(LP4(tag) ‖ LP4(grant_id) ‖ LP4(credential_ref)
  ‖ LP4(effective_scope) ‖ LP4(resource_id) ‖ BE8(introspected_at) ‖ BE8(effective_exp))`, under
  `resource_authority_keys`.
- **Residual.** The transcript is itself resource-signed → it **relocates, does not remove,** the resource TCB
  (`resource_trust: assumed_truthful`, ADR 0004 D9 floor 2 / ADR 0002 Q3). The verifier proves the resource
  *signed* the effective scope, not that the IdP's scope is honest.

### M4 — Federation (tiered)

- **Mechanism.** Each grant carries `broker_id` + `issuer_kid`. The verifier pins per-broker authority keys and
  verifies each broker's `broker_seq` transparency log **independently** (a gap in broker A's seq never masks
  B's). Optional `cross_broker_cert` (broker A signs B's authority for a resource) elevates a federated grant
  from `untrusted → transitive`.
- **Schema delta.** `grant_evidence.{broker_id, issuer_kid}` (absent ⇒ single-broker, today's behavior);
  optional `grant_evidence.cross_broker_cert`. `broker_grant_head` generalizes to a per-`broker_id` map.
- **Verifier semantics.** `compute_broker_trust` runs per `broker_id`; aggregate `broker_trust =
  worst(per-broker)`. New fields `brokers_total/_seq_verified`, `cross_broker_suppression`,
  `federation_status`, `per_broker_trust[]`. The R2 disjointness machinery needs NEW logic here (today it is a
  fixed pairwise array over single key sets — see the note below): every other role's keys must be disjoint
  from the *union* of all per-broker key sets; distinct brokers MAY share a root unless a cross-broker cert is
  active (then issuer≠subject).
- **Capstone.** **Reachable**, gated by `cross_broker_suppression==0 && brokers_seq_verified==brokers_total`.
- **Signature domain.** `feir.broker.federation.cert.v1` = `sha256(LP4(tag) ‖ LP4(issuer_broker_id) ‖
  LP4(subject_broker_id) ‖ LP4(scope) ‖ LP4(resource_id) ‖ BE8(not_after))`; the per-broker head reuses
  `feir.broker.grant_head.v1` unchanged (partitioning is in the log-fold, so existing golden vectors stay
  valid).
- **Residual.** Globally-consistent cross-broker equivocation is still an offline floor (ADR 0004 D9 floor 1) —
  only the out-of-band monitor catches a coordinated multi-broker rewrite.

### M5 — Revocation (tiered)

- **Mechanism.** A new top-level bundle object `revocation_list` — signed, time-bounded, carrying a Merkle root
  of revoked `grant_id`s — pinned under a new role key set `revocation_keys`. A use of a revoked grant inside
  the list's window is a violation. With `online_crl_url` configured the verifier fetches a fresh CRL.
- **Schema delta.** `revocation_list{issuer_kid, issued_at, not_after, merkle_root, sig}`; new `revocation_keys`
  verify-opt; optional `extensions.broker.revocation_check` (a use's online-CRL proof). Reuses the
  attestation/taxonomy "signed, pinned-issuer, time-bounded, role-separated artifact" pattern wholesale.
- **Verifier semantics.** New `revocation_status ∈ {absent, fresh, stale, online_fresh, revoked_present}`,
  `revoked_grants_matched`, `revoked_uses_blocked`. Freshness is re-derived against the latest anchored
  checkpoint timestamp (the same temporal anchor D7 uses).
- **Capstone.** **Gated**: `revocation_status ∉ {stale, revoked_present} && revoked_uses_blocked==0`. `absent`
  does NOT block (a bundle with no list is the legitimate baseline, like pre-D6); `stale` blocks (the offline
  freshness limit, surfaced honestly); `online_fresh` affirmatively satisfies it.
- **Signature domain.** `feir.broker.revocation.list.v1` = `sha256(LP4(tag) ‖ LP4(broker_id) ‖ BE8(issued_at) ‖
  BE8(not_after) ‖ LP4(merkle_root))`, under `revocation_keys` (role-separated — a broker must not sign its own
  revocation list).
- **Residual.** Revocation is inherently time-dependent: the bundled-list path is only as fresh as the list,
  and an offline verifier cannot know a grant revoked 5 minutes ago unless the list is fresh. Stated, surfaced
  via `revocation_status`, never silently passed.

### M6 — Cosig (M-of-N grant approval)

- **Mechanism.** A grant may require M-of-N approver cosignatures before it is Tier-B-eligible. The verifier
  counts distinct approver signatures that verify under the pinned `cosig_approver_keys` (a new role key set
  added to the R2 disjointness check — see §5); `< M` ⇒ the grant is not indexed (its use becomes `unmatched_violation`).
- **Schema delta.** `grant_evidence.{cosignatures[], cosig_threshold, cosig_signers[]}`; new
  `cosig_approver_keys` verify-opt (FATAL config error on overlap with any role, like the existing
  disjointness loop). Use-side unchanged.
- **Verifier semantics.** New `cosigned_grants_total/_satisfied`, `cosig_threshold_failures`, `cosig_status`.
  The same approver key signing twice counts once (no threshold inflation).
- **Capstone.** **Gated**: `cosig_threshold_failures==0 && (cosigned_grants_total==0 ||
  cosigned_grants_satisfied==cosigned_grants_total)`. Cosig is an issuance-side gate, transparent to the
  capstone's meaning when satisfied.
- **Signature domain.** `feir.broker.cosig.approval.v1` = `sha256(LP4(tag) ‖ LP4(grant_id) ‖ LP4(approver_kid) ‖
  LP4(credential_binding) ‖ BE8(threshold_m) ‖ BE8(exp))` — binding `credential_binding` + `threshold_m`
  prevents an approval being replayed onto a re-minted grant or a different threshold.
- **Residual.** Governance/dual-control at issuance; the approver set is a TCB (an approver who is also the
  taxonomy/attestation signer could self-approve, which the disjointness check forbids).

## 4. Capstone (D8) classification

| Mode | Reaches `attested_complete_over_brokered_surface`? | New gate / label |
|---|---|---|
| N-Use | **Yes** iff two-phase + PoP-reverified | +`bounded_reuse_overspent==0 && _seq_replays==0` |
| Delegation | **Yes** iff every chain verified | +`delegation_chains_verified==total && monotonicity_violations==0` |
| Native/STS | **No** (PoP broken) | exclusion `!native_credential_present`; parallel `attested_complete_over_introspected_surface` |
| Federation | **Yes** iff every broker's head verified | +`cross_broker_suppression==0 && brokers_seq_verified==brokers_total` |
| Revocation | **Gated** | +`revocation_status∉{stale,revoked_present} && revoked_uses_blocked==0` (`absent` does not block) |
| Cosig | **Gated** | +`cosig_threshold_failures==0 && (total==0 || satisfied==total)` |

The conjunction grows from its current 13 AND-terms (12 load-bearing conjuncts + the `coverage_manifest`-present
gate precondition, per ADR 0004) toward ~19. Per ADR 0004's discipline, **each new conjunct gets a
per-conjunct removal test** (remove it → drops to `claimed_over_manifest`). Only Native's
`!native_credential_present` is *strictly* necessary; the rest also fire as `unmatched_violation` but are kept
explicit so the capstone's meaning is self-documenting.

## 5. Cross-mode interactions (reconciliations)

- **Delegation × N-Use** compose: `use_limit` is read ONLY from the root `grant_evidence`, never a hop assertion
  (a delegator cannot grant more uses than exist).
- **Revocation × Delegation** cascade: a chain shares the root `grant_id`, so revoking the root revokes all
  leaves automatically.
- **Cosig × Native/STS**: cosig approves the *grant-of-use-authority* (the broker record), decoupled from the
  external STS mint; the cosig preimage binds the introspection `credential_ref`.
- **The R2 disjointness machinery (Cosig + Federation note).** Today the check is a FIXED pairwise array
  literal over five single key sets — `[(broker, resource, taxonomy, attestation, tsa)]` — plus a hard-coded
  `authority_keys` loop (verify.rs ~1591–1627). Cosig and Federation are therefore NOT "extensions of an
  extension point": Cosig adds a sixth `cosig_approver_keys` entry (an array + loop edit), and Federation
  replaces the single `broker_authority_keys` slot with a per-`broker_id` map and adds new union-disjointness
  logic (approvers/resource/etc. disjoint from the *union* of all per-broker key sets; brokers MAY share a
  root, but a cross-broker cert's issuer≠subject). Both are code changes to those literals/loops, surfaced
  here so the implementer doesn't expect a ready-made registry.
- **Federation × Revocation**: per-broker lists; `revocation_status = worst(per-broker)`.

## 6. Build order (dependency-ordered; each lands producer + verifier + golden fixtures in one reviewed commit)

1. `bounded_reuse` (scope_class only; smallest; resolves Q2)
2. Cosig (issuance-side only; no use path)
3. Delegation (signed assertions + monotonic verifier check)
4. Revocation (artifact pattern; reuses the D7 machinery)
5. Native/STS (new record kind + tuple + transcript binding; resolves Q3)
6. Federation (heaviest: per-broker head partition; needs an activation boundary)

## 7. The staging map (the "stage" deliverable — schema slots / hooks to RESERVE; NO code)

| Mode | Producer hooks (file:fn) | Reserve | Verifier hooks (verify.rs) | Feature flag | Fixtures |
|---|---|---|---|---|---|
| N-Use | `broker.go` ClassifyScope/Prepare/Descriptor/grant_evidence; `resourceshim` Ledger key `(grant_id,seq)`; `server.go` grantRequest/buildUseRecord | `ScopeClass="bounded_reuse"`; `grant_evidence.use_limit`; `use_evidence.use_sequence_number` | match loop (per-class single-use), report fields | `WithBoundedReuse(maxN)` | `adversarial.rs` use_evidence_n(+seq): N ok / N+1 / dup-seq / past-exp |
| Delegation | `broker.go` Request.DelegationAssertions + Prepare(monotonic); `grant_evidence.delegation_assertions` | tag `feir.broker.delegation.hop.v1`; `grant_evidence.delegation_assertions[]` | per-hop sig + scopeSubset; leaf cnf/exp bind | `WithDelegation()` | valid chain / widened hop / forged sig / missing hop |
| Native/STS | `broker.go` Descriptor.mode/lease_id; new `POST /v2/introspection` + buildIntrospectionRecord | `Descriptor.lease_id`; kind `introspection_transcript`; evidence kind `introspection` | classify_role tuple; transcript↔grant bind | `WithNativeCredentials()` | grant+transcript Tier-B-eligible / wrong grant / missing transcript |
| Federation | `broker.go` grant_evidence.{broker_id,issuer_kid,cross_broker_cert}; per-broker broker_seq | tag `feir.broker.federation.cert.v1`; those fields | per-`broker_id` head partition; multi-broker pin | `WithFederation(brokerID)` | two brokers gapless / cross-broker cert / per-broker gap |
| Revocation | new top-level `revocation_list` builder (attestation-style); optional use revocation_check | bundle key `revocation_list`; `revocation_keys` opt | revocation_status + revoked-use violation | `WithRevocationList(key)` | revoked-use in-window / stale / wrong issuer / substitution |
| Cosig | `broker.go` Request.Cosignatures/CosigThreshold + Prepare(≥M); `grant_evidence.cosignatures` | tag `feir.broker.cosig.approval.v1`; those fields; `cosig_approver_keys` opt | ≥M-of-N check + disjointness FATAL | `WithCosignature(M,keys)` | M-of-N met / M−1 / approver⊆broker FATAL / forged cosig |

**Cross-cutting reservations.** All new discriminators live under the open `extensions.broker` object and new
evidence fields ride inside the signed, whole-payload-hashed evidence — so a pre-0005 verifier ignores unknown
fields and the `evidence_hash` still re-derives. `grant_type:"oauth-scope"` already exists; `event_type` needs
no new value (introspection rides `tool_call` + the kind discriminator). Reserve the new domain tags and the
reserved `record_id`/idempotency prefixes (`introspection-`, `revocation-`) now.

## 8. Compatibility & version-gating flags

- **Additive at the record-schema layer** — no `schema_version`/`canon_version` bump. Unknown
  `extensions.broker.kind` → `classify_role`→`None` (generic integrity-bound, never grant/use-counted).
  `bounded_reuse` → an old verifier demotes to Tier-A like `session_grant`. Top-level `revocation_list` →
  ignored (`absent`). The load-bearing guarantee: a new producer's extra signed evidence fields ride inside the
  whole-payload hash, so an old verifier computing `sha256(RCP-canon(grant_evidence))` over the full map gets
  the same hash and the signature still verifies.
- **NOT-additive flag #1 — Delegation monotonicity is verifier-version-gated.** Today `delegation_chain` is
  unsigned labels; the signed-hop monotonicity check is a NEW verifier rejection path. A pre-0005 verifier
  under-enforces B9 (accepts a widened chain). Ship producer + verifier together; surface the gap.
- **NOT-additive flag #2 — Federation per-broker `broker_seq` is observably non-additive to strict-D6.** Two
  interleaved brokers in one flat head read as a gap → false suppression to an old verifier. Needs a
  `federation_active` activation boundary (mirroring the D6 activation boundary, ADR 0004:304) so single-broker
  bundles are untouched; ship producer + verifier in lockstep.

## 9. Amendments to ADR 0002 (to apply alongside the first implementation)

- **Deferred-modes list (:362)** → append `[RESOLVED/STAGED in ADR 0005]` with the six-mode summary.
- **Open Q2 (:434)** → `[RESOLVED in ADR 0005 §M1]`: yes, as `bounded_reuse` — a Tier-B-eligible bounded reuse
  of the identical `(action, resource_id)`, reopening a bounded slice of B3 (stated).
- **Open Q3 (:437)** → `[RESOLVED in ADR 0005 §M3]`: post-mint resource-signed introspection transcript; it
  **relocates** the resource TCB (consistent with ADR 0004 D9 floor 2), it does not remove it.
- **B9 row (:327)** → append `[strengthened in ADR 0005 §M2: per-hop SIGNED assertions, monotonic non-increase
  re-verified offline]`.

## Open questions (next round)

- Native/STS: should `attested_complete_over_introspected_surface` ever count toward a compliance export, or is
  it strictly informational until a TEE binds the IdP (D7-style)?
- Revocation: is a transparency-log-style append-only revocation feed (vs. a periodic signed list) worth the
  extra producer complexity to shrink the freshness window?
- Cosig: do approver thresholds need per-`(resource, action)` policy, or is a per-grant `M-of-N` sufficient?
