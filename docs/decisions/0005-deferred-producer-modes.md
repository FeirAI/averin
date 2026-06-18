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

> **Implementation status (updated):** **ALL SIX deferred modes are now built** — M1 (`bounded_reuse`/N-Use),
> M6 (Cosig), M2 (Delegation), M5 (Revocation), M3 (Native/STS), and M4 (Federation) — see their
> §M1/§M6/§M2/§M5/§M3/§M4 status notes. M1 is end-to-end (incl. the online `POST /v2/grants` path); M6, M2, M5,
> M3, and M4 each ship the verifier semantics + the Go producer (+ a shared golden vector for M6/M2/M3; M4 reuses
> the existing `grant_head_root` fold so no new vector; M5 reuses the canonical-doc-signing path), with only their
> online producer-orchestration HTTP path deferred. The ADR 0002 amendments §9 are applied (M1 was first); the Q3
> resolution (§9, M3) is live.
>
> **Online HTTP flows + operator readiness (built):** the online grant flow is now live for **M6 Cosig + M2
> Delegation + M3 Native/STS**. Cosig/Delegation are two-phase — `POST /v2/grants/prepare` mints + reveals the
> challenge (the broker-minted credential_binding/exp), the approvers/delegators sign it, `POST
> /v2/grants/finalize` binds the cosignatures/hops + commits (the gapless `broker_seq` is allocated at finalize,
> so the D6 log invariant holds); `WithCosigPolicy` / `FEIR_COSIG_APPROVER_KEYS` pin the M-of-N. Native is
> single-phase — `POST /v2/grants` with `mode:"token_exchange"` + `lease_id` issues the native grant (no PoP, no
> capability), and `POST /v2/introspection` records the resource-signed transcript (the resource signs the
> `feir.resource.introspection.v1` challenge with its raw key). Operator readiness: `feir-verify bundle b.json
> opts.json` pins the role-disjoint key sets (authentic verification + every mode gate) and surfaces all mode
> statuses; `docs/operator-verification.md` is the operator guide. **Still deferred (clearly labeled, optional):**
> the Merkle-non-disclosure revocation mode. (M4's optional `cross_broker_cert` transitive-trust tier —
> `feir.broker.federation.cert.v1` + shared golden vector + FFI e2e — is now implemented; see §M4.)

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

> **Status: verifier + producer + cross-language golden vector IMPLEMENTED; online HTTP path deferred.**
> Verifier semantics `6282136`: `delegation_hop_challenge`, `verify_delegation_chain` (re-walks from the
> broker-signed root cnf_kid — hop0 delegator == grant cnf; hop[i] delegator == hop[i-1] delegate; each sig
> verified under the delegator key; monotonicity = equality), the leaf binding (`GrantInfo.effective_cnf_kid` +
> narrowed `effective_exp = min(grant exp, hop exps)`, with the use↔grant predicate keyed on those so a
> sub-agent's PoP matches and the root cannot use a delegated-away credential), the four report fields + two
> capstone conjuncts, all fail-closed (an invalid/forged/broken-link/wrong-root/non-monotone chain is NOT
> indexed → its use is an `unmatched_violation`). Go producer `a012a43`: `broker.DelegationHopChallenge`
> (byte-identical, pinned by the SHARED golden vector incl. multibyte + an int64-edge BE8 case) +
> `broker.AttachDelegation` (the fail-closed phase-2 embed that re-walks exactly as the verifier). Tested: Rust
> adversarial (1-hop / 2-hop verify, leaf-not-root binding, widened-scope, forged-sig, broken-link, wrong-root,
> and delegation × D2 PoP under the leaf key) + Go (golden vector + AttachDelegation valid / 2-hop / 5 reject
> cases). **Deferred:** the online `POST /v2/grants` flow is inherently two-phase (the hop challenge binds the
> minted grant_id, so agents can only sign after issuance), staged but not built. **Residual (demonstrator):**
> monotonicity is EQUALITY, not a true narrowing lattice — a legitimately-narrower hop is fail-closed
> (rejected), the documented future extension; a TCB on the scope vocabulary either way.

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

> **Status: verifier + producer + shared golden vector + FFI e2e IMPLEMENTED; the introspected-capstone-LABEL
> e2e + online introspection HTTP path deferred.** Verifier `feb4f74`: a native grant (signed
> `grant_evidence.mode=="token_exchange"` + `lease_id`) is indexed into a SEPARATE `native_grants_by_id`, NEVER
> the brokered `grants_by_id` — so the two surfaces are DISJOINT (a brokered use naming a native grant_id is an
> `unmatched_violation`; a native credential never reaches `uses_matched`/`uses_pop_reverified`). The native
> early-branch is fully additive (the brokered path is byte-for-byte unchanged). A resource-signed
> `introspection_transcript` record (kind `introspection_transcript` → `classify_role` Resource) is the SOLE
> native-use artifact; the M3 pre-pass verifies each closed transcript — the structured
> `feir.resource.introspection.v1` sig under a pinned, role-separated `resource_authority_keys` issuer +
> grant-bind + `credential_ref == grant.lease_id` + resource match + `effective_scope ⊆ grant.scope`
> (space-delimited OAuth token subset, no broadening) + `effective_exp <= grant.exp` + `introspected_at >=
> issued_at` — every failure a hard `unmatched_violation` → `!ok`. **The native-use-matching question is
> RESOLVED: the transcript is the sole action-accountability artifact (no brokered use receipt).** Report fields
> `native_credential_present`, `introspection_transcripts_total/_verified`, `introspection_scope_narrowed`,
> `introspection_status`. **Capstone:** the standard `attested_complete_over_brokered_surface` gains
> `!native_credential_present`; a NEW strictly-weaker PARALLEL label `attested_complete_over_introspected_surface`
> requires `uses_matched==0` (PURITY) + `native_credential_present` + `introspection_status=="attested"` (every
> closed transcript verified AND every native grant covered, total>0). A MIXED native+PoP bundle reaches NEITHER
> label (`claimed_over_manifest`). D4×M3: a native grant for a taxonomy-escalating `(resource,action)` is
> mis-scoped (fail-closed); native×cosig/delegation is a deferred composition (fail-closed). Triple-reviewed
> SOUND (read-only finder + Opus + GLM 5.2/opencode, no fail-open; the `credential_ref`↔`lease_id` and native-D4
> binding gaps both reviewers flagged were TDD-fixed pre-commit). Producer `13c3839`:
> `broker.IntrospectionTranscriptChallenge` (byte-identical, pinned by the SHARED golden vector incl. multibyte +
> int64-edge) + `broker.NativeGrantEvidence` + `broker.IntrospectionEvidence`, with an FFI e2e where a
> Go-produced native grant + transcript reaches `introspection_status:"attested"` under the Rust verifier (+ four
> fail-closed negative controls). Tested: Rust adversarial (16 native/introspection cases incl. MIXED-reaches-
> neither + the per-conjunct capstone load-bearing) + Go (golden vector + the FFI e2e). **Deferred:** the
> introspected-capstone-LABEL e2e + the online `POST /v2/introspection` two-phase flow ride the (separately
> deferred) online HTTP path, exactly as the brokered-capstone e2e uses the online server. **Residual (ADR
> floor):** the transcript is resource-signed → it RELOCATES, does not remove, the resource TCB
> (`resource_trust: assumed_truthful`, ADR 0004 D9 floor 2 / ADR 0002 Q3) — the verifier proves the resource
> SIGNED the effective scope, not that the IdP's scope is honest.

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

> **Status: verifier (V1 partition + V2 per-broker keys) + Go producer + FFI e2e IMPLEMENTED; the optional
> `cross_broker_cert` transitive-trust tier + the online introspection/federation HTTP path deferred.** The
> HEAVIEST mode — it partitions the most fail-open-prone subsystem (the D6 grant-transparency suppression
> detector) per `broker_id`. **V1** `68dc01b`: an ACTIVATION BOUNDARY (a committed, integrity-proven broker grant
> carrying a non-empty signed `grant_evidence.broker_id`) dispatches to `compute_federation_trust` — a per-broker
> replica of `compute_broker_trust` kept SEPARATE so the single-broker path is byte-for-byte unchanged. Each
> broker's grants must form their OWN gapless `[1..n_b]` `broker_seq` prefix with their OWN `cumulative_root` chain
> re-derived against that broker's entry in the checkpoint's `broker_grant_heads` MAP (`parse_grant_heads_map`),
> `prior_head_hash` chaining the broker's OWN previous head — so a gap in broker A is caught in A's partition and
> can NEVER be masked by broker B's interleaved grants (the §8 flag-2 crux). Every failure (smuggled grant [no
> broker_id/broker_seq], dropped/missing/inflated head, phantom-broker head, fork, grant_id equivocation across
> `(broker_id, broker_seq, content_hash)`) is a hard `issues` violation → `!ok`. New fields `federation_status`
> {absent | sequence_verified | sequence_consistent_export | suppression}, `brokers_total/_seq_verified`,
> `cross_broker_suppression`, `per_broker_trust[]`; capstone gains `cross_broker_suppression==0 &&
> brokers_seq_verified==brokers_total`. **V2** `2de786b`: optional `federated_broker_keys` (per-`broker_id`
> authority key map) — a federated grant elevates ONLY under its own broker's pinned set (an unpinned broker_id →
> empty slice → never verifies; a grant signed by another broker's key is not accountable AND its use is
> `unmatched_violation` → `!ok`); the R2 disjointness extends to the UNION of all broker key sets; D7
> `authority_kids` folds the per-broker keys. **Producer** `0eaa051`: `broker.Request.BrokerID` →
> `grant_evidence.broker_id` (the real `Prepare` path) + `broker.BrokerGrantHeads` (the per-broker head MAP,
> reusing the existing cross-language-pinned `GrantHeadRoot` fold — NO new signature domain or golden vector). FFI
> e2e: a two-broker Go-built bundle reaches `federation_status:"sequence_verified"` under the Rust verifier (V1
> shared-root + V2 per-broker-key variants), with dropped-head suppression + cross-broker-forgery negative
> controls. TRIPLE-reviewed per piece (finder + Opus + GLM) AND a WHOLE-FEATURE aggregate review (Opus + GLM SHIP,
> no fail-open; the third reviewer's NO-SHIP was verified a false positive — pre-existing legacy integrity/authority
> separation, not relay-reachable, no false capstone). 23 Rust federation adversarial tests + 2 Go FFI e2e + 5
> aggregate-review coverage additions. **Residual (ADR floor):** a globally-consistent cross-broker equivocation
> (divergent histories never co-committed in one bundle) stays the offline floor (ADR 0004 D9 floor 1) — only the
> out-of-band monitor catches a coordinated multi-broker rewrite.
>
> **UPDATE — `cross_broker_cert` (the optional transitive tier) implemented.** A grant whose subject `broker_id`
> is NOT pinned can elevate to `transitive` trust iff it carries a `grant_evidence.cross_broker_cert` signed by a
> PINNED issuer broker vouching for the subject's KEY (`feir.broker.federation.cert.v1`, with `subject_kid` in
> the preimage — see the signature-domain note below). Two-piece + triple-reviewed (finder + Opus + GLM): the
> review caught a REAL high-severity fail-open both the finder and Opus independently confirmed — the cert-derived
> subject key was elevated as broker authority with NO role-disjointness check (a pinned/compromised issuer could
> vouch for a resource/tsa/etc. key → role confusion); fixed TDD (failing regression → guard → re-review). New
> report field `transitive_grants`; the federation capstone is unaffected (per-broker suppression still applies).
> 8 Rust adversarial tests (positive + 7 fail-closed vectors incl. the role-confusion regression) + a shared
> `federation_cert_challenge` golden vector (Go ↔ Rust byte-identical) + a Go→Rust FFI e2e. **Still deferred:** the
> Merkle-non-disclosure revocation mode.

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
  LP4(subject_broker_id) ‖ LP4(subject_kid) ‖ LP4(scope) ‖ LP4(resource_id) ‖ BE8(not_after))` where
  `subject_kid = cnf_kid(subject_pubkey)`. **Binding `subject_kid` (the subject's KEY, not just its id) is
  load-bearing:** without it, the issuer's (public) cert could be replayed over a grant signed by ANY key
  claiming the subject's id (key substitution). The cert carries `subject_pubkey`; the verifier derives
  `subject_kid`, re-checks the issuer sig, then runs the grant's normal `verify_authority` under
  `subject_pubkey` (a cert alone never trusts a grant — the grant must independently be signed by the vouched
  key). The cert-derived subject key is ALSO checked disjoint from every non-broker role
  (resource/tsa/taxonomy/attestation/cosig/revocation) — else a pinned (or compromised) issuer could vouch for
  a non-broker key and launder it into broker authority (a runtime backdoor around the startup R2 disjointness
  fatal). The per-broker head reuses `feir.broker.grant_head.v1` unchanged (partitioning is in the log-fold, so
  existing golden vectors stay valid).
- **Residual.** Globally-consistent cross-broker equivocation is still an offline floor (ADR 0004 D9 floor 1) —
  only the out-of-band monitor catches a coordinated multi-broker rewrite.

### M5 — Revocation (tiered)

> **Status: verifier + producer + FFI e2e IMPLEMENTED; online CRL + Merkle-non-disclosure deferred.** Verifier
> `ae4b3b7`: `evaluate_revocation` (a top-level signed, time-bounded `revocation_list` under a pinned,
> role-separated `revocation_keys` — sig domain `feir.revocation.v1` over the RCP-canonical list minus `sig`,
> reusing the deployment_attestation pattern wholesale; freshness = latest anchored TSA time within
> `[issued_at, not_after]`), the use-loop gate (a matched use of a grant on a FRESH list is blocked BEFORE it
> is consumed/counted), the `revocation_keys` R2 + generic-authority disjointness extension, 3 report fields +
> the capstone conjunct. `stale` blocks the capstone but not the bundle (blocking on stale data would be a DoS);
> `absent` is the honest baseline. Go producer `56f8b1d`: `api.BuildRevocationList` + an FFI e2e where a
> Go-built list spliced into a real anchored grant+use bundle blocks the revoked use under the Rust verifier.
> Tested: Rust adversarial (fresh-no-match / fresh-blocks-revoked / stale / forged-sig / role-overlap-fatal) +
> Go e2e. **Deferred:** the opt-in online CRL (`online_crl_url` → `online_fresh`) and the Merkle-root
> NON-disclosure mode (per-use proofs without disclosing the full list — today the full `revoked_grant_ids` are
> disclosed + sig-covered). **Residual (ADR floor):** an offline verifier cannot know of a revocation never
> delivered in a fresh list — surfaced via `revocation_status`, never silently passed.

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

> **Status: verifier + producer + cross-language e2e IMPLEMENTED; online HTTP path deferred.** Verifier
> semantics `55a21b2` (the `cosig_approver_keys` role-disjoint VerifyOption, the
> `feir.broker.cosig.approval.v1` challenge, distinct-approver counting + the `>= M` indexing gate, the four
> report fields, the two capstone conjuncts, + a fail-closed guard for cosignatures-without-threshold). Go
> producer `668e531`: `broker.CosigApprovalChallenge` (byte-identical to the verifier, pinned by the SHARED
> golden vector) + `broker.AttachCosignatures` (the fail-closed phase-2 embed). FFI e2e `eb4e464`: a cosigned
> grant produced entirely in Go seals + anchors + verifies clean under the Rust verifier
> (`cosig_status:"satisfied"`), with a one-key-short negative control. Tested: Rust adversarial (threshold
> met / below / duplicate-counts-once / forged / unpinned-fail-closed / disjointness-fatal / equivocating
> sibling / cosignatures-without-threshold) + Go (golden vector incl. an int64-edge BE8 case + the e2e).
> **Deferred:** the online `POST /v2/grants` flow is inherently two-phase — the cosig challenge binds the
> minted `credential_binding`, so an approver can only sign after the broker prepares and reveals it — so it
> needs a prepare→approve→finalize API, staged but not yet built. Today cosig is reachable as a producer
> library (`broker.AttachCosignatures`) + the verifier enforces it for any bundle that carries it.

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
