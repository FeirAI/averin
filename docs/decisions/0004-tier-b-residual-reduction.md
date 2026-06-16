# ADR 0004 — Tier-B residual reduction: toward honest Level-3 completeness

**Status:** Accepted (design; **rev 3** — Codex review READY TO BUILD across 3 rounds: 5 rev-1
MUST-FIXES + the rev-2 D7 subject-binding blocker all resolved). Building D1–D8 piece-by-piece, each
commit adversarially code-reviewed before commit.
**Date:** 2026-06-15
**Builds on:** ADR 0002 (credential broker), ADR 0003 (Tier-B demonstrator, built `tierb[1..5]`). This
ADR addresses the **deferred items / accepted residuals** ADR 0003 enumerated, reducing each as far as
software honestly can and stating precisely what stays residual.

**rev 2 changes (Codex review round 1):**
- **MF1 (D8/D9):** the capstone does NOT close resource *truthful-labeling* — a resource can sign a
  valid intent/outcome pair for action A while performing action B. Added `resource_trust:
  assumed_truthful` to the report (always surfaced), moved resource mislabeling + side-effect closure
  into the **permanent** D9 residual floor, and re-scoped the D8 label to *resource-signed receipt*
  completeness, explicitly conditional on `resource_trust`.
- **MF2 (D6):** a broker-signed `grant_head` alone proves only internal consistency. The head is now
  **bound into the anchored, witnessed checkpoint chain** (fork-detected #2, anchored #3, witnessed
  #15) and hash-chained to the prior head — an externally-pinned, cumulative log. Without that, the
  state is only `sequence_consistent_export`, not `sequence_verified`.
- **MF3 (D8):** the capstone now requires EVERY matched use to be a closed two-phase
  (`use_intent`+`use_outcome`) pair; a one-phase receipt forces `claimed_over_manifest`.
- **MF4 (D2):** the resource MUST recompute `commit("input", params, params_nonce)` and reject a
  mismatch BEFORE the side effect; the params domain is `input`; the report distinguishes
  commitment-bound PoP from disclosed-param verification.
- **MF5 (D4):** taxonomy carries resource-bound action lists + digest/version/effective-interval;
  `taxonomy_status: validated` (artifact-level) only with a valid signature + pinned role-separated
  issuer + matched pinned digest/version. The effective interval is enforced PER-USE (a listed action
  outside it → `stale`); the honest per-use signal is `uses_action_unverified` (a D4/D8 gate needs BOTH
  `validated` and `uses_action_unverified == 0`).

## What this ADR is — and the honesty bar it holds

ADR 0003 shipped the Tier-B demonstrator with a set of *honestly-labeled* residuals: the resource is a
TCB member, `broker_trust:"assumed"`, `attestation_status:"unevaluated"`, every matched use is
`uses_action_unverified` (no taxonomy), the verifier does not re-run the PoP, and `action_completeness`
never reaches `attested_complete`. This ADR **reduces** each residual with a concrete mechanism, and
**refuses to over-claim**: where a residual is only partially closable (it needs runtime/TEE
enforcement, or is information-theoretically irreducible offline), the verifier reports the *reduced*
state with a label that does not assert more than is proven.

The cardinal rule (inherited from the whole project): **a verifier output never claims more than the
bundle cryptographically proves.** Every new state below is gated on evidence the offline verifier can
check, and every irreducible gap is surfaced, not hidden.

## D1 — Dedicated `credential` commit domain (retire the `input` overload)

**Residual (ADR 0003 / server.go):** a `credential_grant` overloads the `input` hiding-commit domain
for the credential descriptor (the closed RCP domain registry — `input`/`output`/`rationale` — has no
`credential` slot). Cryptographically sound, but consumers must special-case "`input` on a grant means
the descriptor."

**Mechanism:** add `credential` to the RCP `FieldDomain` registry (the domain-separation tag
`feir.commit.v1`/domain string), the schema's `<field>_commit` slots, the FFI `feir_commit` domain
allowlist, the disclosure verifier (`FieldDomain::parse`), and the SDK field lists. The grant builder
commits the descriptor under `credential`; the use builder keeps `input` for genuine op params.

**Closes:** the overload — fully. **Residual:** none. **Build artifact:** RCP registry + schema + FFI +
verifier + SDK update, with a golden disclosure test for the new domain.

## D2 — Full offline PoP re-verification (shrink the resource-shim TCB)

**Residual (ADR 0003 R4 / MUST-FIX 4):** the verifier does NOT re-run the Ed25519 PoP — it trusts the
shim validated `use_sig` under the `cnf` key. The named next step: carry enough that the verifier
re-runs it.

**The params-commitment subtlety (why this needs care):** the PoP challenge binds a
`params_commitment`. If that were `sha256(params)` (non-hiding) and carried in the signed body, a
low-entropy op's params would be brute-forceable from the bundle — defeating the `input_commit` hiding
commitment. So the PoP must bind a **hiding** params commitment.

**Mechanism (MF4 — the resource recompute is load-bearing):**
1. The **agent** generates a params hiding-commitment nonce `params_nonce`, computes `params_commit =
   commit("input", params, params_nonce)` (hiding; domain is **`input`** — consistent with D1, which
   keeps `input` for genuine op params), and signs the PoP over THAT commitment (not `sha256(params)`).
   It sends `(params, params_nonce, use_sig)` to the resource. (The PoP freshness `nonce` is handled as
   in ADR 0003 — agent-supplied + the consume-before-act ledger; a resource-issued challenge nonce is
   an optional strengthening, not required here.)
2. **The resource RE-COMPUTES `commit("input", params, params_nonce)` and rejects a mismatch against
   the `params_commit` the PoP bound, BEFORE the side effect.** Without this recompute an agent could
   sign a commitment to *different* params than the resource actually receives/runs — so the recompute
   is the security-critical step, not an optimization. On match, the resource uses that hiding
   commitment as the receipt's `input_commit` (committed-and-PoP-bound value coincide) and records
   `(params, params_nonce)` as the disclosure secret. It carries in `use_evidence`: the agent **`cnf`
   public key** and the **`use_sig`** (`cnf_kid` binds which key).
3. The **verifier** reconstructs the challenge `sha256(LP(tag) ‖ grant_id ‖ resource_id ‖ action ‖
   input_commit.commitment ‖ credential_binding ‖ nonce)` — every component read from the proven
   `use_evidence` + `grant_evidence.credential_binding` + the record's `input_commit` — confirms it
   equals `pop_challenge_hash`, AND verifies `use_sig` under the carried `cnf` pubkey (id == `cnf_kid`).

**Report distinction:** the verifier emits `pop_verified: reverified` (the offline Ed25519 re-check
passed and the challenge binds the receipt's own committed params) vs `pop_verified: shim_asserted`
(ADR-0003 fallback: only `pop_challenge_hash` present, no `cnf`/`use_sig` to re-run). A receipt claiming
re-verification whose re-check FAILS is an `unmatched_violation`. So the report never conflates
"shim said PoP was fine" with "the verifier independently re-ran PoP".

**Closes:** the verifier independently proves PoP-at-use AND that it binds the receipt's *own*
committed params — the shim is **no longer TCB for PoP validation or params binding**. **Residual:** the
shim is still TCB for *nonce freshness* and *consume-before-act ordering* (runtime, not offline-
provable), and for the agent↔resource param-match it is the resource's recompute (step 2) that enforces
it at runtime; the verifier only re-checks the *bound* commitment, so a resource that skips the
recompute is caught only if the bound commitment diverges from the disclosed params (which the
disclosure verifier already checks). **Build artifact:** agent params commitment + resource recompute-
or-reject + carried `cnf`/`use_sig`; verifier PoP re-check gated into the match predicate; golden tests
(valid re-verify, forged `use_sig`, challenge-mismatch, wrong `cnf`, params-commitment≠disclosed).

## D3 — Nonce/replay cross-check across visible receipts

**Residual (ADR 0003 R5):** `ledger_commitment` is carried but the verifier never reads it; a replayed
PoP nonce across two visible receipts is not flagged offline (only the per-`grant_id` single-use cap
is).

**Mechanism:** the verifier tracks every `(resource_id, nonce)` seen across **closed** use receipts; a
duplicate is a replay/duplicate-submission `unmatched_violation` (independent of the per-`grant_id`
single-use rule — it also catches reusable-grant replays). Optionally cross-check `ledger_commitment`
re-derives from `(jti, nonce, used_at)` IF the verifier is given the ledger-tag preimage (it can, since
those fields are in `use_evidence`).

**Closes:** offline detection of a replayed nonce among *visible* receipts — fully. **Residual:** a
never-anchored replayed receipt stays invisible (D6/irreducible). **Build artifact:** nonce-dedup in
the use loop + `ledger_commitment` re-derivation check; golden tests (same-nonce two receipts →
violation; `ledger_commitment` tamper → violation).

## D4 — Signed operation taxonomy (retire `uses_action_unverified` for validated grants)

**Residual (ADR 0003 R6):** no signed taxonomy validates `scope_class == single_operation`, so EVERY
matched use is `uses_action_unverified` and can never upgrade `action_completeness`.

**Mechanism:** a signed **operation taxonomy** — an out-of-band artifact pinned like the TSA/authority
keys — carrying two **resource-bound** lists of `{resource_id, action}` entries: `single_operation_actions`
(pairs the issuer asserts ARE a single bounded, non-escalating, non-async operation) and an optional
`escalating_actions` (pairs affirmatively marked NOT single-operation). Entries are resource-bound so a
taxonomy vetted for one resource cannot validate a colliding action name on another. It also carries
(MF5, mirroring ADR 0002) a monotonic **version** and an **effective interval** `[effective_from,
effective_until]`, and is signed by a **taxonomy authority key** pinned in verify options and
**role-separated from broker/resource** (a key shared with either role is a FATAL config error — it
could self-validate a taxonomy). The verifier pins BOTH an expected content **digest** (`sha256:` over
the RCP-canonical taxonomy minus `sig`) and the expected **version**; absent either pin, no taxonomy can
reach `validated` (fail-closed).

`taxonomy_status` reports **artifact trust ONLY** (it does NOT assert every matched use was verified):
- **`validated`** — signature verifies under the pinned role-separated issuer AND the pinned
  digest+version both match;
- **`stale`** — validly signed+pinned, but a listed action fell outside the effective interval for some
  matched use;
- **`untrusted`** — unsigned / wrong issuer / pinned digest|version mismatch / no pin / malformed.

A matched use counts as **action-verified** (NOT `uses_action_unverified`) ONLY when the grant is
`single_operation`, the taxonomy is signed+pinned, the grant's `(resource_id, action)` is listed, and
the interval covers BOTH the grant's `issued_at` and the use's `used_at`. Because `taxonomy_status` is
artifact-level, **the honest per-use signal is `uses_action_unverified`** (0 ⇔ all verified); any D4/D8
gate MUST require BOTH `taxonomy_status == validated` AND `uses_action_unverified == 0`, never the status
alone. A `single_operation` grant whose `(resource_id, action)` is in `escalating_actions` is **rejected
as mis-scoped AT ISSUANCE** (a hard `issues` failure when the grant is indexed, whether or not it is ever
exercised — a dangerous capability must not be invisible just because no use receipt is present).

**Closes:** R6 for taxonomy-`validated` `(resource, action)` pairs within the effective window.
**Residual:** (a) the taxonomy's *semantic correctness* (does "db.query:orders-ro" truly denote one
bounded operation?) remains TCB — surfaced as the `taxonomy_status` label + the pinned issuer/version,
never as a proof of the claim's correctness; (b) `action_verified` trusts the broker's grant **labels**
(`action`/`resource_id`/`scope_class` in the signed grant_evidence) — it proves the LABELED operation is
taxonomy-classified single-op, NOT that the minted credential behind `credential_binding` is no broader
than its label. This gap is **reducible, not irreducible**: when the credential descriptor is disclosed
(`credential_commit` opened), the verifier can cross-check `sha256(descriptor) == credential_binding` and
the descriptor's `act/aud/jti/cnf/exp/single_use` against `grant_evidence` to prove label↔credential
consistency offline. That cross-check is part of the **D6** `broker_trust` reduction (below) and is not
yet implemented; until then — and whenever the descriptor is not disclosed — the gap rests on
`broker_trust`, never asserted by D4 as proof. Both are stated, not hidden. **Build artifact:** taxonomy schema (resource-bound lists +
digest/version/interval) + signing + pinned verify option (digest+version, fail-closed) + role-separation
config check + the per-use resource-bound action-verified split + escalating mis-scope rejection; golden
tests (validated single-op → verified; action listed for another resource → still `action_unverified`;
stale interval → still `action_unverified`; wrong issuer/digest/version, unpinned, missing version,
tampered body → `untrusted`; escalating single-op grant → mis-scoped violation) + a cross-language
`sha256:` digest-preimage golden vector so a Go/FFI auditor computing `taxonomy_digest` cannot drift.

## D5 — Two-phase intent/outcome gateway (reduce the F4 record-after-action gap)

**Residual (ADR 0003 F4):** a use is recorded AFTER the action — a resource that acts then crashes
before the receipt is durable leaves an INVISIBLE action. This is the real Level-3 gap.

**Mechanism:** a **two-phase** resource gateway. The resource records a `use_intent` (kind=`use_intent`)
**BEFORE** the side effect (carrying the same PoP-validated `use_evidence` minus the outcome), then a
`use_outcome` (kind=`use_outcome`, referencing the intent's `record_id`) **AFTER**. The verifier joins
intents to outcomes:
- a **closed** `use_intent` with a matching **closed** `use_outcome` → a complete two-phase use (the
  grant-match predicate runs on the pair);
- a **closed** `use_intent` with NO closed outcome → a recorded **`intent_without_outcome`** anomaly
  (the action started and was recorded, but completion was not) — surfaced, not silently dropped;
- backward-compat: a one-phase `use` receipt (ADR 0003) is still accepted and counted toward
  `uses_matched` (the demonstrator supports both; two-phase is opt-in via the resource gateway mode) —
  BUT a one-phase receipt can NEVER satisfy the D8 capstone (MF3): its presence forces
  `claimed_over_manifest`, because it carries the record-after-action gap two-phase exists to reduce.

**Closes:** an action whose **intent was anchored** before the side effect is now visible even if the
outcome never lands — the crash-after-act case becomes a *detectable anomaly* rather than an invisible
action. **Residual (irreducible, see D8/D9):** an action whose **intent was never anchored** is still
invisible — the resource could decline to record the intent. Two-phase moves the trust boundary from
"trust the resource to record after acting" to "trust the resource to record-intent-before-acting",
which is strictly stronger but not elimination. **Build artifact:** `use_intent`/`use_outcome` record
kinds + roles; the resource gateway two-phase mode; verifier intent↔outcome join +
`intent_without_outcome` count; golden tests.

## D6 — Grant transparency: reduce `broker_trust` from `assumed`

**Residual (ADR 0003):** `broker_trust:"assumed"` — the bundle cannot prove the broker did not mint a
credential WITHOUT recording a grant. Record-before-issue is a runtime invariant, not an offline proof.

**Why a broker-signed head alone is insufficient (MF2):** a contiguous `[1..N]` plus a broker-signed
`grant_head=N` proves only *internal consistency of one export* — a malicious broker can omit a grant,
renumber the visible sequence, and sign a fresh lower head (or start a fresh log). Completeness needs
the head to be **externally pinned and cumulative**, not self-asserted.

**Mechanism (anchor the head into the existing transparency machinery):** the demonstrator already has
a fork-detected (#2), anchored (#3), witnessed (#15) checkpoint chain that transitively commits every
grant `content_hash` (the `committed_set`). D6 binds the grant log INTO it:
1. Each grant carries a broker-assigned `broker_seq` (strictly increasing, gapless), bound into the
   signed `grant_evidence`.
2. Each **checkpoint body** carries `broker_grant_head = { max_seq, prior_head_hash, cumulative_root }`
   where `cumulative_root` is a hash-chain/Merkle root over `(broker_seq → grant content_hash)` for all
   grants committed up to this checkpoint, and `prior_head_hash` links to the previous checkpoint's
   `broker_grant_head`. The head is therefore **part of the anchored, witnessed, fork-detected
   checkpoint** — the broker cannot equivocate on it without a detectable fork (#2) or a witness/anchor
   mismatch (#3/#15).
3. The verifier checks, over the **closed** grant set: `broker_seq` forms a gapless prefix `[1..max_seq]`
   of the latest anchored `broker_grant_head`, the `cumulative_root` re-derives from the closed grants,
   and the `prior_head_hash` chain is intact across checkpoints. A gap, a tail omission (`max_seq` >
   max closed `broker_seq`), or a root mismatch is a **detectable suppression** violation.

**Second `broker_trust` lever — credential label fidelity (D4 cross-reference):** D4's `action_verified`
trusts the broker's grant LABELS (`action`/`resource_id`/`scope_class`). When the credential descriptor
is disclosed (the `credential_commit` opened), D6 additionally cross-checks `sha256(descriptor) ==
grant_evidence.credential_binding` and the descriptor's `act/aud/jti/cnf/exp/single_use` against the
signed `grant_evidence` — proving the broker did not mislabel a broad credential as a benign single-op
action. A mismatch is a broker-equivocation violation; absent the disclosure the label fidelity remains a
`broker_trust` residual. (Surfaced here so D4's label-trust gap is tracked, not orphaned.)

**Reduces:** `broker_trust` from `assumed` to **`sequence_verified`** — because the head is anchored +
hash-chained + witnessed, the broker can no longer drop a middle/tail grant, renumber, or fork the log
without detection. (If a deployment ships `broker_seq` but does NOT bind the head into anchored
checkpoints, the verifier reports the weaker **`sequence_consistent_export`** — internal consistency
only, honestly labeled.) **Residual:** a broker that mints a credential through a path that NEVER
assigns a `broker_seq` AND never records the grant at all is the never-anchored class (D9) — but every
*recorded* grant is now in a tamper-evident, anchored, gapless log. **Build artifact:** `broker_seq` +
`broker_grant_head` in the checkpoint body + the cumulative root; verifier gap/root/chain/head check;
golden tests (gap → violation; tail omission → violation; root mismatch → violation; forked head →
detected; clean anchored sequence → `sequence_verified`; unanchored head → `sequence_consistent_export`).

## D7 — Deployment attestation evaluation (claims, not enforced reality)

**Residual (ADR 0003):** `attestation_status:"unevaluated"` — isolation/egress/non-transferability are
asserted, never checked.

**Mechanism (honest boundary):** a signed **`deployment_attestation`** record (signed by a pinned
*attestation authority* key — e.g. an attestation service, or in a real deployment a TEE quote) that
asserts the runtime properties (sandbox isolation, egress policy, key non-transferability) with a
freshness window.

**Subject binding is mandatory (rev-3 fix):** the attestation must SIGN a `subject` that binds it to
*this* deployment/export, not merely be a fresh signature by the pinned issuer. Without it, a valid
fresh attestation issued for a DIFFERENT deployment could be replayed into this export and satisfy the
D8 attestation conjunct — the verifier could not tell it apart from an attestation for the deployment
actually under review. The signed `subject` binds at minimum: the `project_id`, the `coverage_manifest`
(or deployment-manifest) digest, the latest anchored checkpoint identity + `broker_grant_head` digest
(D6), the **broker / resource / taxonomy authority key ids**, the `resource_id` set, and the export
window + claim types. The verifier checks the attestation's **signature, pinned issuer, freshness,
window coverage, AND that every `subject` field matches the bundle under review**, then sets
`attestation_status` from `unevaluated` to **`attested_claims`** (all checks pass) or `failed` (bad
signature/issuer, stale, or subject mismatch). It surfaces the `subject` digest in the report. **It does
NOT verify the runtime properties themselves** — real enforcement needs a TEE/remote-attestation chain
that is out of scope for a software demonstrator.

**Reduces:** `attestation_status` off `unevaluated` to a clearly-labeled `attested_claims` (the verifier
proves a fresh, pinned-issuer attestation EXISTS, not that the runtime obeyed it). To keep this honest
the report surfaces the attestation's **issuer key id, freshness window, and claim type(s)** alongside
the status, so a reader sees exactly *what* was attested *by whom* *for when* — never rendered as
TEE-style enforcement. **Residual (out-of-scope):** binding the attestation to actual runtime
enforcement (TEE quote → measured boot → the running broker/resource binary) is real-infra work;
documented as the boundary. **Build artifact:** `deployment_attestation` schema (incl. the signed
`subject` binding) + pinned attestation-authority key + verifier evaluation;
`attestation_status: unevaluated|attested_claims|failed` + the surfaced issuer/window/claim/subject
fields; golden tests INCLUDING a substitution test — a valid, fresh, pinned-issuer attestation whose
`subject` names a DIFFERENT project/manifest/checkpoint/key-set → `failed` (not `attested_claims`).

## D8 — The `attested_complete` gate (the honest capstone)

The capstone is the conjunction of every reduction above — and, per MF1+MF3, two conditions the rev-1
draft omitted: **every** matched use must be a closed two-phase pair, and the label is explicitly
*conditional on resource truthful labeling* (which is NOT closed — see D9). The gate emits
`action_completeness: attested_complete_over_brokered_surface` ONLY when ALL hold:

> all in-scope records L2-proven ∧ **every matched use is a closed `use_intent`+`use_outcome` pair**
> (MF3 — a one-phase ADR-0003 receipt anywhere forces `claimed_over_manifest`, never the capstone) ∧
> every matched use taxonomy-`validated` (D4/MF5) ∧ PoP `reverified` (D2/MF4) ∧ no replay (D3) ∧ no
> `intent_without_outcome` in the closed set (D5) ∧ `broker_trust == sequence_verified` (D6/MF2,
> anchored head) ∧ `attestation_status == attested_claims` (D7) ∧ `unmatched_violation == 0` ∧ no
> unexplained `unmatched_pending` in the closed set.

**The label means exactly (MF1):** *every resource-signed receipt over the brokered surface is
two-phase, PoP-re-verified, taxonomy-validated, replay-free, and committed to an anchored, gapless
broker log — **conditional on the resource having truthfully labeled what it did***. It does NOT prove
the resource performed action A rather than B, nor that there were no undeclared side effects: that is
the irreducible **resource TCB** (D9). To keep the conditional VISIBLE, the report ALWAYS carries
`resource_trust: assumed_truthful` alongside `attested_complete_over_brokered_surface`, so a reader can
never mistake the capstone for "everything the agent did." **Build artifact:** the conjunctive gate +
the mandatory two-phase requirement + `resource_trust` field in `report_to_canon`; golden tests (full
gate → capstone; each single condition removed → `claimed_over_manifest`; a bundle with even one
one-phase matched use → `claimed_over_manifest`).

## D9 — The irreducible residual (stated permanently, not "fixed")

Two distinct floors remain irreducible offline, and the capstone label asserts nothing beyond them:

1. **Never-anchored / outside-broker suppression.** A resource (or agent) that acts and NEVER records
   OR anchors anything produces a bundle indistinguishable from one where the action never happened. D5
   reduces this to "never-anchored *intent*", D6 to "never-sequenced grant", but the floor remains:
   actions taken entirely outside the broker/resource path — or recorded but never anchored — are
   outside the proof.

2. **Resource truthful execution + labeling + side-effect closure (MF1).** Even with a perfect
   anchored two-phase intent/outcome pair, the resource is TCB for whether it *actually performed the
   labeled action* (not a different one), and whether the labeled action had *no undeclared side
   effects*. D2 binds the PoP to the committed params, and D4 validates the action *taxonomy class*,
   but neither proves the resource's real-world effect matched its receipt. This is the irreducible
   resource TCB; it is surfaced as `resource_trust: assumed_truthful` and bounds the D8 capstone.

`attested_complete_over_brokered_surface` says exactly "every resource-signed receipt on the brokered
surface is two-phase, PoP-re-verified, taxonomy-validated, replay-free, and in an anchored gapless
broker log — conditional on `resource_trust: assumed_truthful`" and no more. Closing floor 2 needs the
runtime enforcement of D7 (real TEE attestation), not a verifier change. This is the honest Level-3
boundary; it is documented, not papered over.

## Build order (each commit adversarially reviewed; dependency-ordered)

1. **D1** dedicated `credential` commit domain (foundational cleanup; touches RCP/schema/SDK).
2. **D3** nonce/replay cross-check + `ledger_commitment` re-derivation (small, isolated verifier add).
3. **D2** full offline PoP re-verification (agent params-commitment + carried `cnf`/`use_sig` + verifier
   re-check; shrinks the shim TCB).
4. **D4** signed operation taxonomy (action-verified split).
5. **D6** grant transparency (`broker_seq` + `grant_head`; `broker_trust: sequence_verified`).
6. **D7** deployment attestation evaluation (`attestation_status: attested_claims`).
7. **D5** two-phase intent/outcome gateway (`intent_without_outcome` anomaly).
8. **D8** the `attested_complete` conjunctive gate (the capstone, depends on all above).

Each step lands the producer (broker/resource/SDK) AND the verifier check AND golden adversarial tests
in one reviewed commit, and updates the claim/report labels honestly. D9 is documentation only.

## Honest residuals AFTER this ADR (the new floor)

- **Never-anchored / outside-the-broker action suppression** (D9 floor 1) — irreducible offline.
- **Resource truthful execution + labeling + side-effect closure** (D9 floor 2, MF1) — the resource is
  TCB for whether it really did the labeled action with no undeclared effects; surfaced as
  `resource_trust: assumed_truthful`; bounds the D8 capstone. Closing it needs runtime/TEE enforcement.
- **Deployment-attestation *enforcement*** (vs. claims) — needs TEE/remote-attestation infra; the
  verifier proves a fresh, pinned-issuer *claim*, labeled `attested_claims` (D7 boundary).
- **Taxonomy + attestation authority correctness** — these are pinned-key TCB, surfaced as
  `taxonomy_status` (validated/stale/untrusted, MF5) and `attestation_status` (with issuer/window/claim
  type) — trust is *pinned, named, and freshness-gated*, never *assumed*.
- **Grant log external pinning** — `sequence_verified` requires the `broker_grant_head` bound into the
  anchored/witnessed checkpoint chain (MF2); a deployment without that gets the weaker, honestly-labeled
  `sequence_consistent_export`.
- **Shim nonce-freshness + consume-before-act *ordering*, and the agent↔resource params recompute** —
  runtime, not offline-provable (D2 boundary); the verifier re-checks the *bound* commitment only.
