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
single-use rule — it also catches reusable-grant replays). The verifier ALSO re-derives
`ledger_commitment` from `(jti, nonce, used_at)` and compares it to the carried value for **every** closed
use receipt — a mismatch is an `unmatched_violation`. This is mandatory, not optional: the preimage is
always present (those fields are gated as well-formed in `use_evidence` before the check), so there is no
"if the verifier is given the preimage" branch — it is intrinsic to the receipt, never an out-of-band pin.

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
which is strictly stronger but not elimination. **Build artifact [IMPLEMENTED, verifier side]:**
`classify_role` maps `(use_intent|use_outcome, tool_gateway)` → resource role. A pre-pass binds each
CLOSED `use_outcome` to its `intent_ref` AND `grant_id` read from the **signed `use_outcome` payload**
(re-derived against `authority.evidence_hash` + the resource `evidence_sig`), NOT the unsigned sibling
`extensions.broker.intent_ref` — else the record-signing key (a relay, a different trust domain than the
resource) could redirect a resource-signed outcome to a different intent. A closed outcome that is not
fully validatable (integrity / resource authority / re-derivable payload) is itself a Tier-B violation
(parity with a one-phase use — no laundering). The use loop runs the SAME full predicate (D2 PoP / D3 replay / D4 action) on a `use_intent` as
on a one-phase `use`; a `use_intent` completes (counts toward `uses_matched`) ONLY if a valid outcome (a)
references it, (b) attests the SAME grant, AND (c) proves the **before-act ordering** via the
RESOURCE-SIGNED `intent_hash` in the `use_outcome` payload equalling the intent's content_hash (the
resource attests it observed THAT intent before signing the outcome — a hash it could not know unless the
intent already existed; the relay-controlled top-level `causal_prev_hashes` is kept only as a DAG
consistency check, since the record-signing key could backfill it). An unordered/backfilled pair does not
complete. The matching outcome is consumed by **record_id** (so duplicate same-`intent_ref`
outcomes account independently; indexed by `(intent_ref, grant_id)` to avoid an O(intents·outcomes) scan),
and consumption happens only AFTER every acceptance check (incl. PoP) passes (a later-rejected intent must
not mask its outcome). Else the intent is an `intent_without_outcome` anomaly (surfaced, NOT a violation,
does not consume a single-use grant); every un-consumed validated outcome is an orphan **violation**
(a completion with no recorded pre-action intent). A one-phase `use` (ADR 0003) is still accepted/counted
for back-compat (it cannot reach the D8 capstone — MF3). Tests (10): complete pair → matched;
intent-without-outcome → anomaly; one-phase → matched; mismatched/phantom/unsigned-sibling `intent_ref`,
wrong-grant, wrong-signed-kind, not-causally-after, and failed-PoP → not completed; orphan + forged +
duplicate-same-intent outcomes → violation; all order-independent.
**Producer [D5.2, IMPLEMENTED]:** `POST /v2/use-intent` records the `use_intent` (kind=use_intent, the same
validate+consume+PoP path as one-phase `/v2/use`) BEFORE the side effect; `POST /v2/use-outcome` records the
`use_outcome` AFTER, resolving the intent by `intent_record_id` and binding its `content_hash` as the
resource-signed `intent_hash` (the before-act ordering proof). The signed `use_outcome` payload carries
`{kind, grant_id, intent_ref, intent_hash, status}`; the unsigned sibling discriminator routes the role.
One-phase `/v2/use` is unchanged. Go tests assert producer structure + the signed binding + bundle
integrity; the intent↔outcome MATCHING semantics (which need a verifiable anchor — the test StubTSA token
is not crypto-valid) are exercised in the Rust adversarial suite. **Idempotency hardening [D5.2 round-2]:**
all three endpoints resolve retries on the request's `idempotency_key` via `RecordByIdem` (the SAME key the
store dedupes on), requiring an EXACT `(record_id, session_id, broker kind)` match to collapse as an honest
retry — anything else under that key is a `409` raised BEFORE the credential-consuming `ValidateUse`. This
closes two holes in the prior session-scan-by-`useID` approach: (1) a generic `/v2/records` row already
occupying the key (random `record_id` the scan missed) would let `ValidateUse` burn the nonce and then
`PutRecord` silently collapse the seal onto that foreign row (`created=false`) — an action with no persisted
receipt; (2) `/v2/use` and `/v2/use-intent` derive the same `useID` from `(project, key)`, so reusing one
key across phases returned the wrong-kind record and skipped validation. Go tests cover the preseed-collision
and cross-phase-key cases for all three endpoints.

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

**Second `broker_trust` lever — credential label fidelity (D4 cross-reference) [D6.4, IMPLEMENTED]:** D4's
`action_verified` trusts the broker's grant LABELS (`action`/`resource_id`/`scope_class`). When the
credential descriptor is disclosed (the `credential_commit` opened + verified), the verifier additionally
cross-checks `sha256(descriptor) == grant_evidence.credential_binding` and the descriptor's
`act/aud/jti/cnf/exp/single_use` against the signed `grant_evidence`
(`action`/`resource_id`/`grant_id`/`cnf_kid`/`exp`/`scope_class=="single_operation"`) — proving the broker
did not mislabel a broad credential as a benign single-op action. The labels AND the `credential_commit`
live in the SAME record, bound by its content signature, so the check runs on any **integrity-proven**
broker grant — it does NOT require a pinned broker authority key (that is the separate
`authority`/`grant_verified` axis). Surfaced as `cred_label_checks`/`cred_label_matched`; a shortfall is a
broker-equivocation **violation** (hard `issues`). Absent the disclosure, label↔credential fidelity remains
a `broker_trust` residual. Cross-language byte-exactness (descriptor `cnf` base64url ↔ Rust `cnf_kid`) is
pinned by an end-to-end Go test against the real broker-minted descriptor.

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

**Producer↔verifier contracts (the verifier MUST re-derive identically to the producer):**
- **Grant-log membership = the role TUPLE, not signature trust.** A record is in the transparency log iff
  `(extensions.broker.kind=="grant", authority.enforcement_point=="credential_broker")` — the same
  `classify_role` tuple the verifier already uses. Membership is NOT gated on `evidence_sig` verifying: a
  broker must not be able to drop a grant from the log by under-signing it (that IS the suppression D6
  detects). Per-grant trust (`evidence_sig` under a pinned broker key → `grant_verified`) is a SEPARATE
  axis. So `cumulative_root` folds every recorded tuple-classified grant; `grant_verified` counts the
  subset whose sig verifies.
- **D6 activation boundary (STRICT).** D6 is *active* for a bundle once it carries ANY D6 signal: a
  well-formed committed `broker_grant_head`, a checkpoint carrying a *present-but-malformed* head (a
  tampered D6 head — pre-D6 checkpoints never emit the field, so it both activates D6 and is a violation
  in its own right), or any tuple-classified grant carrying a `broker_seq`. Once active, EVERY
  tuple-classified grant the verified DAG commits MUST carry a `broker_seq >= 1`. A committed broker grant
  with NO `broker_seq` is one SMUGGLED OUT of the transparency log (it would be silently absent from every
  head's `max_seq` + `cumulative_root`), so the verifier treats it as a suppression violation (down-ranks
  `broker_trust` → `assumed` and fails the bundle), NOT as a benign pre-D6 row. The producer always
  assigns a `broker_seq`, so a fresh project's log is a clean `[1..N]`. A project that recorded broker
  grants BEFORE D6 must BACKFILL a `broker_seq` onto each (re-seal them into the log) before its first D6
  checkpoint; an un-backfilled legacy grant present alongside any D6 signal is — correctly —
  indistinguishable from a smuggled one and must not pass. The demonstrator is built fresh and has no
  legacy grants. (Earlier drafts excluded seq-less grants on BOTH sides so legacy bundles were "not
  wedged"; that left a suppression hole — a broker could drop a grant from every head by omitting its
  `broker_seq` — so strict D6 closes it at the cost of requiring legacy backfill.)
- **Inherent residual — total suppression / pre-D6 equivalence.** The one case strict D6 CANNOT decide
  offline: a bundle with NO D6 signal *at all* — every committed broker grant seq-less AND no
  `broker_grant_head` field on any checkpoint — is *byte-indistinguishable* from a legitimate pre-D6
  export, so it verifies clean with `broker_trust:"assumed"`. An attacker who never emits a single D6
  signal can therefore suppress the entire grant log and look exactly like a project that never adopted
  D6. Activating on the mere *presence* of broker grants would false-positive every genuine pre-D6 bundle,
  so this is not closable from the bundle alone; it is the same class of limit as equivocation, pushed to
  the **out-of-band transparency monitor** (which has seen the project's adoption history and knows D6 is
  expected) plus the TSA time anchor. Note the boundary is *all-or-nothing*: the moment ONE seq'd grant or
  ONE head (well-formed or malformed) appears, strict D6 engages and every other committed grant must be
  in the log — partial suppression is always caught.
- **Consistent snapshot.** The producer reads the frontier, record count, and grant log under one ingest
  lock so the head folds exactly the grants the checkpoint frontier commits; the verifier re-derives over
  that same closed (anchored-checkpoint-committed) grant set.
- **Single-instance ordering / multi-instance residual.** Gapless RECORDED order (no higher seq anchored
  before a lower) relies on single-process ingest serialization (as the DAG frontier already does); a
  multi-instance deployment must hold a distributed per-project lock across allocate→seal→insert (the
  Postgres advisory lock is the extension point). Stated, not hidden.

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
documented as the boundary. **Build artifact [IMPLEMENTED, verifier side]:** a top-level
`deployment_attestation` object `{issuer_kid, issued_at, not_after, claim_types[], subject{...}, sig}`
signed (domain `feir.attestation.v1`) over its RCP-canonical bytes minus `sig`, verified under a pinned
`attestation_keys` issuer (role-separated — disjoint from broker/resource/taxonomy, a FATAL config error
otherwise). The signed `subject` binds `project_id`, `coverage_manifest_digest`, the latest anchored
`checkpoint_hash` + `broker_grant_head_root`, the `authority_kids` set (the **broker + resource**
authority pinned key ids — NOT the taxonomy issuer, which is no authority over this deployment's
grants/uses, is validated separately via `taxonomy_status`, and which the attestation producer never
holds), and the `resource_ids` set. **Freshness is offline-anchored:** the latest anchored checkpoint's
TSA timestamp must fall within `[issued_at, not_after]` (no wall clock is trusted). The verifier emits
`attestation_status: unevaluated|attested_claims|failed` plus surfaced `attestation_issuer_kid` /
`attestation_issued_at` / `attestation_not_after` / `attestation_claim_types` / `attestation_subject_digest`.
Tests include the mandatory **substitution test** (a valid, fresh, pinned-issuer attestation whose
`subject` names a DIFFERENT project/checkpoint → `failed`, not `attested_claims`), bad-sig, issuer-kid
mismatch, stale-window, absent (→`unevaluated`), and the role-separation fatal. **Producer [D7.2,
IMPLEMENTED]:** `Server.WithAttestation(key)` makes `/v2/export` emit a top-level `deployment_attestation`
signed (domain `feir.attestation.v1`, the digest = sha256 of the RCP-canonical attestation minus `sig`,
signed in pure Go via the LP-prefixed preimage matching the Rust core) over a subject binding the project /
latest checkpoint_hash + broker_grant_head_root / the authority key-id set / the resource-id set. The JSON
opts path (`verify_bundle_with_json`) now parses `attestation_keys`, so the Go server / an external auditor
can pin the issuer and elevate to `attested_claims`. Without a configured key, no attestation is emitted
(bundle verifies `unevaluated`). The Go test pins the issuer and confirms the verifier's signature + issuer
+ subject checks pass cross-language (only the test StubTSA's non-crypto-valid anchor blocks the freshness
step); the full `attested_claims` path is in the Rust suite. **Freshness window [D7.2 round-2]:** the
producer brackets `[issued_at, not_after]` on the latest checkpoint's own `created_ts` (the verifier checks
the anchored TSA genTime, ≈ `created_ts`, NOT export time), with `issued_at = created_ts − issuedSkew`
(default 1h) and `not_after = created_ts + validity` (default **7 days** — widened from 24h so a slow/queued
anchor whose genTime lands hours-to-days after the seal still falls inside; both overridable via
`WithAttestationWindow`). A wide `not_after` is safe because the subject binds the exact `checkpoint_hash` +
frontier coverage, so a stale attestation cannot be replayed onto a moved-on bundle. If `created_ts` is
missing/unparseable (a legacy/externally-produced checkpoint), `issued_at` widens to ~30 days below export
time rather than fail an honest attestation **closed** (its anchored genTime may predate `now − issuedSkew`).

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
never mistake the capstone for "everything the agent did." **Build artifact [IMPLEMENTED]:** the
conjunctive gate in `report_to_canon` emits `action_completeness: attested_complete_over_brokered_surface`
iff `ok ∧ coverage_manifest present ∧ uses_matched>0 ∧ !one_phase_use_present ∧ intent_without_outcome==0
∧ taxonomy_status=="validated" ∧ uses_action_unverified==0 ∧ uses_pop_reverified==uses_matched ∧
broker_trust=="sequence_verified" ∧ attestation_status=="attested_claims" ∧ unmatched_violation==0 ∧
unmatched_pending==0 ∧ side_effect_closure_status=="closed"` (T6, the 12th conjunct: the brokered surface
stayed within the operator's AFFIRMATIVELY-declared side-effect closure — load-bearing beyond `ok` because
an `unclosed` surface already forces `!ok` but a `not_declared` manifest does NOT, so without it a perfect
bundle declaring ZERO closure would reach the capstone); else `claimed_over_manifest` (a manifest is
present) or `not_claimed`. (Term-count: the formula has 13 AND-terms, but `coverage_manifest present` is
the *gate precondition* — removing it yields `not_claimed`, not `claimed_over_manifest` — so it is counted
apart from the 12 *load-bearing conjuncts* whose individual removal drops the label to `claimed_over_manifest`.) A new `one_phase_use_present` flag (set when a matched one-phase `use` is counted)
enforces MF3, and `resource_trust: "assumed_truthful"` is emitted UNCONDITIONALLY (MF1). Tests: full
conjunction → capstone; EACH of the 12 conjuncts individually removed → `claimed_over_manifest` (every
conjunct is load-bearing, incl. the T6 `not_declared` case which proves it adds beyond `ok`);
no manifest → `not_claimed`; a real bundle with a one-phase matched use sets the flag and is blocked
end-to-end; `resource_trust` always present.

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
   **T6 closes the ACTIONABLE half (ADR 0002 open Q1):** the operator declares, in the D7-digest-bound
   `coverage_manifest`, a `side_effect_closure` — per `(resource_id, action)`, the resources it may
   transitively touch — and the verifier proves that declaration is *complete over the observed brokered
   surface* (every resource a grant/use names is within the declared closure, else an `unclosed_side_effects`
   violation; `side_effect_closure_status` ∈ `not_declared|closed|unclosed`, the 12th D8 conjunct requires
   `closed`). This proves the manifest **declares** a complete closure over what happened — it does NOT prove
   the runtime **obeyed** it nor that the closure is semantically complete; those stay the irreducible TCB
   above, closable only by D7-style runtime/TEE enforcement.

`attested_complete_over_brokered_surface` says exactly "every resource-signed receipt on the brokered
surface is two-phase, PoP-re-verified, taxonomy-validated, replay-free, and in an anchored gapless
broker log — conditional on `resource_trust: assumed_truthful`" and no more. Closing floor 2 needs the
runtime enforcement of D7 (real TEE attestation), not a verifier change. This is the honest Level-3
boundary; it is documented, not papered over.

**Residuals surfaced during implementation (all facets of the two floors, stated not hidden):**
- **D6 total grant-suppression = pre-D6 equivalence (floor 1).** A bundle with NO D6 signal at all
  (every committed broker grant seq-less, no `broker_grant_head` on any checkpoint) is byte-identical
  to a legitimate pre-D6 export, so it verifies `broker_trust:"assumed"` — an all-or-nothing instance
  of "never-sequenced grant". The moment ONE seq'd grant or head (even malformed) appears, strict D6
  engages; total suppression is pushed to the out-of-band transparency monitor + TSA anchor.
- **Globally-consistent grant equivocation (floor 1).** A broker that renumbers AND rewrites every head
  + prior-head-chain into a self-consistent fabricated history is indistinguishable offline; only the
  monitor (which has seen the real history over time) detects it. `sequence_verified` is the offline
  ceiling.
- **Relay/record-key trust boundary (floor 2, hardened).** D5 binds the two-phase join (intent_ref,
  grant_id, `intent_hash` ordering, kind) to the RESOURCE signature, so a relay holding only the
  record-signing key cannot fabricate completion or ordering. What the resource SIGNS is trusted; what
  it actually DID remains the resource TCB.
- **Label↔credential fidelity (floor 2, reduced by D6.4).** When the credential descriptor is disclosed,
  D6.4 proves `sha256(descriptor)==credential_binding` and that the descriptor's scope/subject/timing/
  action match the signed grant labels — closing the "broker mislabeled the credential" gap. Absent the
  disclosure it remains a `broker_trust` residual; it never reaches the resource's real-world effect.

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
