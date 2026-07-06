# Integrating averin with vultrino — the enforcement plane meets the evidence plane

> **Design note, not an implementation.** This document specifies how
> [vultrino](https://github.com/) (a credential proxy for AI agents) and averin (a
> tamper-evident flight recorder for AI agents) compose into one system, and
> states honestly what that composition proves cryptographically versus what stays
> in the trusted computing base. No code in either repo changes as a result of this
> note; it is the map a future wiring commit follows. The bar is **accuracy** —
> every file/line and API name below resolves against the current trees of both
> projects (averin `1b2ddc2`, vultrino `1d814bc`).

## 1. The thesis: two planes, one accountable action

vultrino and averin solve adjacent halves of the same problem — *an AI agent takes a
privileged action and someone must answer for it* — and they barely overlap.

- **vultrino is the runtime enforcement plane.** It holds the real credential, the
  agent never sees it. At request time vultrino *decides* (policy engine), *gates*
  (human approval), *meters* (single-/limited-use tokens, rate limits), *injects*
  the secret into the outbound call, and *fails closed* if any of that is unmet.
  Its job is **to stop or shape the action before it happens.** It is online,
  stateful, and authoritative over whether the side effect occurs.

- **averin is the tamper-evident evidence plane.** It does not decide anything at
  runtime. It takes a *claim* that something was observed, decided, or done —
  canonicalizes it, hiding-commits the low-entropy fields, hashes, signs under a
  tenant-held key, links it into an append-only DAG, checkpoints it, and anchors the
  checkpoint to a third-party RFC 3161 timestamp. Its job is **to make what
  happened independently provable afterward, offline, without trusting the vendor.**

These are complementary, not redundant. vultrino *prevents and shapes*; averin
*proves and preserves*. Today vultrino's own audit story is an explicit stub
(`src/web/routes.rs:158` and `:883` both `// TODO: Implement audit logging`; the
config carries an `audit_file` slot at `src/config/mod.rs:230-231` that nothing
writes to). averin is exactly the audit backend that slot is shaped for — except
instead of a flat, forgeable log file, every entry is a signed, hash-linked,
offline-verifiable Decision Record.

> **One line:** vultrino decides whether the agent may act and injects the secret;
> averin seals an offline-verifiable proof of every such decision and its outcome.

## 2. Why they fit — the mirrored invariants

The strongest evidence that these two were meant to plug together is that they
*independently arrived at the same security invariants*. averin's credential-broker
hardening (ADR 0003/0004 plus this session's convergence) and vultrino's execution
core enforce the same five properties under different names:

| Invariant | vultrino (enforcement) | averin (evidence) |
|---|---|---|
| **Consume before the side effect** | `consume_use_token` is reserved "fail-closed, just before the side effect," after preflight (`src/server/mod.rs:456-463`); `plugin.execute` is the "point of no return" (`:478-482`). | R5 consume-before-act: `ValidateUse` consumes the single-use nonce/jti *before* the resource acts; `/v2/use-intent` is sealed before the side effect (`server/internal/api/server.go:1243-1245`). |
| **At-most-once execution** | `claim_approval_for_execution` + `executed` flag guard a double-run when two polls race (`:606-666`). | jti == grant_id == record_id (`server.go:769`); the consume-before-act ledger rejects a second spend of the same capability. |
| **A failed spend must not burn the credential** | a *transient* preflight failure leaves the token unconsumed and retryable; only a committed `plugin.execute` finalizes terminally (`RunError` taxonomy, `:89-114`). | on a read-path failure *after* `ValidateUse`, averin **releases** the nonce/jti rather than burning it (`server.go:1322-1369`). |
| **Re-evaluate authority at resume, never bypass on approval** | `resume_approved` re-runs policy read-only; a `Deny` still blocks an already-approved action; the use token is left unconsumed when it does (`:540-547`). | D2 PoP re-verification at use; a human/authority signature is evidence, not a policy bypass; TTL cap is checked *after* ed25519 PoP (`7def358`). |
| **Bound the blast radius of a single grant** | outstanding *pending* approvals + consumed uses must not exceed `max_uses`; the count-and-insert is atomic under the storage lock (`store_approval_reserving`, `:371-389`). | per-project denial budget keyed by `sha256(project_id)` so the DoS control is not itself a memory-DoS (`d2a60bc`); D6 gapless `broker_seq`. |

Two systems converging on the same fail-closed, consume-before-act, no-bypass-on-
approval, bounded-blast-radius invariants is not a coincidence — it is what a
correct credential-mediation design looks like from either the enforcement or the
evidence side. The integration's value is that it makes vultrino's *runtime*
invariants **externally and offline provable**: averin turns "trust that vultrino
consumed the token before acting" into "here is the signed, anchored receipt
proving it did, in order, under this grant."

## 3. Concept mapping

| vultrino concept | averin concept | averin ingest point |
|---|---|---|
| **Use Token** issuance (`vut_…`; `credential_scope`, `action_scope`, `max_uses`, `expires_at`; `src/auth/tokens.rs`) | **broker grant** — `gateway_enforced`, sender-constrained, PoP capability; `single_operation` or **`bounded_reuse`** when `max_uses = N` | `POST /v2/grants` |
| **`execute_gated` decision**, pre-side-effect (`src/server/mod.rs:267`) | **use-intent** — D5 phase 1, sealed *before* the resource acts, consumes the capability | `POST /v2/use-intent` |
| **`run_action` consume** at the point of no return (`:456-482`) | **consume-before-act** receipt (R5); for one-phase flows, the single `use` receipt | `POST /v2/use` *(one-phase)* |
| **`plugin.execute` outcome** + `RunError` tag (committed/terminal/retryable) | **use-outcome** — D5 phase 2, completes the intent with the real result | `POST /v2/use-outcome` |
| **Action Approval** decision by a human (`ApprovalStatus::{Pending,Approved,Denied,Expired}`, `src/approval/mod.rs`) | **authority evidence** — `human_signed` `evidence_sig` over the v2 preimage, verified under a pinned approver key | authority block on the grant/use record |
| **Policy Engine** verdict (`PolicyDecision::{Allow,Deny,Prompt}`, `src/policy`) | **`policy_engine_signed` authority** + outcome **taxonomy** (D4) + `side_effect_closure` (T6) | authority/taxonomy block on the record |
| **RequesterInfo** (`principal_kind`/`principal_id`/`role`) | **caller-declared identity** on the record; the authority gradient (`caller_declared → verified`) | `caller` fields on every record |
| **Audit Log** view (the TODO) | tamper-evident **DAG + checkpoint + RFC 3161 anchor + offline verifier** | `GET /v2/dag`, `/v2/verify`, `/v2/export` |
| **Credential proxy / isolation** (agent never sees the secret) | `gateway_enforced` authority; optionally the **Native/STS introspection-transcript** mode (ADR 0005 §M3) to shrink the resource TCB | — |
| **MCP tool surface** (`http_request`, `check_approval`, …) | averin **MCP server** (`record_decision`, `get_session_trace`, `verify_record`; `server/internal/mcp/mcp.go`) | — |

Note the exact alignment on metering: a vultrino use token created with `--uses N`
is, in averin's vocabulary, a **`bounded_reuse` grant with `use_limit = N`**, deduped
per `(grant_id, use_sequence_number)` — precisely the mode specified in
[ADR 0005 §M1](decisions/0005-deferred-producer-modes.md). vultrino is a concrete
real-world driver for that deferred producer mode; wiring it is the first
implementation customer for ADR 0005's N-Use design.

## 4. Architecture & data flow

vultrino gains one new, thin component: a **averin evidence sink** — an async client
that POSTs to a averin server at vultrino's existing decision points. It is the
implementation of the dormant `audit_file` config slot, pointed at a averin
`base_url` + `project_id` + API key instead of a local file.

```
                 agent (never sees the secret)
                        │  MCP: http_request / check_approval
                        ▼
        ┌───────────────────────────────────────────┐
        │  vultrino — ENFORCEMENT PLANE              │
        │                                            │
        │  execute_gated()                           │   ── emit ──▶  POST /v2/records   (decision)
        │   ├─ policy.evaluate → Allow/Deny/Prompt   │   ── emit ──▶  POST /v2/grants    (token issuance)
        │   ├─ approval gate (human sign-off)        │   ── emit ──▶  authority evidence (approval = human_signed)
        │   └─ run_action()                          │
        │        ├─ consume_use_token (fail-closed)  │   ── emit ──▶  POST /v2/use-intent (BEFORE side effect)
        │        ├─ plugin.execute  ◀ point of no    │
        │        │                    return         │
        │        └─ response / RunError tag          │   ── emit ──▶  POST /v2/use-outcome (AFTER side effect)
        └───────────────────────────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────────────────┐
        │  averin — EVIDENCE PLANE                     │
        │  canonicalize → commit → hash → sign →     │
        │  DAG-link → checkpoint → RFC 3161 anchor   │
        └───────────────────────────────────────────┘
                        │
                        ▼
        offline bundle  ──  averin-verify bundle export.json
        (no network, no trust in either vendor)
```

The seam is small and one-directional: vultrino emits, averin seals. averin needs **no
new code** for the MVP — vultrino is simply another producer speaking the existing
`/v2/*` ingest contract, the same one the OpenAI proxy and MCP server already use
(`server/internal/api/server.go:409-420`, all guarded behind the API-key gate at
`:429`).

### 4.1 The two-phase wiring (the core of it)

vultrino's `run_action` is *already* structured as a two-phase commit around a side
effect, which is exactly averin's D5 intent/outcome shape:

1. **Preflight** — resolve plugin, validate params. No side effect, nothing
   consumed. A failure here is `RunError::terminal` (bad params) or `::retryable`
   (plugin not loaded). → **Emit nothing to the use ledger** (averin never sees a
   consume that didn't happen — honest).
2. **Consume** — `consume_use_token` reserves the use, fail-closed, immediately
   before the point of no return (`:456-463`). → **`POST /v2/use-intent`** here, in
   the same fail-closed step: averin seals "vultrino is about to perform `action` on
   `credential` under grant `G`, PoP-verified," and consumes the averin capability.
3. **Act** — `plugin.execute`; the side effect may now occur (`:478-482`).
4. **Outcome** — on success, `RunError::committed` failure, or terminal post-consume
   failure. → **`POST /v2/use-outcome`** completing the intent with the real status
   and the `RunError` tag mapped into averin's outcome **taxonomy (D4)**.

This mapping is faithful to vultrino's own `committed`/`terminal`/`retryable`
distinction (`src/server/mod.rs:89-114`), which carries *precisely* the information
averin's two-phase model wants:

| `RunError` state | What ran | averin evidence |
|---|---|---|
| terminal preflight (bad params, exhausted token) | nothing | no intent sealed — the action provably never started |
| `committed` (`plugin.execute` failed mid-flight) | side effect *may* have occurred | `use-intent` with no clean `use-outcome`, or an outcome tagged `committed_error` — the honest "we cannot claim it didn't happen" state |
| success | side effect occurred | `use-intent` + `use-outcome` with status; D5 complete |

A simpler integration can skip the two-phase split and emit a single
**`POST /v2/use`** at the consume point — but the two-phase form is the honest one,
because vultrino genuinely has a window between "credential spent" and "outcome
known," and averin is built to record exactly that window (`server.go:1243-1245`).

### 4.2 Approvals become verified authority

A vultrino Action Approval is a human (or policy) sign-off recorded in
`ApprovalRequest` with a single-decision capability token. In averin terms an approval
is **authority evidence**: when the approval is granted, vultrino emits an
`evidence_sig` of kind `human_signed` (or `policy_engine_signed` for a
`PolicyDecision::Prompt` auto-decision) over averin's v2 authority preimage, which
binds `project_id` for tenant isolation (`3669782`).

This places vultrino approvals on averin's **authority gradient**:

- **`caller_declared`** — vultrino asserts "this was approved" but no approver key is
  pinned in averin. averin records the claim, integrity-bound, but does not elevate it.
- **`verified`** — the approver's public key is pinned in averin's authority key set
  (role-separated per R2: disjoint from broker/resource/taxonomy/attestation keys,
  `5406096`). Now averin *cryptographically verifies* the approval signature and the
  record can participate in the higher-tier capstone.

The ownership and at-most-once properties vultrino already enforces on approvals
(the requester-principal check at `src/server/mod.rs:588-596`; `executed` guard) are
what make the emitted authority evidence trustworthy to seal — averin is sealing a
decision vultrino has already made tamper-resistant on its own side.

## 5. What this closes — and the honest residuals

### Closes
- **vultrino's audit gap.** The `audit_file` TODO becomes a tamper-evident,
  hash-linked, third-party-anchored, **offline-verifiable** evidence chain instead
  of an appendable text file an attacker with disk access can rewrite.
- **Cross-system non-repudiation.** "The agent spent this credential, in this order,
  under this human approval, and here is the result" becomes a single signed bundle
  an external auditor verifies with `averin-verify bundle` — no trust in vultrino *or*
  averin's operator required (self-host holds the signing key).
- **A real driver for ADR 0005 N-Use** (`bounded_reuse`), exercising that design.

### Residuals and floors (stated, not papered over — averin house rule)
- **vultrino is in the TCB for the evidence it emits.** averin proves "vultrino, under
  key K, asserted X and it has not been altered since" — *not* "X is physically what
  the plugin did." This is the same `resource is TCB` floor averin already states for
  Tier B (ADR 0004 §D9). To shrink it, drive the WASM plugin layer to co-sign its
  own effective action, or adopt the Native/STS **introspection-transcript** mode
  (ADR 0005 §M3): a second resource-signed record attesting the *effective* scope,
  which relocates rather than closes the TCB — and averin labels it with the weaker
  `attested_complete_over_introspected_surface` capstone, never the PoP-proven one.
- **Evidence emission must not gate enforcement by default.** A averin outage must not
  prevent vultrino from denying or shaping an action — so the sink is **fail-open**
  for availability by default (the enforcement decision is vultrino's alone). For
  regulated deployments offer an opt-in **`require_evidence` strict mode** that
  fail-*closes* the action if averin will not seal the intent — at the cost of binding
  the action's availability to averin's. Whichever mode, a persistent seal failure
  must raise an operator alarm, never be silently dropped.
- **The two-phase crash window is real and is recorded honestly.** If vultrino dies
  between `/v2/use-intent` (consume) and `/v2/use-outcome`, the bundle shows an
  intent with no outcome — which is the *correct* state, not a bug: the side effect
  may or may not have completed, and averin refuses to claim either. This mirrors
  vultrino's own `committed` semantics.
- **Clock trust.** vultrino's timestamps are `caller_declared` until averin's
  checkpoints are TSA-anchored; only then is the ordering third-party-attestable.

## 6. The MCP bridge

Both speak MCP, which makes a combined agent deployment clean: the agent calls
vultrino's MCP tools (`http_request`, `check_approval`; args in
`src/mcp/types.rs:243-282`) for enforcement, while averin's MCP server
(`server/internal/mcp/mcp.go`) exposes `record_decision` / `get_session_trace`
(the causal DAG) / `verify_record`. The high-value
touch: vultrino's MCP tool responses carry back the averin **`record_id`** of the
sealed receipt, so the agent — and its operator — get a verifiable evidence handle
inline with every privileged action, turning "trust me" into "verify this id."

## 7. Build order (staging map — no code now)

Dependency-ordered, smallest first, each independently shippable:

1. **averin sink scaffold** in vultrino — config block (`averin.base_url`,
   `averin.project_id`, `averin.api_key`, `averin.mode = observe|require_evidence`) + an
   async client. Emit `POST /v2/records` for every `execute_gated` decision. No
   behavior change; pure observation. This *is* the `audit_file` TODO, redirected.
2. **Grant emission** — on use-token issuance, `POST /v2/grants`; map `--uses N` →
   `bounded_reuse` / `use_limit`, `--credential`/`--action` → grant scope.
3. **Two-phase use** — `POST /v2/use-intent` at the consume point in `run_action`,
   `POST /v2/use-outcome` after `plugin.execute`; map `RunError` → D4 taxonomy.
4. **Approvals → authority** — emit `human_signed`/`policy_engine_signed`
   `evidence_sig` on approval grant; document pinning the approver key into averin's
   authority set to cross `caller_declared → verified`.
5. **TCB-shrink (optional)** — `require_evidence` strict mode; Native/STS
   introspection-transcript co-signing from the WASM plugin layer.

## 8. What each side provides

- **averin provides (already built):** the `/v2/{records,grants,use,use-intent,use-outcome,checkpoints}`
  ingest contract, authority/PoP/role-separation verification, the consume-before-act
  ledger, the DAG/checkpoint/anchor machinery, and the offline verifier + bundle
  export. No new averin code is required for steps 1–4. Optional follow-up: a published
  "vultrino producer profile" pinning the exact field/taxonomy mapping as a golden
  fixture in `spec/`.
- **vultrino builds (new, small, all on the emit side):** the averin sink client + config,
  and the five emit hooks at the decision points named above. None of it touches
  vultrino's enforcement logic — the sink only observes and seals.

---

### Cross-references
- averin credential broker: [ADR 0002](decisions/0002-credential-broker-level-3.md),
  [ADR 0003](decisions/0003-tier-b-demonstrator.md),
  [ADR 0004](decisions/0004-tier-b-residual-reduction.md) (D2 PoP, D4 taxonomy, D5
  two-phase, D6 `broker_seq`, D8 capstone, R2/R5).
- N-Use / `bounded_reuse`: [ADR 0005 §M1](decisions/0005-deferred-producer-modes.md).
- Coverage limits & trust levels: [coverage-limits.md](coverage-limits.md).
- Production-readiness for the averin side of this deployment:
  [deployment-readiness.md](deployment-readiness.md).
