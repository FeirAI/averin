# Feir Dev Handoff — Seal Budget & Chargeback Evidence for leria

**Status of feir:** built (records / seal / verify / export / grants / anchor, on `main`). **This is a small,
well-scoped ask** so the metering plane (**leria**) can seal spend-governance evidence into feir's append-only DAG.
Most of the work is **leria's** (it reshapes its records to feir's existing schema); feir's genuine build is **one
thing**: a typed `record_kind`.

**Authoritative spec (verified against feir source, with file:line):**
[`/Users/dzcodes/Projects/leria/docs/_meta/feir-integration-handoff.md`](/Users/dzcodes/Projects/leria/docs/_meta/feir-integration-handoff.md).

## Why

leria's two governance-grade outputs — **budget exhaustion** ("a spend red line was hit") and **chargeback**
(reconciled spend allocated to a cost-center) — must be provable: *"the agent was throttled because it hit its
budget; here is the tamper-evident record."* leria seals them via your existing `POST /v2/records`.

## What needs NO feir change (leria conforms to your schema)

The earlier "recognize leria as a source" framing was wrong — feir has **no source-allowlist** concept
(`authority.source` is a trust-level enum; `normalizeAuthority` forces generic records to `caller_declared`). So
leria simply seals like any caller. **leria's records are reshaped on its side to your existing closed schema:**
the required `project_id`/`session_id`/`idempotency_key` top-level keys, the budget/chargeback payload under
**`extensions`** (the only freeform-tolerated object), and **integer micros only** (no floats — your
`canon.rs`/`server.go` reject them). So a conforming leria record **seals + verifies + exports today**, no feir
change required for the happy path.

## The one genuine feir build ask — a typed `record_kind`

leria's records describe a `budget.exhausted` or a `chargeback.posted`, but those are **not** in feir's allowed
`event_type` enum (`spec/decision-record.schema.json`), and an off-enum record verifies only as a generic record.
**Make the optional typed `record_kind` a real, supported value-set** — `budget-exhausted` / `chargeback-posted` —
and **preserve it through `verify` and `export`** so spend governance is a **first-class evidence category**:

- a board export can be **filtered by `record_kind`** ("all budget red lines hit this quarter") without parsing
  `extensions`;
- `GET /v2/verify` over a chain containing these records verifies them as their typed kind.

This pairs with govder's noted `cost`/`tokens` envelope addition so cost becomes a typed evidence dimension.
**Without it, leria's records are off-enum and dodge first-class verify/export** — which is why it's a
prerequisite, not an optional nicety.

## Acceptance

1. A `POST /v2/records` with `record_kind ∈ {budget-exhausted, chargeback-posted}` is accepted, hash-chained, and
   returns a record id.
2. The `record_kind` is preserved through `GET /v2/verify` (verifies as the typed kind) and `GET /v2/export`
   (surfaced, **filterable** by `record_kind`).
3. A conforming leria record (required keys + `extensions` payload + integer micros) **seals AND verifies** — no
   seal-but-fail-verify.

## What feir does NOT do

No ledger, budgets, metering, pricing, or enforcement — all leria/govder. feir **proves** the spend governance the
other planes performed. The seam is one-directional: leria → feir (seal); feir surfaces it on verify/export like
everything else. feir signs with its own seed; leria is a record author, **not** an authority signer.
