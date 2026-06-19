# ADR 0006 — Role-key compromise/rotation + verifier structure (design-only)

**Status:** Proposed (DESIGN ONLY — no production code ships with this ADR).
**Date:** 2026-06-19
**Builds on:** ADR 0003 (R2 role separation; the role-disjoint key sets), ADR 0004 (D1–D9, the D8 capstone),
ADR 0005 (the six producer modes + their pinned role keys), and the existing **signing-key** rotation model
(`TrustedKey { status, status_changed_at }`, `verify.rs`) which this ADR generalizes to the role keys.

## 0. What this ADR is

A design for three items the deep review flagged as needing design before implementation. None changes
behavior on its own; each states the mechanism, the verifier semantics, the capstone interaction, and the
residual floor, and (1) and (3) only ever make the verdict MORE restrictive or better-typed — never looser.

1. **Role-key compromise/rotation** — the substantive gap. The 8 non-signing **role** key sets are pinned as
   plain keys with no lifecycle; a compromised broker/resource/attestation/… key cannot be retired.
2. **`verify_bundle_with` structure** — a 2091-line function; a phased, golden-vector-guarded extraction.
3. **`action_completeness` onto `VerifyReport`** — promote the capstone from an inline serialization to a
   typed field computed during verification.

---

## 1. Role-key compromise / rotation (the gap)

### 1.1 Today

Per-record **signing** keys already have a lifecycle: a pinned `TrustedKey` carries `status`
(`active` | `rotated` | `compromised`) and `status_changed_at`. A record signed by a compromised key is
still trusted iff it was transitively committed by an anchor **≤ `status_changed_at`** (the key was good
then); after that boundary it fails to elevate. Under pinning, ONLY the auditor-supplied (authoritative)
status/time is honored — the bundle's self-asserted values are ignored, so an attacker cannot future-date a
compromise to launder a later forgery (`verify.rs`, the `changed_at`/`worst_status` block).

The 8 **role** key sets — `broker_authority_keys`, `resource_authority_keys`, `tsa_keys`,
`attestation_keys`, `cosig_approver_keys`, `revocation_keys`, `federated_broker_keys` (per broker_id), and
the taxonomy key — are pinned as **plain `Vec<VerifyingKey>`** with no status. Consequence: if a broker
authority key is compromised, an auditor has no way to express "grants this key signed **after** time T no
longer elevate." They can only drop the key entirely — which also un-trusts every *legitimate* pre-compromise
grant it signed (a strictly-worse, all-or-nothing choice). This is the gap.

### 1.2 Mechanism

Generalize the signing-key model to role keys. Replace each pinned role-key entry's bare `ed25519pub:` string
with EITHER that string (status defaults to `active`) OR an object:

```json
{ "key": "ed25519pub:…", "status": "compromised", "status_changed_at": "2026-06-01T00:00:00.000Z" }
```

so the opts wire shape stays backward-compatible (a bare string ⇒ `active`, no boundary). Internally, replace
`Vec<VerifyingKey>` with `Vec<RoleKey>` where `RoleKey { vk, status, status_changed_at }` — structurally the
same as `TrustedKey`, so the existing `worst_status` / anchored-`≤ status_changed_at` comparison is reused
verbatim, not reinvented.

### 1.3 Verifier semantics (the gate)

A role signature (the grant elevation under `broker_authority_keys`, the use receipt under
`resource_authority_keys`, the cosig approval, the revocation-list signature, the attestation signature, the
TSA token, the federation cert) elevates **only when** the signing role key's effective status permits it at
the evidence's **anchored** time:

- `active` → elevates (today's behavior).
- `rotated` / `compromised` with `status_changed_at = T` → elevates **iff** the elevating evidence is
  transitively committed by a verified anchor with genTime **≤ T**; otherwise it does NOT elevate (the mode
  reads its un-elevated floor: a grant stays `assumed`, a use stays unmatched, a revocation list `stale`,
  an attestation `failed`, a cosig `failed`).
- A compromised role key with **no** anchor to date the evidence ⇒ **fail-closed** (cannot prove the
  signature predates the compromise). This is the same offline floor revocation freshness already lives with.

Authoritative-under-pinning carries over unchanged: the role-key status/time come from the auditor's opts,
never the bundle, so a forger cannot self-assert a future compromise boundary to keep a stolen key "active."

### 1.4 Capstone interaction & residual floor

The D8 capstone only gets MORE restrictive: a post-compromise role signature that used to elevate now does
not, so a bundle relying on it drops to the weaker labeled tier (or `not_claimed`), never silently passes. The
floor is the offline one: revocations/compromises the bundle could not yet have been anchored against are not
enforceable from the bundle alone (the out-of-band transparency monitor owns that tail) — identical to the
M5 revocation-freshness floor, stated plainly, not hidden.

### 1.5 Why it is safe to add

It is monotone: every bundle that verifies today still verifies (bare-string keys ⇒ `active` ⇒ unchanged), and
the only new outcomes are *down*grades of post-compromise elevations. It reuses the audited signing-key
status machinery rather than adding a parallel one.

---

## 2. `verify_bundle_with` structure (2091 lines → phases)

The function is already a **straight-line pipeline** of independent phases sharing a few accumulators
(`issues`, `record_trust`, the `by_hash`/committed-set indices). It is long, not tangled — which makes a
mechanical, low-risk extraction possible. The golden vectors + the 234 adversarial fixtures assert a
**byte-identical report**, so any extraction that changes a byte fails CI loudly; that is the safety net that
makes this tractable.

Proposed seams (each becomes a named `fn` taking the shared context by `&`/`&mut`, returning its slice of the
report — NO logic change, pure code-motion):

1. `parse_and_validate_opts` — opts JSON → `VerifyOptions` + the R2 role-disjointness fatal check.
2. `classify_records` — per-record integrity + signature + role + `record_trust` rows (already factored
   partly).
3. `verify_checkpoint_history` — chain, anchors, frontier/heads, gap report.
4. `compute_trusts` — `compute_broker_trust` + `compute_federation_trust` (already extracted) + resource.
5. `evaluate_modes` — taxonomy/attestation/cosig/delegation/revocation(+merkle)/introspection (each is
   already a self-contained block; lift to a `fn` per mode).
6. `assemble_capstone` — the D8 conjunction (see §3) + `issues`/`ok` finalization.

Constraints: keep the SAME field-insertion ORDER (the report is a canonical object; reordering changes
nothing semantically but keep it to minimize diff), and extract **one seam per commit**, each gated by the
full Rust + wasm + cgo suites, so a regression is bisectable to a single seam. This is readability/maintenance
only — explicitly NOT worth a big-bang rewrite of the trust root.

---

## 3. `action_completeness` onto `VerifyReport`

Today the capstone is computed **inline during JSON serialization** (`verify.rs`, the
`("action_completeness".into(), { … })` block) — stringly-typed and not present on the `VerifyReport` struct,
so Rust callers (and the report-to-struct round-trip) cannot read it without re-parsing JSON.

Promote it: add `pub action_completeness: ActionCompleteness` to `VerifyReport`, where

```rust
enum ActionCompleteness {
    NotClaimed,
    ClaimedOverManifest,
    AttestedCompleteOverBrokeredSurface,
    AttestedCompleteOverIntrospectedSurface,
}
```

computed in `verify_bundle` (where every conjunct input is already in scope) and serialized FROM the field
(one `match` → the existing strings, byte-identical). This makes the capstone a first-class, exhaustively-typed
result instead of a string assembled at the edge — the compiler then enforces that every code path sets it,
and the §2 `assemble_capstone` seam has a typed return. Behavior-preserving; the golden vectors pin the
serialized strings.

---

## 4. Implementation order & status

Recommended order, each independently shippable and test-guarded:

1. **(3) `action_completeness` typed field** — smallest, behavior-preserving, unblocks the §2 capstone seam.
2. **(2) `verify_bundle_with` seams** — one extraction per commit, full-suite-gated, bisectable.
3. **(1) Role-key rotation** — the real feature; lands last because it is the largest trust-root change and
   benefits from the cleaner post-(2) structure. Ships with new golden vectors for a post-compromise
   downgrade per role.

> **Status:** DESIGN ONLY. No code, schema, or behavior change ships with this ADR. Implementation is gated on
> explicit go-ahead, given all three touch the trust root and (1) is a new security-relevant feature.
