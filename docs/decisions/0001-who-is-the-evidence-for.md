# ADR 0001 — Who is the evidence FOR?

**Status:** Accepted (Phase 1 founding decision, spec §13)
**Date:** 2026-06-15

## Context
A signed, hash-chained record proves **provenance and integrity**, not **reality**
(spec §0). The architecture forks on *who the evidence must convince*:

- **"Evidence for yourself" (incident reconstruction):** tolerates a single customer-held
  signing key. The customer is not the adversary; they want to know what their agent did.
- **"Evidence a third party trusts, against yourself":** a malicious customer holding the
  only key can fabricate a clean trail (threat #15). Defending this needs an external
  witness / co-signer, not just a customer key.

## Decision
**Lead with incident reconstruction; build the external-anchoring spine now so the stronger
claim is reachable without a schema change.**

Concretely for Phase 1:
1. Single customer-held key is the default custody model (self-host) — strongest
   anti-vendor-forgery; the vendor cannot forge or alter customer records.
2. **External anchoring is in Phase 1, not deferred** — RFC 3161 TSA timestamp on every
   signed checkpoint + a customer-controlled, object-locked witness copy + full checkpoint
   history in every export. This partially defends threat #15 and fully un-backdates
   checkpoints (threat #3). **Honest limit (RCP §10.1 step 6):** *omission* of a session that
   was already anchored is detectable; *forking* (running a parallel suppressed chain under
   the same key) is detectable **only if both chains are observed** — which is exactly why the
   witness copy must live in an append-only, customer-controlled, object-locked store outside
   vendor control. Given only one internally consistent chain, a verifier cannot prove a
   parallel chain didn't exist. We state this in-product, not hide it.
3. The schema leaves room for an **optional co-signature** (a second, independent signer —
   e.g. the vendor or a notary) without a model change: `key.rotation_prev_key_sig` and the
   `anchor` block establish the multi-party pattern; a future `cosig` follows the same
   domain-separated preimage rules.

## Consequences
- Marketing/UI lead = "verifiable incident reconstruction," honestly Level 1–2 (spec §0).
- The honest **limit** is stated in-product: single-key self-host does not defend against a
  malicious customer except via the external witness/anchor (partial). Documented, not hidden.
- We do **not** build the credential broker (Level 3) now, but never ship a schema or claim
  it can't slot into (spec §12).
