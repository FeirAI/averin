# Decision Record schema v2

`schema_version: "2"` · `canon_version: "rcp-1"` · signing domain `flightrecorder.record.v2`

Each meaningful agent event is one **Decision Record**: a canonicalized body (RCP v1), with
sensitive fields committed via hiding commitments, hashed (`content_hash`), signed (`sig`),
and **DAG-linked** to its causal parents via `causal_prev_hashes`. This freezes the v2 data
model. Per the **schema-now / enforce-later** discipline, every field that cannot be added
honestly later is present now even though its *enforcement* (credential broker, policy
co-signing, full coverage) ships progressively.

See `decision-record.schema.json` for the machine-checkable schema and `rcp-1.md` for how a
body becomes bytes. Field reference (grouped as in spec §6):

## Versioning & domain separation
- `schema_version` `"2"`, `canon_version` `"rcp-1"`, `domain` `"flightrecorder.record.v2"`.

## Identity
- `record_id`, `project_id`, `session_id` (the "run"), `agent_id`, `agent_version`.

## DAG ordering (NOT a linked list)
- `span_id`, `parent_span_id` (`string|null`; null = root span — explicit, RCP §6).
- `causal_prev_hashes`: array of `sha256:…` content-hashes of causal parents. Semantically a
  **set**: MUST be **de-duplicated and sorted ascending by byte order** before canonicalization
  (RCP §7) so equivalent parent sets hash identically. A record with `[]` is a run root.
- `display_seq`: server-assigned **UI-only ordering — NOT a trust primitive**.

## Time (three clocks; agent clock untrusted — threat #11)
- `agent_ts` (agent host, **untrusted**), `received_ts` (server receipt),
  `anchored_ts` (external TSA, set at checkpoint). Trust ordering comes from causal
  hash-links + the anchored checkpoint, never from `agent_ts`.

## Observed event (observed, not necessarily complete)
- `event_type`: `llm_call|tool_call|decision|approval_gate|handoff|spawn_child|incomplete|credential_grant`.
  `credential_grant` is a credential-broker grant record (Level 3 — see ADR 0002): the broker recorded
  that it issued a scoped, short-lived credential under `gateway_enforced` authority. Its grant-specific
  fields (`issuance_status`, `scope_class`, `conformance_level`, `credential_binding`) live under
  `extensions.broker` — NOT as new top-level keys — so the closed record schema is unchanged.
- `action`, `status`: `ok|error|blocked|pending_approval|incomplete`.
- `observed_via`: `proxy|sdk|otel|broker` — provenance of the observation itself (Level-2 honesty).
  `broker` marks a record produced by the credential broker (a grant) or a resource use-receipt.
- `input_commit` / `output_commit` / `rationale_commit` / `credential_commit`: `{alg, commitment,
  low_entropy}` hiding commitments (RCP §8.3). `credential_commit` is the credential-broker grant's
  descriptor under its dedicated domain (ADR 0004 D1; a grant no longer overloads `input_commit`).
- `tokens`: `{in:int, out:int}`. `cost_micros_usd`: **integer micro-USD — NO floats**.

## Authority (the moat — gradient, not annotation)
- `authority.source`: `caller_declared|policy_engine_signed|human_signed|gateway_enforced`.
- `authority.enforcement_point`: `sdk|proxy|tool_gateway|credential_broker|external`.
- `authority.decision_basis`: `auto|human_approved|policy_allowed|policy_denied`.
- `policy_hash` (content hash of the EXACT policy — resolve by hash, threat #14),
  `policy_snapshot_ref` `{uri,digest,object_version}`, `grant_id`, `grant_type`
  (`id-jag|oauth-scope|role|none`), `authorizing_principal`, `delegation_chain[]`.
- `evidence_hash`, `evidence_sig` (`ed25519:…|null` — the signature **from the authority
  system**; presence is what upgrades `declared` → `verified`), `evaluated_at`,
  `expires_at`, `nonce`.

## Content addressing (mutable keys are a vuln — threat #5)
- `content`: `{uri, digest (sha256:…), length:int, content_type, enc_key_id, object_version}`.
  `object_version` (S3 version id / ETag) pins immutability.

## Integrity & key epoch
- `content_hash` (RCP §8.1), `sig` (RCP §8.2).
- `key`: `{signing_key_id, key_epoch:int, key_valid_from, key_valid_until,
  key_status (active|retired|revoked|compromised), status_changed_at (required iff status is
  revoked|compromised), key_attestation_ref (attests the status/time), rotation_prev_key_sig}`.
  **Enforceable rule (RCP §10.2):** a record signed by a `revoked`/`compromised` key is
  trustworthy **only if** an anchored checkpoint with anchor-time `T ≤ status_changed_at`
  transitively commits the record's `content_hash`; otherwise the verifier reports it
  **untrusted** (never a silent pass).

## Misc
- `framework` (e.g. `openai-agents`), `extensions` (the ONLY place unknown fields tolerated).

---

## Checkpoint object (frontier commitment — see rcp-1 §9.4 / §10)
`schema_version: "2"`, `canon_version: "rcp-1"`, `domain: "flightrecorder.checkpoint.v2"`.
Fields: `checkpoint_id`, `project_id`, `checkpoint_seq` (per-project monotonic from 0, +1, no
gaps), `prev_checkpoint_hash` (`sha256:…|null`; null only at seq 0 — chains checkpoints),
`frontier` (de-duplicated, byte-sorted set of current head `content_hash`es — RCP §10),
`record_count` (cumulative distinct records, non-decreasing), `created_ts`, `checkpoint_hash`,
`sig`, and a post-sign `anchor` `{scheme, token_b64, anchored_ts, tsa_url, witness_uri,
witness_object_version}`. Machine schema: `checkpoint.schema.json`. The deterministic frontier
computation and the offline verification algorithm (omission/fork/backdate detection) are
specified in RCP §10.
