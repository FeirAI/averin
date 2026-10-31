# Decision Record schema v2

`schema_version: "2"` · `canon_version: "rcp-1"` · signing domain `flightrecorder.record.v2`

Each meaningful agent event is one **Decision Record**: a canonicalized body (RCP v1), with
sensitive fields committed via hiding commitments, hashed (`content_hash`), signed (`sig`),
and **DAG-linked** to its causal parents via `causal_prev_hashes`. This freezes the v2 data
model. Per the **schema-now / enforce-later** discipline, every field that cannot be added
honestly later is present now even though its *enforcement* (credential broker, policy
co-signing, full coverage) ships progressively.

See `decision-record.schema.json` for the machine-checkable schema and `rcp-v1.md` for how a
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
  averin's recorder always seals the set that way (the server replaces any caller-supplied parents
  with the sorted, de-duplicated union of the session's current heads), and averin's verifier
  rejects an unsorted or duplicated set: the record is untrusted (see RCP §7). Seal and verify run
  the same shape check, so in the default enforce mode the server cannot seal a record the verifier
  rejects (`AVERIN_SEAL_SHAPE=shadow` is the rollback exception).
- `display_seq`: server-assigned **UI-only ordering — NOT a trust primitive**.

## Time (three clocks; agent clock untrusted — threat #11)
- `agent_ts` (agent host, **untrusted**), `received_ts` (server receipt),
  `anchored_ts` (external TSA, set at checkpoint). Trust ordering comes from causal
  hash-links + the anchored checkpoint, never from `agent_ts`.

## Observed event (observed, not necessarily complete)
- `event_type`: `llm_call|tool_call|decision|approval_gate|handoff|spawn_child|incomplete|credential_grant|gateway_refusal`.
  `credential_grant` is a credential-broker grant record (Level 3 — see ADR 0002): the broker recorded
  that it issued a scoped, short-lived credential under `gateway_enforced` authority. Its grant-specific
  fields (`issuance_status`, `scope_class`, `conformance_level`, `credential_binding`) live under
  `extensions.broker` — NOT as new top-level keys — so the closed record schema is unchanged.
  `gateway_refusal` is a record that a gateway refused an action (`record_kind` `gateway-refusal`,
  `status` `refused`, `observed_via` `gateway`, detail under `extensions.gateway_refusal`, no
  `authority` block). It is reserved for `POST /v2/refusals`: the generic ingest path rejects it.
- `action`, `status`: `ok|error|blocked|pending_approval|incomplete|refused`. `refused` is used only
  by gateway refusal records.
- `observed_via`: `proxy|sdk|otel|broker|gateway`: provenance of the observation itself (Level-2 honesty).
  `broker` marks a record produced by the credential broker (a grant) or a resource use-receipt.
  `gateway` marks a gateway refusal record.
- `record_kind` (optional, a sibling of `event_type` that does not replace it): a typed evidence kind,
  one of `budget-exhausted|chargeback-posted|gateway-refusal` in the JSON Schema. It is an ordinary
  signed top-level field. The verifier admits it as a known top-level key and acts only on
  `gateway-refusal`.
- `input_commit` / `output_commit` / `rationale_commit` / `credential_commit`: `{alg, commitment,
  low_entropy}` hiding commitments (RCP §9.3). `credential_commit` is the credential-broker grant's
  descriptor under its dedicated domain (ADR 0004 D1; a grant no longer overloads `input_commit`).
- `tokens`: `{in:int, out:int}`. `cost_micros_usd`: **integer micro-USD — NO floats**.

## Authority (the moat — gradient, not annotation)
- `authority.source`: `caller_declared|policy_engine_signed|human_signed|delegate_signed|gateway_enforced`.
- `authority.enforcement_point`: `sdk|proxy|tool_gateway|credential_broker|external`.
- `authority.decision_basis`: `auto|human_approved|policy_allowed|policy_denied`.
- `policy_hash` (content hash of the EXACT policy — resolve by hash, threat #14),
  `policy_snapshot_ref` `{uri,digest,object_version}`, `grant_id`, `grant_type`
  (`id-jag|oauth-scope|role|none`), `authorizing_principal`, `delegation_chain[]`.
- `evidence_hash`, `evidence_sig` (`ed25519:…|null` — the signature **from the authority
  system**), `evaluated_at`, `expires_at`, `nonce`. Presence of a signature does not by itself make
  authority `verified`. For a non-`caller_declared` source, averin's verifier reports: `legacy_unbound`
  for a valid historical v2 signature (it binds the evidence, not the record body); `verified` only
  for a v3 proof (`proof_version`, `subject_projection`, `subject_digest`, see
  `authority-subject-v1.md`) whose signature verifies under a pinned key and whose digest matches the
  record body; `unverifiable` when the claim is well formed but no authority keys are pinned;
  `failed` when evidence is missing or malformed or no pinned key verifies it. `caller_declared`
  (and an unknown source) is `declared`; no authority block is `none`.

## Content addressing (mutable keys are a vuln — threat #5)
- `content`: `{uri, digest (sha256:…), length:int, content_type, enc_key_id, object_version}`.
  `object_version` (S3 version id / ETag) pins immutability.

## Integrity & key epoch
- `content_hash` (RCP §9.1), `sig` (RCP §9.2).
- `key`: `{signing_key_id, key_epoch:int, key_valid_from, key_valid_until,
  key_status (active|retired|revoked|compromised), status_changed_at (required iff status is
  revoked|compromised), key_attestation_ref (attests the status/time), rotation_prev_key_sig}`.
  **Enforceable rule (RCP §10.2):** a record signed by a `revoked`/`compromised` key is
  trustworthy **only if** an anchored checkpoint with anchor-time `T ≤ status_changed_at`
  transitively commits the record's `content_hash`; otherwise the verifier reports it
  **untrusted** (never a silent pass).
  **averin today:** the producer requirements for the block stay. averin's verifier does not read
  `key_valid_from`, `key_valid_until`, `key_attestation_ref` or `rotation_prev_key_sig` (it only
  rejects a member outside this list), so a record signed outside its stated window is not rejected
  on that basis. averin writes `key_valid_from` as a fixed placeholder (`2026-01-01`) for every key
  and epoch and never writes the other three, so the window carries no validity meaning there; the
  record's own key signs these fields, so a check would add no integrity without an auditor-pinned
  window, which is not implemented. Status and its time come from the
  bundle's `keys[]` entry or the auditor's pinned key list (under pinning the bundle's own time is
  ignored); rotation is verified through separate `key_rotations` statements. The effective status is
  the worst of record, bundle and pin; `retired` counts like `active`; a missing or unknown
  `key_status` counts as `unknown` and the record is untrusted (details in RCP §10.2).

## Misc
- `framework` (e.g. `openai-agents`), `extensions` (the ONLY place unknown fields tolerated).

---

## Checkpoint object (frontier commitment; see rcp-v1.md §9.4 / §10)
`schema_version: "2"`, `canon_version: "rcp-1"`, `domain: "flightrecorder.checkpoint.v2"`.
Fields: `checkpoint_id`, `project_id`, `checkpoint_seq` (per-project monotonic from 0, +1, no
gaps), `prev_checkpoint_hash` (`sha256:…|null`; null only at seq 0 — chains checkpoints),
`frontier` (de-duplicated, byte-sorted set of current head `content_hash`es — RCP §10),
`record_count` (cumulative distinct records, non-decreasing), `created_ts`, `checkpoint_hash`,
`sig`, a `key` block, optional grant-transparency heads, and a post-sign `anchor` `{scheme, token_b64,
anchored_ts, tsa_url, tsa_key_id, witness_uri, witness_object_version}`. Machine schema: `checkpoint.schema.json`.
averin's verifier rejects a checkpoint with a member outside this list (top level, `key`, and the
grant-head objects), and one whose `frontier` is not strictly ascending by bytes. The `anchor` block
is the one open object: it is added after signing and is outside `checkpoint_hash` and `sig`, so the
verifier reads only the members its scheme needs and ignores the rest.
The deterministic frontier computation and the offline verification algorithm (omission/fork/backdate
detection) are specified in RCP §10.

- `key`: `{signing_key_id, key_epoch:int, key_valid_from, key_valid_until, key_status
  (active|retired|revoked|compromised), status_changed_at, key_attestation_ref}`, the same block as
  on a record except that it has no `rotation_prev_key_sig`. The verifier applies the RCP §10.2 status
  rule to the checkpoint's signing key as it does to a record's, and, as for records, does not read
  the validity window or `key_attestation_ref`.
- `broker_grant_head` (optional): `{max_seq:int, prior_head_hash, cumulative_root}`, the cumulative
  root over the broker's grant log up to `max_seq`, chained to the previous checkpoint's root. It is
  inside the signed, anchored checkpoint so the broker cannot equivocate on its grant log.
- `broker_grant_heads` (optional, federated brokers): a map from `broker_id` to the same
  `{max_seq, prior_head_hash, cumulative_root}` object. A well-formed checkpoint carries at most one of
  the two forms.
- `anchor` contents per scheme (`rfc3161`, `test-anchor`), including what each scheme signs and which
  time is used, are specified in RCP §10.1.1.
