# ADR 0008: Prompt text is committed, not signed; the recording key can be rotated

Status: accepted (limitations AVE-02 and AVE-04).

## Context

1. The SDKs, the recording proxy and the MCP server put prompt and answer text under
   `extensions.content_preview`. Only the three top-level fields `input`, `output` and `rationale` went
   through `commitLowEntropyFields`, so that text was signed verbatim, exported with every bundle and could
   never be erased (GDPR Art. 17).
2. averin signs with one key and always published only that key at epoch 0. Replacing a leaked key made
   every older record look unsigned to a verifier holding only the bundle, and there was no way to say
   "trust the old key only up to this date".

## Decision: commit the text (AVE-02)

- At ingest, `liftContentPreview` moves `input`/`output`/`rationale` out of `extensions.content_preview` to
  the top level. They then take the existing path: a salted hiding commitment in the signed body
  (`*_commit`, `extensions.feir_evidence.payloads`), the raw text in the encrypted content store with
  retention purge, a disclosure secret persisted atomically with the record. Erasing the text leaves the
  chain verifiable; the verifier already handles a missing payload.
- The SDKs, proxy and MCP server now send the fields at the top level. Old clients keep working through the
  lift, so no coordinated client upgrade is needed.
- Fail closed: `content_preview` must be an object holding only those three keys, may not repeat a
  top-level field, and is refused on a body-bound v3 authority record (the caller signed that body, the
  server cannot rewrite it).
- Existing records cannot be migrated in place: their bodies are signed and hash-chained, so rewriting one
  would break the chain and every checkpoint over it. The migration is therefore (a) new records are
  committed from the first request after the upgrade, with no client change, and (b) the verifier reports
  `cleartext_content_records`, the number of legacy records whose text is permanent, so an operator can
  size the exposure and, if required, start a fresh store under a new project and destroy the old one.

## Decision: signed key rotation (AVE-04)

- New config: `AVERIN_SIGNING_KEY_EPOCH`, `AVERIN_RETIRED_SIGNING_KEYS_FILE`, `AVERIN_KEY_ROTATIONS_FILE`.
  New records and checkpoints carry the epoch; exports list the current and every retired key with status
  and `status_changed_at`, plus the statements in `key_rotations`.
- A statement is signed by the new key and, for a scheduled rotation, also by the old key, over the digest
  of the statement body, under the new domain `averin.key_rotation.v1` (a Lean `Family`, in the domain
  separation catalogue and the oracle corpus).
- The verifier extends the externally pinned set by the successor of a pinned key, only through a verified
  scheduled statement and only while the old key's pinned and bundle status is not revoked or compromised.
  A compromise statement links the keys and extends nothing. A successor that is also a pinned role key is
  refused (role separation).
- `averin-keyrotate` writes both files and self-checks; `averin-server` validates the lineage at startup
  and refuses to start on an inconsistency.

## Consequences

- A bundle from a rotated server verifies from the old pin alone, and a stolen old key cannot hand its
  trust to anyone once the auditor marks it compromised.
- The statement does not prove when the old key actually stopped signing; see KEY-ROTATION.md.
- Raw KMS-backed signing keys remain a separate item (AVE-20).
