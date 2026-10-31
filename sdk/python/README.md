# averin — Python SDK

Record tamper-evident, authority-bound decision evidence from your AI agents to a averin server.

```python
import averin

fr = averin.Client("http://localhost:8080", project_id="proj-1")
fr.record(
    session_id="run-42",
    action="db.query",
    event_type="tool_call",
    rationale="checking balance before transfer",
    authority={"decision_basis": "policy_allowed", "grant_type": "role"},
    cost_micros_usd=18000,   # integer micro-USD (no floats)
)
```

An `authority` dict is passed through unchanged and may carry only the members the record schema lists
(`source`, `enforcement_point`, `decision_basis`, ..., `nonce`); in the default enforce mode the server answers `400` for any other member.
Put custom fields in `extensions`.

The SDK never reimplements the crypto — it submits records and the server seals them through the
Rust integrity core. Integer-only money/token fields are enforced at build time.

**Authentication:** pass `api_key="..."` to `Client` to send a project token as an
`Authorization: Bearer` header. The client posts to `/v2/records?project=<project_id>` (URL-encoded,
equal to the record's `project_id`), which is where the server's project-key check reads the project,
so a server with `AVERIN_API_KEYS` set (required unless `AVERIN_DEV_MODE=1`) accepts a token that has
the write role for that project and answers `401` otherwise. A custom `transport` receives that URL.

For an externally approved v3 record, first assign `record_id`, `span_id`, and `agent_ts`, and
provide precomputed hiding commitments for any content. Call
`averin.prepare_v3_authority_subject(draft)` and give the returned structured record to the
external authority. After it attaches `subject_digest` and `evidence_sig` to `authority`, pass
that same returned record to `Client.submit(prepared, idempotency_key="...")`. Preparation fills
the server's semantic defaults and FEIR lineage before approval; `submit` adds only the
idempotency key outside the signed subject. The server verifies the v3 proof against the record
it seals. The SDK does not sign or accept a caller-supplied opaque digest.

**Idempotency:** each `record()` auto-generates a unique idempotency key (so server-side retries
collapse). To make a *client* retry-after-timeout idempotent, pass a stable
`idempotency_key="..."` you reuse across retries of the same logical call.

Apache-2.0.
