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

The SDK never reimplements the crypto — it submits records and the server seals them through the
Rust integrity core. Integer-only money/token fields are enforced at build time.

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
