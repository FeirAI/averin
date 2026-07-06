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

**Idempotency:** each `record()` auto-generates a unique idempotency key (so server-side retries
collapse). To make a *client* retry-after-timeout idempotent, pass a stable
`idempotency_key="..."` you reuse across retries of the same logical call.

Apache-2.0.
