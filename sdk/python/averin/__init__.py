"""averin — flight recorder SDK for AI agents.

Record what your agent did — tool calls, rationale, and declared authority — to a averin server,
where it is sealed (signed + hash-linked) by the integrity core. The SDK never reimplements the
crypto; it submits records and the server seals them through the Rust core.

Quickstart:

    import averin
    fr = averin.Client("http://localhost:8080", project_id="proj-1")
    fr.record(session_id="run-42", action="db.query",
              event_type="tool_call", rationale="checking balance before transfer",
              authority={"decision_basis": "policy_allowed", "grant_type": "role"})
"""

from .client import Client, build_record

__all__ = ["Client", "build_record"]
__version__ = "0.1.0"
