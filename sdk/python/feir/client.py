"""feir Python SDK client. Stdlib-only (urllib); the transport is injectable for testing."""

from __future__ import annotations

import json
import urllib.request
import uuid
from typing import Any, Callable, Optional

# A transport takes (url, headers, body_bytes) and returns the response body as text.
Transport = Callable[[str, dict, bytes], str]

EVENT_TYPES = {
    "llm_call",
    "tool_call",
    "decision",
    "approval_gate",
    "handoff",
    "spawn_child",
    "incomplete",
}


def _urllib_transport(url: str, headers: dict, body: bytes) -> str:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (caller-supplied URL)
        return resp.read().decode("utf-8")


def build_record(
    project_id: str,
    session_id: str,
    action: str,
    *,
    event_type: str = "tool_call",
    status: str = "ok",
    observed_via: str = "sdk",
    rationale: Optional[str] = None,
    inp: Any = None,
    output: Any = None,
    authority: Optional[dict] = None,
    cost_micros_usd: Optional[int] = None,
    tokens_in: Optional[int] = None,
    tokens_out: Optional[int] = None,
    parent_span_id: Optional[str] = None,
    framework: Optional[str] = None,
    extensions: Optional[dict] = None,
) -> dict:
    """Build the (unsealed) record body the server will seal.

    `cost_micros_usd` and token counts are integers (RCP forbids floats); a float raises ValueError
    so the mistake surfaces at the SDK, not silently at the verifier.
    """
    if event_type not in EVENT_TYPES:
        raise ValueError(f"event_type must be one of {sorted(EVENT_TYPES)}")
    for name, val in (("cost_micros_usd", cost_micros_usd), ("tokens_in", tokens_in), ("tokens_out", tokens_out)):
        # bool is an int subclass in Python — reject it explicitly so True is not sealed as 1.
        if val is not None and (isinstance(val, bool) or not isinstance(val, int)):
            raise ValueError(f"{name} must be an integer (no floats/bools in signed records)")

    rec: dict[str, Any] = {
        "project_id": project_id,
        "session_id": session_id,
        "action": action,
        "event_type": event_type,
        "status": status,
        "observed_via": observed_via,
        "agent_ts": _now_ms(),
    }
    if parent_span_id is not None:
        rec["parent_span_id"] = parent_span_id
    if cost_micros_usd is not None:
        rec["cost_micros_usd"] = cost_micros_usd
    if tokens_in is not None or tokens_out is not None:
        rec["tokens"] = {"in": tokens_in or 0, "out": tokens_out or 0}
    # Raw content is sent for the server to commit (self-host) or omitted if the caller pre-commits.
    content: dict[str, Any] = {}
    if inp is not None:
        content["input"] = inp
    if output is not None:
        content["output"] = output
    if rationale is not None:
        content["rationale"] = rationale
    if content:
        rec.setdefault("extensions", {})["content_preview"] = content
    if authority is not None:
        # source is decided by the server (never silently "verified"); we pass the declared basis.
        rec["authority"] = dict(authority)
    if framework is not None:
        rec["framework"] = framework
    if extensions is not None:
        rec.setdefault("extensions", {}).update(extensions)
    return rec


class Client:
    """A thin client that submits records to a feir server's ingestion API."""

    def __init__(
        self,
        base_url: str,
        project_id: str,
        *,
        api_key: Optional[str] = None,
        transport: Optional[Transport] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.project_id = project_id
        self.api_key = api_key
        self._transport = transport or _urllib_transport

    def record(self, session_id: str, action: str, *, idempotency_key: Optional[str] = None, **kwargs) -> dict:
        """Build, submit, and return the sealed record."""
        body = build_record(self.project_id, session_id, action, **kwargs)
        return self.submit(body, idempotency_key=idempotency_key)

    def submit(self, record_body: dict, *, idempotency_key: Optional[str] = None) -> dict:
        idem = idempotency_key or str(uuid.uuid4())
        payload = dict(record_body)
        payload["idempotency_key"] = idem
        headers = {"Content-Type": "application/json", "Idempotency-Key": idem}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = json.dumps(payload).encode("utf-8")
        resp = self._transport(f"{self.base_url}/v2/records", headers, body)
        parsed = json.loads(resp)
        results = parsed.get("results", [])
        return results[0]["record"] if results else parsed


def _now_ms() -> str:
    # RFC3339 UTC, fixed millisecond precision (matches the RCP timestamp profile). The server also
    # stamps received_ts; agent_ts here is the untrusted agent clock.
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
