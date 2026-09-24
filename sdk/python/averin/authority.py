"""Prepare the exact semantic record an external v3 authority will inspect and sign."""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

SUBJECT_PROJECTION = "averin.authority.subject.v1"
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXTERNAL_SOURCES = {"policy_engine_signed", "human_signed", "delegate_signed"}
_PROFILE = {
    "schema_version": "2",
    "canon_version": "rcp-1",
    "domain": "flightrecorder.record.v2",
}
_DEFAULTS = {
    "agent_id": "unknown",
    "agent_version": "unknown",
    "event_type": "decision",
    "action": "",
    "observed_via": "sdk",
    "status": "ok",
}


def prepare_v3_authority_subject(record: dict[str, Any]) -> dict[str, Any]:
    """Freeze server semantic defaults before external approval.

    Give this returned structured record to the authority system for v3 signing,
    attach its ``subject_digest`` and ``evidence_sig`` to ``authority``, then pass
    the *same* record to ``Client.submit``. This helper does not hash or sign.
    ``idempotency_key`` is supplied separately to ``submit`` and is not signed.
    """
    rec = deepcopy(record)
    if "idempotency_key" in rec:
        raise ValueError("supply idempotency_key to Client.submit, outside the signed subject")
    for field in ("input", "output", "rationale"):
        if field in rec:
            raise ValueError(f"v3 requires a preapproved {field}_commit, not raw {field}")
    for field, expected in _PROFILE.items():
        if field in rec and rec[field] != expected:
            raise ValueError(f"v3 requires {field}={expected!r}")
        rec[field] = expected
    for field, value in _DEFAULTS.items():
        rec.setdefault(field, value)
    rec.setdefault("parent_span_id", None)
    for field in (
        "project_id", "record_id", "session_id", "span_id", "agent_ts",
        "agent_id", "agent_version", "event_type", "action", "observed_via", "status",
    ):
        value = rec.get(field)
        if not isinstance(value, str) or (field not in ("action",) and not value):
            raise ValueError(f"v3 requires final string {field} before signing")
    if rec["parent_span_id"] is not None and not isinstance(rec["parent_span_id"], str):
        raise ValueError("v3 parent_span_id must be a string or null")
    authority = rec.get("authority")
    if not isinstance(authority, dict) or authority.get("source") not in _EXTERNAL_SOURCES:
        raise ValueError("v3 requires a policy, human, or delegate authority block")
    if not isinstance(authority.get("evidence_hash"), str) or not _HASH.fullmatch(authority["evidence_hash"]):
        raise ValueError("v3 requires a canonical evidence_hash")
    if "subject_digest" in authority or "evidence_sig" in authority:
        raise ValueError("v3 subject must be prepared before attaching its proof")
    if authority.get("proof_version", "v3") != "v3" or authority.get("subject_projection", SUBJECT_PROJECTION) != SUBJECT_PROJECTION:
        raise ValueError("unsupported v3 authority proof profile")
    authority["proof_version"] = "v3"
    authority["subject_projection"] = SUBJECT_PROJECTION
    extensions = rec.get("extensions")
    if extensions is not None:
        if not isinstance(extensions, dict):
            raise ValueError("v3 extensions must be an object")
        if "content_preview" in extensions:
            raise ValueError("v3 requires commitments instead of raw content_preview")
        feir = extensions.get("feir_evidence")
        if feir is not None:
            if not isinstance(feir, dict):
                raise ValueError("v3 feir_evidence must be an object")
            feir["capture_authority"] = rec["observed_via"]
            feir["lineage"] = {
                "session_id": rec["session_id"],
                "span_id": rec["span_id"],
                "parent_span_id": rec["parent_span_id"],
            }
    return rec
