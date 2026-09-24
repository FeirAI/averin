import json
import re
from pathlib import Path

import averin


def test_v3_prepared_fixture_is_the_exact_submitted_semantic_record():
    fixture = json.loads((Path(__file__).resolve().parents[3] / "spec/golden-vectors/authority-sdk-v3.json").read_text())
    draft = fixture["draft_record"]
    before = json.dumps(draft, sort_keys=True)
    prepared = averin.prepare_v3_authority_subject(draft)
    assert prepared == fixture["prepared_record"]
    assert json.dumps(draft, sort_keys=True) == before
    prepared["authority"]["subject_digest"] = fixture["subject_digest"]
    prepared["authority"]["evidence_sig"] = "ed25519:external-approver-proof"
    signed_semantics = json.dumps(prepared, sort_keys=True)
    captured = {}

    def transport(_url, _headers, body):
        sent = json.loads(body)
        assert sent.pop("idempotency_key") == "sdk-v3-fixed"
        captured["sent"] = sent
        return json.dumps({"results": [{"record": {"content_hash": "sha256:sealed"}}]})

    c = averin.Client("http://localhost:8080", "p1", transport=transport)
    c.submit(prepared, idempotency_key="sdk-v3-fixed")
    assert json.dumps(captured["sent"], sort_keys=True) == signed_semantics
    assert json.dumps(prepared, sort_keys=True) == signed_semantics


def test_v3_prepare_rejects_incomplete_or_server_rewritten_subjects():
    fixture = json.loads((Path(__file__).resolve().parents[3] / "spec/golden-vectors/authority-sdk-v3.json").read_text())
    for change in (
        {"record_id": ""},
        {"agent_ts": ""},
        {"schema_version": "3"},
        {"idempotency_key": "inside-subject"},
        {"input": "raw secret"},
    ):
        draft = dict(fixture["draft_record"], **change)
        try:
            averin.prepare_v3_authority_subject(draft)
            assert False, f"accepted {change}"
        except ValueError:
            pass


def test_build_record_basics():
    rec = averin.build_record("p1", "s1", "db.query", event_type="tool_call", cost_micros_usd=18000)
    assert rec["project_id"] == "p1"
    assert rec["event_type"] == "tool_call"
    assert rec["cost_micros_usd"] == 18000
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", rec["agent_ts"])


def test_floats_and_bools_rejected_at_sdk():
    # bool is an int subclass in Python — must be rejected too
    for kwargs in ({"cost_micros_usd": 1.5}, {"tokens_in": 2.0}, {"cost_micros_usd": True}):
        try:
            averin.build_record("p", "s", "a", **kwargs)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_bad_event_type_rejected():
    try:
        averin.build_record("p", "s", "a", event_type="nonsense")
        assert False
    except ValueError:
        pass


def test_client_submits_with_idempotency_and_returns_record():
    captured = {}

    def transport(url, headers, body):
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = json.loads(body)
        # echo a server-style response
        return json.dumps({"results": [{"created": True, "record": {"content_hash": "sha256:abc", "sig": "ed25519:xyz"}}]})

    c = averin.Client("http://localhost:8080/", "p1", transport=transport)
    out = c.record("s1", "db.query", idempotency_key="fixed-key", rationale="why")

    assert captured["url"] == "http://localhost:8080/v2/records"
    assert captured["headers"]["Idempotency-Key"] == "fixed-key"
    assert captured["body"]["idempotency_key"] == "fixed-key"
    assert captured["body"]["project_id"] == "p1"
    assert captured["body"]["extensions"]["content_preview"]["rationale"] == "why"
    assert out["content_hash"] == "sha256:abc"


def test_transport_preserves_opaque_identity_for_server_validation():
    captured = {}

    def transport(_url, _headers, body):
        captured["project_id"] = json.loads(body)["project_id"]
        return json.dumps({"error": "project_id must be NFC-normalized"})

    c = averin.Client("http://x", "e\u0301", transport=transport)
    # Python SDK does not inspect server error bodies, but it must send the exact identity.
    c.record("s", "read", idempotency_key="k")
    assert captured["project_id"] == "e\u0301"


def test_auto_idempotency_key_is_unique():
    keys = set()

    def transport(url, headers, body):
        keys.add(headers["Idempotency-Key"])
        return json.dumps({"results": [{"created": True, "record": {}}]})

    c = averin.Client("http://x", "p1", transport=transport)
    c.record("s1", "a")
    c.record("s1", "a")
    assert len(keys) == 2
