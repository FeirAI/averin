#!/usr/bin/env python3
"""Generate vectors/approver-evidence.v1.json: golden vectors for approver identity in signed evidence.

govder signs the authority evidence of a sealed record; averin's verifier re-derives that evidence
from the record's own fields and refuses a record whose signed evidence_hash does not match
(core/src/verify.rs govder_evidence_rederivable). For an approval record the evidence now
commits to `decided_by` and `sign_offs_digest` (XV-11). This file pins the exact evidence bytes
and hashes both sides must reproduce.

This is an INDEPENDENT reference: Python standard library only, written from the RCP v1 text rules
(sorted keys by UTF-16 code unit, minimal string escapes, raw UTF-8 for everything else, NFC),
sharing no code with govder's Go canonicalizer or averin's Rust one.

  python3 scripts/vectors/gen_approver_evidence.py > vectors/approver-evidence.v1.json
  python3 scripts/vectors/gen_approver_evidence.py --check    # fail if the committed file is stale
Then update vectors/vectors.lock and copy the file byte for byte into govder (whose lock pins the
same sha256).
"""
import hashlib
import json
import os
import sys
import unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SPEC = [
    "evidence = the RCP v1 canonical object over: event_type (= extensions.govder.type), event_id, agent_id (= record agent_id, may be empty), tenant_id (= record project_id), outcome, occurred_at; plus the OPTIONAL members below, each present only when it applies.",
    "previous_parent_id / attempted_new_parent_id / reverted_to_parent_id: body.<key> when a non-empty string.",
    "decided_by: body.decided_by verbatim when a non-empty string.",
    "sign_offs_digest: 'sha256:' + lowercase hex of sha256(RCP serialization of body.sign_offs), included when body.sign_offs is a non-empty array. The array keeps the order it was sealed in; each element is canonicalized as it appears.",
    "evidence_hash = 'sha256:' + lowercase hex of sha256(evidence serialization).",
    "RCP v1: object keys sorted by UTF-16 code unit after NFC; no whitespace; strings escape only the quote, the backslash and U+0000..U+001F (short forms \\b \\t \\n \\f \\r, else \\u00xx lowercase); every other character is emitted as raw UTF-8 after NFC; integers are plain decimal.",
    "A verifier that reproduces evidence_hash from the record's own fields and a signer that commits to the same bytes are bound to the same approver names. These vectors say nothing about whether the named subjects are humans, are authenticated, or are recent.",
]


def nfc(s):
    return unicodedata.normalize("NFC", s)


def esc(s):
    out = ['"']
    for ch in nfc(s):
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canon(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return esc(v)
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: nfc(k).encode("utf-16-be"))
        return "{" + ",".join(esc(k) + ":" + canon(v[k]) for k in keys) + "}"
    raise TypeError(type(v))


def sha(s):
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def so(identity, kind="human", cls="teammate", grant="", controller="", approve=True):
    return {"identity": identity, "kind": kind, "class": cls, "grant_ref": grant,
            "controller": controller, "approve": approve}


def evidence_for(c):
    ev = {
        "event_type": c["event_type"], "event_id": c["event_id"], "agent_id": c["agent_id"],
        "tenant_id": c["tenant_id"], "outcome": c["outcome"], "occurred_at": c["occurred_at"],
    }
    body = c.get("body", {})
    for k in ("previous_parent_id", "attempted_new_parent_id", "reverted_to_parent_id", "decided_by"):
        if isinstance(body.get(k), str) and body[k] != "":
            ev[k] = body[k]
    digest = None
    if isinstance(body.get("sign_offs"), list) and body["sign_offs"]:
        digest = sha(canon(body["sign_offs"]))
        ev["sign_offs_digest"] = digest
    text = canon(ev)
    return text, sha(text), digest


def case(name, note, event_id, body, agent="agent-7", outcome="ok", tenant="acme"):
    c = {"name": name, "note": note, "event_type": "approval", "event_id": event_id,
         "agent_id": agent, "tenant_id": tenant, "outcome": outcome,
         "occurred_at": "2026-10-10T12:00:00.000Z", "body": body}
    text, h, d = evidence_for(c)
    c["evidence_canonical"] = text
    c["evidence_hash"] = h
    c["sign_offs_digest"] = d
    return c


def build():
    two = [so("alice@acme.test"), so("bob@acme.test")]
    base = {"approval_id": "appr-1", "status": "approved", "owner": "owner-1", "credential": "cred-1",
            "action": "money.refund"}
    cases = [
        case("single-approver", "one approver, no recipe: decided_by only", "ev-appr-1-approved",
             dict(base, decided_by="alice@acme.test")),
        case("two-person-recipe-row-0", "founder sentence: two distinct approvers, row 0 of the set", "ev-appr-1-approved-signoff-0",
             dict(base, decided_by="bob@acme.test", sign_offs=two, sign_off_index=0, sign_off_kind="human",
                  sign_off_class="teammate", sign_off_grantid="")),
        case("two-person-recipe-row-1", "same set, row 1: the evidence differs only by event_id", "ev-appr-1-approved-signoff-1",
             dict(base, decided_by="bob@acme.test", sign_offs=two, sign_off_index=1, sign_off_kind="human",
                  sign_off_class="teammate", sign_off_grantid="")),
        case("order-matters", "the same two approvers in the other order give a different digest", "ev-appr-1-approved-signoff-0",
             dict(base, decided_by="bob@acme.test", sign_offs=list(reversed(two)))),
        case("unicode-identity", "identities are NFC-normalized and emitted as raw UTF-8", "ev-appr-2-approved",
             dict(base, decided_by="Amélie@acme.test", sign_offs=[so("Amélie@acme.test"), so("Zoë@acme.test")])),
        case("denied", "a denial binds who denied it", "ev-appr-3-denied",
             dict(base, status="denied", decided_by="carol@acme.test"), outcome="blocked"),
        case("pending-no-decider", "a pending approval has no decided_by and no sign-offs: the evidence is the legacy field set",
             "ev-appr-4-pending", dict(base, status="pending", decided_by="")),
    ]
    return {
        "format": "feir.approver-evidence",
        "version": 1,
        "owner": "averin",
        "generator": "scripts/vectors/gen_approver_evidence.py (independent RCP v1 reference, Python standard library only)",
        "spec": SPEC,
        "consumers": ["govder internal/averin (evidenceForRecordV3)", "averin core/src/verify.rs (govder_evidence_rederivable)"],
        "cases": cases,
    }


def main():
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        path = os.path.join(ROOT, "vectors", "approver-evidence.v1.json")
        with open(path, "rb") as f:
            have = f.read().decode("utf-8")
        if have != text:
            sys.stderr.write("vectors/approver-evidence.v1.json is stale; regenerate it\n")
            return 1
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
