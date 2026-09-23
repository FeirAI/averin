#!/usr/bin/env python3
"""Textually validate claim inventory references and recurring CI job IDs."""

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "formal/claims.json"
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def job_ids(workflow_text):
    # GitHub jobs are two-space keys under jobs:. This deliberately checks IDs,
    # not friendly names or whether GitHub branch protection requires a job.
    return set(re.findall(r"^  ([a-z][a-z0-9-]*):\s*$", workflow_text, re.M))


def check_manifest(data, root, workflow_text):
    errors = []
    if data.get("schema") != 1 or not isinstance(data.get("claims"), list) or not data["claims"]:
        return ["manifest must have schema 1 and a nonempty claims list"]
    jobs = job_ids(workflow_text)
    ids = set()
    for claim in data["claims"]:
        cid = claim.get("id", "<missing id>")
        if cid in ids:
            errors.append(f"duplicate claim id: {cid}")
        ids.add(cid)
        for field in ("claim", "class", "targets", "assumptions", "sources", "proofs", "gates"):
            if not claim.get(field):
                errors.append(f"{cid}: empty {field}")
        for gate in claim.get("gates", []):
            if gate not in jobs:
                errors.append(f"{cid}: missing CI job {gate}")
        for ref in claim.get("sources", []) + claim.get("proofs", []):
            path = (root / ref.get("file", "")).resolve()
            symbol = ref.get("symbol", "")
            if not path.is_relative_to(root) or not path.is_file():
                errors.append(f"{cid}: missing/invalid file {ref.get('file')}")
            elif not symbol or symbol not in path.read_text():
                errors.append(f"{cid}: missing symbol {symbol!r} in {ref.get('file')}")
    return errors


def main():
    data = json.loads(MANIFEST.read_text())
    errors = check_manifest(data, ROOT, WORKFLOW.read_text())
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"validated references and CI IDs for {len(data['claims'])} claims (textual check only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
