#!/usr/bin/env python3
"""Textually validate claim inventory references and recurring CI job IDs."""

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "formal/claims.json"
WORKFLOW = ROOT / ".github/workflows/ci.yml"
# A symbol is matched as a substring, so a short one ("main", "check") matches almost any file and
# says nothing about the claim. Require something specific.
MIN_SYMBOL = 8


def job_ids(workflow_text):
    # GitHub jobs are two-space keys under jobs:. This deliberately checks IDs,
    # not friendly names or whether GitHub branch protection requires a job.
    return set(re.findall(r"^  ([a-z][a-z0-9-]*):\s*$", workflow_text, re.M))


def job_blocks(workflow_text):
    """Each job ID with the text of its block (up to the next job key)."""
    starts = [(m.group(1), m.start()) for m in re.finditer(r"^  ([a-z][a-z0-9-]*):\s*$", workflow_text, re.M)]
    ends = [start for _, start in starts[1:]] + [len(workflow_text)]
    return {job: workflow_text[start:end] for (job, start), end in zip(starts, ends)}


def required_jobs(workflow_text):
    """The jobs the single required check `ci-required` needs (one inline `needs: [...]` list)."""
    block = job_blocks(workflow_text).get("ci-required", "")
    m = re.search(r"^    needs:\s*\[([^\]]*)\]\s*$", block, re.M)
    if m is None:
        return None
    return {job.strip() for job in m.group(1).split(",") if job.strip()}


def scheduled_jobs(workflow_text):
    """Jobs whose own `if:` limits them to the schedule or manual dispatch."""
    return {
        job for job, block in job_blocks(workflow_text).items()
        if re.search(r"^    if:.*github\.event\.schedule", block, re.M)
    }


def check_manifest(data, root, workflow_text):
    errors = []
    if data.get("schema") != 1 or not isinstance(data.get("claims"), list) or not data["claims"]:
        return ["manifest must have schema 1 and a nonempty claims list"]
    jobs = job_ids(workflow_text)
    required = required_jobs(workflow_text)
    if required is None:
        return ["ci.yml has no ci-required job with an inline needs list"]
    scheduled = scheduled_jobs(workflow_text)
    ids = set()
    for claim in data["claims"]:
        cid = claim.get("id", "<missing id>")
        if cid in ids:
            errors.append(f"duplicate claim id: {cid}")
        ids.add(cid)
        for field in ("claim", "class", "targets", "assumptions", "sources", "proofs", "gates"):
            if not claim.get(field):
                errors.append(f"{cid}: empty {field}")
        # `gates` back the claim on every pull request: each must be a job ci-required needs.
        # `scheduled_gates` run only on the schedule or manual dispatch; they are named
        # separately so a claim never reads as gated on every change by a job that is not.
        for gate in claim.get("gates", []):
            if gate not in jobs:
                errors.append(f"{cid}: missing CI job {gate}")
            elif gate not in required:
                errors.append(f"{cid}: gate {gate} is not required by ci-required (list it under scheduled_gates if it runs only on a schedule)")
        for gate in claim.get("scheduled_gates", []):
            if gate not in jobs:
                errors.append(f"{cid}: missing CI job {gate}")
            elif gate not in scheduled or gate in required:
                errors.append(f"{cid}: scheduled gate {gate} is not a schedule-only job")
        for ref in claim.get("sources", []) + claim.get("proofs", []):
            path = (root / ref.get("file", "")).resolve()
            symbol = ref.get("symbol", "")
            if not path.is_relative_to(root) or not path.is_file():
                errors.append(f"{cid}: missing/invalid file {ref.get('file')}")
            elif len(symbol) < MIN_SYMBOL:
                errors.append(f"{cid}: symbol {symbol!r} in {ref.get('file')} is too short to identify a definition")
            elif symbol not in path.read_text():
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
