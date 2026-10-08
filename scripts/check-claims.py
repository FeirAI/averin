#!/usr/bin/env python3
"""Textually validate claim inventory references and recurring CI job IDs."""

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "formal/claims.json"
WORKFLOW = ROOT / ".github/workflows/ci.yml"
KIT_REGISTER = ROOT / "formal/kit-claims.json"
# A symbol is matched as a substring, so a short one ("main", "check") matches almost any file and
# says nothing about the claim. Require something specific.
MIN_SYMBOL = 8
# Files and directories scanned for overclaim phrases.
COPY_PATHS = ["docs", "formal/README.md", "formal/claims.json", "README.md"]
RUN_ID = re.compile(r"[0-9]{6,}")

# Phrases that overstate what the evidence is. Each entry: (regex, text that excuses the sentence or None, why).
# A sentence containing the regex is an error unless it also matches the excuse.
OVERCLAIMS = [
    (re.compile(r"verified on the final source", re.I), None,
     "evidence of record is a named CI run, not a claim about a 'final source'"),
    (re.compile(r"confirmed on final source", re.I), None,
     "evidence of record is a named CI run, not a claim about a 'final source'"),
    (re.compile(r"\b48\s*/\s*48\b"), re.compile(r"CI run|/actions/runs/|run [0-9]{6,}", re.I),
     "'48/48' must sit in a sentence that names the CI run it came from"),
    (re.compile(r"(?=.*\b(?:DAG|chain|anchor))(?=.*proven by (?:the )?decision-core)", re.I | re.S), None,
     "decision-core is checked by tests and Kani harnesses, not proven; DAG, chain and anchor properties are Lean model theorems"),
]


def jobs_section(workflow_text):
    """The text after the top-level `jobs:` key (two-space keys elsewhere, such as `on:` triggers, are not jobs)."""
    m = re.search(r"^jobs:\s*$", workflow_text, re.M)
    return workflow_text[m.end():] if m else ""


def job_ids(workflow_text):
    # GitHub jobs are two-space keys under jobs:. This deliberately checks IDs,
    # not friendly names or whether GitHub branch protection requires a job.
    return set(re.findall(r"^  ([a-z][a-z0-9-]*):\s*$", jobs_section(workflow_text), re.M))


def job_blocks(workflow_text):
    """Each job ID with the text of its block (up to the next job key)."""
    workflow_text = jobs_section(workflow_text)
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


def unconditional_jobs(workflow_text):
    """Jobs with no job-level `if:` (excluding the aggregator): they run on every event."""
    return {
        job for job, block in job_blocks(workflow_text).items()
        if job != "ci-required" and not re.search(r"^    if:", block, re.M)
    }


def copy_files(root):
    for entry in COPY_PATHS:
        path = root / entry
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.is_file() and p.suffix in {".md", ".json", ".txt"})
        elif path.is_file():
            yield path


def check_copy(text, name):
    """Overclaim phrases in one document; a sentence is a blank-line or sentence-end delimited span."""
    errors = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n\s*\n", text):
        for pattern, excuse, why in OVERCLAIMS:
            if pattern.search(sentence) and not (excuse and excuse.search(sentence)):
                errors.append(f"{name}: overclaim phrase {pattern.pattern!r}: {why}")
    return errors


def check_copy_tree(root):
    errors = []
    for path in copy_files(root):
        errors += check_copy(path.read_text(errors="replace"), str(path.relative_to(root)))
    return errors


def check_manifest(data, root, workflow_text):
    errors = []
    if data.get("schema") != 1 or not isinstance(data.get("claims"), list) or not data["claims"]:
        return ["manifest must have schema 1 and a nonempty claims list"]
    jobs = job_ids(workflow_text)
    required = required_jobs(workflow_text)
    if required is None:
        return ["ci.yml has no ci-required job with an inline needs list"]
    scheduled = scheduled_jobs(workflow_text)
    unconditional = unconditional_jobs(workflow_text)
    if unconditional != required:
        only_run = sorted(unconditional - required)
        only_need = sorted(required - unconditional)
        errors.append(
            "ci-required needs must equal the jobs with no job-level if: "
            f"(run on every event but not needed: {only_run}; needed but conditional or missing: {only_need})")
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
        for field, kind in (("evidence_run", "gates"), ("scheduled_evidence_run", "scheduled_gates")):
            if field in claim:
                if not isinstance(claim[field], str) or not RUN_ID.fullmatch(claim[field]):
                    errors.append(f"{cid}: {field} must be a GitHub Actions run id (digits)")
                elif not claim.get(kind):
                    errors.append(f"{cid}: {field} is set but the claim has no {kind}")
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


def check_kit_register(kit, legacy_ids):
    """Each kit claim must name the legacy claim it backs, so the two registers cannot drift apart."""
    errors = []
    for claim in kit.get("claims", []):
        cid = claim.get("id", "<missing id>")
        m = re.fullmatch(r"legacy register: ([a-z0-9-]+)", claim.get("$comment", ""))
        if m is None:
            errors.append(f"kit claim {cid}: $comment must read 'legacy register: <claim id>'")
        elif m.group(1) not in legacy_ids:
            errors.append(f"kit claim {cid}: legacy claim {m.group(1)!r} is not in formal/claims.json")
    return errors


def main():
    data = json.loads(MANIFEST.read_text())
    errors = check_manifest(data, ROOT, WORKFLOW.read_text()) + check_copy_tree(ROOT)
    if KIT_REGISTER.is_file():
        errors += check_kit_register(json.loads(KIT_REGISTER.read_text()), {c["id"] for c in data["claims"]})
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"validated references and CI IDs for {len(data['claims'])} claims (textual check only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
