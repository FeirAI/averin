#!/usr/bin/env python3
"""Generate vectors/authority-v3.v1.json: the cross-plane golden vectors for the authority proof.

averin is the verifier and the oracle: it owns the canonical form (RCP v1, formal/oracle, whose
expected bytes come from the executable Lean definitions the proofs are about) and the v3 subject
projection and signing preimage (spec/golden-vectors). govder SIGNS authority proofs, so it keeps a
byte-identical copy of this file (pinned in vectors/vectors.lock) and checks that its canonical
serializer, subject digest and v3 preimage reproduce every byte.

This script only REPACKAGES averin's own reference artifacts into one file; it computes nothing
itself, so it cannot disagree with the oracle. Python standard library only. From the repo root:
  python3 scripts/vectors/gen_authority_v3.py > vectors/authority-v3.v1.json
  python3 scripts/vectors/gen_authority_v3.py --check    # fail if the committed file is stale
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load(*parts):
    with open(os.path.join(ROOT, *parts), "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def build():
    oi, oe = load("formal", "oracle", "inputs.json"), load("formal", "oracle", "expected.json")
    canon_cases = load("spec", "golden-vectors", "canon.json")
    subj = load("spec", "golden-vectors", "authority-subject-v3.json")

    spec = [
        "canon_oracle: 'value' encodes a canonical value; an object is {\"obj\": [[key, value], ...]} with member order deliberately unsorted. Integers are JSON integers within int64 (read them exactly, not as floats). 'hex' is the canonical RCP v1 serialization produced by averin's executable Lean oracle (formal/oracle/expected.json).",
        "esc_oracle: 'cp' is a Unicode code point; 'hex' is how that character appears INSIDE a canonical string (its escaping or its UTF-8 bytes), without the surrounding quotes; a verifier checks it on the one-code-point string minus the two quote bytes.",
        "int_oracle: the canonical serialization of an integer, as hex.",
        "canon_json: 'input' is JSON text a producer parses strictly (duplicate keys and non-canonical forms are the producer's to reject); 'canonical_hex' is the canonical serialization.",
        "subject_v3: 'record' is the semantic record; subject_digest = sha256 over lp(projection) + canonical(record without the recorder envelope and the recursive proof fields); preimage_hex is the length-framed v3 signing preimage over (tag, projection, source, project_id, record_id, evidence_hash, subject_digest) with the stated inputs.",
        "A signer or verifier of the authority proof reproduces every vector byte for byte. Neither fixes policy: these vectors say nothing about which approver or which evidence an authority may use.",
    ]
    out = {
        "format": "feir.authority-v3",
        "version": 1,
        "owner": "averin",
        "generator": "scripts/vectors/gen_authority_v3.py (repackages formal/oracle and spec/golden-vectors; computes nothing)",
        "spec": spec,
        "consumers": ["govder internal/authority (CanonValue.Serialize, SubjectDigest, PreimageV3)"],
        "canon_oracle": [{"name": i["name"], "value": i["value"], "hex": e["hex"]} for i, e in zip(oi["canon"], oe["canon"])],
        "esc_oracle": [{"cp": cp, "hex": e["hex"]} for cp, e in zip(oi["esc"], oe["esc"])],
        "int_oracle": [{"int": e["int"], "hex": e["hex"]} for e in oe["ints"]],
        "canon_json": [{"name": c["name"], "input": c["input"], "canonical_hex": c["canonical_hex"]} for c in canon_cases["cases"]],
        "subject_v3": {
            "record": subj["record"],
            "source": "human_signed",
            "project_id": "p1",
            "record_id": "r1",
            "evidence_hash": subj["record"]["authority"]["evidence_hash"],
            "subject_digest": subj["subject_digest"],
            "preimage_hex": subj["preimage_hex"],
        },
    }
    return json.dumps(out, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    text = build()
    if "--check" in sys.argv:
        path = os.path.join(ROOT, "vectors", "authority-v3.v1.json")
        with open(path, "rb") as f:
            if f.read().decode("utf-8") != text:
                sys.stderr.write("vectors/authority-v3.v1.json is stale: rerun scripts/vectors/gen_authority_v3.py\n")
                sys.exit(1)
        print("ok   vectors/authority-v3.v1.json matches its sources")
    else:
        sys.stdout.write(text)
