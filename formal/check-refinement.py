#!/usr/bin/env python3
"""Structural Rust <-> Lean refinement gate for averin's integrity core.

The Lean kernel (formal/lean) proves properties of a *model* of the preimages, the canonical
serializer, and the DAG/chain checks. This gate keeps the model honest: it fails if the Rust source
drifts away from what the proofs are about — a tag renamed, a field added to a preimage, an escape
changed, a domain check removed. It is intentionally narrow and textual; byte-level agreement is
separately pinned by the golden vectors and the Kani harnesses (formal/run-kani.sh).
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "core" / "src"
LEAN = ROOT / "formal" / "lean" / "Averin"

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)


def read(p: Path) -> str:
    return p.read_text()


def fn_body(text: str, name: str) -> str:
    m = re.search(r"fn " + re.escape(name) + r"\b[^{]*\{", text)
    if not m:
        fail(f"could not locate Rust fn {name}")
        return ""
    i, depth = m.end(), 1
    while depth and i < len(text):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i]


preimage = read(LEAN / "Preimage.lean")
lean_families = {
    m.group(1): (m.group(2), m.group(3), m.group(4))
    for m in re.finditer(
        r'def (\w+) : Family :=\s*⟨"[^"]*",\s*"([^"]+)",\s*\[([^\]]*)\],\s*(true|false)⟩', preimage
    )
}


def lean_schema(name: str) -> list[str]:
    fields = lean_families[name][1]
    return re.findall(r"\.framed|\.fixed (\d+)", fields) and [
        "lp" if f.startswith(".framed") else "fixed" + f.split()[1]
        for f in re.findall(r"\.framed|\.fixed \d+", fields)
    ]


def rust_schema(body: str) -> list[str]:
    """Sequence of framing operations after the tag, in source order."""
    ops = []
    for m in re.finditer(r"lp4\(|lp_into\(|lp_str_into\(|be8\(|for part in \[([^\]]*)\]", body):
        if m.group(0).startswith("for part"):
            parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
            ops.extend(["lp"] * len(parts))
        elif m.group(0).startswith("be8"):
            ops.append("fixed8")
        else:
            ops.append("lp")
    # The loop body `lp4(&mut pre, part...)` itself is not an extra field.
    loop_bodies = len(re.findall(r"for part in \[[^\]]*\][^{]*\{\s*lp4\(", body))
    for _ in range(loop_bodies):
        ops.remove("lp")
    return ops[1:]  # drop the leading tag


verify = read(SRC / "verify.rs")
sign = read(SRC / "sign.rs")
record = read(SRC / "record.rs")
checkpoint = read(SRC / "checkpoint.rs")
commit = read(SRC / "commit.rs")
authority = read(SRC / "authority.rs")
anchor = read(SRC / "anchor.rs")
canon = read(SRC / "canon.rs")

# 1. Every tag / domain the Lean families use is the literal the Rust code uses.
constants = {
    "recordSig": re.search(r'RECORD_SIG_TAG: &str = "([^"]+)"', sign),
    "checkpointSig": re.search(r'CHECKPOINT_SIG_TAG: &str = "([^"]+)"', sign),
    "authoritySig": re.search(r'AUTHORITY_SIG_TAG: &str = "([^"]+)"', authority),
    "testAnchorSig": re.search(r'ANCHOR_TAG: &str = "([^"]+)"', anchor),
    "commitment": re.search(r'COMMIT_TAG: &str = "([^"]+)"', commit),
    "recordHash": re.search(r'RECORD_DOMAIN: &str = "([^"]+)"', record),
    "checkpointHash": re.search(r'CHECKPOINT_DOMAIN: &str = "([^"]+)"', checkpoint),
}
for fam, m in constants.items():
    if not m:
        fail(f"Rust constant for {fam} not found")
    elif fam not in lean_families:
        fail(f"Lean family {fam} missing")
    elif lean_families[fam][0] != m.group(1):
        fail(f"{fam}: Lean tag {lean_families[fam][0]!r} != Rust {m.group(1)!r}")

sign_verify_tags = set(re.findall(r'crate::sign::verify\("([^"]+)"', verify))
lean_tags = {v[0] for v in lean_families.values()}
for tag in sign_verify_tags:
    if tag not in lean_tags:
        fail(f"verify.rs signs/verifies under tag {tag!r} which no Lean family models")
for fam in ["taxonomySig", "revocationSig", "merkleRootSig", "attestationSig"]:
    if fam in lean_families and lean_families[fam][0] not in sign_verify_tags:
        fail(f"Lean family {fam} tag {lean_families[fam][0]!r} no longer used in verify.rs")

# 2. Challenge / hash families: tag literal and field schema match the Rust builder exactly.
builders = {
    "usePop": "use_pop_challenge",
    "cosig": "cosig_approval_challenge",
    "delegationHop": "delegation_hop_challenge",
    "introspection": "introspection_transcript_challenge",
    "federation": "federation_cert_challenge",
    "ledger": "ledger_commitment",
    "revocationLeaf": "revocation_leaf",
}
for fam, fn in builders.items():
    body = fn_body(verify, fn)
    if fam not in lean_families:
        fail(f"Lean family {fam} missing")
        continue
    tag = lean_families[fam][0]
    if f'"{tag}"' not in body:
        fail(f"{fn}: Rust tag literal differs from Lean {fam} tag {tag!r}")
    want, got = lean_schema(fam), rust_schema(body)
    if want != got:
        fail(f"{fn}: Rust field framing {got} != Lean {fam} schema {want}")

gh = fn_body(verify, "grant_head_root")
if '"averin.broker.grant_head.v1"' not in gh or "extend_from_slice(&acc)" not in gh:
    fail("grant_head_root no longer matches Lean grantHeadSeed/grantHeadStep")

# 3. Record/checkpoint hashing: preimage shape and the domain checks the seal theorem relies on.
hb = fn_body(record, "hash_body")
if not re.search(r"lp_str_into\(&mut preimage, &domain\).*lp_str_into\(&mut preimage, &canon_version\)", hb, re.S):
    fail("hash_body no longer frames LP(domain) ‖ LP(canon_version)")
if "extend_from_slice(canon.as_bytes())" not in hb:
    fail("hash_body no longer appends the unframed canonical UTF-8 bytes")
if "domain != RECORD_DOMAIN" not in fn_body(record, "verify_content_hash"):
    fail("verify_content_hash no longer pins the record domain (Seal.recordHashOf assumes it)")
if "domain != CHECKPOINT_DOMAIN" not in fn_body(checkpoint, "verify_checkpoint_sealed"):
    fail("verify_checkpoint_sealed no longer pins the checkpoint domain")
if "verify_strict" not in fn_body(sign, "verify"):
    fail("sign::verify no longer uses verify_strict")
sp = fn_body(sign, "preimage")
if "lp_str_into(&mut pre, tag)" not in sp or "extend_from_slice(content_hash.as_bytes())" not in sp:
    fail("sign.rs preimage no longer LP(tag) ‖ utf8(content_hash)")

# 4. Canonical string escaping: exactly the table Canon.escChar models.
ws = fn_body(canon, "write_string")
expected = [
    r"""'"' => out.push_str("\\\"")""",
    r"""'\\' => out.push_str("\\\\")""",
    r"""'\u{08}' => out.push_str("\\b")""",
    r"""'\u{09}' => out.push_str("\\t")""",
    r"""'\u{0A}' => out.push_str("\\n")""",
    r"""'\u{0C}' => out.push_str("\\f")""",
    r"""'\u{0D}' => out.push_str("\\r")""",
    r"""c if (c as u32) < 0x20 =>""",
    r"""out.push_str("\\u00")""",
]
for e in expected:
    if e not in ws:
        fail(f"write_string escape table drifted from Canon.escChar (missing {e!r})")
if "Int(n) => out.push_str(&n.to_string())" not in canon:
    fail("integer serialization no longer i64::to_string (Canon.serInt models shortest decimal)")
if "utf16_cmp" not in fn_body(canon, "write"):
    fail("object members are no longer sorted by utf16_cmp before writing")

# 5. DAG / chain checks the Lean theorems take as hypotheses.
dag = read(SRC / "dag.rs")
if "MissingParent" not in fn_body(dag, "build") or "Cycle" not in fn_body(dag, "build"):
    fail("dag::build no longer rejects missing parents and cycles (Dag.ParentsResolve/Acyclic)")
vc = fn_body(checkpoint, "validate_chain")
for needle, what in [("FirstSeqNotZero", "seq 0 start"), ("FirstPrevNotNull", "null prev at seq 0"),
                     ("SeqGap", "gap-free seq"), ("PrevHashMismatch", "prev hash link"),
                     ("FrontierMemberMissing", "frontier presence"),
                     ("LatestFrontierMismatch", "latest frontier == heads")]:
    if needle not in vc:
        fail(f"validate_chain no longer checks {what} ({needle}) — Chain.Valid / Dag.bundle_eq_closure assume it")

if errors:
    for e in errors:
        print(f"refinement check: FAIL: {e}", file=sys.stderr)
    sys.exit(1)
print(f"refinement check: OK ({len(lean_families)} preimage families, escape table, DAG/chain checks)")
