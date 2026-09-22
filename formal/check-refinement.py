#!/usr/bin/env python3
"""Tag-string inventory: every domain-separation tag in the Rust is a family in the Lean catalogue.

Byte-level agreement between the Rust and the Lean model is NOT checked here. That is the job of the
executable Lean oracle (formal/lean/Oracle/Main.lean -> formal/oracle/expected.json, checked by
core/tests/oracle.rs) and the golden vectors. This script does the one thing a textual check is the
right tool for: an inventory of tag literals, so that

  * a tag the Rust signs or hashes under cannot exist without a `Family` in Preimage.lean
    (a new context would otherwise sit outside every domain-separation theorem), and
  * a `Family` in Preimage.lean cannot outlive the Rust tag it models (a stale model).

Structure (extend the tables, not the logic):
  NAMED_TAGS     Lean family -> (Rust file, regex capturing the constant's literal). Pins the family to
                 the exact constant the Rust uses.
  TAG_SITES      (Rust file, regex capturing a tag literal) for call sites that pass tags inline.
  ALLOWLIST      Rust tag literal -> reason it deliberately has no Lean family.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PREIMAGE = ROOT / "formal" / "lean" / "Averin" / "Preimage.lean"

NAMED_TAGS = {
    "recordSig": ("core/src/sign.rs", r'RECORD_SIG_TAG: &str = "([^"]+)"'),
    "checkpointSig": ("core/src/sign.rs", r'CHECKPOINT_SIG_TAG: &str = "([^"]+)"'),
    "authoritySig": ("core/src/authority.rs", r'AUTHORITY_SIG_TAG: &str = "([^"]+)"'),
    "testAnchorSig": ("core/src/anchor.rs", r'ANCHOR_TAG: &str = "([^"]+)"'),
    "commitment": ("core/src/commit.rs", r'COMMIT_TAG: &str = "([^"]+)"'),
    "recordHash": ("core/src/record.rs", r'RECORD_DOMAIN: &str = "([^"]+)"'),
    "checkpointHash": ("core/src/checkpoint.rs", r'CHECKPOINT_DOMAIN: &str = "([^"]+)"'),
}

TAG_SITES = [
    # Signed statements verified through sign::verify with an inline tag.
    ("core/src/verify.rs", r'crate::sign::verify\(\s*"([^"]+)"'),
    # Broker/resource challenge and hash preimages framed with lp4.
    ("core/src/verify.rs", r'lp4\(&mut \w+, b"([^"]+)"'),
    ("core/src/verify.rs", r'for part in \[\s*"([^"]+)"'),
    ("core/src/verify.rs", r'const TAG: &str = "([^"]+)"'),
]

ALLOWLIST: dict[str, str] = {}

errors: list[str] = []

lean = {
    m.group(1): m.group(2)
    for m in re.finditer(r'def (\w+) : Family :=\s*⟨"[^"]*",\s*"([^"]+)"', PREIMAGE.read_text())
}
lean_tags = set(lean.values())
if not lean:
    errors.append(f"no Family definitions found in {PREIMAGE}")

rust_tags: dict[str, str] = {}  # tag -> first place it was seen

for fam, (path, rx) in NAMED_TAGS.items():
    m = re.search(rx, (ROOT / path).read_text())
    if not m:
        errors.append(f"{path}: constant for Lean family {fam} not found ({rx})")
    elif fam not in lean:
        errors.append(f"Preimage.lean: family {fam} missing")
    elif lean[fam] != m.group(1):
        errors.append(f"{fam}: Lean tag {lean[fam]!r} != Rust {path} {m.group(1)!r}")
    else:
        rust_tags.setdefault(m.group(1), path)

for path, rx in TAG_SITES:
    for m in re.finditer(rx, (ROOT / path).read_text()):
        rust_tags.setdefault(m.group(1), path)

for tag, where in sorted(rust_tags.items()):
    if tag not in lean_tags and tag not in ALLOWLIST:
        errors.append(f"{where}: tag {tag!r} has no Family in Preimage.lean (add one, or allowlist it with a reason)")

for fam, tag in sorted(lean.items()):
    if tag not in rust_tags:
        errors.append(f"Preimage.lean: family {fam} tag {tag!r} is no longer used by the Rust (stale model)")

if errors:
    for e in errors:
        print(f"tag inventory: FAIL: {e}", file=sys.stderr)
    sys.exit(1)
print(f"tag inventory: OK ({len(lean)} Lean families, {len(rust_tags)} Rust tags)")
