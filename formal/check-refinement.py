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
CATALOGUE = ROOT / "formal" / "lean" / "Averin" / "Catalogue.lean"

# Whole-tree sweep: every averin.*.vN / flightrecorder.*.vN string literal in production code (tests
# excluded) must be a Preimage family tag or a Catalogue tag. This catches a new context introduced
# anywhere (a new sign/hash call site, a new id namespace, a new evidence domain). Files are lexed,
# not grepped: comments are dropped and every string literal ("…", '…', `…` raw/template strings) is
# searched, so a tag in a Go raw string, after a `//` inside a string ("http://x"), or in a TS/Python
# SDK is seen. A tag assembled at runtime cannot be seen by any textual check, so the sweep also
# rejects the pieces: a literal that is exactly tag-shaped but unversioned ("averin.x", unless
# UNVERSIONED_ALLOWLIST names it) or exactly a version suffix (".v1").
SWEEP_ROOTS = [
    ("core/src", "*.rs"),
    ("server/internal", "*.go"),
    ("server/cmd", "*.go"),
    ("sdk", "*.py"),
    ("sdk", "*.ts"),
    ("verifier", "*.js"),
    ("web/src", "*.ts"),
    ("web/src", "*.js"),
    ("web/src", "*.svelte"),
]
SKIP_PARTS = {"tests", "test", "testdata", "node_modules", "dist", "target"}
TAG_IN_LITERAL = re.compile(r"\b((?:averin|flightrecorder)\.[a-z0-9_]+(?:\.[a-z0-9_]+)*\.v[0-9]+)\b")
UNVERSIONED = re.compile(r"(?:averin|flightrecorder)\.[A-Za-z0-9_.]+")
VERSION_ONLY = re.compile(r"\.v[0-9]+")
UNVERSIONED_ALLOWLIST = {
    "averin.session": "OTel span attribute name (server OTel ingest), never hashed as a domain",
    "averin.event_type": "OTel span attribute name (server OTel ingest), never hashed as a domain",
    "averin.apiToken": "web UI browser-storage key, never hashed or signed",
}


def string_literals(text: str, lang: str):
    """Yield (line, literal body) for every string literal outside comments. `lang` is the file suffix.

    Handles // and /* */ comments (# in Python), backslash escapes, Go/JS backtick strings, and
    Rust/Go char literals (so '"' does not open a string; a Rust lifetime 'a is skipped)."""
    i, n, line = 0, len(text), 1
    hash_comments = lang == ".py"
    c_comments = lang != ".py"
    quotes = {'"', "`"} if lang in (".go", ".js", ".ts", ".svelte") else {'"'}
    if lang in (".py", ".js", ".ts", ".svelte"):
        quotes.add("'")
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c_comments and text.startswith("//", i) or hash_comments and c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c_comments and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
        elif c == "'" and lang in (".rs", ".go"):
            m = re.match(r"'(\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'", text[i:])
            i += m.end() if m else 1  # a char literal, or a Rust lifetime / label
        elif c in quotes:
            start_line, j, buf = line, i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and c != "`":
                    buf.append(text[j:j + 2])
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            yield start_line, "".join(buf)
            i = j + 1
        else:
            i += 1


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

ALLOWLIST: dict[str, str] = {
    # RFC 3161 tokens are parsed and verified, never produced; they carry no averin tag.
}

errors: list[str] = []

lean = {
    m.group(1): m.group(2)
    for m in re.finditer(r'def (\w+) : Family :=\s*⟨"[^"]*",\s*"([^"]+)"', PREIMAGE.read_text())
}
lean_tags = set(lean.values())
cat_block = re.search(r"def catalogueTags : List String :=(.*?)(?:\n\n|/--)", CATALOGUE.read_text(), re.S)
ns_block = re.search(r"def serverIdNamespaces : List String :=(.*?)\n\n", CATALOGUE.read_text(), re.S)
catalogue_tags = set()
for blk in (cat_block, ns_block):
    if not blk:
        errors.append(f"could not parse catalogueTags / serverIdNamespaces in {CATALOGUE}")
    else:
        catalogue_tags |= set(re.findall(r'"([^"]+)"', blk.group(1)))
lean_tags |= catalogue_tags
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

swept = 0
for root, pattern in SWEEP_ROOTS:
    base = ROOT / root
    if not base.is_dir():
        errors.append(f"sweep root {root} is missing")
        continue
    for f in sorted(base.rglob(pattern)):
        rel = f.relative_to(ROOT)
        if (f.name.endswith(("_test.go", ".test.ts", "_test.py")) or f.name.startswith("test_")
                or SKIP_PARTS & set(rel.parts)):
            continue
        for n, lit in string_literals(f.read_text(errors="replace"), f.suffix):
            for m in TAG_IN_LITERAL.finditer(lit):
                swept += 1
                rust_tags.setdefault(m.group(1), f"{rel}:{n}")
            if UNVERSIONED.fullmatch(lit) and not TAG_IN_LITERAL.fullmatch(lit) \
                    and lit not in UNVERSIONED_ALLOWLIST:
                errors.append(f"{rel}:{n}: unversioned tag-shaped literal {lit!r} (version it, or add it "
                              "to UNVERSIONED_ALLOWLIST with a reason)")
            if VERSION_ONLY.fullmatch(lit):
                errors.append(f"{rel}:{n}: bare version literal {lit!r}: tags must be written whole, "
                              "never concatenated")

for tag in sorted(catalogue_tags):
    if tag not in rust_tags:
        errors.append(f"Catalogue.lean: tag {tag!r} no longer appears in the swept code (stale model)")

for tag, where in sorted(rust_tags.items()):
    if tag not in lean_tags and tag not in ALLOWLIST:
        errors.append(f"{where}: tag {tag!r} has no Family in Preimage.lean or entry in Catalogue.lean "
                      "(add one, or allowlist it with a reason)")

for fam, tag in sorted(lean.items()):
    if tag not in rust_tags:
        errors.append(f"Preimage.lean: family {fam} tag {tag!r} is no longer used by the Rust (stale model)")

if errors:
    for e in errors:
        print(f"tag inventory: FAIL: {e}", file=sys.stderr)
    sys.exit(1)
print(f"tag inventory: OK ({len(lean)} Lean families + {len(catalogue_tags)} catalogue tags; "
      f"{len(rust_tags)} distinct tags in the code, {swept} literal sites swept)")
