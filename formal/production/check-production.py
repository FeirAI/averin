#!/usr/bin/env python3
"""Toolchain-free checks for the production refinement (formal/production, plan 012).

  python3 formal/production/check-production.py             # all checks below
  python3 formal/production/check-production.py --glue DIR  # also: DIR's *_Template.lean externals
  python3 formal/production/check-production.py --no-stale  # skip 1 (used before regeneration)
  python3 formal/production/check-production.py --update-hashes
  python3 formal/production/check-production.py --self-test  # the cfg filter's accepted/rejected forms

1. stale: the recorded sha256 of every extracted source file and of the committed generated Lean
   match the checkout. Any edit to the extracted Rust must be followed by a regeneration
   (run-production-refinement.sh --write), which re-proves everything.
2. call-path: each production entry point in manifest.json calls the extracted, proved function
   (exact body, or required fragments), and every proved function is defined exactly once.
3. cfg: the extracted source files contain no cfg-selected code other than `#[cfg(test)]`,
   `#[cfg(kani)]` and `#[cfg(any(kani, test))]` items, so no feature selection can swap in
   unproved code (`--self-test` checks the accepted and rejected forms).
4. glue: Extracted/{Types,Funs}External.lean define exactly the externals the manifest lists, the
   generated files contain no `sorry`/`axiom`, and (with --glue) Aeneas requested exactly those.

Every failure prints `production refinement: FAIL (<reason>): ...` with reason stale | call-path |
cfg | glue, which formal/check-mutants.sh uses as the named detector.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROD = ROOT / "formal" / "production"
MANIFEST = PROD / "manifest.json"


def fail(reason: str, msg: str) -> None:
    print(f"production refinement: FAIL ({reason}): {msg}")
    sys.exit(1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fn_body(src: str, name: str) -> tuple[str, int]:
    """Body of `fn name` (between its outermost braces) and the number of definitions."""
    pat = re.compile(rf"(?m)^\s*(?:pub(?:\([a-z]+\))?\s+)?fn\s+{re.escape(name)}\b")
    matches = list(pat.finditer(src))
    if not matches:
        return "", 0
    start = src.index("{", matches[0].end())
    depth, i = 0, start
    while True:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return src[start + 1 : i], len(matches)


def norm(s: str) -> str:
    s = re.sub(r"//[^\n]*", "", s)
    return re.sub(r"\s+", " ", s).strip()


def check_stale(m: dict) -> None:
    for rel, want in m["sources"].items():
        got = sha256(ROOT / rel)
        if got != want:
            fail("stale", f"{rel} changed (sha256 {got}, manifest {want}); regenerate and re-prove "
                 "with `bash formal/run-production-refinement.sh --write`")


def check_callers(m: dict) -> None:
    for c in m["callers"]:
        src = (ROOT / c["file"]).read_text()
        body, n = fn_body(src, c["fn"])
        if n != 1:
            fail("call-path", f"{c['file']}: expected exactly one `fn {c['fn']}`, found {n}")
        b = norm(body)
        if "body" in c and b != norm(c["body"]):
            fail("call-path", f"{c['file']}::{c['fn']} no longer delegates to the proved code: {b!r}")
        for frag in c.get("contains", []):
            if norm(frag) not in b:
                fail("call-path", f"{c['file']}::{c['fn']} does not contain {frag!r}")
        # whole-file occurrence counts (comments stripped), e.g. the only write of the claims
        whole = norm(src)
        for pattern, want in c.get("file_counts", {}).items():
            got = len(re.findall(pattern, whole))
            if got != want:
                fail("call-path", f"{c['file']}: /{pattern}/ occurs {got} times, expected {want}")
    # every extracted function is defined once in its module, not also elsewhere under another cfg
    for sym in m["extracted"]:
        *mods, name = sym.split("::")
        rel = "core/src/" + "/".join(mods) + ".rs"
        src = (ROOT / rel).read_text()
        _, n = fn_body(src, name)
        if n != 1:
            fail("call-path", f"{rel}: expected exactly one `fn {name}`, found {n}")


# The only cfg attributes an extracted file may carry: test-only and proof-only items, which the
# production build never compiles. Anything else (a feature, a target, `not(..)`) could select code
# the proofs never saw.
ALLOWED_CFG = ("#[cfg(test)]", "#[cfg(kani)]", "#[cfg(any(kani, test))]")


def cfg_violation(line: str) -> str | None:
    """Why `line` (one source line) is cfg-selected production code, or None."""
    s = line.strip()
    if s.startswith("//"):
        return None
    if "cfg!(" in s or "cfg_attr" in s:
        return "cfg-selected code in an extracted file"
    if s.startswith("#[cfg") and s not in ALLOWED_CFG:
        return "only " + ", ".join(ALLOWED_CFG) + " items are allowed"
    return None


def check_cfg(m: dict) -> None:
    files = {k for k in m["sources"] if k.startswith("core/src/")}
    for rel in sorted(files):
        for ln, line in enumerate((ROOT / rel).read_text().splitlines(), 1):
            why = cfg_violation(line)
            if why:
                fail("cfg", f"{rel}:{ln}: `{line.strip()}` ({why})")


def self_test() -> None:
    ok = ["#[cfg(test)]", "#[cfg(kani)]", "#[cfg(any(kani, test))]", "    #[cfg(test)]",
          "// #[cfg(feature = \"x\")] in a comment", "let x = 1;"]
    bad = ["#[cfg(feature = \"x\")]", "#[cfg(any(kani, feature = \"x\"))]", "#[cfg(not(test))]",
           "#[cfg(any(test, kani))]", "#[cfg(all(kani, test))]", "#[cfg(target_arch = \"wasm32\")]",
           "#[cfg_attr(test, derive(Debug))]", "if cfg!(debug_assertions) {", "#[cfg(any(kani,test))]"]
    for s in ok:
        if cfg_violation(s):
            fail("cfg", f"self-test: accepted form rejected: {s!r}")
    for s in bad:
        if not cfg_violation(s):
            fail("cfg", f"self-test: feature/target-selected form accepted: {s!r}")
    print("production refinement: cfg self-test OK")


def defined_names(text: str) -> set[str]:
    return set(re.findall(r"(?m)^(?:noncomputable\s+)?(?:def|axiom|opaque)\s+([A-Za-z0-9_.]+)", text))


def check_glue(m: dict, template_dir: Path | None) -> None:
    ext = m["aeneas"]["externals"]
    funs = defined_names((PROD / "Extracted" / "FunsExternal.lean").read_text())
    types = defined_names((PROD / "Extracted" / "TypesExternal.lean").read_text())
    want_funs = set(ext["funs"])
    if not want_funs <= funs:
        fail("glue", f"FunsExternal.lean lacks {sorted(want_funs - funs)}")
    # the helpers the glue defines besides the requested externals (names as written, inside
    # `namespace AverinTrusted` / `namespace AverinGlue`)
    extra = funs - want_funs - {"averin_decision_core.toStr", "nfc", "sha256", "u8OfUInt8",
                                "uint8OfU8", "stringBytes", "stringSlice"}
    if extra:
        fail("glue", f"FunsExternal.lean defines unlisted names {sorted(extra)}")
    if types != set(ext["types"]):
        fail("glue", f"TypesExternal.lean defines {sorted(types)}, manifest {sorted(ext['types'])}")
    axioms = set(re.findall(r"(?m)^axiom\s+([A-Za-z0-9_.]+)",
                            (PROD / "Extracted" / "FunsExternal.lean").read_text()))
    if axioms != {"nfc", "sha256"}:
        fail("glue", f"FunsExternal.lean declares axioms {sorted(axioms)} (only the two trusted primitives)")
    for rel in m["aeneas"]["generated"]:
        text = (PROD / rel).read_text()
        for bad in ("sorry", "axiom ", "native_decide", "implemented_by", "@[extern"):
            if bad in text:
                fail("glue", f"{rel} contains `{bad}`")
    if template_dir is not None:
        req_funs: set[str] = set()
        req_types: set[str] = set()
        for f, acc in (("FunsExternal_Template.lean", req_funs), ("TypesExternal_Template.lean", req_types)):
            p = template_dir / f
            if p.exists():
                acc |= set(re.findall(r"(?m)^axiom\s*\n?\s*([A-Za-z0-9_.]+)", p.read_text()))
        if req_funs != want_funs:
            fail("glue", f"Aeneas requests external functions {sorted(req_funs)}, manifest {sorted(want_funs)}")
        if req_types != set(ext["types"]):
            fail("glue", f"Aeneas requests external types {sorted(req_types)}, manifest {sorted(ext['types'])}")


def main() -> int:
    m = json.loads(MANIFEST.read_text())
    args = sys.argv[1:]
    if args[:1] == ["--self-test"]:
        self_test()
        return 0
    if args[:1] == ["--update-hashes"]:
        for rel in m["sources"]:
            m["sources"][rel] = sha256(ROOT / rel)
        MANIFEST.write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n")
        print("production refinement: source hashes updated")
        return 0
    template_dir = Path(args[args.index("--glue") + 1]) if "--glue" in args else None
    check_cfg(m)
    check_callers(m)
    check_glue(m, template_dir)
    if "--no-stale" in args:
        print("production refinement: checks OK (call-path, cfg, glue)")
        return 0
    check_stale(m)
    print("production refinement: checks OK (stale, call-path, cfg, glue)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
