#!/usr/bin/env python3
"""Toolchain-free checks for the production refinement (formal/production, plan 012).

  python3 formal/production/check-production.py             # all checks below
  python3 formal/production/check-production.py --glue DIR  # also: DIR's *_Template.lean externals
  python3 formal/production/check-production.py --no-stale  # skip 1 (used before regeneration)
  python3 formal/production/check-production.py --update-hashes
  python3 formal/production/check-production.py --self-test  # the cfg and glue scanners' accepted/rejected forms

1. stale: the recorded sha256 of every extracted source file, of the committed generated Lean and
   of the hand-written glue (Extracted/{Types,Funs}External.lean) match the checkout. Any edit to
   the extracted Rust must be followed by a regeneration (run-production-refinement.sh --write),
   which re-proves everything; a glue edit is visible as a manifest change.
2. call-path: each production entry point in manifest.json calls the extracted, proved function
   (exact body, or required fragments), and every proved function is defined exactly once.
3. cfg: every crate file the extraction came from (Aeneas `Source:` headers) is listed and hashed;
   those files contain no cfg-selected code other than `#[cfg(test)]`, `#[cfg(kani)]` and
   `#[cfg(any(kani, test))]` items, wherever on a line an attribute sits (comments and string
   literals are ignored; any `cfg_attr`, inner `#![cfg..]` or `cfg!(..)` fails); every file that
   declares a module on the extracted path (core/src/lib.rs, core/src/verify.rs) declares it once,
   with no cfg/cfg_attr/path attribute, and carries no inner cfg other than the Kani-only
   `#![cfg_attr(kani, feature(allocator_api))]`; and a feature-gated module (rfc3161) is not named
   by extracted production code. So no feature selection can swap in unproved code
   (`--self-test` checks the accepted and rejected forms).
4. glue: Extracted/{Types,Funs}External.lean define exactly the externals the manifest lists
   (every def/abbrev/instance/axiom/opaque/theorem/structure form, with attributes and
   modifiers), use no notation/macro/attribute/elaboration commands, the generated files contain
   no `sorry`/`axiom`, and (with --glue) Aeneas requested exactly those.

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
# the proofs never saw. Compared with all whitespace removed; any other spelling fails closed.
ALLOWED_CFG = ("#[cfg(test)]", "#[cfg(kani)]", "#[cfg(any(kani, test))]")
_ALLOWED_CFG_NORM = {re.sub(r"\s+", "", a) for a in ALLOWED_CFG}
# Crate-level attributes a declaring file (lib.rs) may carry: Kani-only compiler features.
ALLOWED_INNER = ("#![cfg_attr(kani, feature(allocator_api))]",)
_ALLOWED_INNER_NORM = {re.sub(r"\s+", "", a) for a in ALLOWED_INNER}


def rust_code(src: str) -> str:
    """`src` with comments and string/char literal contents blanked (newlines kept), so attribute
    and `mod` scans see code only, wherever on a line it sits."""
    out = list(src)
    i, n = 0, len(src)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif re.match(r'b?r#*"', src[i:i + 40]) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r'(b?r)(#*)"', src[i:])
            close = '"' + m.group(2)
            j = src.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            blank(i + 1, j - 1)
            i = j
        elif c == '"' or (c == "b" and src.startswith('b"', i) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        elif c == "'":
            m = re.match(r"'(\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])'", src[i:])
            if m:  # a char literal; otherwise a lifetime or label
                blank(i + 1, i + m.end() - 1)
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def _attr_end(code: str, start: int) -> int:
    """Index just past the `]` that closes the attribute opening at `start` (`#[` or `#![`)."""
    depth, j = 0, code.index("[", start)
    while j < len(code):
        if code[j] in "[(":
            depth += 1
        elif code[j] in "])":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(code)


ATTR = re.compile(r"#\s*(!)?\s*\[")


def attributes(code: str, src: str | None = None):
    """(line, inner, normalized text, source text) of every attribute in blanked `code` (offsets
    equal those of `src`), wherever it starts on a line."""
    for m in ATTR.finditer(code):
        end = _attr_end(code, m.start())
        yield (code.count("\n", 0, m.start()) + 1, bool(m.group(1)), code[m.start():end],
               (src if src is not None else code)[m.start():end])


def cfg_violations(src: str, declaring: bool = False) -> list[tuple[int, str, str]]:
    """Why each cfg-selected construct of `src` could select production code the proofs did not
    see: outer `#[cfg(..)]` other than the test/proof-only forms, any `cfg_attr` (it can attach a
    `cfg` or `path`), any inner `#![cfg..]` (it gates the whole module) and any `cfg!(..)`. In a
    declaring file (`declaring=True`, e.g. lib.rs) the allowlisted crate-level Kani attribute is
    accepted too."""
    code = rust_code(src)
    bad = []
    for line, inner, blanked, text in attributes(code, src):
        norm = re.sub(r"\s+", "", blanked)
        head = re.match(r"#!?\[(\w+)", norm)
        name = head.group(1) if head else ""
        if name not in ("cfg", "cfg_attr"):
            continue
        if inner:
            if declaring and norm in _ALLOWED_INNER_NORM:
                continue
            bad.append((line, text, "an inner cfg attribute gates the whole module"))
        elif name == "cfg_attr":
            bad.append((line, text, "cfg_attr can attach cfg/path selections"))
        elif norm not in _ALLOWED_CFG_NORM:
            bad.append((line, text, "only " + ", ".join(ALLOWED_CFG) + " items are allowed"))
    for m in re.finditer(r"\bcfg\s*!\s*\(", code):
        bad.append((code.count("\n", 0, m.start()) + 1, "cfg!(..)", "cfg-selected code in an extracted file"))
    return bad


def cfg_violation(line: str) -> str | None:
    """Why the single source line `line` is cfg-selected production code, or None (self-test API)."""
    v = cfg_violations(line)
    return v[0][2] if v else None


def mod_decl_violations(src: str, mod: str) -> list[str]:
    """In a declaring file, the declaration of extracted module `mod` must be exactly one plain
    `mod mod;`/`mod mod {..}` with no cfg, cfg_attr or path attribute (which could swap in another
    file or drop it), and the file must have no inner cfg (checked by cfg_violations)."""
    code = rust_code(src)
    decls = list(re.finditer(rf"(?:\bpub(?:\s*\([^)]*\))?\s+)?\bmod\s+{re.escape(mod)}\b", code))
    if len(decls) != 1:
        return [f"expected exactly one `mod {mod}` declaration, found {len(decls)}"]
    # walk back over the attributes immediately preceding the declaration
    head = code[: decls[0].start()].rstrip()
    bad = []
    while head.endswith("]"):
        opens = [m.start() for m in ATTR.finditer(head) if _attr_end(head, m.start()) == len(head)]
        if not opens:
            break
        text = src[opens[-1]:len(head)]
        name = re.match(r"#!?\[(\w+)", re.sub(r"\s+", "", text))
        if name and name.group(1) in ("cfg", "cfg_attr", "path"):
            bad.append(f"`mod {mod}` carries `{text.strip()}`")
        head = head[: opens[-1]].rstrip()
    return bad


def extraction_sources() -> set[str]:
    """The crate files Aeneas says the committed extraction came from (`Source: '...'` headers)."""
    found: set[str] = set()
    for f in ("Types.lean", "Funs.lean"):
        found |= set(re.findall(r"Source: '(core/src/[^']+)'", (PROD / "Extracted" / f).read_text()))
    return found


def declaring_files(m: dict) -> dict[str, set[str]]:
    """{declaring file: {extracted module names it declares}} for every module on the extracted
    path (`a::b::f` is declared as `mod a` in lib.rs and `mod b` in a.rs or a/mod.rs)."""
    decl: dict[str, set[str]] = {}
    for sym in m["extracted"]:
        mods = sym.split("::")[:-1]
        for k, name in enumerate(mods):
            parent = mods[:k]
            if not parent:
                rel = "core/src/lib.rs"
            else:
                rel = "core/src/" + "/".join(parent) + ".rs"
                if not (ROOT / rel).exists():
                    rel = "core/src/" + "/".join(parent) + "/mod.rs"
            decl.setdefault(rel, set()).add(name)
    return decl


def check_cfg(m: dict) -> None:
    files = {k for k in m["sources"] if k.startswith("core/src/")}
    # Every crate file the committed extraction was generated from must be hashed and cfg-checked.
    unlisted = extraction_sources() - files
    if unlisted:
        fail("cfg", f"the extraction comes from files the manifest does not list: {sorted(unlisted)}")
    for rel in sorted(files):
        for ln, text, why in cfg_violations((ROOT / rel).read_text()):
            fail("cfg", f"{rel}:{ln}: `{text.strip()}` ({why})")
    for rel, mods in sorted(declaring_files(m).items()):
        src = (ROOT / rel).read_text()
        for ln, text, why in cfg_violations(src, declaring=True):
            if rel in files or text.lstrip().startswith("#!") or text.lstrip().startswith("# !"):
                fail("cfg", f"{rel}:{ln}: `{text.strip()}` ({why})")
        for mod in sorted(mods):
            for why in mod_decl_violations(src, mod):
                fail("cfg", f"{rel}: {why}")
    # A feature-gated module (rfc3161) is allowed only off the extracted path: no extracted or
    # declaring file names it outside cfg(test)/cfg(kani) code, so enabling the feature cannot
    # change an extracted item (the extraction itself uses default features).
    lib = rust_code((ROOT / "core/src/lib.rs").read_text())
    for fm in re.finditer(r"#\s*\[\s*cfg\s*\(\s*feature\s*=\s*\"?\s*\"?[^\]]*\]\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(\w+)", lib):
        gated = fm.group(1)
        if gated in declaring_files(m).get("core/src/lib.rs", set()):
            fail("cfg", f"core/src/lib.rs: extracted module `{gated}` is feature-gated")
        for rel in sorted(files):
            code = production_code(rust_code((ROOT / rel).read_text()))
            if re.search(rf"\b{gated}\s*::", code):
                fail("cfg", f"{rel} names the feature-gated module `{gated}` on the extracted path")


def production_code(code: str) -> str:
    """Blanked code with every `#[cfg(test)]`/`#[cfg(kani)]`/`#[cfg(any(kani, test))]` item removed
    (the attribute, then the item up to its closing `;` or balanced `}`)."""
    out = list(code)
    for m in ATTR.finditer(code):
        end = _attr_end(code, m.start())
        if re.sub(r"\s+", "", code[m.start():end]) not in _ALLOWED_CFG_NORM:
            continue
        j, depth = end, 0
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            elif code[j] == ";" and depth == 0:
                j += 1
                break
            j += 1
        for k in range(m.start(), j):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def self_test() -> None:
    ok = ["#[cfg(test)]", "#[cfg(kani)]", "#[cfg(any(kani, test))]", "    #[cfg(test)]",
          "#[cfg(any(kani,test))]", "// #[cfg(feature = \"x\")] in a comment", "let x = 1;",
          "let s = \"#[cfg(feature = \\\"x\\\")]\";", "let r = r#\"cfg!(x) #![cfg(y)]\"#;",
          "/* #[cfg(feature = \"x\")] */ fn f() {}", "fn f<'a>(x: &'a str) -> char { '#' }",
          "#[derive(Debug)] struct S;", "#[inline] fn f() {}"]
    bad = ["#[cfg(feature = \"x\")]", "#[cfg(any(kani, feature = \"x\"))]", "#[cfg(not(test))]",
           "#[cfg(any(test, kani))]", "#[cfg(all(kani, test))]", "#[cfg(target_arch = \"wasm32\")]",
           "#[cfg_attr(test, derive(Debug))]", "if cfg!(debug_assertions) {", "#[ cfg ( feature = \"x\" ) ]",
           "fn f() {} #[cfg(feature = \"x\")] fn g() {}", "struct S { #[cfg(feature = \"x\")] a: u8 }",
           "#![cfg(feature = \"x\")]", "#![cfg(test)]", "# ! [cfg_attr(kani, feature(allocator_api))]",
           "let x = 1; if cfg ! (unix) {}", "#[cfg_attr(feature = \"x\", path = \"alt.rs\")] mod m;",
           "#[cfg(feature =\n \"x\")]"]
    for s in ok:
        if cfg_violation(s):
            fail("cfg", f"self-test: accepted form rejected: {s!r}")
    for s in bad:
        if not cfg_violation(s):
            fail("cfg", f"self-test: feature/target-selected form accepted: {s!r}")
    # declaring files: the allowlisted crate-level Kani attribute only, and plain module declarations
    if cfg_violations("#![cfg_attr(kani, feature(allocator_api))]\npub mod canon;", declaring=True):
        fail("cfg", "self-test: the crate-level Kani attribute was rejected in a declaring file")
    if not cfg_violations("#![cfg(feature = \"x\")]\npub mod canon;", declaring=True):
        fail("cfg", "self-test: an inner cfg in a declaring file was accepted")
    decl_ok = ["pub mod canon;", "mod canon;", "#[doc(hidden)]\npub mod canon;", "pub(crate) mod canon;",
               "#[cfg(feature = \"rfc3161\")]\npub mod rfc3161;\npub mod canon;"]
    decl_bad = ["#[cfg(not(feature = \"x\"))]\npub mod canon;", "#[cfg(feature = \"x\")] pub mod canon;",
                "#[path = \"alt.rs\"]\nmod canon;", "#[cfg_attr(test, path = \"alt.rs\")]\n#[doc(hidden)]\nmod canon;",
                "pub mod canon;\n#[cfg(feature = \"x\")]\n#[path = \"alt.rs\"]\npub mod canon;", "pub mod hashx;"]
    for s in decl_ok:
        if mod_decl_violations(s, "canon"):
            fail("cfg", f"self-test: plain module declaration rejected: {s!r}")
    for s in decl_bad:
        if not mod_decl_violations(s, "canon"):
            fail("cfg", f"self-test: gated/redirected module declaration accepted: {s!r}")
    # production_code drops test/proof items only
    pc = production_code(rust_code("#[cfg(test)]\nmod t { use crate::rfc3161::x; }\nfn f() { rfc3161::y() }"))
    if "rfc3161::x" in pc or "rfc3161::y" not in pc:
        fail("cfg", "self-test: production_code does not remove exactly the test/proof items")
    glue_self_test()
    print("production refinement: cfg self-test OK")


def lean_code(text: str) -> str:
    """Lean source without comments, doc comments and string literals (so `def` inside prose or
    `@[rust_fun "..."]` strings is not read as a declaration)."""
    text = re.sub(r"/-.*?-/", " ", text, flags=re.S)
    text = re.sub(r"--[^\n]*", " ", text)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


# A declaration command: optional attributes (on the same or earlier lines), modifiers, keyword.
_DECL = re.compile(
    r"(?m)^\s*(?:@\[[^\]]*\]\s*)*(?:(?:private|protected|noncomputable|partial|unsafe|nonrec)\s+)*"
    r"(def|abbrev|instance|axiom|opaque|theorem|lemma|structure|inductive|class|constant)\b"
    r"(?:\s*\([^)]*\))?\s*(?:\[[^\]]*\]\s*)?([A-Za-z0-9_.']+|:|where|\{)?")
# Commands that change how other declarations elaborate or compile; never allowed in the glue.
_FORBIDDEN_GLUE = re.compile(
    r"(?m)^\s*(?:@\[[^\]]*\]\s*)*(?:(?:local|scoped)\s+)?(macro_rules|macro|notation|syntax|elab|elab_rules|infixl|infixr|infix|prefix|postfix|attribute|unif_hint|run_cmd|#eval|initialize|builtin_initialize)\b")


def defined_names(text: str) -> set[str]:
    """Every name `text` declares (def, abbrev, instance, axiom, opaque, theorem, structure, ...,
    with attributes and modifiers). An anonymous instance is reported as `<anonymous instance>`."""
    names = set()
    for m in _DECL.finditer(lean_code(text)):
        kw, name = m.group(1), m.group(2)
        if kw == "instance" and (name is None or name in (":", "where", "{")):
            names.add("<anonymous instance>")
        elif name and name not in (":", "where", "{"):
            names.add(name)
    return names


def forbidden_glue_commands(text: str) -> list[str]:
    return [m.group(1) for m in _FORBIDDEN_GLUE.finditer(lean_code(text))]


def glue_self_test() -> None:
    sample = """
/-! doc: def notADecl -/
-- def alsoNot
@[rust_fun "a::b"] def a.b (x : Nat) : Nat := x
@[simp, rust_fun
  "c::d"]
noncomputable def c.d : Nat := 0
abbrev E := Nat
instance fooInst : Inhabited E := ⟨0⟩
instance : Inhabited Bool := ⟨true⟩
private theorem t : True := trivial
protected def p.q := 1
@[implemented_by a.b] opaque o : Nat
axiom ax : Nat
structure S where
  x : Nat
"""
    want = {"a.b", "c.d", "E", "fooInst", "<anonymous instance>", "t", "p.q", "o", "ax", "S"}
    got = defined_names(sample)
    if got != want:
        fail("glue", f"self-test: defined_names found {sorted(got)}, expected {sorted(want)}")
    bad = forbidden_glue_commands("attribute [implemented_by x] y\nnotation \"x\" => 1\nlocal macro \"m\" : term => `(1)")
    if bad != ["attribute", "notation", "macro"]:
        fail("glue", f"self-test: forbidden glue commands found {bad}")
    if forbidden_glue_commands("def x := 1 -- attribute [simp] x\n/- notation -/"):
        fail("glue", "self-test: a comment was read as a glue command")


def check_glue(m: dict, template_dir: Path | None) -> None:
    ext = m["aeneas"]["externals"]
    for g in m["aeneas"]["glue"]:
        cmds = forbidden_glue_commands((PROD / g).read_text())
        if cmds:
            fail("glue", f"{g} uses commands the glue may not use: {sorted(set(cmds))}")
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
