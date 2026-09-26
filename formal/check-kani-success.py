#!/usr/bin/env python3
"""Require one exact, complete Kani 0.68 harness result with no failed property."""

import argparse
import re
import sys
from pathlib import Path


# The only replacements any proof may carry, as Kani prints them. Each is attached by
# `#[kani::stub]` to named harnesses only (core/src/canon.rs, formal/README.md):
#   the numeric-route guard: the general top-level parser panics if a numeric spelling reaches it;
#   A1, a std-permitted behavior selection: `align_offset` returns `usize::MAX`;
#   G1, a fail-closed std-path guard: `Vec::push` asserts it never reallocates.
NUMERIC_GUARD = "- Stub: parse_top_level_general -> reject_general_in_integer_proof"
ALIGN_A1 = "- Stub: < * const u8 > :: align_offset -> align_offset_usize_max"
PUSH_G1 = "- Stub: std :: vec :: Vec :: push -> push_without_growth"


def expected_stubs(qualified: str) -> list[str]:
    """The exact, sorted stub lines a fully qualified harness must report (and no others)."""
    module, _, name = qualified.rpartition("::")
    if module != "canon::kani_proofs":
        return []
    if name == "integer_roundtrip" or name.startswith("integer_roundtrip_"):
        return sorted([NUMERIC_GUARD, ALIGN_A1])
    if name == "utf16_key_order_is_transitive" or name.startswith("utf16_key_order_is_exact_"):
        return [PUSH_G1]
    if re.fullmatch(r"string_escape_roundtrip_\d{5}", name):
        return [ALIGN_A1]
    return []


def stubs_match(output: str, harness: str, expect_guard: bool) -> tuple[bool, str]:
    stub_lines = sorted(line.strip() for line in output.splitlines() if "- Stub:" in line)
    expected = expected_stubs(harness)
    if expect_guard != (NUMERIC_GUARD in expected):
        return False, "numeric guard expectation does not match the harness allowlist"
    if stub_lines != expected:
        return False, f"stubs {stub_lines!r} differ from the exact allowlist {expected!r}"
    return True, "exact stub allowlist"


def successful(output: str, exit_code: int, harness: str, expect_guard: bool = False) -> tuple[bool, str]:
    if exit_code != 0:
        return False, "Kani exited nonzero"
    selected = re.findall(r"^Checking harness (.+)\.\.\.$", output, re.MULTILINE)
    if selected != [harness]:
        return False, f"selected harnesses {selected!r} differ from {harness!r}"
    okay, why = stubs_match(output, harness, expect_guard)
    if not okay:
        return False, why
    if output.count("VERIFICATION:- SUCCESSFUL") != 1:
        return False, "missing or repeated successful verification marker"
    if not re.search(r"^\s*\*\* 0 of [1-9]\d* failed(?: \([^)]*\))?$", output, re.MULTILINE):
        return False, "missing completed zero-failure property summary"
    if " - Status: FAILURE" in output:
        return False, "a Kani property failed (including unwind or unsupported checks)"
    if not re.search(
        r"^Complete - 1 successfully verified harnesses, 0 failures, 1 total\.$",
        output,
        re.MULTILINE,
    ):
        return False, "missing exact one-harness completion summary"
    return True, "one exact harness completed successfully"


def successful_many(output: str, exit_code: int, harnesses: list[str]) -> tuple[bool, str]:
    """One Kani invocation over several harnesses: every one must be selected exactly once and
    its own section must satisfy exactly the single-harness conditions."""
    if exit_code != 0:
        return False, "Kani exited nonzero"
    starts = [m.start() for m in re.finditer(r"^Checking harness .+\.\.\.$", output, re.MULTILINE)]
    tail = output.find("\nManual Harness Summary:")
    if tail == -1 or not starts or tail < starts[-1]:
        return False, "missing harness sections or final summary"
    sections = [output[a:b] for a, b in zip(starts, starts[1:] + [tail])]
    names = [re.match(r"Checking harness (.+)\.\.\.", sec).group(1) for sec in sections]
    if sorted(names) != sorted(harnesses) or len(set(names)) != len(names):
        return False, f"selected harnesses {names!r} differ from {harnesses!r}"
    for name, sec in zip(names, sections):
        okay, why = stubs_match(sec, name, NUMERIC_GUARD in expected_stubs(name))
        if not okay:
            return False, f"{name}: {why}"
        if sec.count("VERIFICATION:- SUCCESSFUL") != 1 or "VERIFICATION:- FAILED" in sec:
            return False, f"{name}: missing or repeated successful verification marker"
        if not re.search(r"^\s*\*\* 0 of [1-9]\d* failed(?: \([^)]*\))?$", sec, re.MULTILINE):
            return False, f"{name}: missing completed zero-failure property summary"
        if " - Status: FAILURE" in sec:
            return False, f"{name}: a Kani property failed"
    total = len(harnesses)
    if not re.search(
        rf"^Complete - {total} successfully verified harnesses, 0 failures, {total} total\.$",
        output[tail:],
        re.MULTILINE,
    ):
        return False, "missing exact all-harness completion summary"
    return True, f"{total} exact harnesses completed successfully"


def self_test() -> None:
    harness = "canon::kani_proofs::integer_roundtrip_zero"
    good = (
        f"Checking harness {harness}...\n"
        "Check 1: loop.unwind.1\n\t - Status: SUCCESS\n"
        "SUMMARY:\n ** 0 of 1 failed\nVERIFICATION:- SUCCESSFUL\n"
        "Manual Harness Summary:\n"
        "Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n"
    )
    plain = "canon::kani_proofs::accepted_integer_spelling_2_minus"
    assert successful(good.replace(harness, plain), 0, plain)[0]
    assert not successful(good, 0, harness)[0], "integer proof without its guards"
    header = f"Checking harness {harness}...\n"
    guarded = good.replace(header, header + f"  {ALIGN_A1}\n  {NUMERIC_GUARD}\n")
    assert successful(guarded, 0, harness, expect_guard=True)[0]
    assert not successful(guarded, 0, harness)[0]
    assert not successful(guarded.replace(f"  {ALIGN_A1}\n", ""), 0, harness, expect_guard=True)[0]
    assert not successful(guarded.replace("reject_general_in_integer_proof", "empty_stub"), 0, harness, expect_guard=True)[0]
    assert not successful(guarded.replace("align_offset_usize_max", "align_offset_zero"), 0, harness, expect_guard=True)[0]
    assert not successful(guarded.replace("- Stub: parse_top_level_general", "- Stub: other::parse_top_level_general"), 0, harness, expect_guard=True)[0]
    assert not successful(guarded.replace("- Stub: parse_top_level_general", "- Stub: parse_top_level_general_extra"), 0, harness, expect_guard=True)[0]
    assert not successful(guarded + "  - Stub: another -> stub\n", 0, harness, expect_guard=True)[0]
    assert not successful(guarded + f"  {PUSH_G1}\n", 0, harness, expect_guard=True)[0]
    order = "canon::kani_proofs::utf16_key_order_is_exact_2_2"
    ordered = good.replace(harness, order).replace(f"Checking harness {order}...\n", f"Checking harness {order}...\n  {PUSH_G1}\n")
    assert successful(ordered, 0, order)[0]
    assert not successful(ordered.replace("push_without_growth", "push_that_grows"), 0, order)[0]
    assert not successful(ordered + f"  {ALIGN_A1}\n", 0, order)[0]
    assert not successful(ordered.replace(order, "canon::kani_proofs::string_escape_roundtrip"), 0, "canon::kani_proofs::string_escape_roundtrip")[0]
    assert not successful(ordered.replace(order, "b64::kani_proofs::utf16_key_order_is_exact_2_2"), 0, "b64::kani_proofs::utf16_key_order_is_exact_2_2")[0]
    for bad, code in (
        (good, 124),
        (good.replace(harness, "canon::kani_proofs::integer_roundtrip_positive_1"), 0),
        (good.replace("Checking harness ", "Checking no harness "), 0),
        (good.replace(" ** 0 of 1 failed", " ** 1 of 1 failed"), 0),
        (good.replace("Status: SUCCESS", "Status: FAILURE"), 0),
        (good.replace("VERIFICATION:- SUCCESSFUL", "VERIFICATION:- FAILED"), 0),
        (good.replace("1 successfully verified harnesses", "0 successfully verified harnesses"), 0),
        (good.replace("1 total", "2 total"), 0),
    ):
        assert not successful(bad, code, harness)[0]
    a, b = "canon::kani_proofs::string_escape_roundtrip_00000", "canon::kani_proofs::string_escape_roundtrip_00001"
    def sec(name: str) -> str:
        return (f"Checking harness {name}...\n  {ALIGN_A1}\nCheck 1: x\n\t - Status: SUCCESSFUL\n"
                "SUMMARY:\n ** 0 of 3 failed\nVERIFICATION:- SUCCESSFUL\n")
    summary = "\nManual Harness Summary:\nComplete - 2 successfully verified harnesses, 0 failures, 2 total.\n"
    many = sec(a) + sec(b) + summary
    assert successful_many(many, 0, [a, b])[0]
    assert successful_many(sec(b) + sec(a) + summary, 0, [a, b])[0]
    for bad, code, want in (
        (many, 1, [a, b]),
        (many, 0, [a]),
        (sec(a) + sec(a) + summary, 0, [a, b]),
        (sec(a) + sec(b).replace(f"  {ALIGN_A1}\n", "") + summary, 0, [a, b]),
        (sec(a) + sec(b).replace("0 of 3 failed", "1 of 3 failed") + summary, 0, [a, b]),
        (sec(a) + sec(b).replace("VERIFICATION:- SUCCESSFUL", "VERIFICATION:- FAILED") + summary, 0, [a, b]),
        (sec(a) + sec(b) + summary.replace("2 successfully", "1 successfully"), 0, [a, b]),
        (sec(a) + sec(b), 0, [a, b]),
    ):
        assert not successful_many(bad, code, want)[0]
    print("check-kani-success: self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("exit_code", nargs="?", type=int)
    parser.add_argument("harness", nargs="?")
    parser.add_argument("--expect-guard", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--many", nargs="+", metavar="HARNESS",
                        help="log and exit code of one invocation over these fully qualified harnesses")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.many:
        if args.log is None or args.exit_code is None or args.harness is not None:
            parser.error("--many takes only LOG EXIT_CODE positionally")
        okay, why = successful_many(args.log.read_text(errors="replace"), args.exit_code, args.many)
        print(f"check-kani-success: {why}")
        return 0 if okay else 1
    if None in (args.log, args.exit_code, args.harness):
        parser.error("log, exit_code and fully qualified harness are required")
    okay, why = successful(args.log.read_text(errors="replace"), args.exit_code, args.harness, args.expect_guard)
    print(f"check-kani-success: {why}")
    return 0 if okay else 1


if __name__ == "__main__":
    sys.exit(main())
