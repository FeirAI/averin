#!/usr/bin/env python3
"""Require one exact, complete Kani 0.68 harness result with no failed property."""

import argparse
import re
import sys
from pathlib import Path


def successful(output: str, exit_code: int, harness: str) -> tuple[bool, str]:
    if exit_code != 0:
        return False, "Kani exited nonzero"
    selected = re.findall(r"^Checking harness (.+)\.\.\.$", output, re.MULTILINE)
    if selected != [harness]:
        return False, f"selected harnesses {selected!r} differ from {harness!r}"
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


def self_test() -> None:
    harness = "canon::kani_proofs::integer_roundtrip_zero"
    good = (
        f"Checking harness {harness}...\n"
        "Check 1: loop.unwind.1\n\t - Status: SUCCESS\n"
        "SUMMARY:\n ** 0 of 1 failed\nVERIFICATION:- SUCCESSFUL\n"
        "Manual Harness Summary:\n"
        "Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n"
    )
    assert successful(good, 0, harness)[0]
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
    print("check-kani-success: self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("exit_code", nargs="?", type=int)
    parser.add_argument("harness", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if None in (args.log, args.exit_code, args.harness):
        parser.error("log, exit_code and fully qualified harness are required")
    okay, why = successful(args.log.read_text(errors="replace"), args.exit_code, args.harness)
    print(f"check-kani-success: {why}")
    return 0 if okay else 1


if __name__ == "__main__":
    sys.exit(main())
