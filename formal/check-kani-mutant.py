#!/usr/bin/env python3
"""Require a named Kani mutant to fail on its target assertion, never on a proof bound."""

import argparse
import sys
from pathlib import Path


def failed_checks(output: str) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in output.splitlines():
        if line.startswith("Check "):
            if current is not None:
                checks.append(current)
            current = {"name": line}
        elif current is not None:
            for field in ("Status", "Description", "Location"):
                marker = f" - {field}: "
                if marker in line:
                    current[field.lower()] = line.split(marker, 1)[1]
                    break
        elif line.startswith("SUMMARY:"):
            break
    if current is not None:
        checks.append(current)
    return [check for check in checks if check.get("status") == "FAILURE"]


def target_counterexample(
    output: str, exit_code: int, source: str, description: str
) -> tuple[bool, str]:
    # Kani 0.68.0 returns 1 for a completed failed verification (observed on m9).
    # Any other exit is a tool, timeout, or signal failure, not a mutant kill.
    if exit_code != 1:
        return False, "Kani did not exit as a completed failed verification"
    if "VERIFICATION:- FAILED" not in output:
        return False, "Kani did not report a completed failed verification"
    failures = failed_checks(output)
    if not failures:
        return False, "no failed property in Kani output"
    for check in failures:
        detail = " ".join(check.values()).lower()
        if "unwind" in detail or "unsupported" in detail:
            return False, "unwinding or unsupported-property failure"
    for check in failures:
        if source in check.get("location", "") and description in check.get("description", ""):
            return True, "target assertion has a counterexample"
    return False, "failed properties do not include the intended source and assertion"


def completed_simple_gate(
    gate: str, output: str, exit_code: int, expect_success: bool
) -> tuple[bool, str]:
    if gate == "inventory":
        marker = "tag inventory: OK" if expect_success else "tag inventory: FAIL:"
    else:
        marker = "test result: ok." if expect_success else "test result: FAILED."
    expected_exit = 0 if expect_success else (1 if gate == "inventory" else 101)
    if exit_code == expected_exit and marker in output:
        return True, "completed gate result"
    return False, "missing completed gate result (tool/build/timeout failure is not a mutant kill)"


def self_test() -> None:
    prefix = """Check 1: target.assertion.1
\t - Status: FAILURE
\t - Description: \"assertion failed: expected equality\"
\t - Location: core/src/b64.rs:210:10 in function target
"""
    unwind = """Check 2: target.unwind.1
\t - Status: FAILURE
\t - Description: \"unwinding assertion loop.0\"
\t - Location: core/src/b64.rs:190:10 in function target
"""
    tail = "\nSUMMARY:\n ** 1 of 2 failed\nVERIFICATION:- FAILED\n"
    assert target_counterexample(prefix + tail, 1, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(prefix + tail, 0, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(prefix + tail, 124, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(prefix + tail, 137, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(prefix + tail, 143, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(prefix + tail, 2, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(prefix, 1, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(unwind + tail, 1, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(prefix + unwind + tail, 1, "core/src/b64.rs", "assertion failed")[0]
    assert not target_counterexample(prefix + tail, 1, "core/src/canon.rs", "assertion failed")[0]
    assert not target_counterexample(prefix + tail, 1, "core/src/b64.rs", "index out of bounds")[0]
    assert completed_simple_gate("oracle", "test result: FAILED. 1 failed", 101, False)[0]
    assert not completed_simple_gate("oracle", "error: could not compile", 101, False)[0]
    assert not completed_simple_gate("golden", "test result: FAILED. 1 failed", 124, False)[0]
    assert not completed_simple_gate("golden", "test result: FAILED. 1 failed", 137, False)[0]
    assert not completed_simple_gate("golden", "test result: FAILED. 1 failed", 0, False)[0]
    assert completed_simple_gate("inventory", "tag inventory: FAIL: renamed tag", 1, False)[0]
    assert not completed_simple_gate("inventory", "Traceback: missing file", 1, False)[0]
    assert not completed_simple_gate("inventory", "tag inventory: FAIL: renamed tag", 124, False)[0]
    assert completed_simple_gate("oracle", "test result: ok. 8 passed", 0, True)[0]
    assert completed_simple_gate("verdict", "test result: FAILED. 1 failed", 101, False)[0]
    assert completed_simple_gate("adversarial", "test result: ok. 284 passed", 0, True)[0]
    assert not completed_simple_gate("oracle", "test result: ok. 8 passed", 1, True)[0]
    print("check-kani-mutant: self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("exit_code", nargs="?", type=int)
    parser.add_argument("source", nargs="?")
    parser.add_argument("description", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--gate", choices=("inventory", "oracle", "golden", "verdict", "adversarial"))
    parser.add_argument("--expect-success", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if None in (args.log, args.exit_code):
        parser.error("log and exit_code are required")
    output = args.log.read_text(errors="replace")
    if args.gate:
        okay, why = completed_simple_gate(args.gate, output, args.exit_code, args.expect_success)
    else:
        if None in (args.source, args.description):
            parser.error("source and description are required for Kani")
        okay, why = target_counterexample(
            output, args.exit_code, args.source, args.description
        )
    print(f"check-kani-mutant: {why}")
    return 0 if okay else 1


if __name__ == "__main__":
    sys.exit(main())
