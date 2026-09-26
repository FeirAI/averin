#!/usr/bin/env python3
"""Require a named Kani mutant to fail on its target assertion, never on a proof bound."""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "check_kani_success", Path(__file__).resolve().parent / "check-kani-success.py"
)
_success = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_success)


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
    output: str, exit_code: int, harness: str, source: str, description: str,
    expect_guard: bool = False,
) -> tuple[bool, str]:
    # Kani 0.68.0 returns 1 for a completed failed verification (observed on m9).
    # Any other exit is a tool, timeout, or signal failure, not a mutant kill.
    if exit_code != 1:
        return False, "Kani did not exit as a completed failed verification"
    if "VERIFICATION:- FAILED" not in output:
        return False, "Kani did not report a completed failed verification"
    selected = re.findall(r"^Checking harness (.+)\.\.\.$", output, re.MULTILINE)
    if selected != [harness]:
        return False, f"selected harnesses {selected!r} differ from {harness!r}"
    okay, why = _success.stubs_match(output, harness, expect_guard)
    if not okay:
        return False, why
    failed_harnesses = re.findall(r"^Verification failed for - (.+)$", output, re.MULTILINE)
    if failed_harnesses != [harness]:
        return False, "intended harness lacks an exact failed-harness summary"
    completions = re.findall(r"^Complete - (.+)$", output, re.MULTILINE)
    if completions != ["0 successfully verified harnesses, 1 failures, 1 total."]:
        return False, "missing exact one-harness failure completion"
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
    gate: str, output: str, exit_code: int, expect_success: bool,
    required_test: str | None = None,
) -> tuple[bool, str]:
    if gate in ("production", "production-proof"):
        # formal/production/check-production.py and formal/run-production-refinement.sh print
        # `production refinement: ... OK` or `production refinement: FAIL (<reason>): ...`.
        if expect_success:
            if required_test is not None:
                return False, "named detector is only valid for failed checks"
            ok_marker = ("production refinement: OK" if gate == "production-proof"
                         else "production refinement: checks OK")
            if exit_code == 0 and ok_marker in output:
                return True, "completed production refinement check"
            return False, "production refinement check did not complete OK"
        failure = re.search(r"(?m)^production refinement: FAIL \(([a-z-]+)\):", output)
        if exit_code != 1 or failure is None:
            return False, "missing completed production refinement failure"
        if failure.group(1) == "toolchain":
            return False, "toolchain failure is not a mutant kill"
        if required_test is not None and failure.group(1) != required_test:
            return False, f"production refinement failed for {failure.group(1)!r}, not {required_test!r}"
        return True, "completed gate failure from intended detector"
    if gate == "inventory":
        if required_test is not None:
            return False, "inventory has no named test detector"
        marker = "tag inventory: OK" if expect_success else "tag inventory: FAIL:"
        expected_exit = 0 if expect_success else 1
        if exit_code == expected_exit and marker in output:
            return True, "completed inventory result"
        return False, "missing completed inventory result"
    if expect_success:
        if required_test is not None:
            return False, "named detector is only valid for failed tests"
        complete = re.search(r"(?m)^test result: ok\. ([1-9][0-9]*) passed;", output)
        if exit_code == 0 and complete:
            return True, "completed gate with at least one passing test"
        return False, "gate did not complete at least one passing test"
    complete = re.search(r"(?m)^test result: FAILED\. .*\b([1-9][0-9]*) failed;", output)
    if exit_code != 101 or not complete:
        return False, "missing completed test failure (tool/build/timeout failure is not a mutant kill)"
    if required_test is not None:
        name = re.escape(required_test)
        detector = re.search(rf"(?m)^---- (?:[\w:]+::)?{name} stdout ----$", output)
        if detector is None:
            return False, f"named detector {required_test} did not fail"
    return True, "completed gate failure from intended detector"


def self_test() -> None:
    harness = "b64::kani_proofs::one_byte_tail_is_canonical"
    selected = f"Checking harness {harness}...\n"
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
    tail = f"\nSUMMARY:\n ** 1 of 2 failed\nVERIFICATION:- FAILED\nVerification failed for - {harness}\nComplete - 0 successfully verified harnesses, 1 failures, 1 total.\n"
    good = selected + prefix + tail
    def accepted(log: str, exit_code: int = 1, name: str = harness,
                 source: str = "core/src/b64.rs", description: str = "assertion failed",
                 expect_guard: bool = False) -> bool:
        return target_counterexample(log, exit_code, name, source, description, expect_guard)[0]

    assert accepted(good)
    for bad_exit in (0, 2, 124, 137, 143):
        assert not accepted(good, bad_exit)
    assert not accepted(selected + prefix)
    assert not accepted(selected + unwind + tail)
    assert not accepted(selected + prefix + unwind + tail)
    assert not accepted(good, source="core/src/canon.rs")
    assert not accepted(good, description="index out of bounds")
    assert not accepted(prefix + tail)
    assert not accepted(good, name="b64::kani_proofs::two_byte_tail_is_canonical")
    assert not accepted(good.replace(f"Verification failed for - {harness}",
                                    "Verification failed for - another::harness"))
    assert not accepted(good.replace(f"Verification failed for - {harness}",
                                    f"Verification failed for - {harness}_suffix"))
    assert not accepted(good.replace("1 failures, 1 total", "2 failures, 2 total"))
    assert not accepted(good + "Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n")
    integer = "canon::kani_proofs::integer_roundtrip_zero"
    int_log = good.replace(harness, integer)
    int_sel = f"Checking harness {integer}...\n"
    guarded = int_log.replace(int_sel, int_sel + f"  {_success.NUMERIC_GUARD}\n  {_success.ALIGN_A1}\n")
    assert accepted(guarded, name=integer, expect_guard=True)
    assert not accepted(int_log, name=integer, expect_guard=True)
    assert not accepted(guarded, name=integer)
    assert not accepted(guarded.replace("reject_general_in_integer_proof", "empty_stub"), name=integer, expect_guard=True)
    assert not accepted(guarded.replace("- Stub: parse_top_level_general", "- Stub: other::parse_top_level_general"), name=integer, expect_guard=True)
    assert not accepted(guarded + "  - Stub: another -> stub\n", name=integer, expect_guard=True)
    assert not accepted(good.replace(selected, selected + f"  {_success.PUSH_G1}\n"))
    assert completed_simple_gate("oracle", "test result: FAILED. 0 passed; 1 failed;", 101, False)[0]
    assert not completed_simple_gate("oracle", "error: could not compile", 101, False)[0]
    assert not completed_simple_gate("golden", "test result: FAILED. 0 passed; 1 failed;", 124, False)[0]
    assert not completed_simple_gate("golden", "test result: FAILED. 0 passed; 1 failed;", 137, False)[0]
    assert not completed_simple_gate("golden", "test result: FAILED. 0 passed; 1 failed;", 0, False)[0]
    assert completed_simple_gate("inventory", "tag inventory: FAIL: renamed tag", 1, False)[0]
    assert not completed_simple_gate("inventory", "Traceback: missing file", 1, False)[0]
    assert not completed_simple_gate("inventory", "tag inventory: FAIL: renamed tag", 124, False)[0]
    assert completed_simple_gate("oracle", "test result: ok. 8 passed;", 0, True)[0]
    assert not completed_simple_gate("oracle", "test result: ok. 0 passed", 0, True)[0]
    assert not completed_simple_gate("oracle", "test result: ok. 0 passed; 8 filtered out", 0, True)[0]
    assert completed_simple_gate("verdict", "test result: FAILED. 0 passed; 1 failed;", 101, False)[0]
    named_failure = "---- verify::verdict::differential::verdict_differential stdout ----\ntest result: FAILED. 0 passed; 1 failed;"
    assert completed_simple_gate("verdict", named_failure, 101, False, "verdict_differential")[0]
    assert not completed_simple_gate("verdict", named_failure, 101, False, "other_test")[0]
    assert not completed_simple_gate("verdict", "test result: FAILED. 0 passed; 1 failed;", 101, False, "verdict_differential")[0]
    assert completed_simple_gate("adversarial", "test result: ok. 284 passed;", 0, True)[0]
    prod_fail = "production refinement: FAIL (stale): core/src/canon.rs changed"
    assert completed_simple_gate("production", prod_fail, 1, False, "stale")[0]
    assert not completed_simple_gate("production", prod_fail, 1, False, "call-path")[0]
    assert not completed_simple_gate("production", prod_fail, 2, False, "stale")[0]
    assert not completed_simple_gate("production-proof",
        "production refinement: FAIL (toolchain): missing", 1, False)[0]
    assert completed_simple_gate("production-proof",
        "production refinement: FAIL (proof): lake build failed", 1, False, "proof")[0]
    assert completed_simple_gate("production", "production refinement: checks OK (stale)", 0, True)[0]
    assert completed_simple_gate("production-proof", "production refinement: OK", 0, True)[0]
    assert not completed_simple_gate("production-proof", "production refinement: checks OK", 0, True)[0]
    assert not completed_simple_gate("oracle", "test result: ok. 8 passed;", 1, True)[0]
    print("check-kani-mutant: self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("exit_code", nargs="?", type=int)
    parser.add_argument("harness", nargs="?")
    parser.add_argument("source", nargs="?")
    parser.add_argument("description", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--gate", choices=("inventory", "oracle", "golden", "verdict", "adversarial",
                                           "production", "production-proof"))
    parser.add_argument("--expect-success", action="store_true")
    parser.add_argument("--required-test")
    parser.add_argument("--expect-guard", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if None in (args.log, args.exit_code):
        parser.error("log and exit_code are required")
    output = args.log.read_text(errors="replace")
    if args.gate:
        okay, why = completed_simple_gate(
            args.gate, output, args.exit_code, args.expect_success, args.required_test
        )
    else:
        if None in (args.harness, args.source, args.description):
            parser.error("harness, source and description are required for Kani")
        okay, why = target_counterexample(
            output, args.exit_code, args.harness, args.source, args.description,
            args.expect_guard,
        )
    print(f"check-kani-mutant: {why}")
    return 0 if okay else 1


if __name__ == "__main__":
    sys.exit(main())
