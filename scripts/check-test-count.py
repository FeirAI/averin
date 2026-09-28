#!/usr/bin/env python3
"""Fail unless a filtered `cargo test` actually ran tests.

    cargo test ... FILTER 2>&1 | python3 scripts/check-test-count.py --min N
    python3 scripts/check-test-count.py --self-test

cargo exits 0 when a name filter matches nothing ("0 passed; ... N filtered out"), so a renamed or
deleted test would silently pass a gate. This reads cargo's output (echoing it), sums the `passed`
counts of every `test result:` line, and requires at least N passed and no failure summary.
"""

from __future__ import annotations

import re
import sys

RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed", re.M)


def check(text: str, minimum: int) -> str | None:
    results = RESULT.findall(text)
    if not results:
        return "no `test result:` line (did cargo test run?)"
    if any(status != "ok" or int(failed) for status, _, failed in results):
        return "a test binary reported failures"
    passed = sum(int(p) for _, p, _ in results)
    if passed < minimum:
        return f"{passed} tests passed, at least {minimum} required (filter matched nothing?)"
    return None


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        ok = "running 1 test\ntest x ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n"
        cases = [(ok, 1, None), (ok.replace("1 passed", "0 passed"), 1, "x"), ("", 1, "x"),
                 (ok.replace("ok. 1 passed; 0 failed", "FAILED. 1 passed; 1 failed"), 1, "x"), (ok + ok, 2, None)]
        for text, minimum, want in cases:
            if (check(text, minimum) is None) != (want is None):
                print(f"check-test-count self-test: wrong verdict for min={minimum}: {text!r}", file=sys.stderr)
                return 1
        print("check-test-count self-test: OK")
        return 0
    if len(args) != 2 or args[0] != "--min" or not args[1].isdigit() or int(args[1]) < 1:
        print(__doc__, file=sys.stderr)
        return 2
    text = sys.stdin.read()
    sys.stdout.write(text)
    why = check(text, int(args[1]))
    if why:
        print(f"check-test-count: FAIL: {why}", file=sys.stderr)
        return 1
    print(f"check-test-count: OK ({sum(int(p) for _, p, _ in RESULT.findall(text))} passed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
