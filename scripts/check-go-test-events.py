#!/usr/bin/env python3
"""Require named Go tests to execute successfully in a `go test -json` stream."""

import argparse
import json
import sys


REQUIRED = (
    "TestBrokerSeqVoidPostgres",
    "TestBrokerSeqVoidGrantLandsFirstPostgres",
    "TestBrokerSeqVoidMarkerFailsPostgres",
)
API_PACKAGE = "github.com/feirai/averin/server/internal/api"


def check_events(lines, required=REQUIRED):
    required = tuple(required)
    if len(set(required)) != len(required) or not required:
        return ["required test list must be nonempty and unique"]
    seen_run = set()
    seen_pass = set()
    errors = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {number}: invalid Go test JSON: {exc}")
            continue
        if not isinstance(event, dict):
            errors.append(f"line {number}: Go test event must be a JSON object")
            continue
        package = event.get("Package", "")
        name = event.get("Test", "")
        action = event.get("Action", "")
        if action == "fail":
            errors.append(f"{package or '<unknown package>'} {name or '<package>'}: fail")
        if package != API_PACKAGE or not isinstance(name, str):
            continue
        for root in required:
            if name != root and not name.startswith(root + "/"):
                continue
            if name == root and action == "run":
                seen_run.add(root)
            if name == root and action == "pass":
                seen_pass.add(root)
            if action == "skip":
                errors.append(f"{name}: {action}")
            break
    for root in required:
        if root not in seen_run or root not in seen_pass:
            errors.append(f"{root}: missing run/pass event")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require", action="append", metavar="TEST",
                        help="replace the default required list; repeat for each test")
    args = parser.parse_args()
    errors = check_events(sys.stdin, args.require or REQUIRED)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("required Postgres API tests ran and passed without skipped subtests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
