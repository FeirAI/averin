#!/usr/bin/env python3
"""Scheduling classes of the string_escape_roundtrip Kani family, for CI slicing.

    python3 formal/kani-string-slices.py --list ascii|mixed|pure   # harness names, one per line
    python3 formal/kani-string-slices.py --list smoke               # the committed PR smoke subset
    python3 formal/kani-string-slices.py --check                   # partition, class sizes, smoke list

The obligation list is the one check-kani-shards.py proves equal to the original domain
(`--list string_escape_roundtrip`); this script only splits it by cost, for KANI_SHARD_ONLY:

  ascii  every scalar ASCII (the empty string, 128 singles, 128^2 pairs): 16,513 cases, a few
         seconds of CBMC each;
  mixed  exactly one of U+00E9 / U+1F600 (the 2 singles and the 512 pairs with one ASCII scalar):
         514 cases, at most 19 s of CBMC each on the final source;
  pure   both scalars non-ASCII (U+00E9 U+00E9, U+00E9 U+1F600, U+1F600 U+00E9, U+1F600 U+1F600):
         4 cases (on the final source at most 19 s of CBMC each; an earlier source did not finish
         U+1F600 U+1F600 in 60 minutes).

The case-id mapping mirrors `string_proof_case` in core/src/canon.rs (0 empty, 1..=130 singles,
then ordered pairs, first scalar major; scalar indices 128 and 129 are the two non-ASCII ones). A
drift here only mis-schedules a case: every case of the checked list is still in exactly one class
(`--check`), and the family is verified only when every case passes.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAMILY = "string_escape_roundtrip"
SIZES = {"ascii": 16513, "mixed": 514, "pure": 4}
SMOKE = ROOT / "formal/kani-string-smoke.txt"


def smoke(c: dict) -> list:
    """The committed smoke subset: sorted, distinct cases of the checked list, from every class."""
    names = [l.strip() for l in SMOKE.read_text().splitlines() if l.strip() and not l.startswith("#")]
    if names != sorted(set(names)):
        raise SystemExit("kani-string-slices: the smoke list must be sorted and distinct")
    for cls, members in c.items():
        if not set(names) & set(members):
            raise SystemExit(f"kani-string-slices: the smoke list has no {cls} case")
    unknown = set(names) - set(sum(c.values(), []))
    if unknown:
        raise SystemExit(f"kani-string-slices: smoke cases not in the checked list: {sorted(unknown)}")
    return names


def scalars(k: int) -> list[int]:
    if k == 0:
        return []
    if k <= 130:
        return [k - 1]
    j = k - 131
    return [j // 130, j % 130]


def klass(k: int) -> str:
    return ("ascii", "mixed", "pure")[sum(1 for i in scalars(k) if i >= 128)]


def checked_list() -> list[str]:
    out = subprocess.run([sys.executable, str(ROOT / "formal/check-kani-shards.py"), "--list", FAMILY],
                         check=True, capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if line]


def classes() -> dict[str, list[str]]:
    result: dict = {c: [] for c in SIZES}
    for name in checked_list():
        m = re.fullmatch(rf"{FAMILY}_(\d{{5}})", name)
        if not m:
            raise SystemExit(f"kani-string-slices: unexpected harness name {name}")
        result[klass(int(m.group(1)))].append(name)
    return result


def main() -> int:
    args = sys.argv[1:]
    if args == ["--check"] or (len(args) == 2 and args[0] == "--list" and args[1] in (*SIZES, "smoke")):
        c = classes()
        sizes = {k: len(v) for k, v in c.items()}
        if sizes != SIZES:
            print(f"kani-string-slices: class sizes {sizes}, expected {SIZES}", file=sys.stderr)
            return 1
        if len(set(sum(c.values(), []))) != sum(SIZES.values()):
            print("kani-string-slices: classes overlap", file=sys.stderr)
            return 1
        names = smoke(c)
        if args[0] == "--check":
            print(f"kani-string-slices: {sizes} partition the {sum(SIZES.values())} checked cases; "
                  f"smoke list of {len(names)} OK")
        elif args[1] == "smoke":
            print("\n".join(names))
        else:
            print("\n".join(c[args[1]]))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
