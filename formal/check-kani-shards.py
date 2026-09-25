#!/usr/bin/env python3
"""Check that each sharded Kani family partitions its original input domain exactly once.

A family is a list of Kani harnesses whose conjunction is the original named property: optional
lemma harnesses (proved first) followed by shards that each run the family's unchanged assertion
body over one concrete slice of the original domain. For every family this checker parses the
actual shard table from core/src/canon.rs, pins the shared assertion body and the shard macro,
and enumerates the original domain to prove that every input lies in exactly one shard.
"""

import argparse
import re
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "core/src/canon.rs"
RUNNER = Path(__file__).resolve().parent / "run-kani.sh"


def compact(text: str) -> str:
    return re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", text))


def section(source: str, start: str, end: str) -> str:
    i = source.find(start)
    if i == -1:
        raise ValueError(f"missing source item: {start}")
    j = source.find(end, i + len(start))
    if j == -1:
        raise ValueError(f"missing end of source item: {start}")
    return source[i:j]


# ---- accepted_integer_spelling: length 1..=4, every byte in the numeric spelling alphabet ----

SPELLING_ALPHABET = sorted(set(b"0123456789-+.eE"))
SPELLING_SHARD = re.compile(
    r"^\s*spelling_shard!\(\s*(accepted_integer_spelling_\w+)\s*,\s*(\d+)\s*,\s*b'(.)'\s*\);\s*$",
    re.MULTILINE,
)


def spelling_rows(source: str) -> list[tuple[str, int, int]]:
    return [(name, int(length), ord(first)) for name, length, first in SPELLING_SHARD.findall(source)]


def validate_spelling_wiring(source: str) -> None:
    c = compact(source)
    if "fnspelling_byte(b:u8)->bool{b.is_ascii_digit()||matches!(b,b'-'|b'+'|b'.'|b'e'|b'E')}" not in c:
        raise ValueError("spelling alphabet predicate changed")
    literal = re.search(r'const SPELLING_BYTES: \[u8; (\d+)\] = \*b"([^"]*)";', source)
    if not literal or sorted(set(literal.group(2).encode())) != SPELLING_ALPHABET or len(
        literal.group(2)
    ) != int(literal.group(1)) or len(literal.group(2)) != len(SPELLING_ALPHABET):
        raise ValueError("SPELLING_BYTES is not exactly the spelling alphabet, each byte once")
    lemma = (
        "#[kani::proof]fnspelling_alphabet_is_exact(){letany_byte:u8=kani::any();"
        "assert_eq!(spelling_byte(any_byte),SPELLING_BYTES.contains(&any_byte));}"
    )
    if lemma not in c:
        raise ValueError("spelling alphabet lemma harness changed")
    body = compact(
        section(source, "fn accepted_integer_spelling_case(len: usize, first: u8)", "macro_rules! spelling_shard")
    )
    expected = (
        "fnaccepted_integer_spelling_case(len:usize,first:u8){"
        "letmutraw:[u8;4]=kani::any();"
        "forbin&raw[1..]{kani::assume(spelling_byte(*b));}"
        "raw[0]=first;"
        "letbytes=&raw[..len];"
        "assert!(bytes.iter().all(|b|b.is_ascii()));"
        "lettext=unsafe{core::str::from_utf8_unchecked(bytes)};"
        "letparsed=CanonValue::parse_typed(text);"
        "ifmatches!(parsed,Ok(CanonValue::Int(_))){"
        "letdigits=text.strip_prefix('-').unwrap_or(text).as_bytes();"
        "assert!(!digits.is_empty()&&digits.iter().all(|b|b.is_ascii_digit()));"
        'assert!(digits[0]!=b\'0\'||digits.len()==1,"noleadingzero");'
        'assert!(text!="-0","nonegativezero");}'
        "core::mem::forget(parsed);}"
    )
    if not body.startswith(expected) or body.count("kani::assume(") != 1:
        raise ValueError("shared spelling assertion body changed")
    arm = compact(section(source, "macro_rules! spelling_shard", "// These sixty lines"))
    arm_expected = (
        "macro_rules!spelling_shard{($name:ident,$len:literal,$first:literal)=>{"
        "#[kani::proof]#[kani::unwind(16)]fn$name(){accepted_integer_spelling_case($len,$first);}};}"
    )
    if arm != arm_expected:
        raise ValueError("spelling shard macro changed (no extra assumption or stub allowed)")


def validate_spelling(rows: list[tuple[str, int, int]]) -> list[str]:
    names = [name for name, _, _ in rows]
    if len(names) != len(set(names)):
        raise ValueError("duplicate spelling shard name")
    for name, length, first in rows:
        if not 1 <= length <= 4 or first not in SPELLING_ALPHABET:
            raise ValueError(f"spelling shard {name} lies outside the original domain")
    # The original domain: every length 1..=4 and every byte string over the alphabet. A shard
    # (length, first) fixes the length and first byte and keeps the rest symbolic over the whole
    # alphabet, so a string is in exactly the shards whose (length, first) match it.
    for length in range(1, 5):
        for first in SPELLING_ALPHABET:
            hits = sum(1 for _, l, f in rows if (l, f) == (length, first))
            if hits != 1:
                raise ValueError(f"spelling (length {length}, first {chr(first)!r}) is in {hits} shards")
    if len(rows) != 4 * len(SPELLING_ALPHABET):
        raise ValueError("spelling shard table has extra rows")
    return ["spelling_alphabet_is_exact"] + names


FAMILIES = {
    "accepted_integer_spelling": (spelling_rows, validate_spelling_wiring, validate_spelling),
}


def family_harnesses(family: str, source: str) -> list[str]:
    rows, wiring, validate = FAMILIES[family]
    wiring(source)
    return validate(rows(source))


def self_test() -> None:
    source = SOURCE.read_text()
    good = family_harnesses("accepted_integer_spelling", source)
    assert len(good) == 61 and good[0] == "spelling_alphabet_is_exact"
    line = "    spelling_shard!(accepted_integer_spelling_2_minus, 2, b'-');\n"
    assert line in source
    for changed in (
        source.replace(line, ""),
        source.replace(line, line + line.replace("_2_minus", "_2_minus_again")),
        source.replace(line, line.replace(", 2, b'-'", ", 3, b'-'")),
        source.replace(line, line.replace("b'-'", "b'x'")),
        source.replace(line, line.replace(", 2, ", ", 5, ")),
        source.replace('*b"0123456789-+.eE"', '*b"0123456789-+.eF"'),
        source.replace("raw[0] = first;", "raw[0] = first; kani::assume(raw[1] != b'0');"),
        source.replace("for b in &raw[1..] {", "for b in &raw[..] {"),
        source.replace('assert!(text != "-0", "no negative zero");', ""),
        source.replace("let bytes = &raw[..len];", "let bytes = &raw[..len.min(3)];"),
        source.replace("accepted_integer_spelling_case($len, $first);", "accepted_integer_spelling_case($len, b'1');"),
        source.replace("#[kani::unwind(16)]\n            fn $name()", "#[kani::unwind(16)]\n            #[kani::stub(nfc, nfc)]\n            fn $name()"),
        source.replace("matches!(b, b'-' | b'+' | b'.' | b'e' | b'E')", "matches!(b, b'-' | b'+' | b'.' | b'e')"),
        source.replace("assert_eq!(spelling_byte(any_byte), SPELLING_BYTES.contains(&any_byte));", ""),
    ):
        try:
            family_harnesses("accepted_integer_spelling", changed)
        except ValueError:
            pass
        else:
            raise AssertionError("spelling shard drift escaped the checker")
    print("check-kani-shards: self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", metavar="FAMILY", help="print every harness of FAMILY, lemmas first")
    parser.add_argument("--has", metavar="HARNESS", help="accept only a harness of some checked family")
    parser.add_argument("--families", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.families:
        print("\n".join(FAMILIES))
        return 0
    try:
        source = SOURCE.read_text()
        checked = {family: family_harnesses(family, source) for family in FAMILIES}
    except ValueError as error:
        print(f"check-kani-shards: FAIL: {error}", file=sys.stderr)
        return 1
    if args.list:
        if args.list not in checked:
            print(f"check-kani-shards: unknown family {args.list}", file=sys.stderr)
            return 2
        print("\n".join(checked[args.list]))
        return 0
    if args.has:
        return 0 if any(args.has in names for names in checked.values()) else 1
    for family, names in checked.items():
        print(f"check-kani-shards: OK {family} ({len(names)} harnesses, exact partition)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
