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


# ---- utf16_key_order_is_exact: two keys of one or two arbitrary scalars each ----

KEY_ORDER_SHARD = re.compile(
    r"^\s*key_order_shard!\(\s*(utf16_key_order_is_exact_\w+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\);\s*$",
    re.MULTILINE,
)


def key_order_rows(source: str) -> list[tuple[str, int, int]]:
    return [(name, int(a), int(b)) for name, a, b in KEY_ORDER_SHARD.findall(source)]


def validate_key_order_wiring(source: str) -> None:
    key = compact(section(source, "fn key<'a>(count: usize,", "/// The assertion body shared by the four"))
    expected_key = (
        "fnkey<'a>(count:usize,buf:&'amut[u8;8],units:&mut[u16;4])->(&'astr,usize){"
        "letc1:char=kani::any();letn1=c1.len_utf8();c1.encode_utf8(&mutbuf[..4]);"
        "letmutu=c1.encode_utf16(&mutunits[..2]).len();letmutn=n1;"
        "ifcount==2{letc2:char=kani::any();letn2=c2.len_utf8();"
        "c2.encode_utf8(&mutbuf[n1..n1+4]);u+=c2.encode_utf16(&mutunits[u..u+2]).len();n+=n2;}"
        "(unsafe{core::str::from_utf8_unchecked(&buf[..n])},u)}"
    )
    if key != expected_key:
        raise ValueError("key-order key construction changed (every scalar must stay arbitrary)")
    case = compact(section(source, "fn utf16_key_order_exact_case(", "/// Key order is exactly RFC 8785"))
    expected_case = (
        "fnutf16_key_order_exact_case(count_a:usize,count_b:usize){"
        "let(mutba,mutbb)=([0u8;8],[0u8;8]);let(mutua,mutub)=([0u16;4],[0u16;4]);"
        "let(sa,na)=key(count_a,&mutba,&mutua);let(sb,nb)=key(count_b,&mutbb,&mutub);"
        "assert_eq!(utf16_cmp(sa,sb),ua[..na].cmp(&ub[..nb]));}"
    )
    if case != expected_case:
        raise ValueError("key-order shared assertion body changed")
    arm = compact(section(source, "macro_rules! key_order_shard", "// These four lines"))
    expected_arm = (
        "macro_rules!key_order_shard{($name:ident,$count_a:literal,$count_b:literal)=>{"
        "#[kani::proof]#[kani::stub(std::vec::Vec::push,push_without_growth)]#[kani::unwind(6)]"
        "fn$name(){utf16_key_order_exact_case($count_a,$count_b);}};}"
    )
    if arm != expected_arm:
        raise ValueError("key-order shard macro changed")
    steered = compact(section(source, "fn utf16_key_order_is_exact_steered()", "/// Key order is transitive"))
    expected_steered = (
        "fnutf16_key_order_is_exact_steered(){lethi:char=kani::any();letastral:char=kani::any();"
        "kani::assume(('\\u{E000}'..='\\u{FFFF}').contains(&hi)&&astralasu32>=0x10000);"
        "let(mutbh,mutbs)=([0u8;4],[0u8;4]);"
        "let(sh,ss)=(&*hi.encode_utf8(&mutbh),&*astral.encode_utf8(&mutbs));"
        "assert_eq!(utf16_cmp(sh,ss),Ordering::Greater);assert_eq!(utf16_cmp(ss,sh),Ordering::Less);}"
    )
    if steered != expected_steered:
        raise ValueError("steered key-order conjunct changed")


def validate_key_order(rows: list[tuple[str, int, int]]) -> list[str]:
    names = [name for name, _, _ in rows]
    if len(names) != len(set(names)):
        raise ValueError("duplicate key-order shard name")
    # The original harness drew each key's scalar count from `two: bool`, i.e. 1 or 2.
    for a in (1, 2):
        for b in (1, 2):
            hits = sum(1 for _, x, y in rows if (x, y) == (a, b))
            if hits != 1:
                raise ValueError(f"key-order counts ({a}, {b}) are in {hits} shards")
    if len(rows) != 4:
        raise ValueError("key-order shard table has extra rows")
    return ["utf16_key_order_is_exact_steered"] + names


# ---- every std or production replacement: exact bodies and exact attachment sites ----

GUARD_BODIES = {
    "fn align_offset_usize_max<T>(": "fnalign_offset_usize_max<T>(_:*constT,_:usize)->usize{usize::MAX}",
    "fn push_without_growth<T, A: std::alloc::Allocator>(": (
        "fnpush_without_growth<T,A:std::alloc::Allocator>(v:&mutVec<T,A>,value:T){letlen=v.len();"
        'assert!(len<v.capacity(),"Vec::pushreachedreallocationinano-growthproof");'
        "unsafe{v.as_mut_ptr().add(len).write(value);v.set_len(len+1);}}"
    ),
}

ALLOWED_STUBS = {
    "parse_top_level_general, reject_general_in_integer_proof": {"integer_roundtrip", "integer_roundtrip_shard"},
    "<*const u8>::align_offset, align_offset_usize_max": {"integer_roundtrip", "integer_roundtrip_shard"},
    "std::vec::Vec::push, push_without_growth": {
        "utf16_key_order_is_transitive", "key_order_shard", "utf16_key_order_is_exact_steered",
    },
}


def validate_stub_sites(source: str) -> None:
    for other in ("b64.rs", "hashx.rs"):
        if "kani::stub" in (SOURCE.parent / other).read_text():
            raise ValueError(f"core/src/{other} proofs must not stub anything")
    for start, body in GUARD_BODIES.items():
        i = source.find(start)
        if i == -1 or source.count(start) != 1:
            raise ValueError(f"guard body missing or duplicated: {start}")
        j = source.find("\n    }\n", i)
        if compact(source[i : j + 6]) != body:
            raise ValueError(f"guard body changed: {start}")
    seen = {key: set() for key in ALLOWED_STUBS}
    for match in re.finditer(r"#\[kani::stub\((.*?)\)\]", source):
        target = match.group(1)
        if target not in ALLOWED_STUBS:
            raise ValueError(f"stub not in the allowlist: {target}")
        rest = source[match.end() :]
        fn = re.search(r"\bfn (\$name|\w+)\(", rest)
        site = fn.group(1) if fn else ""
        if site == "$name":
            macro = re.findall(r"macro_rules! (\w+)", source[: match.start()])
            site = macro[-1] if macro else ""
        if site not in ALLOWED_STUBS[target]:
            raise ValueError(f"stub {target} attached to {site}, outside its allowlist")
        seen[target].add(site)
    for target, sites in ALLOWED_STUBS.items():
        if seen[target] != sites:
            raise ValueError(f"stub {target} is missing from {sorted(sites - seen[target])}")


FAMILIES = {
    "accepted_integer_spelling": (spelling_rows, validate_spelling_wiring, validate_spelling),
    "utf16_key_order_is_exact": (key_order_rows, validate_key_order_wiring, validate_key_order),
}


def family_harnesses(family: str, source: str) -> list[str]:
    rows, wiring, validate = FAMILIES[family]
    validate_stub_sites(source)
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
    order = family_harnesses("utf16_key_order_is_exact", source)
    assert order[0] == "utf16_key_order_is_exact_steered" and len(order) == 5
    row = "    key_order_shard!(utf16_key_order_is_exact_2_2, 2, 2);\n"
    assert row in source
    for changed in (
        source.replace(row, ""),
        source.replace(row, row.replace(", 2, 2)", ", 2, 1)")),
        source.replace(row, row + row.replace("_2_2", "_2_2b")),
        source.replace("if count == 2 {", "if count == 3 {"),
        source.replace("let c2: char = kani::any();", "let c2: char = kani::any_where(|c: &char| c.is_ascii());"),
        source.replace("utf16_key_order_exact_case($count_a, $count_b);", "utf16_key_order_exact_case($count_a, 1);"),
        source.replace("astral as u32 >= 0x10000", "astral as u32 >= 0x10001"),
    ):
        try:
            family_harnesses("utf16_key_order_is_exact", changed)
        except ValueError:
            pass
        else:
            raise AssertionError("key-order shard drift escaped the checker")
    for changed in (
        source.replace("        usize::MAX\n", "        0\n", 1),
        source.replace('assert!(\n            len < v.capacity(),', 'kani::assume(\n            len < v.capacity(),'),
        source.replace("v.set_len(len + 1);", "v.set_len(len);"),
        source.replace("    fn spelling_alphabet_is_exact() {", "    #[kani::stub(std::vec::Vec::push, push_without_growth)]\n    fn spelling_alphabet_is_exact() {"),
        source.replace("    #[kani::stub(std::vec::Vec::push, push_without_growth)]\n    #[kani::unwind(6)]\n    fn utf16_key_order_is_transitive", "    #[kani::unwind(6)]\n    fn utf16_key_order_is_transitive"),
        source.replace("#[kani::stub(<*const u8>::align_offset, align_offset_usize_max)]", "#[kani::stub(<*const u8>::align_offset, other)]", 1),
        source.replace("    fn utf16_key_order_is_exact_steered() {", "    #[kani::stub(nfc, nfc_identity)]\n    fn utf16_key_order_is_exact_steered() {"),
    ):
        try:
            family_harnesses("accepted_integer_spelling", changed)
        except ValueError:
            pass
        else:
            raise AssertionError("guard or stub-site drift escaped the checker")
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
