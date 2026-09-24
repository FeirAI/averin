#!/usr/bin/env python3
"""Check that integer Kani shards exactly cover the original full-domain harness."""

import argparse
import re
import sys
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "core/src/canon.rs"
RUNNER = Path(__file__).resolve().parent / "run-kani.sh"
SHARD = re.compile(
    r"^\s*integer_roundtrip_shard!\(\s*(integer_roundtrip_\w+)\s*,\s*"
    r"(u8|u16|u32)\s*,\s*(zero|positive|negative)\s*,\s*"
    r"(\d+)\s*,\s*(\d+)\s*\);\s*$",
    re.MULTILINE,
)


def expected_ranges() -> dict[str, tuple[str, str, int, int]]:
    expected = {"integer_roundtrip_zero": ("u8", "zero", 0, 0)}
    for width in range(1, 6):
        lower = 10 ** (width - 1)
        upper = 10**width - 1
        input_type = "u8" if width <= 2 else "u16" if width <= 4 else "u32"
        expected[f"integer_roundtrip_positive_{width}"] = (input_type, "positive", lower, upper)
        expected[f"integer_roundtrip_negative_{width}"] = (input_type, "negative", lower, upper)
    return expected


def read_ranges(source: str) -> list[tuple[str, str, str, int, int]]:
    return [(name, input_type, sign, int(lo), int(hi)) for name, input_type, sign, lo, hi in SHARD.findall(source)]


def validate_wiring(source: str, runner: str) -> None:
    helper_start = source.find("fn integer_roundtrip_case(n: i64)")
    original_start = source.find("fn integer_roundtrip()")
    if helper_start == -1 or original_start <= helper_start:
        raise ValueError("shared integer assertion body missing or out of order")
    helper_without_comments = re.sub(r"//[^\n]*", "", source[helper_start:original_start])
    helper = re.sub(r"\s+", "", helper_without_comments)
    checked_prefix = (
        "lettext=n.to_string();"
        "letnumeric_prefix=text.as_bytes().first()."
        "is_some_and(|b|*b==b'-'||b.is_ascii_digit());"
        'assert!(numeric_prefix,"decimalspellingneedssignordigit");'
        "kani::assume(numeric_prefix);"
        'letparsed_n=matchCanonValue::parse_typed(&text){'
        'Ok(CanonValue::Int(parsed_n))=>parsed_n,'
        'Ok(_)=>panic!("formattedintegerparsedasnon-integer"),'
        'Err(_)=>panic!("formattedintegerwasrejected"),};'
    )
    if checked_prefix not in helper or helper.count("kani::assume(") != 1:
        raise ValueError("integer prefix must be asserted before the identical assumption and parse")
    for required in (
        'assert!(parsed_n==n,"parsedintegerdiffers");',
        'assert!(CanonValue::Int(parsed_n).serialize()==text,"serializedintegerspellingdiffers");',
    ):
        if required not in helper:
            raise ValueError(f"shared integer assertion body changed: {required}")
    original = re.search(
        r"fn integer_roundtrip\(\)\s*\{\s*"
        r"let n: i64 = kani::any_where\(\|n: &i64\| \*n > -100_000 && \*n < 100_000\);\s*"
        r"integer_roundtrip_case\(n\);",
        source,
    )
    if not original:
        raise ValueError("original full-domain integer_roundtrip harness was changed or removed")
    arms = (
        "($name:ident, u8, zero, 0, 0)",
        "($name:ident, $ty:ty, positive, $lo:expr, $hi:expr)",
        "($name:ident, $ty:ty, negative, $lo:expr, $hi:expr)",
    )
    positions = [source.find(arm) for arm in arms]
    if -1 in positions or positions != sorted(positions):
        raise ValueError("integer shard macro arms missing or out of order")
    table_start = source.find("// These eleven lines are the proof-domain table", positions[-1])
    if table_start == -1:
        raise ValueError("integer shard table marker missing")
    bodies = [source[positions[i] : positions[i + 1]] for i in range(2)]
    bodies.append(source[positions[-1] : table_start])
    if any("kani::assume(" in body for body in bodies):
        raise ValueError("integer shard macro added a narrowing assumption")
    for body, required in zip(
        bodies,
        (
            "integer_roundtrip_case(0);",
            "integer_roundtrip_case(magnitude as i64);",
            "integer_roundtrip_case(-(magnitude as i64));",
        ),
    ):
        if required not in body:
            raise ValueError(f"integer shard macro changed its shared assertion call: {required}")
    for body in bodies[1:]:
        if "let magnitude: $ty = kani::any_where(|m: &$ty| *m >= $lo && *m <= $hi);" not in body:
            raise ValueError("integer magnitude shard changed its bounded input construction")
    for required in (
        'integer_shards="$(python3 formal/check-kani-domains.py --list-integer)"',
        'run_harness "$integer_harness"',
        'done <<< "$integer_shards"',
    ):
        if required not in runner:
            raise ValueError(f"extended runner omits integer shards: {required}")


def validate_fail_closed_guard(source: str, runner: str) -> None:
    compact = re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", source))
    route = (
        "ifinput.as_bytes().first().is_some_and(|b|*b==b'-'||b.is_ascii_digit())"
        "{letn=p.parse_number()?;p.finish_top_level()?;returnOk(CanonValue::Int(n));}"
        "letv=parse_top_level_general(&mutp)?;p.finish_top_level()?;Ok(v)"
    )
    if route not in compact:
        raise ValueError("numeric-first production dispatch or trailing check changed")
    finish = (
        "fnfinish_top_level(&mutself)->Result<(),ParseError>{self.skip_ws();"
        'ifself.i!=self.s.len(){Err(self.err("trailingdataaftertop-levelvalue"))}'
        "else{Ok(())}}"
    )
    if finish not in compact:
        raise ValueError("shared top-level trailing check changed")
    for required in (
        "Some(b'-')|Some(b'0'..=b'9')=>self.parse_number().map(CanonValue::Int),",
        "fnparse_number(&mutself)->Result<i64,ParseError>{",
        "matchlexeme.parse::<i64>(){Ok(n)=>Ok(n),",
    ):
        if required not in compact:
            raise ValueError(f"numeric parser type boundary changed: {required}")
    if (
        "fnparse_top_level_general(p:&mutParser<'_>)->Result<CanonValue,ParseError>"
        "{p.skip_ws();p.parse_value()}"
    ) not in compact:
        raise ValueError("general top-level helper no longer delegates to production parser")
    guard = (
        "fnreject_general_in_integer_proof(_:&mutParser<'_>)->Result<CanonValue,ParseError>"
        '{panic!("numericspellingreachedgeneraltop-levelparser")}'
    )
    if guard not in compact:
        raise ValueError("integer general-branch guard must fail unconditionally")
    annotation = "#[kani::stub(parse_top_level_general, reject_general_in_integer_proof)]"
    if source.count(annotation) != 4:
        raise ValueError("original integer harness and all shard macro arms need the guard")
    for required in (
        'if [[ "$1" == integer_roundtrip* ]]; then',
        "python3 formal/check-kani-domains.py >/dev/null || return 2",
        "kani_flags=(-Z stubbing)",
        "guard_flag=(--expect-guard)",
        'cargo kani "${kani_flags[@]}"',
        '"${guard_flag[@]}"',
    ):
        if required not in runner:
            raise ValueError(f"Kani runner omits fail-closed guard wiring: {required}")


def validate(ranges: list[tuple[str, str, str, int, int]]) -> list[str]:
    expected = expected_ranges()
    names = [name for name, _, _, _, _ in ranges]
    if len(names) != len(set(names)):
        raise ValueError("duplicate integer harness name")
    actual = {name: (input_type, sign, lo, hi) for name, input_type, sign, lo, hi in ranges}
    if actual != expected:
        missing = sorted(expected.keys() - actual.keys())
        extra = sorted(actual.keys() - expected.keys())
        changed = sorted(name for name in expected.keys() & actual.keys() if actual[name] != expected[name])
        raise ValueError(f"integer shard table drift: missing={missing}, extra={extra}, changed={changed}")
    for n in range(-99_999, 100_000):
        hits = sum(
            (n == 0 if sign == "zero" else lo <= n <= hi if sign == "positive" else -hi <= n <= -lo)
            for _, _, sign, lo, hi in ranges
        )
        if hits != 1:
            raise ValueError(f"integer {n} occurs in {hits} shards, expected exactly one")
    return names


def self_test() -> None:
    rows = [(name, *bounds) for name, bounds in expected_ranges().items()]
    assert len(validate(rows)) == 11
    for changed in (
        rows[:-1],
        rows + [rows[-1]],
        [(name, ty, sign, lo, hi - 1 if name == "integer_roundtrip_positive_5" else hi) for name, ty, sign, lo, hi in rows],
        [("integer_roundtrip_renamed", ty, sign, lo, hi) if name == "integer_roundtrip_zero" else (name, ty, sign, lo, hi) for name, ty, sign, lo, hi in rows],
        [(name, "u8", sign, lo, hi) if name == "integer_roundtrip_positive_5" else (name, ty, sign, lo, hi) for name, ty, sign, lo, hi in rows],
        [(name, ty, "positive", lo, hi) if name == "integer_roundtrip_negative_3" else (name, ty, sign, lo, hi) for name, ty, sign, lo, hi in rows],
    ):
        try:
            validate(changed)
        except ValueError:
            pass
        else:
            raise AssertionError("domain drift escaped the checker")
    fixture = "\n".join(f"integer_roundtrip_shard!({name}, {ty}, {sign}, {lo}, {hi});" for name, ty, sign, lo, hi in rows)
    assert read_ranges(fixture) == rows
    original = (
        'fn integer_roundtrip_case(n: i64) { let text = n.to_string(); '
        'let numeric_prefix = text.as_bytes().first().is_some_and(|b| *b == b\'-\' || b.is_ascii_digit()); '
        'assert!(numeric_prefix, "decimal spelling needs sign or digit"); kani::assume(numeric_prefix); '
        'let parsed_n = match CanonValue::parse_typed(&text) { '
        'Ok(CanonValue::Int(parsed_n)) => parsed_n, '
        'Ok(_) => panic!("formatted integer parsed as non-integer"), '
        'Err(_) => panic!("formatted integer was rejected"), }; '
        'assert!(parsed_n == n, "parsed integer differs"); '
        'assert!(CanonValue::Int(parsed_n).serialize() == text, "serialized integer spelling differs"); } '
        "fn integer_roundtrip() { let n: i64 = kani::any_where(|n: &i64| "
        "*n > -100_000 && *n < 100_000); integer_roundtrip_case(n); } "
        "($name:ident, u8, zero, 0, 0) => { fn $name() { integer_roundtrip_case(0); } };"
        "($name:ident, $ty:ty, positive, $lo:expr, $hi:expr) => {"
        "let magnitude: $ty = kani::any_where(|m: &$ty| *m >= $lo && *m <= $hi);"
        "integer_roundtrip_case(magnitude as i64); };"
        "($name:ident, $ty:ty, negative, $lo:expr, $hi:expr) => {"
        "let magnitude: $ty = kani::any_where(|m: &$ty| *m >= $lo && *m <= $hi);"
        "integer_roundtrip_case(-(magnitude as i64)); };"
        "// These eleven lines are the proof-domain table"
    )
    runner = '\n'.join(('integer_shards="$(python3 formal/check-kani-domains.py --list-integer)"', 'run_harness "$integer_harness"', 'done <<< "$integer_shards"'))
    validate_wiring(original, runner)
    for missing in runner.splitlines():
        try:
            validate_wiring(original, runner.replace(missing, ""))
        except ValueError:
            pass
        else:
            raise AssertionError("runner omission escaped the checker")
    try:
        validate_wiring(original.replace("-100_000", "-99_999"), runner)
    except ValueError:
        pass
    else:
        raise AssertionError("full-domain harness shrink escaped the checker")
    for changed in (
        original.replace('assert!(numeric_prefix, "decimal spelling needs sign or digit"); ', ""),
        original.replace('assert!(numeric_prefix, "decimal spelling needs sign or digit"); kani::assume(numeric_prefix);',
                         'kani::assume(numeric_prefix); assert!(numeric_prefix, "decimal spelling needs sign or digit");'),
        original.replace("kani::assume(numeric_prefix);", "kani::assume(true);"),
        original.replace("b.is_ascii_digit()", "b.is_ascii_alphabetic()"),
        original.replace('Err(_) => panic!("formatted integer was rejected"),',
                         'Err(_) => n,'),
        original.replace('Ok(_) => panic!("formatted integer parsed as non-integer"),',
                         'Ok(_) => n,'),
        original.replace('assert!(parsed_n == n, "parsed integer differs");', ''),
        original.replace('CanonValue::Int(parsed_n).serialize()', 'CanonValue::Int(n).serialize()'),
    ):
        try:
            validate_wiring(changed, runner)
        except ValueError:
            pass
        else:
            raise AssertionError("checked integer prefix drift escaped the checker")
    try:
        validate_wiring(original.replace("integer_roundtrip_case(0);", "integer_roundtrip_case(1);"), runner)
    except ValueError:
        pass
    else:
        raise AssertionError("zero-shard input drift escaped the checker")
    try:
        validate_wiring(original.replace("integer_roundtrip_case(0);", "kani::assume(false); integer_roundtrip_case(0);"), runner)
    except ValueError:
        pass
    else:
        raise AssertionError("extra shard assumption escaped the checker")
    try:
        validate_wiring(original.replace("integer_roundtrip_case(-(magnitude as i64));", "integer_roundtrip_case(magnitude as i64);"), runner)
    except ValueError:
        pass
    else:
        raise AssertionError("negative-shard sign drift escaped the checker")
    real_source, real_runner = SOURCE.read_text(), RUNNER.read_text()
    validate_fail_closed_guard(real_source, real_runner)
    for changed in (
        real_source.replace('panic!("numeric spelling reached general top-level parser")',
                            'Ok(CanonValue::Int(0))'),
        real_source.replace('panic!("numeric spelling reached general top-level parser")',
                            'Err(ParseError { message: ParseMessage::Static("x"), pos: 0 })'),
        real_source.replace('panic!("numeric spelling reached general top-level parser")', ''),
        real_source.replace('#[kani::stub(parse_top_level_general, reject_general_in_integer_proof)]', '', 1),
        real_source.replace('parse_top_level_general(&mut p)?', 'p.parse_value()?'),
        real_source.replace('p.skip_ws();\n    p.parse_value()', 'p.parse_value()'),
        real_source.replace('return Ok(CanonValue::Int(n));', 'return Ok(CanonValue::Int(0));'),
        real_source.replace('p.finish_top_level()?;', '', 1),
        real_source.replace('Err(self.err("trailing data after top-level value"))', 'Ok(())'),
        real_source.replace('Ok(n) => Ok(n),', 'Ok(n) => Ok(n + 1),'),
        real_source.replace('self.parse_number().map(CanonValue::Int)', 'self.parse_number().map(CanonValue::Bool)'),
    ):
        try:
            validate_fail_closed_guard(changed, real_runner)
        except ValueError:
            pass
        else:
            raise AssertionError("fail-closed numeric guard drift escaped the checker")
    try:
        validate_fail_closed_guard(real_source, real_runner.replace("kani_flags=(-Z stubbing)", ""))
    except ValueError:
        pass
    else:
        raise AssertionError("missing Kani guard flag escaped the checker")
    print("check-kani-domains: self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-integer", action="store_true", help="emit every required integer shard harness")
    parser.add_argument("--has-integer", metavar="HARNESS", help="accept only a named integer shard")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        source = SOURCE.read_text()
        runner = RUNNER.read_text()
        validate_wiring(source, runner)
        validate_fail_closed_guard(source, runner)
        names = validate(read_ranges(source))
    except ValueError as error:
        print(f"check-kani-domains: FAIL: {error}", file=sys.stderr)
        return 1
    if args.has_integer:
        return 0 if args.has_integer in names else 1
    if args.list_integer:
        print("\n".join(names))
    else:
        print(f"check-kani-domains: OK ({len(names)} shards, exactly one per integer in [-99999,99999])")
    return 0


if __name__ == "__main__":
    sys.exit(main())
