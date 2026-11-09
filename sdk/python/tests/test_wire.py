"""_wire: grammars, hex/base64url, strict JSON, both JCS forms, micro-units and ULIDs."""

from __future__ import annotations

import json
import math
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from seam_branchpoint import MAX_SAFE, InvalidUnit, JcsError, UlidGenerator, bucket, from_micros, to_micros, unit_tag
from seam_branchpoint._wire import (
    ULID_RE,
    b64u,
    b64u_decode,
    encode_ulid,
    framed,
    full,
    is_int,
    jcs_flat,
    jcs_tree,
    strict_loads,
    unhex,
)

TABLE = json.loads((Path(__file__).parent / "micros_table.json").read_text("utf-8"))


# --- micro-units ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("row", TABLE["rows"], ids=lambda r: f"{r['kind']}:{r['x']}")
def test_micros_table(row):
    x = int(row["x"]) if row["kind"] == "int" else float(row["x"])
    if "micros" in row:
        assert to_micros(x) == row["micros"]
        assert type(to_micros(x)) is int
    else:
        with pytest.raises(ValueError):
            to_micros(x)


def test_micros_table_is_independently_right():
    """Each expectation follows from the decimal text alone (no call into to_micros), and the table contains rows
    where a binary multiply `round(x * 1e6)` would disagree, so it pins the decimal reading for both SDKs."""
    disagree = 0
    for row in TABLE["rows"]:
        if row["kind"] != "float" or "micros" not in row:
            continue
        exact = int((Decimal(row["x"]) * 1_000_000).to_integral_value(ROUND_HALF_EVEN))
        assert exact == row["micros"], row
        disagree += round(float(row["x"]) * 1e6) != row["micros"]
    assert disagree >= 6


@pytest.mark.parametrize("bad", [True, False, "1", None, Decimal("1"), [1], 1j])
def test_micros_refuses_non_numbers(bad):
    with pytest.raises(TypeError):
        to_micros(bad)


def test_micros_negative_zero_is_plain_zero():
    v = to_micros(-0.0)
    assert v == 0 and str(v) == "0"


@given(st.integers(min_value=-(MAX_SAFE // 1_000_000), max_value=MAX_SAFE // 1_000_000))
def test_micros_ints_scale_exactly(n):
    assert to_micros(n) == n * 1_000_000
    assert to_micros(float(n)) == n * 1_000_000


@given(st.floats(allow_nan=False, allow_infinity=False, min_value=-9e9, max_value=9e9))
def test_micros_matches_decimal_of_repr(x):
    want = int((Decimal(repr(x)) * 1_000_000).to_integral_value(ROUND_HALF_EVEN))
    assert to_micros(x) == want
    assert abs(from_micros(want) - x) <= 5e-7 + abs(x) * 1e-15


@given(st.floats().filter(lambda f: not math.isfinite(f) or abs(f) >= 9007199254.740992))
def test_micros_refuses_non_finite_and_out_of_range(x):
    with pytest.raises(ValueError):
        to_micros(x)


# --- grammars and bytes --------------------------------------------------------------------------------------------
def test_full_never_lets_a_trailing_newline_through():
    assert full(ULID_RE, "01JBP9000000000000000000AB")
    assert not full(ULID_RE, "01JBP9000000000000000000AB\n")
    assert not full(ULID_RE, b"01JBP9000000000000000000AB")
    assert not full(ULID_RE, None)


def test_is_int_refuses_bool_and_float():
    assert is_int(5, 0, 10) and not is_int(True, 0, 10) and not is_int(5.0, 0, 10) and not is_int(11, 0, 10)


@pytest.mark.parametrize("bad", ["0", "0G", "AB", "abc", None, 12, " 00"])
def test_unhex_is_strict(bad):
    with pytest.raises(ValueError):
        unhex(bad)


def test_unhex_ok():
    assert unhex("") == b"" and unhex("00ff") == b"\x00\xff"


@given(st.binary(max_size=64))
def test_b64u_roundtrip(b):
    s = b64u(b)
    assert "=" not in s and b64u_decode(s) == b


@pytest.mark.parametrize("bad", ["a", "ab+c", "ab/c", "ab=="])
def test_b64u_decode_refuses(bad):
    with pytest.raises(ValueError):
        b64u_decode(bad)


def test_framed():
    assert framed(b"ab") == b"\x02\x00\x00\x00ab"


def test_units_are_utf8_without_normalisation():
    salt = bytes(range(32))
    eid = "01JBP9000000000000000000AB"
    assert bucket(salt, eid, "a\x00b") != bucket(salt, eid, "a")  # NUL is a valid unit character
    assert bucket(salt, eid, "\u00e9") != bucket(salt, eid, "e\u0301")  # NFC and NFD are different units
    with pytest.raises(InvalidUnit):
        bucket(salt, eid, "\ud800")
    with pytest.raises(InvalidUnit):
        unit_tag(salt, "x\udfff")


# --- strict JSON ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [b'{"a":1,"a":2}', b"\xef\xbb\xbf{}", b"NaN", b'{"a":Infinity}', b"\xff", b"{"])
def test_strict_loads_refuses(bad):
    with pytest.raises(ValueError):
        strict_loads(bad)


def test_strict_loads_keeps_floats_as_floats():
    assert type(strict_loads(b"1.0")) is float and type(strict_loads(b"1e3")) is float


# --- JCS: receipt domain (flat) ------------------------------------------------------------------------------------
def test_jcs_flat_sorts_and_is_compact():
    assert jcs_flat({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'


@pytest.mark.parametrize("bad", [
    {"a": 1.0}, {"a": 0.5}, {"a": True}, {"a": None}, {"a": {"b": 1}}, {"a": [1]}, {"a": "é"}, {"a": 'q"'},
    {"a": "back\\slash"}, {"a": "\n"}, {"a": "\x7f"}, {"a": -1}, {"a": 2**53}, {"é": 1}, {1: 1},
])
def test_jcs_flat_refuses_outside_the_receipt_domain(bad):
    with pytest.raises(JcsError):
        jcs_flat(bad)


def test_jcs_flat_refuses_non_object():
    with pytest.raises(JcsError):
        jcs_flat([1])  # type: ignore[arg-type]


# --- JCS: batch tree -----------------------------------------------------------------------------------------------
def test_jcs_tree_utf16_key_order_and_escaping():
    # RFC 8785 sorts by UTF-16 code units: U+1F600 (0xD83D 0xDE00) sorts before U+E000, unlike code-point order
    obj = {"\ue000": 1, "\U0001f600": 2, "a": "\u00e9\n\"\x01"}
    assert jcs_tree(obj) == '{"a":"é\\n\\"\\u0001","\U0001f600":2,"\ue000":1}'.encode("utf-8")


def test_jcs_tree_nested_and_negative():
    assert jcs_tree({"x": [1, -2, {"b": [], "a": {}}]}) == b'{"x":[1,-2,{"a":{},"b":[]}]}'


@pytest.mark.parametrize("bad", [1.0, 0.5, True, None, 2**53, -(2**53), {"a": 1.5}, ["\ud800"], {"\udc00": 1},
                                 {1: 2}, b"x", {"a": {1, 2}}])
def test_jcs_tree_refuses(bad):
    with pytest.raises(JcsError):
        jcs_tree(bad)


def test_jcs_tree_refuses_deep_nesting():
    v: object = 1
    for _ in range(80):
        v = [v]
    with pytest.raises(JcsError):
        jcs_tree(v)


_json = st.recursive(
    st.integers(-MAX_SAFE, MAX_SAFE) | st.text(alphabet=st.characters(exclude_categories=["Cs"]), max_size=8),
    lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(alphabet=st.characters(exclude_categories=["Cs"]),
                                                                max_size=6), c, max_size=4),
    max_leaves=12,
)


@given(_json)
def test_jcs_tree_is_valid_json_and_stable(v):
    out = jcs_tree(v)
    back = json.loads(out)
    assert back == v
    assert jcs_tree(back) == out


# --- ULID ----------------------------------------------------------------------------------------------------------
def test_encode_ulid():
    assert encode_ulid(0, 0) == "0" * 26
    assert encode_ulid((1 << 48) - 1, (1 << 80) - 1) == "7" + "Z" * 25
    with pytest.raises(ValueError):
        encode_ulid(1 << 48, 0)


def test_ulid_monotonic_same_ms_and_backwards_clock():
    clock = iter([1000, 1000, 999, 1001]).__next__
    rand = iter([b"\x00" * 10, b"\x00" * 9 + b"\x05"]).__next__
    g = UlidGenerator(clock_ms=clock, rand_bytes=lambda n: rand())
    ids = [g() for _ in range(4)]
    assert ids == sorted(ids) and len(set(ids)) == 4
    assert ids[1] == encode_ulid(1000, 1) and ids[2] == encode_ulid(1000, 2)  # clock went back: still increments
    assert ids[3] == encode_ulid(1001, 5)
    assert all(full(ULID_RE, i) for i in ids)


def test_ulid_overflow_steps_a_logical_ms():
    g = UlidGenerator(clock_ms=lambda: 50, rand_bytes=lambda n: b"\xff" * 10)
    a, b = g(), g()
    assert a == encode_ulid(50, (1 << 80) - 1) and b == encode_ulid(51, (1 << 80) - 1) and a < b
