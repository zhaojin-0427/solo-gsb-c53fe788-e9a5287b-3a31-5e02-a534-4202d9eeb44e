import json

import pytest

from app.jcs import CanonicalizationError, canonicalize


def j(value):
    return canonicalize(value).decode()


def test_structure_and_member_ordering():
    assert j({}) == "{}"
    assert j({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert j([1, 2, 3]) == "[1,2,3]"
    assert j([True, False, None]) == "[true,false,null]"
    assert j({"b": {"d": 4, "c": 3}, "a": [1, 2]}) == \
        '{"a":[1,2],"b":{"c":3,"d":4}}'


def test_string_escaping():
    assert j("\t\n\r\b\f") == r'"\t\n\r\b\f"'
    assert j("\x1f") == '"\\u001F"'
    assert j("\x00") == '"\\u0000"'
    assert j('"\\') == r'"\"\\"'
    assert j("é→中") == '"é→中"'


@pytest.mark.parametrize("value,expected", [
    (0.0, "0"),
    (-0.0, "0"),
    (1.0, "1"),
    (-1.0, "-1"),
    (10.0, "10"),
    (0.1, "0.1"),
    (0.000001, "0.000001"),
    (0.0000001, "1e-7"),
    (1.5e-7, "1.5e-7"),
    (100000000000000000000.0, "100000000000000000000"),
    (1e21, "1e21"),
    (3.141592653589793, "3.141592653589793"),
    (5e-324, "5e-324"),
    (1.7976931348623157e308, "1.7976931348623157e308"),
])
def test_number_serialization(value, expected):
    assert j(value) == expected


def test_big_integer_preserved():
    n = 123456789012345678901234567890
    assert j(n) == str(n)


def test_utf16_key_ordering():
    keys = ["a", "é", "\U0001f600", "€"]
    order = list(json.loads(j({k: 1 for k in keys})).keys())
    assert order == ["a", "é", "€", "\U0001f600"]


def test_non_finite_rejected():
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalizationError):
            canonicalize(bad)


def test_non_string_key_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({1: 2})


def test_idempotent_recanonicalization():
    doc = {"unicode": "кириллица", "nested": {"z": [1, {"y": 2}], "a": None},
           "num": 1e-7}
    out = canonicalize(doc)
    assert canonicalize(json.loads(out)) == out
