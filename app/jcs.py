"""JSON Canonicalization Scheme (RFC 8785).

Implements deterministic serialization of JSON values:

* object members are sorted by UTF-16 code unit (JCS rule);
* numbers use ECMAScript's ``Number::toString`` shortest form;
* strings use JSON escaping with no U+2028/U+2029 special-casing.

Only JSON-native types are accepted (``dict``/``list``/``str``/``int``/
``float``/``bool``/``None``).  NaN and Infinity are rejected because they
have no JSON representation.
"""

from __future__ import annotations

import math
from typing import Any

# Uppercase hex digits mandated by RFC 8785.
_HEX = "0123456789ABCDEF"


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized to JCS."""


def _escape_string(value: str) -> str:
    out: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append("\\u%04X" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _ecma_number_to_string(value: float) -> str:
    """Serialize a float following ECMAScript Number::toString (base 10).

    Python's ``repr`` already produces the shortest round-tripping decimal
    (since Python 3.1), but its threshold for switching to exponential
    notation differs from ECMAScript, so we rebuild from repr's significant
    digits: fixed notation for 1e-6 <= |x| < 1e21, exponential otherwise.
    """
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("non-finite numbers are not valid JSON")

    if value == 0.0:  # also covers -0.0, which JS prints as "0"
        return "0"

    negative = value < 0.0

    # Decompose repr's shortest representation into significant digits and
    # a decimal exponent: value == int(digits) * 10**exp10.
    s = repr(abs(value))
    if "e" in s:
        mantissa, exp_part = s.split("e")
        exp10 = int(exp_part)
    else:
        mantissa, exp10 = s, 0
    if "." in mantissa:
        whole, frac = mantissa.split(".")
        point_pos = len(whole)
        digit_str = whole + frac
    else:
        point_pos = len(mantissa)
        digit_str = mantissa

    first = next((i for i, ch in enumerate(digit_str) if ch not in "0."), None)
    # Index (in digit_str) of the last nonzero digit.
    last = len(digit_str) - 1
    while last >= 0 and digit_str[last] == "0":
        last -= 1
    digits = digit_str[first:last + 1]
    # Decimal point sits after point_pos digits of digit_str; the first
    # significant digit is at index first, so the 10's exponent of the
    # integer represented by `digits` is point_pos - last - 1.
    exp10 += point_pos - last - 1

    # Position of the most significant digit relative to the decimal point:
    # value is in [10**k, 10**(k+1)).
    k = exp10 + len(digits) - 1

    if -6 <= k <= 20:
        # Fixed notation.
        point = len(digits) + exp10  # digits before the decimal point
        if point >= len(digits):
            result = digits + "0" * (point - len(digits))
        elif point <= 0:
            result = "0." + "0" * (-point) + digits
        else:
            result = digits[:point] + "." + digits[point:]
    else:
        # Exponential notation: d.dddde±k.
        if len(digits) > 1:
            result = digits[0] + "." + digits[1:] + "e" + str(k)
        else:
            result = digits + "e" + str(k)

    return ("-" + result) if negative else result


def _key_sort_key(key: str) -> tuple[int, ...]:
    # JCS sorts by UTF-16 code units; BMP characters are one unit, astral
    # characters become surrogate pairs. Decode the UTF-16-LE encoding as
    # little-endian 16-bit integers (we only need the ordering).
    raw = key.encode("utf-16-le")
    return tuple(raw[i] | (raw[i + 1] << 8) for i in range(0, len(raw), 2))


def canonicalize(value: Any) -> bytes:
    """Return the JCS canonical form (UTF-8 bytes) of *value*."""
    return _serialize(value).encode("utf-8")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _ecma_number_to_string(value)
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = list(value.keys())
        for k in keys:
            if not isinstance(k, str):
                raise CanonicalizationError("object keys must be strings")
        if len(set(keys)) != len(keys):
            raise CanonicalizationError("duplicate object member names")
        keys.sort(key=_key_sort_key)
        return "{" + ",".join(f"{_escape_string(k)}:{_serialize(value[k])}" for k in keys) + "}"
    raise CanonicalizationError(f"type {type(value).__name__} is not JSON-serializable")
