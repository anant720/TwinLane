"""Unit tests for RFC 8785 JSON Canonicalization Scheme (JCS)."""

import pytest

from twinlane.protocol.canonical import canonicalize_json, canonicalize_to_str
from twinlane.protocol.errors import CanonicalizationError


def test_jcs_whitespace_removal() -> None:
    """Whitespace outside of strings must be eliminated."""
    data = {"b": 1, "a": 2}
    result = canonicalize_to_str(data)
    assert result == '{"a":2,"b":1}'
    assert " " not in result


def test_jcs_key_sorting() -> None:
    """Object keys must be lexicographically sorted by UTF-16 code units."""
    data = {
        "zeta": 1,
        "alpha": 2,
        "beta": 3,
        "10": 4,
        "2": 5,
    }
    result = canonicalize_to_str(data)
    assert result == '{"10":4,"2":5,"alpha":2,"beta":3,"zeta":1}'


def test_jcs_nested_structures() -> None:
    """Nested dictionaries and lists must be recursively canonicalized."""
    data = {
        "list": [{"z": 9, "a": 1}, 2],
        "meta": {"nested": {"k2": "v2", "k1": "v1"}},
    }
    result = canonicalize_to_str(data)
    assert result == '{"list":[{"a":1,"z":9},2],"meta":{"nested":{"k1":"v1","k2":"v2"}}}'


def test_jcs_number_formatting() -> None:
    """Numbers must adhere to ECMAScript standard."""
    data = {"zero": 0.0, "int": 42, "neg_zero": -0.0}
    result = canonicalize_to_str(data)
    assert result == '{"int":42,"neg_zero":0,"zero":0}'


def test_jcs_nan_and_inf_rejected() -> None:
    """NaN and Infinity are forbidden in RFC 8785."""
    with pytest.raises(CanonicalizationError):
        canonicalize_json({"bad": float("nan")})

    with pytest.raises(CanonicalizationError):
        canonicalize_json({"bad": float("inf")})


def test_jcs_unicode_preservation() -> None:
    """Unicode characters must be preserved without unnecessary escaping."""
    data = {"greeting": "Hello, 世界 🚀"}
    canonical = canonicalize_to_str(data)
    assert "世界" in canonical
    assert "🚀" in canonical
