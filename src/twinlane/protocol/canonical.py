"""RFC 8785 JSON Canonicalization Scheme (JCS) implementation.

Ensures identical byte serialization of JSON structures across different runtimes
for deterministic cryptographic hashing and digital signatures.
"""

import json
import math
from enum import Enum
from typing import Any
from uuid import UUID

from twinlane.protocol.errors import CanonicalizationError


def _normalize_value(val: Any) -> Any:
    """Recursively normalize complex Python objects into JSON primitives for JCS."""
    if val is None or isinstance(val, (bool, str, int)):
        return val
    elif isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            raise CanonicalizationError(
                f"NaN and Infinity are not permitted in RFC 8785 JSON: {val}"
            )
        # RFC 8785 requires -0.0 to serialize as 0
        if val == 0.0:
            return 0
        # If float represents an exact integer within safe range, serialize cleanly
        if val.is_integer() and -9007199254740991 <= int(val) <= 9007199254740991:
            return int(val)
        return val
    elif isinstance(val, Enum):
        return val.value
    elif isinstance(val, UUID):
        return str(val)
    elif hasattr(val, "model_dump"):
        # Pydantic v2 model
        return _normalize_value(val.model_dump(mode="json"))
    elif hasattr(val, "dict"):
        # Pydantic v1 model fallback
        return _normalize_value(val.dict())
    elif isinstance(val, (list, tuple)):
        return [_normalize_value(item) for item in val]
    elif isinstance(val, dict):
        # Sort dictionary keys by UTF-16 code units (equivalent to string sorting in Python)
        return {
            str(k): _normalize_value(v)
            for k, v in sorted(val.items(), key=lambda item: str(item[0]))
        }
    elif isinstance(val, (bytes, bytearray)):
        return val.hex()
    else:
        raise CanonicalizationError(
            f"Unsupported data type for canonicalization: {type(val).__name__}"
        )


def canonicalize_json(data: Any) -> bytes:
    """Serialize a Python data structure to deterministic RFC 8785 canonical JSON bytes.

    Args:
        data: Arbitrary dictionary, list, primitive, or Pydantic model.

    Returns:
        UTF-8 encoded canonical JSON bytes.

    Raises:
        CanonicalizationError: If data contains non-canonicalizable types.
    """
    try:
        normalized = _normalize_value(data)
        canonical_str = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        return canonical_str.encode("utf-8")
    except Exception as e:
        if isinstance(e, CanonicalizationError):
            raise
        raise CanonicalizationError(f"Failed to canonicalize JSON: {e}") from e


def canonicalize_to_str(data: Any) -> str:
    """Serialize a Python data structure to deterministic RFC 8785 canonical JSON string."""
    return canonicalize_json(data).decode("utf-8")
