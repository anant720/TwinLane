"""Unit tests for Quarantine Reader schema validation and non-promotion invariant."""

import pytest

from twinlane.gate.quarantine import QuarantineReader
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.errors import InvalidSchemaError
from twinlane.protocol.provenance import IntegrityLabel, OriginType, Provenance


def test_quarantine_reader_parsing_and_non_promotion() -> None:
    """QuarantineReader parses JSON and guarantees output retains UNTRUSTED label."""
    reader = QuarantineReader()
    json_content = '{"summary": "Benign document summary", "score": 95}'
    item = DataItem(
        item_id="d-q1",
        media_type="application/json",
        content=json_content,
        content_hash=compute_content_hash(json_content),
        provenance=Provenance(origin="web:https://untrusted.test", origin_type=OriginType.WEB),
    )

    result = reader.process_data_item(item, expected_keys=["summary", "score"])
    assert result.parsed_fields["score"] == 95
    assert result.parsed_fields["summary"] == "Benign document summary"

    # Non-Promotion Invariant check
    assert result.provenance.integrity == IntegrityLabel.UNTRUSTED
    assert result.provenance.origin.startswith("quarantine:")


def test_quarantine_reader_schema_mismatch_rejected() -> None:
    """QuarantineReader rejects outputs missing required schema keys."""
    reader = QuarantineReader()
    json_content = '{"other_key": 123}'
    item = DataItem(
        item_id="d-q2",
        media_type="application/json",
        content=json_content,
        content_hash=compute_content_hash(json_content),
        provenance=Provenance(origin="web:https://untrusted.test", origin_type=OriginType.WEB),
    )

    with pytest.raises(InvalidSchemaError, match="missing expected field"):
        reader.process_data_item(item, expected_keys=["mandatory_field"])
