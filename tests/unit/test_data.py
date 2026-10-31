"""Unit tests for DataItem and manifest hashing."""

import pytest
from twinlane.protocol.data import DataItem, compute_content_hash
from twinlane.protocol.provenance import OriginType, Provenance


def test_data_item_valid() -> None:
    """DataItem validates matching hash and creates manifest item."""
    content = "Sample raw document"
    c_hash = compute_content_hash(content)
    prov = Provenance(origin="tool:read_file", origin_type=OriginType.TOOL)

    item = DataItem(
        item_id="d-1",
        content=content,
        content_hash=c_hash,
        provenance=prov,
    )
    assert item.content == content
    manifest_item = item.to_manifest_item()
    assert manifest_item.item_id == "d-1"
    assert manifest_item.content_hash == c_hash


def test_data_item_hash_mismatch_rejected() -> None:
    """DataItem rejects mismatched content and content_hash."""
    prov = Provenance(origin="tool:read_file", origin_type=OriginType.TOOL)
    with pytest.raises(ValueError, match="Content hash mismatch"):
        DataItem(
            item_id="d-bad",
            content="Real text",
            content_hash="0000000000000000000000000000000000000000000000000000000000000000",
            provenance=prov,
        )


def test_data_item_no_content_or_ref_rejected() -> None:
    """DataItem requires either content or content_ref."""
    prov = Provenance(origin="tool:read_file", origin_type=OriginType.TOOL)
    with pytest.raises(ValueError, match="must provide either 'content' or 'content_ref'"):
        DataItem(
            item_id="d-empty",
            content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            provenance=prov,
        )
