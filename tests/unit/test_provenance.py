"""Unit tests for provenance models and label joins."""

from twinlane.protocol.provenance import (
    ConfidentialityLabel,
    IntegrityLabel,
    OriginType,
    Provenance,
    join_confidentiality,
    join_integrity,
)


def test_integrity_join_rules() -> None:
    """Integrity join results in least upper bound (UNTRUSTED if any input is untrusted)."""
    assert join_integrity([]) == IntegrityLabel.TRUSTED
    assert join_integrity([IntegrityLabel.TRUSTED]) == IntegrityLabel.TRUSTED
    assert (
        join_integrity([IntegrityLabel.TRUSTED, IntegrityLabel.EXTRACTED_UNTRUSTED])
        == IntegrityLabel.EXTRACTED_UNTRUSTED
    )
    assert (
        join_integrity(
            [
                IntegrityLabel.TRUSTED,
                IntegrityLabel.EXTRACTED_UNTRUSTED,
                IntegrityLabel.UNTRUSTED,
            ]
        )
        == IntegrityLabel.UNTRUSTED
    )


def test_confidentiality_join_rules() -> None:
    """Confidentiality join selects the maximum label in lattice."""
    assert join_confidentiality([]) == ConfidentialityLabel.PUBLIC
    assert (
        join_confidentiality([ConfidentialityLabel.PUBLIC, ConfidentialityLabel.INTERNAL])
        == ConfidentialityLabel.INTERNAL
    )
    assert (
        join_confidentiality(
            [
                ConfidentialityLabel.PUBLIC,
                ConfidentialityLabel.SECRET,
                ConfidentialityLabel.INTERNAL,
            ]
        )
        == ConfidentialityLabel.SECRET
    )


def test_provenance_model_defaults() -> None:
    """Provenance initializes with secure defaults (UNTRUSTED, PUBLIC)."""
    prov = Provenance(origin="web:https://example.test")
    assert prov.origin_type == OriginType.UNKNOWN
    assert prov.integrity == IntegrityLabel.UNTRUSTED
    assert prov.confidentiality == ConfidentialityLabel.PUBLIC
    assert prov.chain == []
