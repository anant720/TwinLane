"""Provenance metadata models and information-flow security label lattices."""

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, Field


class IntegrityLabel(StrEnum):
    """Integrity security labels for information flow control."""

    TRUSTED = "TRUSTED"
    EXTRACTED_UNTRUSTED = "EXTRACTED_UNTRUSTED"
    UNTRUSTED = "UNTRUSTED"


class ConfidentialityLabel(StrEnum):
    """Confidentiality security labels for information flow control."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SECRET = "SECRET"


class OriginType(StrEnum):
    """Origin categories for content items."""

    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    WEB = "web"
    UNKNOWN = "unknown"


# Strict ordering for lattice joins
_CONFIDENTIALITY_ORDER: dict[ConfidentialityLabel, int] = {
    ConfidentialityLabel.PUBLIC: 0,
    ConfidentialityLabel.INTERNAL: 1,
    ConfidentialityLabel.SECRET: 2,
}


def join_integrity(labels: Iterable[IntegrityLabel]) -> IntegrityLabel:
    """Compute the least upper bound (join) of multiple integrity labels.

    Lattice rule:
    If any input is UNTRUSTED, output is UNTRUSTED.
    Else if any input is EXTRACTED_UNTRUSTED, output is EXTRACTED_UNTRUSTED.
    Else TRUSTED.
    """
    labels_list = list(labels)
    if not labels_list:
        return IntegrityLabel.TRUSTED

    if any(lbl == IntegrityLabel.UNTRUSTED for lbl in labels_list):
        return IntegrityLabel.UNTRUSTED
    if any(lbl == IntegrityLabel.EXTRACTED_UNTRUSTED for lbl in labels_list):
        return IntegrityLabel.EXTRACTED_UNTRUSTED
    return IntegrityLabel.TRUSTED


def join_confidentiality(labels: Iterable[ConfidentialityLabel]) -> ConfidentialityLabel:
    """Compute the least upper bound (join) of multiple confidentiality labels.

    Lattice rule: max(confidentiality) where SECRET > INTERNAL > PUBLIC.
    """
    labels_list = list(labels)
    if not labels_list:
        return ConfidentialityLabel.PUBLIC

    max_val = max(labels_list, key=lambda lbl: _CONFIDENTIALITY_ORDER[lbl])
    return max_val


class Provenance(BaseModel):
    """Provenance tracking metadata for data-lane content items."""

    origin: str = Field(
        ..., description="URI or descriptor of origin (e.g., web:https://..., tool:read_file)"
    )
    origin_type: OriginType = Field(default=OriginType.UNKNOWN, description="Category of origin")
    chain: list[str] = Field(
        default_factory=list,
        description="Array of agent identity fingerprints that processed this item",
    )
    integrity: IntegrityLabel = Field(
        default=IntegrityLabel.UNTRUSTED, description="Integrity security classification"
    )
    confidentiality: ConfidentialityLabel = Field(
        default=ConfidentialityLabel.PUBLIC, description="Confidentiality classification"
    )

    model_config = {"extra": "forbid"}
