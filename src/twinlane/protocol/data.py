"""Data Lane content models, data manifests, and SHA-256 integrity binding."""

import hashlib

from pydantic import BaseModel, Field, model_validator

from twinlane.protocol.provenance import Provenance


def compute_content_hash(content: str) -> str:
    """Compute the lowercase hexadecimal SHA-256 digest of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class DataManifestItem(BaseModel):
    """An entry in the cryptographically signed data manifest."""

    item_id: str = Field(..., description="Unique identifier of data item")
    content_hash: str = Field(..., description="SHA-256 digest of item content")

    model_config = {"extra": "forbid"}


class DataItem(BaseModel):
    """A single content item residing in the Data Lane."""

    item_id: str = Field(..., description="Unique identifier within envelope")
    media_type: str = Field(default="text/plain", description="MIME type of content")
    content_hash: str = Field(..., description="SHA-256 digest of content")
    content: str | None = Field(default=None, description="Inline content payload")
    content_ref: str | None = Field(default=None, description="Out-of-band content reference URI")
    provenance: Provenance = Field(..., description="Provenance metadata and security labels")
    schema_id: str | None = Field(default=None, description="Optional schema reference URI")

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_hash_and_payload(self) -> "DataItem":
        """Verify that inline content matches content_hash when content is provided."""
        if self.content is not None:
            actual_hash = compute_content_hash(self.content)
            if actual_hash.lower() != self.content_hash.lower():
                raise ValueError(
                    f"Content hash mismatch for item '{self.item_id}': declared '{self.content_hash}', computed '{actual_hash}'"
                )
        elif self.content_ref is None:
            raise ValueError(
                f"DataItem '{self.item_id}' must provide either 'content' or 'content_ref'"
            )
        return self

    def to_manifest_item(self) -> DataManifestItem:
        """Extract the manifest entry bound into the signed payload."""
        return DataManifestItem(item_id=self.item_id, content_hash=self.content_hash)
