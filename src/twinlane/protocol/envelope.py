"""TwinLane Wire Envelope models, serialization, and canonical payload generation."""

import json
import secrets
import time
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from twinlane.protocol.canonical import canonicalize_json
from twinlane.protocol.control import ControlLane
from twinlane.protocol.data import DataItem, DataManifestItem
from twinlane.protocol.errors import OversizeMessageError, ProtocolError
from twinlane.protocol.version import PROTOCOL_VERSION, is_version_supported

DEFAULT_MAX_ENVELOPE_BYTES: int = 1_048_576  # 1 MB


class Header(BaseModel):
    """Envelope header providing identity, session, and replay protection metadata."""

    version: int = Field(default=PROTOCOL_VERSION, description="Protocol version number")
    msg_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique message UUID")
    session_id: str = Field(..., description="Conversational session UUID")
    sender: str = Field(..., description="Sender public key fingerprint (ed25519:<hex>)")
    recipient: str = Field(..., description="Recipient public key fingerprint")
    seq: int = Field(..., ge=1, description="Monotonically increasing sequence counter per session")
    nonce: str = Field(
        default_factory=lambda: secrets.token_hex(16),
        description="128-bit cryptographically random hex nonce",
    )
    issued_at: int = Field(
        default_factory=lambda: int(time.time()),
        description="Unix timestamp (seconds) of issue",
    )
    expires_at: int = Field(
        default_factory=lambda: int(time.time()) + 60,
        description="Unix timestamp (seconds) of expiration",
    )

    model_config = {"extra": "forbid"}

    @field_validator("version")
    @classmethod
    def check_version(cls, v: int) -> int:
        if not is_version_supported(v):
            raise ValueError(f"Unsupported protocol version: {v}")
        return v

    @field_validator("nonce")
    @classmethod
    def check_nonce_length(cls, v: str) -> str:
        if len(v) < 16:
            raise ValueError("Nonce must be at least 16 hex characters (64-bit entropy minimum)")
        return v


class Signature(BaseModel):
    """Cryptographic signature object binding header, control lane, and data manifest."""

    alg: str = Field(default="Ed25519", description="Signature algorithm identifier")
    signer: str = Field(..., description="Signer identity fingerprint")
    signature_bytes: str = Field(
        ..., description="Hexadecimal-encoded Ed25519 signature (64 bytes / 128 hex chars)"
    )
    signed_manifest: list[DataManifestItem] = Field(
        default_factory=list, description="Array of item_id and content_hash pairs"
    )

    model_config = {"extra": "forbid"}


class Envelope(BaseModel):
    """The complete TwinLane wire envelope."""

    header: Header = Field(..., description="Envelope header")
    control: ControlLane = Field(..., description="Control Lane command intent")
    data: list[DataItem] = Field(
        default_factory=list, description="Data Lane passive content items"
    )
    signature: Signature | None = Field(
        default=None, description="Optional signature before signing, required at gate"
    )

    model_config = {"extra": "forbid"}

    def get_data_manifest(self) -> list[DataManifestItem]:
        """Generate the Data Manifest list from data items."""
        return [item.to_manifest_item() for item in self.data]

    def get_signable_payload(self) -> dict[str, Any]:
        """Construct the canonical signable dictionary {header, control, data_manifest}."""
        manifest = self.get_data_manifest()
        return {
            "header": self.header.model_dump(mode="json"),
            "control": self.control.model_dump(mode="json"),
            "data_manifest": [m.model_dump(mode="json") for m in manifest],
        }

    def get_canonical_bytes(self) -> bytes:
        """Serialize signable payload into deterministic RFC 8785 canonical JSON bytes."""
        return canonicalize_json(self.get_signable_payload())

    def to_json(self) -> str:
        """Serialize the complete envelope to a JSON string."""
        return json.dumps(self.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str, max_bytes: int = DEFAULT_MAX_ENVELOPE_BYTES) -> "Envelope":
        """Parse an envelope from a JSON string with byte size limits.

        Raises:
            OversizeMessageError: If string length exceeds max_bytes.
            ProtocolError: If JSON parsing or schema validation fails.
        """
        raw_bytes = json_str.encode("utf-8")
        if len(raw_bytes) > max_bytes:
            raise OversizeMessageError(
                f"Envelope size ({len(raw_bytes)} bytes) exceeds maximum limit ({max_bytes} bytes)"
            )

        try:
            parsed = json.loads(json_str)
            return cls.model_validate(parsed)
        except Exception as e:
            if isinstance(e, ProtocolError):
                raise
            raise ProtocolError(f"Failed to parse TwinLane envelope: {e}") from e
