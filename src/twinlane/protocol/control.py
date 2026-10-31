"""Control Lane intent models, schema parameters, and validation."""

from typing import Any

from pydantic import BaseModel, Field, field_validator


class ControlLane(BaseModel):
    """The Control Lane conveying structured, typed command intents.

    Free-text instructions are strictly prohibited in the control lane.
    Every control message must reference a valid capability token.
    """

    intent: str = Field(..., description="Intent identifier from agreed Intent Catalog")
    params: dict[str, Any] = Field(
        default_factory=dict, description="Typed parameters conforming to intent schema"
    )
    capability_token_id: str = Field(
        ..., description="Reference ID of authorizing capability token"
    )

    model_config = {"extra": "forbid"}

    @field_validator("intent")
    @classmethod
    def validate_intent_name(cls, v: str) -> str:
        """Ensure intent name is a clean identifier."""
        if not v or not v.strip():
            raise ValueError("Intent name cannot be empty")
        # Enforce clean snake_case or alphanumeric with underscores/hyphens
        for char in v:
            if not (char.isalnum() or char in "_-"):
                raise ValueError(f"Invalid character '{char}' in intent '{v}'")
        return v
