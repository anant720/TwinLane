"""Gate and policy decision enumerations and results."""

from enum import StrEnum

from pydantic import BaseModel, Field


class Decision(StrEnum):
    """Possible outcomes of the TwinLane Gate verification pipeline."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class GateDecision(BaseModel):
    """Structured decision outcome produced by the Gate."""

    decision: Decision = Field(..., description="ALLOW, DENY, or ESCALATE")
    reason: str = Field(default="", description="Summary explanation of decision")
    step_failed: int | None = Field(
        default=None, description="Pipeline step index where rejection occurred (1-7)"
    )
    violations: list[str] = Field(
        default_factory=list, description="Detailed list of failed validation rules"
    )

    model_config = {"extra": "forbid"}

    @classmethod
    def allow(cls, reason: str = "Authorized") -> "GateDecision":
        """Factory for ALLOW decision."""
        return cls(decision=Decision.ALLOW, reason=reason)

    @classmethod
    def deny(
        cls, reason: str, step: int | None = None, violations: list[str] | None = None
    ) -> "GateDecision":
        """Factory for DENY decision."""
        return cls(
            decision=Decision.DENY,
            reason=reason,
            step_failed=step,
            violations=violations or [],
        )

    @classmethod
    def escalate(cls, reason: str, violations: list[str] | None = None) -> "GateDecision":
        """Factory for ESCALATE decision."""
        return cls(
            decision=Decision.ESCALATE,
            reason=reason,
            violations=violations or [],
        )
