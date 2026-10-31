"""YAML Policy file parsing and Pydantic validation."""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from twinlane.protocol.errors import InvalidSchemaError


class ExtractorSpec(BaseModel):
    """Specification of a registered Sanctioned Extractor."""

    id: str
    type: str  # enum | allowlist | regex
    pattern: str | None = None
    allowed_values: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class ParameterRule(BaseModel):
    """Validation and provenance rules for a specific intent parameter."""

    type: str = "string"
    pattern: str | None = None
    enum: list[str] | None = None
    allowlist: list[str] | None = None
    min_value: float | None = None
    max_value: float | None = None
    max_length: int | None = None
    extractor: str | None = None
    provenance_required: str = "TRUSTED"  # TRUSTED | TRUSTED_OR_SANCTIONED

    model_config = {"extra": "forbid"}


class IntentPolicy(BaseModel):
    """Policy rules governing execution of a specific intent."""

    required_capability: str
    allowed_senders: list[str] = Field(default_factory=lambda: ["*"])
    parameters: dict[str, ParameterRule] = Field(default_factory=dict)
    description: str = ""

    model_config = {"extra": "forbid"}


class PolicyDefaults(BaseModel):
    """Global operational default constraints."""

    max_envelope_size_bytes: int = 1_048_576
    max_json_depth: int = 10
    default_ttl_seconds: int = 60
    max_clock_skew_seconds: int = 30

    model_config = {"extra": "forbid"}


class PolicyConfig(BaseModel):
    """Root configuration object loaded from YAML policy file."""

    version: str = "1.0"
    mode: str = "balanced"  # strict | balanced | observe
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    extractors: list[ExtractorSpec] = Field(default_factory=list)
    intents: dict[str, IntentPolicy] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


def load_policy_from_str(yaml_content: str) -> PolicyConfig:
    """Parse PolicyConfig from YAML string."""
    try:
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            raise InvalidSchemaError("Policy YAML must define a root mapping")
        return PolicyConfig.model_validate(data)
    except Exception as e:
        if isinstance(e, InvalidSchemaError):
            raise
        raise InvalidSchemaError(f"Failed to load policy YAML: {e}") from e


def load_policy_from_yaml(path: str | Path) -> PolicyConfig:
    """Load and parse PolicyConfig from a file path."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")
    return load_policy_from_str(p.read_text(encoding="utf-8"))
