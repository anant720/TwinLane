"""Intent Catalog definitions, parameter schemas, and validation."""

from typing import Any

from pydantic import BaseModel, Field


class IntentDefinition(BaseModel):
    """Specification of an authorized intent in the Intent Catalog."""

    name: str = Field(..., description="Unique intent identifier (e.g. report_result)")
    description: str = Field(..., description="Human-readable summary of purpose")
    param_types: dict[str, type] = Field(
        default_factory=dict, description="Allowed parameter types"
    )
    required_params: list[str] = Field(
        default_factory=list, description="Mandatory parameter names"
    )
    allowed_params: list[str] = Field(
        default_factory=list, description="All allowed parameter names"
    )

    model_config = {"arbitrary_types_allowed": True}

    def validate_params(self, params: dict[str, Any]) -> None:
        """Validate parameter names and types against this intent definition.

        Raises:
            ValueError: If required parameter is missing or unknown parameter is present.
        """
        for req in self.required_params:
            if req not in params:
                raise ValueError(f"Missing required parameter '{req}' for intent '{self.name}'")

        if self.allowed_params:
            for p in params:
                if p not in self.allowed_params:
                    raise ValueError(f"Unknown parameter '{p}' forbidden for intent '{self.name}'")


class IntentCatalog:
    """Registry of approved intents for agent-to-agent interactions."""

    def __init__(self) -> None:
        self._intents: dict[str, IntentDefinition] = {}

    def register(self, intent: IntentDefinition) -> None:
        """Register a new intent specification."""
        self._intents[intent.name] = intent

    def get(self, name: str) -> IntentDefinition | None:
        """Look up an intent specification."""
        return self._intents.get(name)

    def is_known(self, name: str) -> bool:
        """Check if an intent is registered."""
        return name in self._intents


# Global default intent catalog
default_intent_catalog = IntentCatalog()

default_intent_catalog.register(
    IntentDefinition(
        name="report_result",
        description="Worker reports completed task outcome to orchestrator",
        required_params=["task_id", "status"],
        allowed_params=["task_id", "status", "data_ref"],
    )
)

default_intent_catalog.register(
    IntentDefinition(
        name="fetch_url",
        description="Fetch a remote web page fixture",
        required_params=["url"],
        allowed_params=["url"],
    )
)

default_intent_catalog.register(
    IntentDefinition(
        name="read_file",
        description="Read sandboxed document file",
        required_params=["path"],
        allowed_params=["path"],
    )
)

default_intent_catalog.register(
    IntentDefinition(
        name="send_email",
        description="Send an email to a sandboxed outbox",
        required_params=["recipient", "subject"],
        allowed_params=["recipient", "subject", "body_ref"],
    )
)

default_intent_catalog.register(
    IntentDefinition(
        name="http_post",
        description="Mock HTTP POST request",
        required_params=["url", "payload"],
        allowed_params=["url", "payload"],
    )
)
