"""LLM Client interface and abstractions."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """A single chat message exchanged with an LLM."""

    role: str  # "system" | "user" | "assistant"
    content: str

    model_config = {"extra": "forbid"}


class LLMResponse(BaseModel):
    """The generated response from an LLM call."""

    content: str
    model_name: str
    usage: dict[str, int] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class LLMClient(ABC):
    """Abstract interface for LLM completions."""

    @abstractmethod
    def generate(
        self,
        messages: list[ChatMessage],
        temperature: float = 0.0,
        seed: int | None = 42,
        system_instruction: str | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Generate a response synchronously from the model."""
        pass
