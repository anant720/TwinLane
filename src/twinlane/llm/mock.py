"""Deterministic mock LLM client for testing and offline benchmarking."""

import re
from collections.abc import Callable

from twinlane.llm.base import ChatMessage, LLMClient, LLMResponse


class MockLLMClient(LLMClient):
    """Deterministic LLM mock that responds with configured scripts or rule-based generators."""

    def __init__(
        self,
        default_response: str = '{"summary": "Mock summary"}',
        rules: list[tuple[str | re.Pattern[str], str | Callable[[list[ChatMessage]], str]]]
        | None = None,
        model_name: str = "mock-model-v1",
    ) -> None:
        self.default_response = default_response
        self.rules = rules or []
        self.model_name = model_name
        self.call_history: list[list[ChatMessage]] = []

    def add_rule(
        self,
        pattern: str | re.Pattern[str],
        response: str | Callable[[list[ChatMessage]], str],
    ) -> None:
        """Register a pattern-based rule for responses."""
        self.rules.append((pattern, response))

    def generate(
        self,
        messages: list[ChatMessage],
        temperature: float = 0.0,
        seed: int | None = 42,
        system_instruction: str | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Generate response matching the last user message or rule."""
        _ = (temperature, seed, json_mode)
        self.call_history.append(list(messages))

        all_text = " ".join(m.content for m in messages)
        if system_instruction:
            all_text = f"{system_instruction} {all_text}"

        for pattern, handler in self.rules:
            matched = False
            if isinstance(pattern, re.Pattern):
                matched = bool(pattern.search(all_text))
            else:
                matched = pattern.lower() in all_text.lower()

            if matched:
                content = handler(messages) if callable(handler) else handler
                return LLMResponse(
                    content=content,
                    model_name=self.model_name,
                    usage={
                        "prompt_tokens": len(all_text.split()),
                        "completion_tokens": len(content.split()),
                    },
                )

        return LLMResponse(
            content=self.default_response,
            model_name=self.model_name,
            usage={
                "prompt_tokens": len(all_text.split()),
                "completion_tokens": len(self.default_response.split()),
            },
        )
