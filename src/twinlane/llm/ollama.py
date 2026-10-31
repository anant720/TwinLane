"""Local Ollama client using standard HTTP transport."""

from typing import Any

import httpx

from twinlane.llm.base import ChatMessage, LLMClient, LLMResponse
from twinlane.protocol.errors import TwinLaneError


class OllamaClient(LLMClient):
    """Client for local Ollama chat API."""

    def __init__(
        self,
        model_name: str = "llama3:latest",
        base_url: str = "http://localhost:11434",
        timeout: float = 60.0,
    ) -> None:
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate(
        self,
        messages: list[ChatMessage],
        temperature: float = 0.0,
        seed: int | None = 42,
        system_instruction: str | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Call Ollama /api/chat endpoint."""
        url = f"{self.base_url}/api/chat"
        formatted_messages: list[dict[str, str]] = []
        if system_instruction:
            formatted_messages.append({"role": "system", "content": system_instruction})

        for m in messages:
            formatted_messages.append({"role": m.role, "content": m.content})

        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": formatted_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if seed is not None:
            payload["options"]["seed"] = seed
        if json_mode:
            payload["format"] = "json"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, json=payload)
                res.raise_for_status()
                data = res.json()
        except Exception as e:
            raise TwinLaneError(f"Ollama API request failed: {e}") from e

        try:
            content = data["message"]["content"]
            usage = {
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
            }
            return LLMResponse(
                content=content,
                model_name=self.model_name,
                usage=usage,
                raw=data,
            )
        except KeyError as err:
            raise TwinLaneError(f"Malformed Ollama response: {data}") from err
