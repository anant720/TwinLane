"""Google Gemini API client using standard HTTP transport."""

import os
from typing import Any

import httpx

from twinlane.llm.base import ChatMessage, LLMClient, LLMResponse
from twinlane.protocol.errors import TwinLaneError


class GeminiClient(LLMClient):
    """Client for Google Gemini REST API."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gemini-1.5-flash",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model_name = model_name
        self.timeout = timeout
        self.endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        )

    def generate(
        self,
        messages: list[ChatMessage],
        temperature: float = 0.0,
        seed: int | None = 42,
        system_instruction: str | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Call Gemini generateContent endpoint."""
        if not self.api_key:
            raise TwinLaneError(
                "GEMINI_API_KEY not configured. Set the environment variable or use MockLLMClient."
            )

        contents: list[dict[str, Any]] = []
        for m in messages:
            role = "model" if m.role == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": m.content}]})

        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
            },
        }

        if seed is not None:
            payload["generationConfig"]["seed"] = seed
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"
        if system_instruction:
            payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

        url = f"{self.endpoint}?key={self.api_key}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, json=payload)
                res.raise_for_status()
                data = res.json()
        except Exception as e:
            raise TwinLaneError(f"Gemini API request failed: {e}") from e

        try:
            candidate = data["candidates"][0]
            text = candidate["content"]["parts"][0]["text"]
            usage_raw = data.get("usageMetadata", {})
            usage = {
                "prompt_tokens": usage_raw.get("promptTokenCount", 0),
                "completion_tokens": usage_raw.get("candidatesTokenCount", 0),
            }
            return LLMResponse(
                content=text,
                model_name=self.model_name,
                usage=usage,
                raw=data,
            )
        except (KeyError, IndexError) as err:
            raise TwinLaneError(f"Malformed Gemini API response: {data}") from err
