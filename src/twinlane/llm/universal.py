"""Universal LLM client supporting OpenAI, Gemini, Anthropic, Groq, OpenRouter, and Ollama."""

import os
import time
from typing import Any, Literal

import httpx

from twinlane.llm.base import ChatMessage, LLMClient, LLMResponse
from twinlane.protocol.errors import TwinLaneError

ProviderType = Literal[
    "openai",
    "gemini",
    "anthropic",
    "groq",
    "openrouter",
    "ollama",
    "custom",
]

DEFAULT_ENDPOINTS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
    "anthropic": "https://api.anthropic.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://localhost:11434/v1",
}

DEFAULT_MODELS: dict[str, str] = {
    "openai": "gpt-4o-mini",
    "gemini": "gemini-1.5-flash",
    "anthropic": "claude-3-5-haiku-20241022",
    "groq": "llama-3.3-70b-versatile",
    "openrouter": "google/gemini-flash-1.5",
    "ollama": "llama3:latest",
    "custom": "default",
}


class UniversalLLMClient(LLMClient):
    """Multi-provider LLM client for live adversarial evaluation."""

    def __init__(
        self,
        provider: ProviderType = "openai",
        api_key: str | None = None,
        model_name: str | None = None,
        base_url: str | None = None,
        timeout: float = 45.0,
    ) -> None:
        self.provider = provider
        self.api_key = api_key or os.environ.get(f"{provider.upper()}_API_KEY", "")
        self.model_name = model_name or DEFAULT_MODELS.get(provider, "gpt-4o-mini")
        self.base_url = (base_url or DEFAULT_ENDPOINTS.get(provider, "https://api.openai.com/v1")).rstrip("/")
        self.timeout = timeout

    def generate(
        self,
        messages: list[ChatMessage],
        temperature: float = 0.0,
        seed: int | None = 42,
        system_instruction: str | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Dispatch generation request to the selected provider."""
        t0 = time.perf_counter()

        if self.provider == "gemini":
            res = self._call_gemini(messages, temperature, seed, system_instruction, json_mode)
        elif self.provider == "anthropic":
            res = self._call_anthropic(messages, temperature, system_instruction)
        else:
            # OpenAI and OpenAI-compatible providers (Groq, OpenRouter, Ollama /v1, Custom)
            res = self._call_openai_compatible(messages, temperature, seed, system_instruction, json_mode)

        latency_ms = (time.perf_counter() - t0) * 1000.0
        res.usage["latency_ms"] = int(latency_ms)
        return res

    def _call_openai_compatible(
        self,
        messages: list[ChatMessage],
        temperature: float,
        seed: int | None,
        system_instruction: str | None,
        json_mode: bool,
    ) -> LLMResponse:
        """Call standard OpenAI /chat/completions API format."""
        formatted: list[dict[str, str]] = []
        if system_instruction:
            formatted.append({"role": "system", "content": system_instruction})
        for m in messages:
            formatted.append({"role": m.role, "content": m.content})

        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": formatted,
            "temperature": temperature,
        }
        if seed is not None:
            payload["seed"] = seed
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        url = f"{self.base_url}/chat/completions"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            detail = e.response.text[:300] if e.response is not None else str(e)
            raise TwinLaneError(f"Provider '{self.provider}' returned HTTP {e.response.status_code}: {detail}") from e
        except Exception as e:
            raise TwinLaneError(f"Connection to '{self.provider}' ({url}) failed: {e}") from e

        choices = data.get("choices", [])
        if not choices:
            raise TwinLaneError(f"No response choices returned by '{self.provider}': {data}")

        content = choices[0].get("message", {}).get("content", "") or ""
        usage_data = data.get("usage", {})
        usage: dict[str, int] = {
            "prompt_tokens": int(usage_data.get("prompt_tokens", 0)),
            "completion_tokens": int(usage_data.get("completion_tokens", 0)),
            "total_tokens": int(usage_data.get("total_tokens", 0)),
        }
        return LLMResponse(content=content, model_name=self.model_name, usage=usage, raw=data)

    def _call_gemini(
        self,
        messages: list[ChatMessage],
        temperature: float,
        seed: int | None,
        system_instruction: str | None,
        json_mode: bool,
    ) -> LLMResponse:
        """Call Google Gemini generateContent REST endpoint."""
        if not self.api_key:
            raise TwinLaneError("Gemini API Key is required. Please provide a valid Gemini key.")

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

        url = f"{self.base_url}/models/{self.model_name}:generateContent?key={self.api_key}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            detail = e.response.text[:300] if e.response is not None else str(e)
            raise TwinLaneError(f"Gemini API returned HTTP {e.response.status_code}: {detail}") from e
        except Exception as e:
            raise TwinLaneError(f"Gemini API request failed: {e}") from e

        try:
            candidate = data["candidates"][0]
            text = candidate["content"]["parts"][0]["text"]
            usage_raw = data.get("usageMetadata", {})
            usage: dict[str, int] = {
                "prompt_tokens": int(usage_raw.get("promptTokenCount", 0)),
                "completion_tokens": int(usage_raw.get("candidatesTokenCount", 0)),
                "total_tokens": int(usage_raw.get("totalTokenCount", 0)),
            }
            return LLMResponse(content=text, model_name=self.model_name, usage=usage, raw=data)
        except (KeyError, IndexError) as e:
            raise TwinLaneError(f"Invalid Gemini response structure: {data}") from e

    def _call_anthropic(
        self,
        messages: list[ChatMessage],
        temperature: float,
        system_instruction: str | None,
    ) -> LLMResponse:
        """Call Anthropic Claude messages API."""
        if not self.api_key:
            raise TwinLaneError("Anthropic API Key is required. Please provide a valid Anthropic key.")

        formatted_messages: list[dict[str, str]] = []
        for m in messages:
            formatted_messages.append({"role": m.role, "content": m.content})

        headers: dict[str, str] = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": formatted_messages,
            "max_tokens": 1024,
            "temperature": temperature,
        }
        if system_instruction:
            payload["system"] = system_instruction

        url = f"{self.base_url}/messages"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            detail = e.response.text[:300] if e.response is not None else str(e)
            raise TwinLaneError(f"Anthropic returned HTTP {e.response.status_code}: {detail}") from e
        except Exception as e:
            raise TwinLaneError(f"Anthropic API request failed: {e}") from e

        content_parts = data.get("content", [])
        text = "".join(part.get("text", "") for part in content_parts if part.get("type") == "text")
        usage_raw = data.get("usage", {})
        usage: dict[str, int] = {
            "prompt_tokens": int(usage_raw.get("input_tokens", 0)),
            "completion_tokens": int(usage_raw.get("output_tokens", 0)),
            "total_tokens": int(usage_raw.get("input_tokens", 0) + usage_raw.get("output_tokens", 0)),
        }
        return LLMResponse(content=text, model_name=self.model_name, usage=usage, raw=data)
