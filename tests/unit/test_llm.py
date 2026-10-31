"""Unit tests for LLM abstraction and mock/live clients."""

import pytest

from twinlane.llm.base import ChatMessage
from twinlane.llm.gemini import GeminiClient
from twinlane.llm.mock import MockLLMClient
from twinlane.llm.ollama import OllamaClient
from twinlane.protocol.errors import TwinLaneError


def test_mock_llm_client() -> None:
    """Test deterministic mock LLM with rules and history tracking."""
    client = MockLLMClient(default_response="Default summary")

    client.add_rule("summarize", "This is a summary of the text.")
    client.add_rule(
        "malicious prompt", '{"action": "send_email", "args": {"recipient": "bad@evil.test"}}'
    )

    # 1. Matching rule 1
    res1 = client.generate([ChatMessage(role="user", content="Please summarize this document.")])
    assert res1.content == "This is a summary of the text."
    assert res1.model_name == "mock-model-v1"

    # 2. Matching malicious prompt rule
    res2 = client.generate([ChatMessage(role="user", content="Here is a malicious prompt for you")])
    assert "send_email" in res2.content

    # 3. Default fallback
    res3 = client.generate([ChatMessage(role="user", content="Unrecognized input")])
    assert res3.content == "Default summary"

    assert len(client.call_history) == 3


def test_gemini_client_missing_key() -> None:
    """Test Gemini client error when API key is missing."""
    client = GeminiClient(api_key="")
    with pytest.raises(TwinLaneError, match="GEMINI_API_KEY not configured"):
        client.generate([ChatMessage(role="user", content="Hello")])


def test_gemini_client_success_and_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test Gemini client successful payload parsing and error handling."""
    client = GeminiClient(api_key="fake-test-key")

    class MockResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {
                "candidates": [{"content": {"parts": [{"text": "Gemini generated text"}]}}],
                "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 8},
            }

    class MockHttpClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "MockHttpClient":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def post(self, _url: str, **_kwargs: object) -> MockResponse:
            return MockResponse()

    monkeypatch.setattr("httpx.Client", MockHttpClient)

    res = client.generate(
        [ChatMessage(role="user", content="Hello")],
        temperature=0.7,
        seed=100,
        system_instruction="Be concise",
        json_mode=True,
    )
    assert res.content == "Gemini generated text"
    assert res.usage["prompt_tokens"] == 12


def test_ollama_client_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test Ollama client successful payload parsing."""
    client = OllamaClient(model_name="llama3")

    class MockResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {
                "message": {"content": "Ollama response"},
                "prompt_eval_count": 20,
                "eval_count": 15,
            }

    class MockHttpClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "MockHttpClient":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def post(self, _url: str, **_kwargs: object) -> MockResponse:
            return MockResponse()

    monkeypatch.setattr("httpx.Client", MockHttpClient)

    res = client.generate(
        [ChatMessage(role="user", content="Test")],
        temperature=0.2,
        seed=42,
        system_instruction="System",
        json_mode=True,
    )
    assert res.content == "Ollama response"
    assert res.usage["prompt_tokens"] == 20
