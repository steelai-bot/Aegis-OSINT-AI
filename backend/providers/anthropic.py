"""Anthropic LLM provider implementation."""

from typing import Any

from backend.core.config import Settings
from backend.core.http import http_client
from backend.providers.base import BaseLLMProvider, LLMResponse


class AnthropicProvider(BaseLLMProvider):
    name = "anthropic"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def generate(self, prompt: str, **kwargs: Any) -> LLMResponse:
        if not self.settings.anthropic_api_key:
            raise ValueError("AEGIS_ANTHROPIC_API_KEY is required for the Anthropic provider")
        model = kwargs.get("model", "claude-3-5-haiku-latest")
        async with http_client(self.settings) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": self.settings.anthropic_api_key, "anthropic-version": "2023-06-01"},
                json={"model": model, "max_tokens": kwargs.get("max_tokens", 1024), "messages": [{"role": "user", "content": prompt}]},
            )
        payload = response.json()
        text = "".join(block.get("text", "") for block in payload.get("content", []))
        return LLMResponse(text=text, provider=self.name, metadata={"model": model})
