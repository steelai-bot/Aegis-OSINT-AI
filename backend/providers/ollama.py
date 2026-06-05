"""Ollama LLM provider implementation."""

from typing import Any

from backend.core.config import Settings
from backend.core.http import http_client
from backend.providers.base import BaseLLMProvider, LLMResponse


class OllamaProvider(BaseLLMProvider):
    name = "ollama"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def generate(self, prompt: str, **kwargs: Any) -> LLMResponse:
        model = kwargs.get("model", "llama3.1")
        async with http_client(self.settings) as client:
            response = await client.post(
                f"{self.settings.ollama_base_url.rstrip('/')}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
        payload = response.json()
        return LLMResponse(text=payload.get("response", ""), provider=self.name, metadata={"model": model})
