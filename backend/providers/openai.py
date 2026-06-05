"""OpenAI LLM provider implementation."""

from typing import Any

from backend.core.config import Settings
from backend.core.http import http_client
from backend.providers.base import BaseLLMProvider, LLMResponse


class OpenAIProvider(BaseLLMProvider):
    name = "openai"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def generate(self, prompt: str, **kwargs: Any) -> LLMResponse:
        if not self.settings.openai_api_key:
            raise ValueError("AEGIS_OPENAI_API_KEY is required for the OpenAI provider")
        model = kwargs.get("model", "gpt-4o-mini")
        async with http_client(self.settings) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.settings.openai_api_key}"},
                json={"model": model, "messages": [{"role": "user", "content": prompt}]},
            )
        payload = response.json()
        text = payload["choices"][0]["message"]["content"]
        return LLMResponse(text=text, provider=self.name, metadata={"model": model})
