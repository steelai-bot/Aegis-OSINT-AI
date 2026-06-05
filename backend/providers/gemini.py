"""Gemini LLM provider implementation."""

from typing import Any

from backend.core.config import Settings
from backend.core.http import http_client
from backend.providers.base import BaseLLMProvider, LLMResponse


class GeminiProvider(BaseLLMProvider):
    name = "gemini"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def generate(self, prompt: str, **kwargs: Any) -> LLMResponse:
        if not self.settings.gemini_api_key:
            raise ValueError("AEGIS_GEMINI_API_KEY is required for the Gemini provider")
        model = kwargs.get("model", "gemini-1.5-flash")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        async with http_client(self.settings) as client:
            response = await client.post(
                url,
                params={"key": self.settings.gemini_api_key},
                json={"contents": [{"parts": [{"text": prompt}]}]},
            )
        payload = response.json()
        text = payload["candidates"][0]["content"]["parts"][0]["text"]
        return LLMResponse(text=text, provider=self.name, metadata={"model": model})
