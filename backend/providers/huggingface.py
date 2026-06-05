"""Hugging Face Inference Providers LLM implementation."""

from typing import Any

from backend.core.config import Settings
from backend.core.http import http_client
from backend.providers.base import BaseLLMProvider, LLMResponse


class HuggingFaceProvider(BaseLLMProvider):
    name = "huggingface"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def generate(self, prompt: str, **kwargs: Any) -> LLMResponse:
        if not self.settings.huggingface_api_key:
            raise ValueError("AEGIS_HUGGINGFACE_API_KEY is required for the Hugging Face provider")

        model = kwargs.get("model", "openai/gpt-oss-120b")
        max_tokens = kwargs.get("max_tokens", 1024)
        async with http_client(self.settings) as client:
            response = await client.post(
                "https://router.huggingface.co/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.settings.huggingface_api_key}"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                },
            )

        payload = response.json()
        text = payload["choices"][0]["message"]["content"]
        return LLMResponse(text=text, provider=self.name, metadata={"model": model})
