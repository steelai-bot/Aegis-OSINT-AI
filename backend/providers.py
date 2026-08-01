"""
AI Provider Integrations
Supports OpenRouter, OpenAI, Anthropic, Gemini, NVIDIA NIM, Groq, and Mistral.
"""

import os
from typing import Any

import httpx
from pydantic import BaseModel

from backend.http_client import SharedHTTPClient


class AIResponse(BaseModel):
    content: str
    provider: str
    model: str


class AIProvider:
    """Base class for AI providers."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._default_model: str | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        return await SharedHTTPClient().get_client()

    async def chat(self, prompt: str, model: str) -> AIResponse:
        raise NotImplementedError

    async def chat_multimodal(
        self,
        text: str,
        model: str,
        image_urls: list[str] | None = None,
        video_urls: list[str] | None = None,
    ) -> AIResponse:
        """Send a multimodal request (text + optional images/video).

        Default implementation falls back to text-only chat.
        Override in providers that support vision/multimodal inputs.
        """
        return await self.chat(text, model)


class OpenRouterProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "Aegis OSINT AI",
        }
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
        client = await self._get_client()
        resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
        return AIResponse(
            content=data["choices"][0]["message"]["content"], provider="openrouter", model=model
        )


class OpenAIProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
        client = await self._get_client()
        resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
        return AIResponse(
            content=data["choices"][0]["message"]["content"], provider="openai", model=model
        )


class AnthropicProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        client = await self._get_client()
        resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
        return AIResponse(content=data["content"][0]["text"], provider="anthropic", model=model)


class GeminiProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        client = await self._get_client()
        resp = await client.post(url, json=payload, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
        return AIResponse(
            content=data["candidates"][0]["content"]["parts"][0]["text"],
            provider="gemini",
            model=model,
        )


class NvidiaProvider(AIProvider):
    """
    NVIDIA NIM provider with support for MiniMax-M3 and other models.

    MiniMax-M3 is multimodal. To send images or video, set a message's
    "content" to an array of parts (a public URL or a base64 data URI):
        messages: [{ role: "user", content: [
            { type: "text", text: "Describe this." },
            { type: "image_url", image_url: { url: "https://example.com/image.jpg" } },
            { type: "video_url", video_url: { url: "https://example.com/video.mp4" } },
        ]}]
    """

    DEFAULT_MODEL = "minimaxai/minimax-m3"

    async def chat(self, prompt: str, model: str) -> AIResponse:
        return await self._make_request(model, prompt)

    async def chat_multimodal(
        self,
        text: str,
        model: str,
        image_urls: list[str] | None = None,
        video_urls: list[str] | None = None,
    ) -> AIResponse:
        """Send a multimodal request with text + optional images/video."""
        content_parts: list[dict[str, Any]] = [{"type": "text", "text": text}]

        if image_urls:
            for url in image_urls:
                content_parts.append({"type": "image_url", "image_url": {"url": url}})

        if video_urls:
            for url in video_urls:
                content_parts.append({"type": "video_url", "video_url": {"url": url}})

        return await self._make_request(model, content_parts)

    async def _make_request(self, model: str, content: str | list[dict[str, Any]]) -> AIResponse:
        url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": content}],
            "max_tokens": 8192,
            "temperature": 1.00,
            "top_p": 0.95,
        }
        client = await self._get_client()
        resp = await client.post(url, headers=headers, json=payload, timeout=60.0)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("choices"):
            return AIResponse(
                content=f"NVIDIA API returned empty response. The model '{model}' may not be provisioned for this account.",
                provider="nvidia",
                model=model,
            )
        return AIResponse(
            content=data["choices"][0]["message"]["content"], provider="nvidia", model=model
        )


class GroqProvider(AIProvider):
    """Groq AI provider using OpenAI-compatible API."""

    DEFAULT_MODEL = "llama3-8b-8192"

    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
        }

        client = await self._get_client()
        resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
        return AIResponse(
            content=data["choices"][0]["message"]["content"], provider="groq", model=model
        )


class MistralProvider(AIProvider):
    """Mistral AI provider using OpenAI-compatible API."""

    DEFAULT_MODEL = "mistral-small-latest"

    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://api.mistral.ai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
        }

        client = await self._get_client()
        resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
        return AIResponse(
            content=data["choices"][0]["message"]["content"], provider="mistral", model=model
        )


class AIProviderFactory:
    @staticmethod
    def get_provider(provider_name: str) -> AIProvider | None:
        # Map provider IDs to env var names (some share the same key)
        key_map = {
            "openrouter": "OPENROUTER_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "gemini": "GEMINI_API_KEY",
            "nvidia": "NVIDIA_API_KEY",
            "nvidia-minimax": "NVIDIA_API_KEY",
            "groq": "GROQ_API_KEY",
            "mistral": "MISTRAL_API_KEY",
        }

        env_key = key_map.get(provider_name.lower())
        if not env_key:
            return None

        key = os.getenv(env_key)
        if not key:
            return None

        providers = {
            "openrouter": (OpenRouterProvider, None),
            "openai": (OpenAIProvider, None),
            "anthropic": (AnthropicProvider, None),
            "gemini": (GeminiProvider, None),
            "nvidia": (NvidiaProvider, None),
            "nvidia-minimax": (NvidiaProvider, NvidiaProvider.DEFAULT_MODEL),
            "groq": (GroqProvider, GroqProvider.DEFAULT_MODEL),
            "mistral": (MistralProvider, MistralProvider.DEFAULT_MODEL),
        }

        entry = providers.get(provider_name.lower())
        if not entry:
            return None

        cls, default_model = entry
        instance = cls(key)
        instance._default_model = default_model
        return instance
