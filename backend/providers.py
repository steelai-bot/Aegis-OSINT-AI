"""
AI Provider Integrations
Supports OpenRouter, OpenAI, Anthropic, Gemini, and Nvidia.
"""

import os
import httpx
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class AIResponse(BaseModel):
    content: str
    provider: str
    model: str

class AIProvider:
    """Base class for AI providers."""
    def __init__(self, api_key: str):
        self.api_key = api_key

    async def chat(self, prompt: str, model: str) -> AIResponse:
        raise NotImplementedError

class OpenRouterProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "Aegis OSINT AI"
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}]
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return AIResponse(
                content=data["choices"][0]["message"]["content"],
                provider="openrouter",
                model=model
            )

class OpenAIProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}]
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return AIResponse(
                content=data["choices"][0]["message"]["content"],
                provider="openai",
                model=model
            )

class AnthropicProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return AIResponse(
                content=data["content"][0]["text"],
                provider="anthropic",
                model=model
            )

class GeminiProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return AIResponse(
                content=data["candidates"][0]["content"]["parts"][0]["text"],
                provider="gemini",
                model=model
            )

class NvidiaProvider(AIProvider):
    async def chat(self, prompt: str, model: str) -> AIResponse:
        url = "https://infer.nvidia.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}]
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return AIResponse(
                content=data["choices"][0]["message"]["content"],
                provider="nvidia",
                model=model
            )

class AIProviderFactory:
    @staticmethod
    def get_provider(provider_name: str) -> Optional[AIProvider]:
        key = os.getenv(f"{provider_name.upper()}_API_KEY")
        if not key:
            return None
        
        providers = {
            "openrouter": OpenRouterProvider,
            "openai": OpenAIProvider,
            "anthropic": AnthropicProvider,
            "gemini": GeminiProvider,
            "nvidia": NvidiaProvider
        }
        
        cls = providers.get(provider_name.lower())
        return cls(key) if cls else None