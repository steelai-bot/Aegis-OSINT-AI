"""Configuration-driven LLM provider selection."""

from backend.core.config import Settings, get_settings
from backend.providers.base import BaseLLMProvider


class DisabledLLMProvider(BaseLLMProvider):
    name = "disabled"

    async def generate(self, prompt: str, **kwargs):  # type: ignore[no-untyped-def]
        from backend.providers.base import LLMResponse

        return LLMResponse(text="", provider=self.name, metadata={"disabled": True})


def get_llm_provider(settings: Settings | None = None) -> BaseLLMProvider:
    settings = settings or get_settings()
    if settings.llm_provider == "disabled":
        return DisabledLLMProvider()
    if settings.llm_provider == "openai":
        from backend.providers.openai import OpenAIProvider

        return OpenAIProvider(settings=settings)
    if settings.llm_provider == "anthropic":
        from backend.providers.anthropic import AnthropicProvider

        return AnthropicProvider(settings=settings)
    if settings.llm_provider == "gemini":
        from backend.providers.gemini import GeminiProvider

        return GeminiProvider(settings=settings)
    if settings.llm_provider == "ollama":
        from backend.providers.ollama import OllamaProvider

        return OllamaProvider(settings=settings)
    raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")
