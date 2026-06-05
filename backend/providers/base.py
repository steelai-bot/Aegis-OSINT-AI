"""LLM provider abstraction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class LLMResponse:
    text: str
    provider: str
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseLLMProvider(ABC):
    name = "base"

    @abstractmethod
    async def generate(self, prompt: str, **kwargs: Any) -> LLMResponse:
        """Generate text from a provider-specific model."""
