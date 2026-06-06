"""Environment-backed application configuration."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Aegis v2 runtime settings.

    Secrets are intentionally loaded from environment variables or an optional
    `.env` file. Source code must never contain provider API keys or tokens.
    """

    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    app_name: str = "Aegis OSINT Investigation Framework"
    environment: str = "development"
    debug: bool = False
    api_prefix: str = ""

    database_url: str = Field(
        default="postgresql+asyncpg://aegis:aegis@localhost:5432/aegis",
        description="SQLAlchemy async database URL for PostgreSQL.",
    )
    llm_provider: Literal["openai", "anthropic", "gemini", "huggingface", "ollama", "disabled"] = "disabled"

    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    gemini_api_key: str | None = None
    huggingface_api_key: str | None = None
    ollama_base_url: str = "http://localhost:11434"

    shodan_api_key: str | None = None
    virustotal_api_key: str | None = None
    securitytrails_api_key: str | None = None
    hibp_api_key: str | None = None

    http_timeout_seconds: float = 15.0
    http_max_retries: int = 3
    http_backoff_seconds: float = 0.5
    http_user_agent: str = "Aegis-v2-OSINT/0.1"
    serus_ai_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    """Return cached settings for dependency injection."""

    return Settings()
