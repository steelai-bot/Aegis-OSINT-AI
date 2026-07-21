"""
Pydantic Settings for Aegis OSINT AI.
Provides centralized configuration management with auto-initialization.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AegisSettings(BaseSettings):
    """
    Centralized application settings using Pydantic Settings.
    Loads from environment variables and .env file with sensible defaults.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Application settings
    app_name: str = "Aegis OSINT AI"
    app_version: str = "1.0.0"
    debug: bool = False

    # Database settings
    database_path: str = "data/aegis.db"

    # API Keys for AI providers
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    gemini_api_key: str | None = None
    openrouter_api_key: str | None = None
    nvidia_api_key: str | None = None
    groq_api_key: str | None = None
    mistral_api_key: str | None = None

    # API Keys for OSINT plugins
    github_token: str | None = None
    shodan_api_key: str | None = None
    securitytrails_api_key: str | None = None
    virustotal_api_key: str | None = None
    hunter_api_key: str | None = None
    intelx_api_key: str | None = None
    censys_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    urlscan_api_key: str | None = None
    google_search_api_key: str | None = None
    google_search_cx: str | None = None

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000

    # CORS settings
    cors_allow_origins: list = Field(default_factory=lambda: ["*"])
    cors_allow_credentials: bool = False

    @classmethod
    def create_default_env(cls) -> bool:
        """
        Create a default .env file if it doesn't exist.
        Returns True if file was created, False if it already existed.
        """
        env_path = Path(".env")
        if env_path.exists():
            return False

        default_content = """# Aegis OSINT AI Configuration
# Copy this file and fill in your API keys

# AI Providers
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GEMINI_API_KEY=
OPENROUTER_API_KEY=
NVIDIA_API_KEY=
GROQ_API_KEY=
MISTRAL_API_KEY=

# OSINT Providers
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
HUNTER_API_KEY=
INTELX_API_KEY=
CENSYS_API_KEY=
ABUSEIPDB_API_KEY=
URLSCAN_API_KEY=

# Google Custom Search
GOOGLE_SEARCH_API_KEY=
GOOGLE_SEARCH_CX=

# GitHub
GITHUB_TOKEN=

# Database (optional, defaults to data/aegis.db)
DATABASE=data/aegis.db

# Server (optional)
HOST=0.0.0.0
PORT=8000
"""
        env_path.write_text(default_content, encoding="utf-8")
        return True

    def get_enabled_providers(self) -> list[str]:
        """Return list of provider names that have configured API keys."""
        providers = []
        if self.openai_api_key:
            providers.append("openai")
        if self.anthropic_api_key:
            providers.append("anthropic")
        if self.gemini_api_key:
            providers.append("gemini")
        if self.openrouter_api_key:
            providers.append("openrouter")
        if self.nvidia_api_key:
            providers.append("nvidia")
        if self.groq_api_key:
            providers.append("groq")
        if self.mistral_api_key:
            providers.append("mistral")
        if self.github_token:
            providers.append("github")
        if self.shodan_api_key:
            providers.append("shodan")
        if self.virustotal_api_key:
            providers.append("virustotal")
        return providers


# Global settings instance
settings = AegisSettings()


def get_settings() -> AegisSettings:
    """Get the global settings instance."""
    return settings


def reload_settings() -> AegisSettings:
    """Reload settings from environment (useful for testing)."""
    global settings
    settings = AegisSettings()
    return settings
