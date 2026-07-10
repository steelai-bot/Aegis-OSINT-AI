"""
Pydantic Settings for Aegis OSINT AI.
Provides centralized configuration management with auto-initialization.
"""

from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AegisSettings(BaseSettings):
    """
    Centralized application settings using Pydantic Settings.

    The project historically used unprefixed environment variables
    (OPENAI_API_KEY, DATABASE, HOST, PORT, ...).  Some tests and deployments also
    use AEGIS_* names.  Each field below accepts both forms so existing .env
    files continue to work.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application settings
    app_name: str = Field(
        "Aegis OSINT AI",
        validation_alias=AliasChoices("AEGIS_APP_NAME", "APP_NAME"),
    )
    app_version: str = Field(
        "1.0.0",
        validation_alias=AliasChoices("AEGIS_APP_VERSION", "APP_VERSION"),
    )
    debug: bool = Field(False, validation_alias=AliasChoices("AEGIS_DEBUG", "DEBUG"))

    # Database settings
    database_path: str = Field(
        "data/aegis.db",
        validation_alias=AliasChoices("AEGIS_DATABASE_PATH", "DATABASE_PATH", "DATABASE"),
    )

    # API Keys for AI providers
    openai_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_OPENAI_API_KEY", "OPENAI_API_KEY"),
    )
    anthropic_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )
    gemini_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_GEMINI_API_KEY", "GEMINI_API_KEY"),
    )
    openrouter_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"),
    )
    groq_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_GROQ_API_KEY", "GROQ_API_KEY"),
    )
    mistral_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_MISTRAL_API_KEY", "MISTRAL_API_KEY"),
    )
    nvidia_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_NVIDIA_API_KEY", "NVIDIA_API_KEY"),
    )

    # API Keys for OSINT plugins/providers
    github_token: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_GITHUB_TOKEN", "GITHUB_TOKEN"),
    )
    shodan_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_SHODAN_API_KEY", "SHODAN_API_KEY"),
    )
    virustotal_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY"),
    )
    hibp_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_HIBP_API_KEY", "HIBP_API_KEY"),
    )
    hunter_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_HUNTER_API_KEY", "HUNTER_API_KEY"),
    )
    google_search_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_GOOGLE_SEARCH_API_KEY", "GOOGLE_SEARCH_API_KEY"),
    )
    google_search_cx: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_GOOGLE_SEARCH_CX", "GOOGLE_SEARCH_CX"),
    )
    censys_api_id: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_CENSYS_API_ID", "CENSYS_API_ID"),
    )
    censys_api_secret: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_CENSYS_API_SECRET", "CENSYS_API_SECRET"),
    )
    securitytrails_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("AEGIS_SECURITYTRAILS_API_KEY", "SECURITYTRAILS_API_KEY"),
    )

    # Server settings
    host: str = Field("0.0.0.0", validation_alias=AliasChoices("AEGIS_HOST", "HOST"))
    port: int = Field(8000, validation_alias=AliasChoices("AEGIS_PORT", "PORT"))

    # CORS settings
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["*"])
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

        example_path = Path("config/.env.example")
        if example_path.exists():
            env_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            env_path.write_text(
                """# Aegis OSINT AI Configuration

DATABASE=data/aegis.db
HOST=0.0.0.0
PORT=8000
DEBUG=false

OPENROUTER_API_KEY=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GEMINI_API_KEY=
NVIDIA_API_KEY=
GROQ_API_KEY=
MISTRAL_API_KEY=

GITHUB_TOKEN=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
HIBP_API_KEY=
HUNTER_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
GOOGLE_SEARCH_API_KEY=
GOOGLE_SEARCH_CX=
""",
                encoding="utf-8",
            )
        return True

    def get_enabled_providers(self) -> list[str]:
        """Return list of AI provider names that have configured API keys."""
        providers = []
        if self.openai_api_key:
            providers.append("openai")
        if self.anthropic_api_key:
            providers.append("anthropic")
        if self.gemini_api_key:
            providers.append("gemini")
        if self.openrouter_api_key:
            providers.append("openrouter")
        if self.groq_api_key:
            providers.append("groq")
        if self.mistral_api_key:
            providers.append("mistral")
        if self.nvidia_api_key:
            providers.append("nvidia")
        return providers


# Global settings instance
settings = AegisSettings()  # type: ignore[call-arg]


def get_settings() -> AegisSettings:
    """Get the global settings instance."""
    return settings


def reload_settings() -> AegisSettings:
    """Reload settings from environment (useful for testing)."""
    global settings
    settings = AegisSettings()  # type: ignore[call-arg]
    return settings
