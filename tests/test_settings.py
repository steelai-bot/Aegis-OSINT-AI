import pytest
import os
from pathlib import Path
from unittest.mock import patch

from backend.config.settings import AegisSettings, get_settings, reload_settings


def test_settings_defaults():
    """Test that settings have sensible defaults."""
    with patch.dict(os.environ, {
        "HOST": "0.0.0.0",
        "PORT": "8000",
        "DATABASE": "data/aegis.db",
    }, clear=True):
        settings = AegisSettings(_env_file=None)
        
        assert settings.app_name == "Aegis OSINT AI"
        assert settings.app_version == "1.0.0"
        assert settings.debug is False
        assert settings.database_path == "data/aegis.db"
        assert settings.host == "0.0.0.0"
        assert settings.port == 8000


def test_settings_from_env():
    """Test that settings can be loaded from environment variables."""
    os.environ["DEBUG"] = "true"
    os.environ["PORT"] = "9000"
    
    settings = AegisSettings()
    
    assert settings.debug is True
    assert settings.port == 9000


def test_get_enabled_providers():
    """Test that get_enabled_providers returns only configured providers."""
    settings = AegisSettings()
    
    # Without any API keys configured
    providers = settings.get_enabled_providers()
    assert isinstance(providers, list)


def test_create_default_env(tmp_path):
    """Test that create_default_env creates .env file when missing."""
    # Create a temp directory and change to it
    original_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        
        # Ensure .env doesn't exist
        env_path = Path(".env")
        if env_path.exists():
            env_path.unlink()
        
        # Create default env
        result = AegisSettings.create_default_env()
        
        assert result is True
        assert env_path.exists()
        
        # Verify content
        content = env_path.read_text(encoding="utf-8")
        assert "OPENAI_API_KEY" in content
        assert "GROQ_API_KEY" in content
        assert "MISTRAL_API_KEY" in content
        
        # Call again - should return False
        result2 = AegisSettings.create_default_env()
        assert result2 is False
    finally:
        os.chdir(original_cwd)


def test_reload_settings():
    """Test that reload_settings creates a new settings instance."""
    settings1 = reload_settings()
    settings2 = reload_settings()
    
    # Both should be valid settings instances
    assert isinstance(settings1, AegisSettings)
    assert isinstance(settings2, AegisSettings)