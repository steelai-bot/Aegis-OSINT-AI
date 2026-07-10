import os
import shutil
from typing import Any

from dotenv import load_dotenv, set_key


class ProviderManager:
    """
    Manages API keys and provider configurations by securely interacting with .env.
    """
    def __init__(self, env_path: str = ".env"):
        self.env_path = env_path
        self._ensure_env_exists()
        load_dotenv(self.env_path)

        # Default providers that don't come from plugins (like AI providers)
        # and known OSINT providers. We will expand this dynamically if needed,
        # but for now we define a static list for the UI.
        self.known_providers: list[dict[str, Any]] = [
            {"id": "openrouter", "name": "OpenRouter", "description": "AI model routing platform", "supported_authentication": ["api_key"]},
            {"id": "openai", "name": "OpenAI", "description": "OpenAI API (GPT models)", "supported_authentication": ["api_key"]},
            {"id": "anthropic", "name": "Anthropic", "description": "Anthropic API (Claude models)", "supported_authentication": ["api_key"]},
            {"id": "gemini", "name": "Google Gemini", "description": "Google Gemini API", "supported_authentication": ["api_key"]},
            {"id": "nvidia", "name": "Nvidia NIM", "description": "Nvidia inference microservices", "supported_authentication": ["api_key"]},
            {"id": "nvidia-minimax", "name": "Nvidia MiniMax-M3", "description": "Multimodal AI agent (MiniMax-M3) via NVIDIA (text, images, video)", "supported_authentication": ["api_key"]},
            {"id": "groq", "name": "Groq", "description": "Groq AI platform (Llama, Mixtral models)", "supported_authentication": ["api_key"]},
            {"id": "mistral", "name": "Mistral", "description": "Mistral AI API (Mistral, Mixtral models)", "supported_authentication": ["api_key"]},
            {"id": "virustotal", "name": "VirusTotal", "description": "Malware and URL scanning", "supported_authentication": ["api_key"]},
            {"id": "shodan", "name": "Shodan", "description": "Search engine for IoT", "supported_authentication": ["api_key"]},
            {"id": "hunter", "name": "Hunter.io", "description": "Email enumeration", "supported_authentication": ["api_key"]},
            {"id": "intelx", "name": "Intelligence X", "description": "Data breach and dark web search", "supported_authentication": ["api_key"]},
            {"id": "censys", "name": "Censys", "description": "Internet-wide scanning data", "supported_authentication": ["username_password"]},
            {"id": "abuseipdb", "name": "AbuseIPDB", "description": "IP abuse reporting and checking", "supported_authentication": ["api_key"]},
            {"id": "urlscan", "name": "URLScan", "description": "Website scanner", "supported_authentication": ["api_key"]},
            {"id": "googlesearch", "name": "Google Custom Search", "description": "Google Custom Search API", "supported_authentication": ["api_key"]},
            {"id": "googlecx", "name": "Google Search CX", "description": "Google Custom Search Engine ID", "supported_authentication": ["api_key"]},
            {"id": "github", "name": "GitHub", "description": "GitHub API access", "supported_authentication": ["api_key", "oauth", "none"]}
        ]

    def _ensure_env_exists(self):
        if not os.path.exists(self.env_path):
            for example_path in (".env.example", "config/.env.example"):
                if os.path.exists(example_path):
                    shutil.copy(example_path, self.env_path)
                    return
            with open(self.env_path, "w") as f:
                f.write("# Aegis OSINT AI Configuration\n")

    def _get_key_name(self, provider_id: str) -> str:
        """Return the primary env var name for a provider."""
        key_overrides = {
            "github": "GITHUB_TOKEN",
            "googlecx": "GOOGLE_SEARCH_CX",
            "googlesearch": "GOOGLE_SEARCH_API_KEY",
            "nvidia-minimax": "NVIDIA_API_KEY",
        }
        return key_overrides.get(provider_id, f"{provider_id.upper()}_API_KEY")

    def _get_key_names(self, provider_id: str) -> list[str]:
        """Return all env var names required for a provider to be connected."""
        if provider_id == "censys":
            return ["CENSYS_API_ID", "CENSYS_API_SECRET"]
        return [self._get_key_name(provider_id)]

    def get_providers(self) -> list[dict[str, Any]]:
        """Returns all providers with their current connection status."""
        result = []
        for p in self.known_providers:
            key_names = self._get_key_names(p['id'])
            is_connected = all(bool(os.getenv(key_name)) for key_name in key_names)
            result.append({
                "id": p["id"],
                "name": p["name"],
                "description": p["description"],
                "supported_authentication": p["supported_authentication"],
                "status": "connected" if is_connected else "disconnected",
                "last_validation": None
            })
        return result

    def get_provider(self, provider_id: str) -> dict[str, Any]:
        """Returns details for a specific provider."""
        providers = self.get_providers()
        for p in providers:
            if p["id"] == provider_id:
                return p
        raise ValueError(f"Provider {provider_id} not found.")

    def configure_provider(self, provider_id: str, auth_data: dict[str, str]) -> None:
        """Saves provider credentials to .env."""
        if provider_id == "censys":
            username = auth_data.get("username")
            password = auth_data.get("password")
            if username is not None:
                set_key(self.env_path, "CENSYS_API_ID", username)
                os.environ["CENSYS_API_ID"] = username
            if password is not None:
                set_key(self.env_path, "CENSYS_API_SECRET", password)
                os.environ["CENSYS_API_SECRET"] = password
            load_dotenv(self.env_path, override=True)
            return

        key_name = self._get_key_name(provider_id)
        if "api_key" in auth_data:
            set_key(self.env_path, key_name, auth_data["api_key"])
            os.environ[key_name] = auth_data["api_key"]
            load_dotenv(self.env_path, override=True)
        elif "value" in auth_data:
            set_key(self.env_path, key_name, auth_data["value"])
            os.environ[key_name] = auth_data["value"]
            load_dotenv(self.env_path, override=True)

    def disconnect_provider(self, provider_id: str) -> None:
        """Removes provider credentials from .env."""
        for key_name in self._get_key_names(provider_id):
            set_key(self.env_path, key_name, "")
            if key_name in os.environ:
                del os.environ[key_name]
        load_dotenv(self.env_path, override=True)

    def test_provider(self, provider_id: str) -> bool:
        """Tests whether required credentials are configured."""
        return all(bool(os.getenv(key_name)) for key_name in self._get_key_names(provider_id))
