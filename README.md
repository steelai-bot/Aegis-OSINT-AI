# Aegis OSINT AI

A lightweight, modular, and extensible OSINT (Open Source Intelligence) investigation framework for rapid intelligence gathering and entity relationship mapping.

## Key Features

- **Modular Plugin Architecture**: Extend intelligence sources by implementing the `BasePlugin` interface.
- **Entity Graph Backend**: Automatically extracts and maps relationships between discovered entities (domains, emails, IPs, etc.) using a SQLite-based relational graph.
- **Automatic Investigation Timeline**: Every step is logged, providing a clear audit trail of discovery.
- **Professional Reporting**: Generate structured reports in Markdown, JSON, and HTML formats.
- **AI-Powered Planning**: Uses LLMs to dynamically determine the most effective plugin sequence.
- **One-Command Install**: Single `python install.py --run` does everything.
- **Hot Reload Plugins**: Plugin system automatically detects changes without restart.
- **Version Validation**: Plugin metadata validated with semantic versioning.

## Tech Stack

- **Backend**: FastAPI (Python 3.12+) with Pydantic v2
- **Database**: SQLite (Relational Graph Implementation)
- **Frontend**: Jinja2 + HTMX + Alpine.js (no Node.js required)
- **AI Integration**: OpenRouter, OpenAI, Anthropic, Gemini, Groq, Mistral, Nvidia NIM

## Quick Start

```bash
# One-command install + run (Windows, Linux, macOS)
python install.py --run
```

Or step by step:

```bash
git clone https://github.com/steelai-bot/Aegis-OSINT-AI.git
cd Aegis-OSINT-AI
python install.py
# Edit .env with your API keys
python install.py --run
```

The application will be available at `http://localhost:8000`.

## Project Structure

```
.
├── backend/
│   ├── config/
│   │   └── settings.py        # Pydantic Settings configuration
│   ├── engine.py              # Orchestration logic
│   ├── main.py                # FastAPI application & endpoints
│   ├── http_client.py         # Shared async HTTP client
│   ├── models.py              # Pydantic data models
│   ├── planner.py             # AI-driven investigation planning
│   ├── plugin_manager.py      # Plugin discovery and execution (hot reload)
│   ├── provider_manager.py    # Centralized API key management
│   ├── providers.py           # AI provider implementations
│   ├── report.py              # Modular report generation
│   ├── storage.py             # Database abstraction layer
│   ├── static/                # Static assets (CSS, JS)
│   ├── templates/             # Jinja2 templates (dashboard, results, etc.)
│   └── plugins/               # OSINT plugin implementations
├── config/
│   └── .env.example           # API key templates
├── tests/                     # Test suite
├── install.py                 # Unified cross-platform installer
├── requirements.txt           # Python dependencies
├── mypy.ini                   # MyPy configuration
├── pyproject.toml             # Ruff configuration
└── .github/workflows/ci.yml   # GitHub Actions CI/CD
```

## Plugin Development

Create a new file in `backend/plugins/` inheriting from `BasePlugin`:

```python
from backend.plugins.base import BasePlugin
from backend.models import PluginMetadata, PluginResponse, TargetType
from typing import List

class MyPlugin(BasePlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            description="Does something cool",
            version="1.0.0",
            supported_entity_types=[TargetType.DOMAIN],
            required_api_keys=["MY_API_KEY"],
            tags=["new"],
            estimated_time=5
        )

    async def execute(self, query: str, target_type: TargetType) -> List[PluginResponse]:
        return [
            PluginResponse(
                provider=self.metadata.name,
                entity_type=target_type,
                confidence=0.95,
                evidence=[{"key": "value"}]
            )
        ]
```

### Plugin Metadata Fields

- `name`: Unique plugin identifier
- `description`: Human-readable description
- `version`: Semantic version (X.Y.Z format)
- `supported_entity_types`: List of `TargetType` values the plugin can process
- `required_api_keys`: Environment variable names for required credentials
- `dependencies`: Other plugin names this plugin depends on (optional)

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `OPENROUTER_API_KEY` | OpenRouter API key |
| `NVIDIA_API_KEY` | Nvidia NIM API key |
| `GROQ_API_KEY` | Groq API key |
| `MISTRAL_API_KEY` | Mistral API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `SHODAN_API_KEY` | Shodan API key |
| `HUNTER_API_KEY` | Hunter.io API key |
| `INTELX_API_KEY` | Intelligence X API key |
| `CENSYS_API_KEY` | Censys API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `URLSCAN_API_KEY` | URLScan API key |
| `GITHUB_TOKEN` | GitHub API token |
| `DATABASE` | SQLite path (default: `data/aegis.db`) |

Configure providers via the Settings UI or API endpoints.

## API Reference

### Provider Endpoints

- `GET /api/providers` — List all providers
- `GET /api/providers/{provider}` — Get provider details
- `POST /api/providers/{provider}/configure` — Set credentials
- `POST /api/providers/{provider}/test` — Test connection
- `DELETE /api/providers/{provider}` — Remove credentials

### Investigation Endpoints

- `POST /api/search` — Start an investigation
- `GET /api/targets` — List all targets
- `GET /api/targets/{id}/timeline` — Get investigation timeline
- `GET /api/targets/{id}/entities` — Get extracted entities
- `GET /api/targets/{id}/relationships` — Get entity relationships

### Plugin Endpoints

- `GET /api/plugins` — List all plugins with status

### Settings Endpoints

- `GET /api/settings` — Get current settings
- `POST /api/settings/save` — Save settings

## Investigation Flow

1. **Target Submission** — User enters query via `/api/search`
2. **Planning** — AI Planner determines necessary plugins (template or LLM-based)
3. **Execution** — Investigation Engine runs plugins concurrently
4. **Extraction** — Raw data is parsed into Entities and Relationships
5. **Timeline** — Every step, error, and discovery is logged
6. **Reporting** — Results are compiled into HTML/JSON/Markdown

## Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=backend --cov-report=html
```

## CI/CD

GitHub Actions on every push to `main`:
- **Lint**: Ruff code quality checks
- **Type Check**: MyPy static type analysis
- **Tests**: Pytest test suite

## License

MIT
