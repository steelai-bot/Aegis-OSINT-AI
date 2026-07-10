# Aegis OSINT AI

A lightweight, modular, and extensible OSINT (Open Source Intelligence) investigation framework designed for rapid intelligence gathering and entity relationship mapping.

## 🚀 Key Features

- **Modular Plugin Architecture**: Easily add new intelligence sources by implementing the `BasePlugin` interface.
- **Entity Graph Backend**: Automatically extracts and maps relationships between discovered entities (domains, emails, IPs, etc.) using a SQLite-based relational graph.
- **Automatic Investigation Timeline**: Every step of the investigation is logged, providing a clear audit trail of discovery.
- **Professional Reporting**: Generate structured reports in Markdown, JSON, HTML, and **PDF** formats.
- **Scheduled Scans**: Automate recurring investigations using cron expressions (requires APScheduler).
- **AI-Powered Planning**: Uses LLMs to dynamically determine the most effective sequence of plugins for any given target.
- **Centralized Management**: Manage all API keys and configuration through a unified web interface.
- **Hot Reload Plugins**: Plugin system automatically detects changes without restart.
- **Version Validation**: Plugin metadata validated with semantic versioning.

## 🛠️ Tech Stack

- **Backend**: FastAPI (Python 3.12+) with Pydantic v2
- **Database**: SQLite (Relational Graph Implementation)
- **Frontend**: React 18 + TypeScript + Vite + Tailwind CSS v4
- **AI Integration**: Support for OpenRouter, OpenAI, Anthropic, Gemini, Groq, Mistral, and Nvidia NIM

## 📂 Project Structure

```text
.
├── backend/
│   ├── config/
│   │   └── settings.py        # Pydantic Settings configuration
│   ├── engine.py              # Orchestration logic
│   ├── main.py                # FastAPI application & endpoints
│   ├── models.py              # Pydantic data models
│   ├── planner.py             # AI-driven investigation planning
│   ├── plugin_manager.py      # Plugin discovery and execution (with hot reload)
│   ├── providers.py           # AI provider implementations
│   ├── provider_manager.py    # Provider management
│   ├── report.py              # Modular report generation
│   ├── storage.py             # Database abstraction layer
│   └── plugins/               # OSINT plugin implementations
├── config/
│   └── .env.example           # API key templates
├── frontend/
│   ├── index.html             # Entry point (dev mode)
│   ├── app.js                 # Legacy entry (deprecated)
│   └── style.css              # Legacy styles (deprecated)
├── frontend_dist/             # Built React frontend
├── frontend/src/              # React + TypeScript source
│   ├── main.tsx               # Entry point
│   ├── App.tsx                # Main application component
│   └── pages/                 # Page components
├── tests/                     # Test suite
├── requirements.txt           # Python dependencies
├── mypy.ini                   # MyPy configuration
├── pyproject.toml             # Ruff configuration
└── .github/workflows/ci.yml   # GitHub Actions CI/CD
```

## ⚙️ Setup & Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/steelai-bot/Aegis-OSINT-AI.git
    cd Aegis-OSINT-AI
    ```

2. **Set up a virtual environment**:

    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # Linux/macOS
    source .venv/bin/activate
    ```

3. **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

4. **Build the frontend** (requires Node.js):

    ```bash
    npm install
    npm run build --prefix frontend
    ```

5. **Configure API Keys**:
    Copy the example configuration to a `.env` file:

    ```bash
    # The app will auto-create .env on first run if missing
    copy config\.env.example .env
    ```

6. **Run the application**:

    ```bash
    python -m backend.main
    ```

    Or using the run script:

    ```bash
    # Windows
    run.bat
    # Linux/macOS
    ./run.sh
    ```

    The application will be available at `http://localhost:8000`.

## 🧩 Developing Plugins (Plugin Development Guide)

To add a new plugin, create a new file in `backend/plugins/` that inherits from `BasePlugin`:

```python
from backend.plugins.base import BasePlugin
from backend.models import PluginMetadata, PluginResponse, TargetType
from typing import List

class MyNewPlugin(BasePlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            description="Does something cool",
            version="1.0.0",
            supported_entity_types=[TargetType.DOMAIN],
            required_api_keys=["MY_PLUGIN_API_KEY"],
            supported_authentication=["api_key"],
            tags=["new"],
            estimated_time=5
        )

    async def execute(self, query: str, target_type: TargetType) -> List[PluginResponse]:
        # Your logic here
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

## 🏗️ Architecture

- **Backend**: FastAPI with SQLite for Entity Graph storage.
- **ProviderManager**: Centralized credential storage and status tracking for AI providers.
- **InvestigationEngine**: Orchestrates plugin execution safely, isolating failures.
- **PluginManager**: Validates and discovers plugins dynamically with hot reload support.
- **AegisSettings**: Pydantic-based configuration management.

## 🔌 Supported AI Providers

- **OpenAI**: GPT models via OpenAI API
- **Anthropic**: Claude models via Anthropic API
- **Gemini**: Google's Gemini models
- **OpenRouter**: Unified API gateway
- **Groq**: Fast inference API
- **Mistral**: Mistral AI models
- **Nvidia NIM**: Nvidia inference microservice

Configure providers via the Settings UI or API endpoints.

## 🌍 Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `OPENROUTER_API_KEY` | OpenRouter API key |
| `GROQ_API_KEY` | Groq API key |
| `MISTRAL_API_KEY` | Mistral API key |
| `GITHUB_TOKEN` | GitHub API token (for GitHub plugin) |
| `DATABASE` | SQLite database path (default: `data/aegis.db`) |

## 📡 API Reference

### Provider Endpoints

- `GET /api/providers`: List all providers
- `GET /api/providers/{provider}`: Get provider details
- `GET /api/providers/{provider}/status`: Get provider status
- `POST /api/providers/{provider}/configure`: Set credentials
- `POST /api/providers/{provider}/test`: Test connection
- `DELETE /api/providers/{provider}`: Remove credentials

### Investigation Endpoints

- `POST /api/search`: Start an investigation
- `GET /api/targets`: List all targets
- `GET /api/targets/{id}/timeline`: Get investigation timeline
- `GET /api/targets/{id}/entities`: Get extracted entities
- `GET /api/targets/{id}/relationships`: Get entity relationships

### Plugin Endpoints

- `GET /api/plugins`: List all plugins with status

### Settings Endpoints

- `GET /api/settings`: Get current settings
- `POST /api/settings/save`: Save settings

## 🔍 Investigation Flow

1. **Target Submission**: User enters query via `/api/search`
2. **Planning**: AI Planner determines necessary plugins (template or LLM-based)
3. **Execution**: Investigation Engine runs plugins concurrently
4. **Extraction**: Raw data is parsed into Entities and Relationships
5. **Timeline**: Every step, error, and discovery is logged
6. **Reporting**: Results are compiled into HTML/JSON/Markdown

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=backend --cov-report=html
```

## 📋 CI/CD

GitHub Actions workflow runs on every push:
- **Lint**: Ruff code quality checks
- **Type Check**: MyPy static type analysis
- **Tests**: Pytest test suite

## 📄 License

This project is licensed under the MIT License.