# Aegis OSINT AI

A lightweight, modular, and extensible OSINT (Open Source Intelligence) investigation framework for rapid intelligence gathering, entity extraction, relationship mapping, timelines, and reporting.

## 🚀 Key Features

- **FastAPI Backend**: Python API with consistent JSON response envelopes.
- **Modular Plugin Architecture**: Add new intelligence sources by implementing `BasePlugin`.
- **Entity Graph Backend**: Extracts entities and maps relationships between domains, emails, IPs, usernames, and other values.
- **Automatic Investigation Timeline**: Logs investigation steps, plugin execution, discovered entities, relationships, and errors.
- **Professional Reporting**: Generates structured reports in HTML, JSON, Markdown, and PDF formats.
- **Scheduled Scans**: Automates recurring investigations using cron expressions via APScheduler.
- **Provider Manager**: Manages AI and OSINT credentials through `.env` and the web UI.
- **Legacy Static Frontend**: Bundled HTML/CSS/JS frontend works without Node.js or a build step.
- **CI Ready**: Ruff, MyPy, and Pytest configuration included.

## 🛠️ Tech Stack

- **Backend**: FastAPI with Pydantic v2
- **Database**: SQLite
- **Frontend**: Static HTML/CSS/JavaScript served from `frontend/`
- **AI Integration**: OpenRouter, OpenAI, Anthropic, Gemini, Groq, Mistral, and Nvidia NIM
- **Scheduling**: APScheduler
- **PDF Reports**: ReportLab

> Note: The application serves `frontend_dist/` automatically if a future built frontend is present; otherwise it serves the bundled `frontend/` static UI.

## 📂 Project Structure

```text
.
├── backend/
│   ├── config/
│   │   └── settings.py        # Pydantic Settings configuration
│   ├── engine.py              # Investigation orchestration
│   ├── main.py                # FastAPI application and endpoints
│   ├── models.py              # Pydantic data models
│   ├── planner.py             # Template/AI-assisted planning
│   ├── plugin_manager.py      # Plugin discovery and execution
│   ├── provider_manager.py    # Provider credential management
│   ├── providers.py           # AI provider implementations
│   ├── report.py              # Report generation
│   ├── storage.py             # SQLite storage layer
│   └── plugins/               # OSINT plugins
├── config/
│   └── .env.example           # Configuration template
├── frontend/
│   ├── index.html             # Static UI
│   ├── app.js                 # Frontend application logic
│   └── style.css              # Styles
├── tests/                     # Test suite
├── requirements.txt           # Python dependencies
├── mypy.ini                   # MyPy configuration
├── pyproject.toml             # Ruff configuration
└── .github/workflows/ci.yml   # GitHub Actions CI
```

## ⚙️ Setup & Installation

Prerequisite: **Python 3.11+**.

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

4. **Configure API keys**:

    ```bash
    # Linux/macOS
    cp config/.env.example .env

    # Windows
    copy config\.env.example .env
    ```

    Then edit `.env` and add any keys you want to use.

5. **Run the application**:

    ```bash
    python -m backend.main
    ```

    Or use the helper scripts:

    ```bash
    # Windows
    run.bat

    # Linux/macOS
    ./run.sh
    ```

    Open `http://localhost:8000`.

### One-click setup scripts

The setup scripts create the virtual environment, install Python dependencies, create `.env`, initialize the database, and verify frontend files. Node.js is only required if a future `frontend/package.json` exists.

```bash
# Linux/macOS
./setup.sh

# Windows
setup.bat
```

## 🌍 Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE` | SQLite database path, default `data/aegis.db` |
| `HOST` | Server bind host, default `0.0.0.0` |
| `PORT` | Server port, default `8000` |
| `OPENROUTER_API_KEY` | OpenRouter API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `NVIDIA_API_KEY` | Nvidia NIM API key |
| `GROQ_API_KEY` | Groq API key |
| `MISTRAL_API_KEY` | Mistral API key |
| `GITHUB_TOKEN` | GitHub API token |
| `SHODAN_API_KEY` | Shodan API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `HIBP_API_KEY` | Have I Been Pwned API key |
| `HUNTER_API_KEY` | Hunter.io API key |
| `CENSYS_API_ID` | Censys API ID |
| `CENSYS_API_SECRET` | Censys API secret |
| `GOOGLE_SEARCH_API_KEY` | Google Custom Search API key |
| `GOOGLE_SEARCH_CX` | Google Custom Search Engine ID |

`AEGIS_*` variants are also accepted for core settings by `backend.config.settings`.

## 🧩 Developing Plugins

Create a new file in `backend/plugins/` and inherit from `BasePlugin`:

```python
from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin


class MyNewPlugin(BasePlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            description="Does something useful",
            version="1.0.0",
            supported_entity_types=[TargetType.DOMAIN],
            required_api_keys=["MY_PLUGIN_API_KEY"],
            supported_authentication=["api_key"],
            tags=["example"],
            estimated_time=5,
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        return [
            PluginResponse(
                provider=self.metadata.name,
                entity_type=target_type,
                confidence=0.95,
                evidence=[{"example": query}],
                raw={"query": query},
            )
        ]
```

Plugin versions use semantic versioning (`X.Y.Z`). Plugins with missing required credentials are shown as disabled in the UI.

## 📡 API Reference

### Health

- `GET /health`

### Provider Endpoints

- `GET /api/providers`
- `GET /api/providers/{provider}`
- `GET /api/providers/{provider}/status`
- `POST /api/providers/{provider}/configure`
- `POST /api/providers/{provider}/test`
- `DELETE /api/providers/{provider}`

### Investigation Endpoints

- `POST /api/search`
- `POST /api/search/bulk`
- `GET /api/targets`
- `POST /api/targets`
- `GET /api/findings`
- `GET /api/targets/{id}/entities`
- `GET /api/targets/{id}/relationships`
- `GET /api/targets/{id}/timeline`

### Report Endpoints

- `POST /api/reports`
- `GET /api/reports/{report_id}`

### Schedule Endpoints

- `POST /api/schedules`
- `GET /api/schedules`
- `DELETE /api/schedules/{schedule_id}`

### Plugin Endpoints

- `GET /api/plugins`

### Settings Endpoints

- `GET /api/settings`
- `POST /api/settings/save`

## 🔍 Investigation Flow

1. User submits a target through `/api/search` or the UI.
2. The planner selects plugins based on target type.
3. The engine executes plugins and stores findings.
4. Entities and relationships are extracted.
5. Timeline events are recorded.
6. Reports can be generated in HTML, JSON, Markdown, or PDF.

## 🧪 Testing and Quality Checks

```bash
# Tests
pytest tests/ -q

# Lint
ruff check backend tests

# Type check
mypy backend --ignore-missing-imports
```

Current baseline: **21 tests passing**.

## 📋 CI/CD

GitHub Actions runs on pull requests and pushes to `main`:

- Ruff lint
- MyPy type check
- Pytest test suite

## 📄 License

This project is licensed under the MIT License.
