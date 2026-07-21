# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Aegis OSINT AI is a lightweight, modular OSINT investigation framework built with FastAPI (Python 3.12+) backend and Jinja2 + HTMX + Alpine.js frontend. The system uses a plugin architecture for extensible intelligence gathering with AI-powered investigation planning.

## Commands

### Setup & Development

```bash
# Initial setup (Windows)
setup.bat

# Initial setup (Linux/macOS)
./setup.sh

# Start the application (runs backend on http://localhost:8000)
run.bat              # Windows
./run.sh             # Linux/macOS

# Or run backend directly
.venv\Scripts\python.exe -m backend.main   # Windows
python -m backend.main                      # Linux/macOS
```

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_plugin_manager.py -v

# Run with coverage
pytest tests/ --cov=backend --cov-report=html
```

### Linting & Type Checking

```bash
# Lint with Ruff
ruff check backend tests

# Format with Ruff
ruff format backend tests

# Type check with MyPy
mypy backend --ignore-missing-imports
```

### Frontend

Server-rendered Jinja2 templates with HTMX for partial updates and Alpine.js for interactivity:
- **`backend/templates/base.html`**: App shell with sidebar navigation
- **`backend/templates/dashboard.html`**: New investigation form + recent investigations
- **`backend/templates/investigations.html`**: List all targets
- **`backend/templates/results.html`**: Entities/Relationships/Timeline/Graph tabs with vis-network
- **`backend/templates/plugins.html`**: Plugin grid display
- **`backend/templates/settings.html`**: Provider configuration with sections

Static assets:
- **`backend/static/css/components.css`**: Component styles
- **`backend/static/js/modal.js`**: Alpine.js modal component

No Node.js/React build step required; templates are rendered server-side by FastAPI.

## Architecture

### Backend Structure

The backend follows a layered architecture with clear separation of concerns:

- **`backend/main.py`**: FastAPI application entry point. Handles HTTP endpoints, CORS, static file serving, and database initialization via lifespan events.
- **`backend/engine.py`**: `InvestigationEngine` orchestrates the complete OSINT workflow: planning → execution → entity extraction → relationship mapping → timeline logging.
- **`backend/plugin_manager.py`**: Singleton `PluginManager` that discovers, validates, and executes plugins. Supports hot reload detection via file mtime tracking and semantic version validation.
- **`backend/planner.py`**: `AIPlanner` determines the optimal sequence of plugins to execute for a given target, either via template-based logic or LLM-driven planning.
- **`backend/storage.py`**: `SQLiteStorage` abstraction layer for all database operations (targets, findings, entities, relationships, timeline events).
- **`backend/provider_manager.py`**: Centralized credential management for AI providers (OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral, Nvidia NIM).
- **`backend/models.py`**: Pydantic v2 data models for all domain objects (investigations, entities, relationships, plugins, etc.).
- **`backend/config/settings.py`**: Pydantic Settings configuration management with `.env` file support.

### Plugin System

All plugins inherit from `BasePlugin` in `backend/plugins/base.py` and must implement:

1. **`metadata`** property returning `PluginMetadata` with:
   - `name`: Unique identifier (string)
   - `version`: Semantic version (X.Y.Z format, validated by PluginManager)
   - `supported_entity_types`: List of `TargetType` enum values
   - `required_api_keys`: List of environment variable names
   - `dependencies`: Optional list of plugin names this depends on
   
2. **`execute(query, target_type)`** async method returning `List[PluginResponse]`

The PluginManager automatically discovers all Python files in `backend/plugins/` on startup and validates metadata including semver format and dependency resolution.

### Investigation Flow

1. User submits query via `POST /api/search` with target and type
2. Target saved to database with `pending` status
3. `InvestigationEngine.run_investigation()` invoked:
   - Calls `AIPlanner.plan_investigation()` to determine plugin sequence
   - Executes each plugin via `PluginManager.execute_plugin()`
   - Each `PluginResponse` is saved as a finding
   - Entities and relationships extracted from evidence
   - Timeline events logged at each step (investigation created, planning completed, plugin started/completed, errors)
4. Status updated to `completed` or `failed`

### Database Schema

SQLite database (`data/aegis.db` by default) with tables:
- `targets`: Investigation targets (query, target_type, status, timestamps)
- `findings`: Raw plugin results linked to targets
- `entities`: Extracted entities (domains, IPs, emails, etc.) with types and confidence
- `relationships`: Links between entities (DNS record, whois registrar, etc.)
- `timeline`: Audit trail of investigation steps
- `reports`: Generated reports in multiple formats

### Frontend Architecture

Server-rendered Jinja2 templates with HTMX for partial updates and Alpine.js for client-side interactivity:
- **`backend/templates/base.html`**: App shell with sidebar navigation
- **`backend/templates/dashboard.html`**: New investigation form + recent investigations
- **`backend/templates/investigations.html`**: List all targets
- **`backend/templates/results.html`**: Entities/Relationships/Timeline/Graph tabs with vis-network
- **`backend/templates/plugins.html`**: Plugin grid display
- **`backend/templates/settings.html`**: Provider configuration with sections

Components in `backend/templates/components/`:
- `targets_list.html`, `entities.html`, `relationships.html`, `timeline.html`
- `investigation_result.html`, `providers_list.html`, `provider_modal.html`

Static assets in `backend/static/`:
- `css/components.css` — Component styles
- `js/modal.js` — Alpine.js modal component

## Key Implementation Notes

### Adding a New Plugin

1. Create `backend/plugins/your_plugin_plugin.py` inheriting from `BasePlugin`
2. Implement `metadata` property with valid semver version
3. Implement async `execute()` method
4. Return `List[PluginResponse]` with evidence structured as dict/list
5. Plugin auto-discovered on next server restart (hot reload monitors file changes)

### Environment Configuration

Settings loaded via Pydantic Settings from `.env` file (auto-created from `config/.env.example` if missing). Access via `from backend.config.settings import settings`.

Key environment variables:
- `DATABASE`: SQLite database path (default: `data/aegis.db`)
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, etc.: AI provider credentials
- Plugin-specific API keys (e.g., `GITHUB_TOKEN`)

### Testing Patterns

Tests use `pytest` with `pytest-asyncio` for async tests and `respx` for HTTP mocking. Each test file corresponds to a backend module (e.g., `test_plugin_manager.py` tests `plugin_manager.py`).

When testing plugins, mock external API calls with `respx` and test the `execute()` method with sample data.

### CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`) runs on push/PR:
1. **Lint**: Ruff code quality checks
2. **Type Check**: MyPy static analysis
3. **Tests**: Pytest suite

All checks must pass before merge.

## Development Guidelines

### Code Style

- Python: Follow Ruff configuration in `pyproject.toml` (line length 100, Python 3.12 target)
- HTML/Jinja2: Follow existing template patterns with HTMX attributes
- Imports: Use absolute imports (`from backend.models import ...`)
- Type hints: Required for all function signatures

### Plugin Metadata Validation

Plugin versions MUST follow semantic versioning (X.Y.Z). The PluginManager validates this on discovery and rejects invalid versions. Update versions when changing plugin behavior.

### Error Handling

The InvestigationEngine isolates plugin failures - if one plugin fails, the investigation continues with remaining plugins. All errors logged to timeline with `TimelineEventType.ERROR`.

### Database Access

Use `SQLiteStorage` methods for all database operations. The storage layer handles connection management and provides a consistent interface. Some legacy endpoints in `main.py` still use raw `sqlite3` via `get_db()` for targets/findings/reports tables; prefer migrating to `SQLiteStorage` where possible.
