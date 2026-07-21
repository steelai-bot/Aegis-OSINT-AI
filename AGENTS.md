# AGENTS.md - Aegis OSINT AI

Compact instructions for OpenCode agents working in this repository.

## Project Overview

**Aegis OSINT AI** - Lightweight OSINT investigation framework with FastAPI backend (Python 3.12+) and Jinja2 templates. Plugin architecture for extensible intelligence gathering.

## Critical Commands

```bash
# Setup (Windows)
setup.bat

# Setup (Linux/macOS)
./setup.sh

# Run application (backend on http://localhost:8000)
run.bat          # Windows
./run.sh         # Linux/macOS

# Or run backend directly
.venv\Scripts\python.exe -m backend.main   # Windows
python -m backend.main                      # Linux/macOS

# Frontend build (if frontend/ dir exists)
npm install
npm run build --prefix frontend
```

## Test / Lint / Typecheck

```bash
# Run all tests
pytest tests/ -v

# Single test file
pytest tests/test_plugin_manager.py -v

# With coverage
pytest tests/ --cov=backend --cov-report=html

# Lint (Ruff)
ruff check backend tests

# Format (Ruff)
ruff format backend tests

# Type check (MyPy)
mypy backend --ignore-missing-imports
```

**CI Order**: `ruff check` → `mypy` → `pytest` (see `.github/workflows/ci.yml`)

## Architecture Highlights

| Layer | File | Responsibility |
|-------|------|----------------|
| Entry | `backend/main.py` | FastAPI app, endpoints, lifespan (DB init, plugin discovery) |
| Orchestration | `backend/engine.py` | `InvestigationEngine` - plans → executes plugins → extracts entities → logs timeline |
| Plugins | `backend/plugin_manager.py` | Singleton `PluginManager` - discovery, validation, execution, hot-reload |
| Planning | `backend/planner.py` | `AIPlanner` - template or LLM-driven plugin sequence planning |
| Storage | `backend/storage.py` | `SQLiteStorage` - all DB operations (targets, findings, entities, relations, timeline) |
| Providers | `backend/provider_manager.py` | Centralized AI provider credentials (OpenAI, Anthropic, Gemini, etc.) |
| Models | `backend/models.py` | Pydantic v2 models for all domain objects |
| Config | `backend/config/settings.py` | Pydantic Settings from `.env` (auto-created from `config/.env.example`) |

## Plugin System

All plugins in `backend/plugins/` inherit `BasePlugin` (`backend/plugins/base.py`):

```python
@property
def metadata(self) -> PluginMetadata:
    return PluginMetadata(
        name="unique_name",
        version="1.0.0",      # MUST be semver X.Y.Z (validated)
        supported_entity_types=[TargetType.DOMAIN, ...],
        required_api_keys=["MY_API_KEY"],
        dependencies=["other_plugin"],  # optional
    )

async def execute(self, query: str, target_type: TargetType) -> List[PluginResponse]:
    # return structured findings
```

**Auto-discovery**: Plugins discovered on startup; hot-reload via file mtime. Version must be valid semver or plugin rejected.

## Investigation Flow

1. `POST /api/search` → target saved with `pending` status
2. `InvestigationEngine.run_investigation()`:
   - `AIPlanner.plan_investigation()` determines plugin order
   - Plugins executed via `PluginManager.execute_plugin()`
   - Results saved as findings, entities extracted, relationships mapped
   - Timeline events logged at each step
3. Status → `completed` or `failed`

## Database

SQLite at `data/aegis.db` (configurable via `DATABASE` env). Tables: `targets`, `findings`, `entities`, `relationships`, `timeline`, `reports`. Always use `SQLiteStorage` methods, not raw SQL.

## Key Environment Variables

| Variable | Purpose |
|----------|---------|
| `DATABASE` | SQLite path (default: `data/aegis.db`) |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY` | AI providers |
| `GITHUB_TOKEN` | GitHub plugin |
| `SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY` | OSINT plugins |

Loaded from `.env` (auto-created from `config/.env.example`).

## Adding a Plugin

1. Create `backend/plugins/your_plugin_plugin.py` inheriting `BasePlugin`
2. Implement `metadata` (semver required) and async `execute()`
3. Returns `List[PluginResponse]` with `evidence` as dict/list
4. Auto-discovered on restart (hot reload watches file changes)

## Testing Patterns

- `pytest` + `pytest-asyncio` for async tests
- `respx` for HTTP mocking
- Test files mirror backend modules: `test_plugin_manager.py` → `plugin_manager.py`
- Mock external APIs in plugin tests

## Code Style

- Python: Ruff (line-length 100, py312 target, see `pyproject.toml`)
- Imports: Absolute (`from backend.models import ...`)
- Type hints: Required on all function signatures

## Error Handling

- `InvestigationEngine` isolates plugin failures - one plugin fails, others continue
- Errors logged to timeline with `TimelineEventType.ERROR`
- Global exception handler in `main.py` returns JSON `{success: false, errors: [...]}`

## Frontend Note

React frontend was replaced with Jinja2 templates in `backend/templates/`. Static files in `backend/static/`. No `frontend/` dir exists currently.

## Common Gotchas

- **Plugin version must be semver** (X.Y.Z) - rejected otherwise
- **Use `SQLiteStorage` methods** - don't write raw SQL in endpoints
- **ProviderManager is singleton** - instantiated at module level in `main.py`
- **Lifespan handler** (`main.py:90`) initializes DB and discovers plugins
- **Settings from `.env`** - use `from backend.config.settings import settings`
- **Python 3.12+** required (typing features, union syntax)