# Aegis-OSINT-AI — Master Operating Profile

Generated: 2026-06-15

---

## 1. Project Identity

| Field | Value |
|---|---|
| Name | Aegis v2 |
| Type | Defensive OSINT investigation framework |
| Stack | FastAPI + Next.js 16 + PostgreSQL + Docker |
| Remote | `https://github.com/steelai-bot/Aegis-OSINT-AI.git` (origin/main) |
| Latest commit | `949f40d Add collection run history dashboard` |

**Core mandate:** Authorized passive OSINT collection, evidence persistence, provider-backed analysis, and report rendering. No offensive/exploitation tools.

---

## 2. Critical Rules & Guardrails

### From `SKILL.md` (project skill)
- Do NOT run or re-enable files in `legacy/quarantine/`
- Do NOT add exploitation, session replay, credential replay, browser fingerprint cloning, payload execution, or banking-target automation
- Do NOT commit API keys, tokens, `.env` files, or extracted credentials
- Keep integrations configuration-driven and environment-backed

### From `frontend/AGENTS.md`
- This is NOT the Next.js you know — read `node_modules/next/dist/docs/` before writing any frontend code
- Heed deprecation notices

### From `frontend/CLAUDE.md`
- Delegates to `@AGENTS.md` (above)

### Language rule (user preference)
- All code, comments, commit messages, config files and documentation must be written in English
- User-facing responses and explanations can be in Bulgarian for clarity
- This prevents encoding issues with Cyrillic characters in source code and terminal commands

### No local compilation (user preference)
- Do NOT run `npm build`, `npm run build`, `python -m build`, `docker compose build`, or any compilation/build command on the local machine
- Antigravity IDE crashes when local compilation runs
- Use only: linting, type checking, test runs, dev servers
- For build verification, use `npm run lint` for frontend and `pytest` for backend
- Docker images are built by CI or by the user manually, not by the agent

---

## 3. Tech Stack Details

### Backend
- **Language:** Python 3.12+
- **Framework:** FastAPI + Uvicorn
- **ORM:** SQLAlchemy async sessions + Alembic migrations
- **Settings:** Pydantic v2
- **Async HTTP:** httpx
- **LLM providers:** OpenAI, Anthropic, Gemini, Hugging Face, Ollama
- **DB:** PostgreSQL with pgvector

### Frontend
- **Framework:** Next.js 16.2.7 App Router
- **Language:** TypeScript strict
- **Styling:** Tailwind CSS + PostCSS
- **Icons:** lucide-react
- **Build:** ESLint flat config + Next.js production build

### Infrastructure
- **Docker Compose** stack for API + frontend + PostgreSQL
- **Kali Linux 2026.1+** compatible for operator workstations

---

## 4. Route Map

When `AEGIS_API_PREFIX=/api/v1`, routes are under `/api/v1`:

| Route | Purpose |
|---|---|
| `/health` | Health check |
| `/metrics` | Prometheus metrics |
| `/investigations` | CRUD investigations |
| `/targets` | CRUD targets |
| `/findings` | CRUD findings |
| `/reports` | CRUD reports |
| `/agents/run` | Agent execution |
| `/collections/run` | Ad-hoc collection trigger |
| `/collections/runs` | List recent collection runs |
| `/collections/runs/{run_id}` | Single run status |
| `/targets/{target_id}/collect` | Target-wide collection |
| `/investigations/{investigation_id}/collect` | Investigation-wide collection |

---

## 5. Persistence & Migrations

- Alembic migrations in `alembic/versions/`
- Key migrations: `0003_finding_threat_intel_metadata`, `0004_collection_runs`
- Collection async mode requires `0004_collection_runs`
- MVP in-process queue (not durable distributed worker)

---

## 6. Testing

```bash
# Backend (from project root)
& .\.venv\Scripts\python.exe -m pytest backend/tests/ -q

# Frontend (from frontend/)
npm run lint
npm run build
```

Test patterns in this project:
- Integration tests use SQLite async fixtures + monkeypatch for background workers
- Test naming: `test_<feature>_<scenario>`
- Use `pytest-asyncio` for async tests
- `httpx.AsyncClient` with `ASGITransport` for API integration tests

---

## 7. Active Skills Installed (global)

| Skill | Source | Best for |
|---|---|---|
| `plan` | bundled | Task breakdown & implementation planning |
| `research` | bundled | Codebase exploration (read-only) |
| `frontend-design` | github/vercel-labs | UI mockups & design |
| `react-spa` | github/nico-martin | React SPA scaffold (Vite + Tailwind v4) |
| `python-testing-patterns` | github/wshobson | pytest, fixtures, mocking, TDD |
| `osint` | github/danielmiessler | Structured OSINT (people, company, domain, entity) |
| `skill-creator` | github/anthropics | Create/modify skills |
| `agent-browser` | github/vercel-labs | Browser automation |
| `init` | github/zencoderai | Repo initialization & AGENTS.md |
| `cross-review` | github/zencoderai | Cross-model code review |
| `zen-review` | — | Expert code review |
| `zen-comprehensive-review` | — | Multi-model orchestrated review |
| `web-design-guidelines` | github/vercel-labs | UI/UX compliance review |

---

## 8. Agent IDE Configuration

### Claude (`.claude.json`)
- Model: Sonnet 4.6 (Thinking) / Haiku 4.5
- Effort: high
- Projects tracked in JSON

### Antigravity IDE (`settings.json`)
- GitLens AI model: gemini-2.5-flash
- kade allowed commands: `git log`, `git diff`, `git show`, `*`
- Auto-accept: true
- Storage sync: `E:\VScode-projects\Antigravity` (local)
- Proxy: `http://127.0.0.1:8317` (disabled)

### MCP Servers
From `mcp.json`:
- **GitKraken** — stdio via `gitkraken.exe mcp`

From `backend/api/routes/collections.py` references:
- Context7 (`@upstash/context7-mcp`) — library documentation queries
- Supabase MCP — project/DB management
- Filesystem MCP — file operations in allowed directories

---

## 9. TODO Remaining Candidates

From `TODO.md` "Next Candidate Work":
1. [ ] Durable distributed worker/queue support for long-running investigation-wide collection
2. [ ] Frontend controls for target and investigation collection workflows
3. [ ] Production authentication, RBAC, and audit logging before shared deployment

---

## 10. Recent Session History (this project context)

- Latest commit: `949f40d Add collection run history dashboard`
- Implemented: collection run history dashboard (backend endpoint + frontend component)
- Tests: 6 backend integration tests passing
- Frontend: builds cleanly with TypeScript strict + ESLint

---

## 11. Workflow Preferences

- **Testing:** Run backend tests via `.venv\Scripts\python.exe -m pytest`, frontend via `npm run lint && npm run build`
- **Git:** Use `git --no-pager` for status/diff/log; no whitespace errors; Windows LF→CRLF warnings ignored
- **Planning:** Use PLAN MODE for complex tasks; cheap model for research, powerful model for design
- **Output files:** Only on E: drive (never C: to save space)
- **Language:** All code, comments, commit messages, configs, and docs in English only. Bulgarian only for user-facing explanations.