# Implementation Plan / Current Status

## Current Status: ✅ Stabilized Backend + Bundled Static Frontend

This repository is currently stabilized around the existing FastAPI backend and the bundled legacy static frontend in `frontend/`.

### Stabilization Completed

- Fixed frontend serving:
  - FastAPI now serves `frontend_dist/` only if a built frontend exists.
  - Otherwise it falls back to the bundled `frontend/` static UI.
  - Import/startup no longer fails when `frontend_dist/` is missing.
- Fixed backend import/runtime blockers:
  - Corrected `backend/engine.py` indentation and entity extraction logic.
  - Added missing entity/target types needed by plugins.
  - Ensured `SQLiteStorage` creates parent directories and core tables it uses.
  - Fixed SlowAPI route signatures by separating HTTP wrappers from internal search execution.
- Aligned configuration:
  - `.env` auto-creation now uses `config/.env.example` when available.
  - Settings accept both standard env names (`DATABASE`, `PORT`, `OPENAI_API_KEY`, etc.) and `AEGIS_*` variants.
  - Provider manager now uses correct env names for GitHub and Google Search.
  - Censys uses `CENSYS_API_ID` + `CENSYS_API_SECRET`.
- Stabilized setup/update scripts:
  - Node.js is optional for the current bundled static frontend.
  - npm install/build only runs when `frontend/package.json` exists.
- Updated documentation to match the actual repository state.
- Quality baseline:
  - Ruff: passing
  - MyPy: passing
  - Pytest: 21 passing tests

## Completed Backend Features

- Modular plugin system with hot reload detection, semver validation, dependency checks, and error tracking.
- OSINT plugins for DNS, WHOIS, certificate transparency, GitHub, Google Custom Search, metadata, IP geo, username enumeration, Censys, Shodan, VirusTotal, HIBP, and email discovery.
- AI provider layer for OpenRouter, OpenAI, Anthropic, Gemini, Nvidia NIM, Groq, and Mistral.
- SQLite storage for targets, findings, entities, relationships, and timeline events.
- Investigation engine with entity extraction and relationship building.
- Report generation in HTML, JSON, Markdown, and PDF.
- Scheduled scan endpoints with APScheduler.
- Provider/settings endpoints and frontend provider management UI.
- CI workflow for Ruff, MyPy, and Pytest.

## Frontend Status

Current frontend is the bundled static UI:

- `frontend/index.html`
- `frontend/app.js`
- `frontend/style.css`

The previous plan mentioned React + TypeScript + Vite + Tailwind, but those source files are not present in the repository. The backend has been stabilized to serve the current static UI. A future React migration can still be done as a separate phase by adding `frontend/package.json`, source files, and a build output to `frontend_dist/`.

## Recommended Next Phases

1. **Scheduled scans persistence hardening**
   - Restore enabled scheduled jobs from the database on application startup.
   - Validate cron expressions before inserting schedules.

2. **Plugin execution policy**
   - Skip disabled plugins at execution time unless explicitly forced.
   - Surface missing credentials more clearly in investigation results.

3. **Frontend modernization (optional)**
   - Either keep improving the static UI or start a real React/Vite migration.
   - If React migration is chosen, add `package.json`, Vite config, TypeScript config, source components, and deterministic build output.

4. **Report/export UX**
   - Add frontend controls for report format selection and PDF download.

5. **Security hardening**
   - Restrict CORS in production.
   - Add authentication if the app is exposed beyond localhost.
