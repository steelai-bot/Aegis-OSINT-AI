# Aegis v2 TODO

## Phase 0 — Planning and Guardrails

- [x] Create `ARCHITECTURE.md`.
- [x] Create `MIGRATION_PLAN.md`.
- [x] Create `TODO.md`.
- [x] Remove offensive claims from `README.md`.
- [x] Move prohibited legacy modules outside the runnable path or delete them after extraction review.

## Phase 1 — Backend Foundation

- [x] Create backend directory structure.
- [x] Add FastAPI application factory.
- [x] Add `/health` and `/metrics` routes.
- [x] Add Pydantic settings.
- [x] Add async HTTP client wrapper.
- [x] Add event bus abstraction.
- [x] Add base agent classes.
- [x] Add base plugin framework.
- [x] Add base LLM provider framework.
- [x] Add SQLAlchemy model skeleton.
- [x] Add Alembic skeleton.
- [x] Add initial architecture tests.

## Phase 2 — Persistence and API

- [x] Implement async CRUD services.
- [x] Implement investigation endpoints.
- [x] Implement target endpoints.
- [x] Implement finding endpoints.
- [x] Implement report endpoints.
- [x] Add API integration tests.

## Phase 3 — Agent System

- [x] Implement investigation context persistence.
- [x] Implement task result storage.
- [x] Implement event-driven agent workflow.
- [x] Add agent unit tests.

## Phase 4 — Plugin System

- [x] Add WHOIS plugin.
- [x] Add DNS plugin.
- [x] Add crt.sh plugin.
- [x] Add Shodan plugin.
- [x] Add VirusTotal plugin.
- [x] Add SecurityTrails plugin.
- [x] Add HaveIBeenPwned plugin.
- [x] Add plugin configuration tests.

## Phase 5 — AI Layer

- [x] Add OpenAI provider.
- [x] Add Anthropic provider.
- [x] Add Gemini provider.
- [x] Add Hugging Face Inference Providers provider.
- [x] Add Ollama provider.
- [x] Add provider factory tests.

## Phase 6 — Reporting and Correlation

- [x] Add report templates.
- [x] Add Markdown renderer.
- [x] Add HTML renderer.
- [x] Add JSON renderer.
- [x] Add PDF renderer.
- [x] Add finding correlation graph.

## Phase 7 — Frontend

- [x] Initialize Next.js 16 frontend.
- [x] Add dashboard page.
- [x] Add investigations page.
- [x] Add targets page.
- [x] Add findings page.
- [x] Add reports page.
- [x] Add settings page.
- [x] Add plugins page.
- [x] Add websocket live timeline.

## Phase 8 — Docker and Docs

- [ ] Add backend Dockerfile.
- [ ] Add frontend Dockerfile.
- [ ] Add docker compose stack.
- [x] Add Kali Linux compatibility and recent-tool operator documentation.
- [ ] Add remaining operator documentation.
- [ ] Add legacy migration notes.
- [ ] Add security model documentation.
