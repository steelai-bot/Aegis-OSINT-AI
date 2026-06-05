# Aegis v2 TODO

## Phase 0 — Planning and Guardrails

- [x] Create `ARCHITECTURE.md`.
- [x] Create `MIGRATION_PLAN.md`.
- [x] Create `TODO.md`.
- [ ] Remove offensive claims from `README.md`.
- [ ] Move prohibited legacy modules outside the runnable path or delete them after extraction review.

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
- [ ] Add API integration tests.

## Phase 3 — Agent System

- [ ] Implement investigation context persistence.
- [ ] Implement task result storage.
- [ ] Implement event-driven agent workflow.
- [ ] Add agent unit tests.

## Phase 4 — Plugin System

- [x] Add WHOIS plugin.
- [x] Add DNS plugin.
- [x] Add crt.sh plugin.
- [x] Add Shodan plugin.
- [x] Add VirusTotal plugin.
- [x] Add SecurityTrails plugin.
- [x] Add HaveIBeenPwned plugin.
- [ ] Add plugin configuration tests.

## Phase 5 — AI Layer

- [x] Add OpenAI provider.
- [x] Add Anthropic provider.
- [x] Add Gemini provider.
- [x] Add Hugging Face Inference Providers provider.
- [x] Add Ollama provider.
- [x] Add provider factory tests.

## Phase 6 — Reporting and Correlation

- [ ] Add report templates.
- [x] Add Markdown renderer.
- [ ] Add HTML renderer.
- [x] Add JSON renderer.
- [ ] Add PDF renderer.
- [ ] Add finding correlation graph.

## Phase 7 — Frontend

- [ ] Initialize Next.js 16 frontend.
- [ ] Add dashboard page.
- [ ] Add investigations page.
- [ ] Add targets page.
- [ ] Add findings page.
- [ ] Add reports page.
- [ ] Add settings page.
- [ ] Add plugins page.
- [ ] Add websocket live timeline.

## Phase 8 — Docker and Docs

- [ ] Add backend Dockerfile.
- [ ] Add frontend Dockerfile.
- [ ] Add docker compose stack.
- [x] Add Kali Linux compatibility and recent-tool operator documentation.
- [ ] Add remaining operator documentation.
- [ ] Add legacy migration notes.
- [ ] Add security model documentation.
