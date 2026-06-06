# Auth, RBAC, and Audit Plan

Aegis v2 is currently an MVP for authorized, passive OSINT investigations. This
plan tracks security-hardening phases for authentication, role-based access
control, and audit logging while preserving local development behavior unless an
implementation phase explicitly changes it.

## Goals

- Protect operator workflows before shared or production deployment.
- Keep local development and existing MVP demos usable by default.
- Avoid storing browser-visible secrets in `NEXT_PUBLIC_*` frontend variables.
- Add authorization checks in backend dependencies or service boundaries, not
  only in reverse proxy or middleware configuration.
- Capture audit events for sensitive actions, denied attempts, and externally
  visible investigation outputs.

## Current State

- Backend authentication is opt-in and default-off. Protected routes preserve
  current MVP behavior unless `AEGIS_AUTH_ENABLED=true` is configured.
- When backend auth is enabled, protected route families require
  `Authorization: Bearer <token>` matching the environment-backed
  `AEGIS_API_AUTH_TOKEN` setting.
- The first valid-token principal is `Principal(id="local-api-token", role="admin")`.
- Route modules use `require_permission(...)` dependencies with a central
  permission map for investigation, target, finding, collection, agent, report,
  audit, and auth-management permissions.
- `GET /health` remains public by default, but can be protected with
  `AEGIS_AUTH_ALLOW_UNAUTHENTICATED_HEALTH=false`.
- `GET /metrics` is protected when backend auth is enabled.
- There are no user/account/role models and no audit event table.
- Frontend calls the backend directly when `NEXT_PUBLIC_AEGIS_API_URL` is set.

## Endpoint Protection Matrix

| Endpoint family | Initial access recommendation | Notes |
| --- | --- | --- |
| `GET /health` | Public | Required for local and deployment health checks. |
| `GET /metrics` | Protected or internal-only | Keep public only in local/dev. Avoid leaking operational metadata. |
| `/investigations` | Protected | Investigation metadata is sensitive. |
| `/targets` and `/investigations/{id}/targets` | Protected | Target creation requires operator authorization. |
| `/findings` and `/investigations/{id}/findings` | Protected | Findings may contain sensitive intelligence. |
| `/reports` and report rendering | Protected | Reports are export paths and must be auditable. |
| `/collections/*` | Protected privileged workflow | Passive collection may call external providers and persist findings. |
| `/agents/run` | Protected privileged workflow | Agent execution can create or transform investigation intelligence. |

## Roles

The first RBAC design should use a small, stable role set:

| Role | Purpose |
| --- | --- |
| `admin` | Full local/operator administration, auth configuration, and audit review. |
| `analyst` | Create investigations/targets, run collection and agents, render reports. |
| `viewer` | Read investigations, targets, findings, reports, and collection status. |
| `service` | Automation or integration identity for narrowly scoped API workflows. |

Future multi-tenant deployments may add team/project membership, but that should
not be mixed into the first auth hardening pass.

## Permission Matrix

| Permission | Admin | Analyst | Viewer | Service |
| --- | --- | --- | --- | --- |
| `investigation:read` | Yes | Yes | Yes | Optional |
| `investigation:create` | Yes | Yes | No | Optional |
| `target:read` | Yes | Yes | Yes | Optional |
| `target:create` | Yes | Yes | No | Optional |
| `finding:read` | Yes | Yes | Yes | Optional |
| `finding:create` | Yes | Yes | No | Optional |
| `collection:run` | Yes | Yes | No | Optional, narrow scope |
| `collection:status` | Yes | Yes | Yes | Optional |
| `agent:run` | Yes | Yes | No | Optional, narrow scope |
| `report:read` | Yes | Yes | Yes | Optional |
| `report:create` | Yes | Yes | No | Optional |
| `report:render` | Yes | Yes | No | Optional |
| `audit:read` | Yes | No by default | No | No |
| `auth:manage` | Yes | No | No | No |

## Phase 1: Minimal Backend Auth Dependency — Implemented

An opt-in bearer token dependency has been added without database schema changes.

Implemented settings:

```python
auth_enabled: bool = False
api_auth_token: str | None = None
auth_allow_unauthenticated_health: bool = True
```

Implemented behavior:

- `backend/api/security.py` contains the auth dependency.
- FastAPI security utilities parse `Authorization: Bearer <token>`.
- When `auth_enabled=False`, preserve current behavior.
- When enabled, require a valid token for protected endpoint families.
- Keep `GET /health` public unless explicitly configured otherwise.
- Protect `GET /metrics` when backend auth is enabled.

Affected route files:

- `backend/api/routes/investigations.py`
- `backend/api/routes/targets.py`
- `backend/api/routes/findings.py`
- `backend/api/routes/collections.py`
- `backend/api/routes/reports.py`
- `backend/api/routes/agents.py`
- optionally `backend/api/routes/health.py` for metrics protection

Risk controls:

- Default `auth_enabled=False` to avoid accidental lockout.
- Never hardcode tokens or modify `.env` in source changes.
- Do not expose backend bearer tokens through `NEXT_PUBLIC_*` variables.

## Phase 2: RBAC Abstractions — Implemented

Principal and permission abstractions have been introduced before adding real
user models.

Implemented initial design:

- `Principal(id="local-api-token", role="admin")` for the first bearer-token
  implementation.
- `require_permission("collection:run")` style dependencies on protected routes.
- Central permission mapping so route modules do not duplicate RBAC logic.
- Default-off behavior is preserved because permission dependencies allow
  `principal is None` when auth is disabled.

This keeps the first implementation minimal while avoiding a later route rewrite
when real users or service accounts are introduced.

## Phase 3: Audit Event Persistence

Add audit logging as a separate, explicitly approved schema change.

Likely new files:

- `backend/models/audit_event.py`
- `backend/services/audit.py`
- `backend/api/schemas/audit.py` if an audit read endpoint is exposed
- Alembic migration, likely `0005_audit_events.py`

Recommended columns:

| Column | Purpose |
| --- | --- |
| `id` | UUID primary key. |
| `event_type` | Stable event name, indexed. |
| `actor_id` | Principal/user/service identifier, indexed when available. |
| `actor_role` | Role at time of action. |
| `resource_type` | Investigation, target, finding, report, collection run, agent run. |
| `resource_id` | Resource identifier when available. |
| `status` | `success`, `denied`, or `error`. |
| `request_id` | Correlates logs and API requests. |
| `ip_address` | Request origin if available. |
| `user_agent` | Operator/client user agent if available. |
| `metadata_json` | Bounded structured metadata with no secrets. |
| timestamps | Created/updated timestamps using existing model conventions. |

Initial audit taxonomy:

- `auth.denied`
- `investigation.created`
- `target.created`
- `finding.created`
- `collection.queued`
- `collection.completed`
- `collection.failed`
- `agent.run_started`
- `report.created`
- `report.rendered`

Audit metadata must not include provider API keys, bearer tokens, `.env` values,
raw authorization headers, or full sensitive report contents.

## Phase 4: Frontend Authentication Strategy

Do not put real backend bearer tokens in `NEXT_PUBLIC_*` variables. Values with
that prefix are browser-visible.

Preferred options:

1. Keep backend auth disabled for local frontend demos and single-operator local
   development.
2. Add a server-side frontend API proxy later that attaches a server-only token.
3. Add real browser login later with secure sessions or an external identity
   provider.

Until one of these is implemented, backend bearer-token auth should primarily be
used by direct API clients, local operators, or deployment ingress controls.

## Phase 5: Real Users and Multi-Investigation Authorization

Defer until the previous phases are stable:

- user or account model,
- service accounts/API keys,
- OIDC or passwordless login,
- session lifecycle and secure cookie policy,
- team/project membership,
- per-investigation authorization boundaries,
- audit review UI or protected audit export endpoint.

## Recommended Implementation Order

1. Add opt-in auth dependency with default-off behavior. **Implemented.**
2. Apply route-level protection to privileged endpoint families. **Implemented.**
3. Introduce principal and permission abstractions. **Implemented.**
4. Add audit event model, migration, and write-only audit service.
5. Add audit reads for admins only, if needed.
6. Design frontend auth separately; do not expose secrets in browser env.

Each step after this document should be reviewed and approved independently,
especially any database migration, API contract change, or frontend auth flow.