# Security Model

Aegis v2 is designed for authorized, passive OSINT investigations. The current
implementation is an MVP security baseline, not a complete multi-tenant SaaS
security boundary.

## Trust Boundaries

- Frontend: operator console, no secrets stored in browser code.
- Backend API: validates input, owns workflow execution and persistence.
- Database: stores investigations, targets, findings, reports, embeddings,
  agent task results, and audit events after the Phase 3A migration is applied.
- Passive collection plugins: operator-approved OSINT integrations that collect
  defensive intelligence for authorized targets.
- External providers: optional OSINT and LLM APIs configured by environment.
- Legacy quarantine: not trusted and not part of the runtime.

## Secrets

Secrets must be supplied through environment variables or a local `.env` file
that is never committed.

Required practices:

- Use separate keys per environment.
- Scope provider keys to the minimum permissions available.
- Rotate keys after suspected exposure.
- Do not log request headers, provider tokens, rendered secrets, or `.env`
  values.
- Do not bake secrets into Docker images. Pass them at runtime.

## Authentication And RBAC

The backend API has an opt-in bearer-token authentication layer for direct API
clients and controlled deployments. It is disabled by default for local MVP demos
and existing development workflows. When `AEGIS_AUTH_ENABLED=true`, protected
endpoint families require `Authorization: Bearer <token>` backed by the
environment-supplied `AEGIS_API_AUTH_TOKEN` value.

The current RBAC foundation uses FastAPI dependencies and a central permission
map for investigation, target, finding, collection, agent, report, audit, and
auth-management permissions. The initial bearer-token principal is treated as an
`admin`, preserving full operator access for valid configured tokens while
keeping route-level authorization checks in place for future real users or
service accounts.

Current limitations before shared production deployment:

- no persistent user, account, service-account, or session model,
- no per-investigation membership or object-level authorization boundary yet,
- Phase 3A audit event persistence exists in code and migration form, but the
  migration has not been run and route-level audit emissions are not integrated
  yet,
- no browser login flow or secure cookie session policy yet.

Future hardening should add authenticated operator identities, scoped service
accounts, per-investigation authorization checks, audit logs for sensitive
actions, and secure session handling if browser login is introduced.

Middleware or proxy checks must not be the only authorization layer. Re-check
authorization in API dependencies or service methods.

## Abuse Vectors

| Vector | Risk | MVP mitigation |
| --- | --- | --- |
| Unauthorized targets | Legal and safety risk | Operator guide requires authorization before target creation |
| Secret leakage | Provider account compromise | Env-only settings and `.dockerignore` for `.env` files |
| Unsafe legacy execution | Offensive behavior in runtime | Quarantine boundary and architecture tests |
| SSRF through target values | Internal network exposure | Keep plugins passive and add allow/deny policy before active fetch expansion |
| Report data leakage | Sensitive findings exported | Operator review before report handoff |
| Dependency drift | Vulnerable runtime packages | Run `npm audit`, Python dependency checks, and image scans in CI |
| Scraping or API abuse | Provider bans or legal risk | Rate limits, timeouts, retries, and source-specific API terms |
| Collection configuration abuse | Unauthorized source monitoring or SSRF-like behavior | Restrict request-scoped plugin config to authorized public sources and add egress controls before production |

## Network Policy

The backend should use outbound network access only for configured passive
providers and public-source lookups. Do not allow arbitrary operator-supplied
URLs to trigger internal network requests without SSRF protections.

Passive collection endpoints are privileged operator workflows. They now have
route-level permission dependencies for opt-in backend auth. Before shared
production deployment, add per-investigation authorization and audit logging for
ad-hoc collection, target collection, and investigation-wide collection runs.

The Tool Execution Layer adds a service-level policy gate before plugin execution.
It supports runtime modes, plugin-declared execution modes, persistent scoped
approval records, environment fallback approval tokens for local use,
process-local rate limits, and sanitized audit events for decisions and outcomes.
Persistent approval records store token hashes and target hashes rather than raw
token/target values. See `docs/tool_execution_layer.md` for the current MVP
contract.

Recommended controls before production:

- egress allowlist per plugin,
- deny private and link-local IP ranges for external fetches,
- request timeout and response size limits,
- source-specific rate limits,
- structured audit events for every external provider call.

Request-scoped plugin configuration should be limited to authorized public sources
or explicit target-owned assets. Provider credentials must remain environment-backed
and must not be supplied through request payloads, browser code, reports, or logs.

## Docker Deployment Notes

The compose stack is for local development. Before production:

- replace default PostgreSQL credentials,
- enable TLS at the ingress layer,
- run database migrations as a controlled release step,
- scan backend and frontend images,
- configure persistent encrypted database storage,
- avoid exposing PostgreSQL directly to public networks,
- set `AEGIS_DEBUG=false`.
