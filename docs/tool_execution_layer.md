# Tool Execution Layer

Aegis v2 now has an MVP Tool Execution Layer in `backend/services/tool_execution.py`.
It is the policy gate that collection orchestration uses before invoking any
plugin/tool.

## Modes

The runtime mode is controlled by `AEGIS_TOOL_EXECUTION_MODE`:

| Mode | Meaning |
| --- | --- |
| `passive` | Default. Only passive OSINT plugins may run. |
| `operator_assisted` | Allows passive and operator-assisted tools, but non-passive tools require approval. |
| `manual_review_only` | Allows manually reviewed tools when an approval token is supplied. |
| `disabled` | Blocks all tool/plugin execution. |

Plugins declare their own mode with `BasePlugin.execution_mode`. Existing OSINT
plugins default to `passive`. Future active/crawl/offensive-adjacent tooling must
declare a stricter mode and should set `requires_approval = True` when operator
approval is mandatory.

## Approval

Non-passive tools require an approval token. There are two supported approval
sources:

1. a persistent, scoped approval record created through the API, or
2. the legacy environment fallback token for local deployments.

### Persistent approvals

Create a scoped approval with:

```http
POST /tool-execution/approvals
```

Example payload:

```json
{
  "plugin_name": "some_operator_tool",
  "target_type": "domain",
  "target": "example.com",
  "execution_mode": "operator_assisted",
  "authorized_scope": "ticket-123 approved domain recon",
  "reason": "Operator-approved verification for an authorized target.",
  "expires_in_minutes": 30,
  "max_uses": 1
}
```

The create response returns `approval_token` exactly once. The database stores
only a SHA-256 token hash plus scope fields (`plugin_name`, `target_type`,
`target_hash`, `execution_mode`, expiry, and use count). Raw targets are not
stored when the API receives `target`; the service stores a normalized hash.

Operators can review or revoke approvals without exposing token material:

```http
GET /tool-execution/approvals
GET /tool-execution/approvals/{approval_id}
DELETE /tool-execution/approvals/{approval_id}
```

When `AEGIS_AUTH_ENABLED=true`, approval endpoints require the admin-only
`tool_execution:approve` permission. With local MVP auth disabled, the endpoints
remain available for development workflows.

### Environment fallback

For simple local deployments, configure a static fallback token with:

```bash
export AEGIS_TOOL_EXECUTION_APPROVAL_TOKEN="change-me"
```

Collection requests may include `execution_mode`, `approval_token`, and
`authorized_scope`. The approval token is excluded from serialized Pydantic
responses and audit metadata redacts sensitive token-like keys.

## Rate Limits

`AEGIS_TOOL_EXECUTION_RATE_LIMIT_PER_MINUTE` sets a fixed-window limit per
plugin/target/type key. `0` disables tool execution rate limiting.

The limiter backend is selected with `AEGIS_TOOL_EXECUTION_RATE_LIMIT_BACKEND`:

| Backend | Meaning |
| --- | --- |
| `memory` | Default. Process-local fixed-window limiter for local development and single-process deployments. |
| `database` | Durable PostgreSQL-backed fixed-window limiter using `tool_execution_rate_limit_buckets` so API/worker processes share counters. |

When `database` is enabled, `ToolExecutionController` uses the same DB session
passed to collection orchestration. Bucket rows are locked during counter updates
on PostgreSQL. If the database limiter fails, the controller logs the failure and
falls back to the process-local limiter rather than bypassing rate limits. Policy
metadata includes `rate_limit_backend` (`memory`, `database`, `memory_fallback`,
or `disabled`) for operator visibility in API responses and audit events.

## Audit

When a DB session is available, decisions and outcomes are written as sanitized
audit events:

- `tool.execution.decision`
- `tool.execution.completed`
- `tool.execution.failed`
- `tool.execution.approval.created`
- `tool.execution.approval.revoked`

The layer stores target hashes rather than raw targets in audit metadata. Audit
write failures are logged and do not hide successful domain actions.

Operators can read the tool execution audit trail through:

```http
GET /audit/events?event_type_prefix=tool.execution.&limit=100
GET /audit/events/{event_id}
```

`/audit/events` defaults to `event_type_prefix=tool.execution.` so the first
view is focused on policy decisions, outcomes, and approval lifecycle events.
Additional filters include `event_type`, `status`, `actor_id`, `resource_type`,
and `resource_id`. When `AEGIS_AUTH_ENABLED=true`, these endpoints require the
admin-only `audit:read` permission.

The frontend console exposes the same readback surface at `/tool-execution`,
showing persistent approvals beside the `tool.execution.*` audit timeline. It
uses sample fallback data when `NEXT_PUBLIC_AEGIS_API_URL` is not configured.

## Collection API Example

```json
{
  "target": "example.com",
  "target_type": "domain",
  "plugin_name": "some_operator_tool",
  "execution_mode": "operator_assisted",
  "authorized_scope": "ticket-123 approved domain recon",
  "approval_token": "change-me"
}
```

If policy blocks a plugin, the API returns a plugin result with status such as
`blocked`, `approval_required`, or `rate_limited` and includes policy metadata.
