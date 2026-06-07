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

Non-passive tools require an approval token. Configure it with:

```bash
export AEGIS_TOOL_EXECUTION_APPROVAL_TOKEN="change-me"
```

Collection requests may include `execution_mode`, `approval_token`, and
`authorized_scope`. The approval token is excluded from serialized Pydantic
responses and audit metadata redacts sensitive token-like keys.

## Rate Limits

`AEGIS_TOOL_EXECUTION_RATE_LIMIT_PER_MINUTE` sets a process-local fixed-window
limit per plugin/target/type key. `0` disables this MVP limiter. This is suitable
for local/API-process gating and should be replaced or backed by Redis/Postgres
for distributed deployments.

## Audit

When a DB session is available, decisions and outcomes are written as sanitized
audit events:

- `tool.execution.decision`
- `tool.execution.completed`
- `tool.execution.failed`

The layer stores target hashes rather than raw targets in audit metadata. Audit
write failures are logged and do not hide successful domain actions.

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
