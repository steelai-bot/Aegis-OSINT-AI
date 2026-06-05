# Legacy Migration Notes

Aegis v2 does not run the legacy monolithic tool chain. Legacy files retained
under `legacy/quarantine/` are migration inventory only.

## Migration Policy

Safe extraction is allowed only when all of these conditions are met:

1. The behavior is passive OSINT, reporting, parsing, or operator workflow
   support.
2. The extracted code has tests in `backend/tests`.
3. Secrets are read only from environment-backed settings.
4. Network calls use the shared HTTP client or a reviewed async integration.
5. The feature is documented in `ARCHITECTURE.md`, `MIGRATION_PLAN.md`, or
   `docs/operator_guide.md`.

## Prohibited Runtime Areas

Do not migrate code that enables:

- credential replay or password handling for access attempts,
- session hijacking or cookie replay,
- browser fingerprint cloning,
- payload execution or exploit chaining,
- lateral movement or post-exploitation behavior,
- hardcoded target workflows,
- autonomous offensive tool execution.

## Candidate Areas For Safe Extraction

- Report formatting and export helpers.
- Passive domain, certificate, and registry normalization.
- Public-source reference data with legal handling notes.
- High-level breach exposure metadata that does not include credential values.
- PDF and document parsing with redaction controls.

## Review Checklist

Before moving any legacy behavior into `backend/`:

- Identify the exact source file and function.
- Write a short behavior summary.
- Record why it is passive and authorized-use compatible.
- Remove target-specific defaults and hardcoded identifiers.
- Replace direct file writes with service-layer persistence or renderer output.
- Add unit tests and static architecture checks when boundaries matter.

## Quarantine Boundary

Files under `legacy/quarantine/` must not be imported by the backend, frontend,
Docker images, CLI quick starts, or docs intended for normal operation. If a
future extraction needs a quarantined dependency, copy only the reviewed safe
logic into a new v2 module and leave the original quarantined file unused.
