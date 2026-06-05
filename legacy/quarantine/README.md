# Legacy Quarantine

This directory contains pre-v2 scripts and references that are incompatible
with the supported Aegis v2 runtime.

Files here are retained only for extraction review. They must not be imported
by `backend/`, exposed by API routes, or used by the setup wizard. Any safe
logic extracted from this directory must be rewritten as passive v2 services,
plugins, or renderers with tests and documentation.

Quarantined categories:

- exploit scanning and payload execution
- session replay and browser fingerprint cloning
- credential dump parsing or replay workflows
- infostealer and combo-market workflows
- dark-web or Telegram collection pending legal and policy review
- legacy orchestration entrypoints that enabled the above modules
