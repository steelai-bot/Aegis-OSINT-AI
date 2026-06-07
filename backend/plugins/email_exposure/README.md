# Email Exposure Plugin — Phase 1 Passive MVP

`EmailExposurePlugin` follows the existing Aegis v2 plugin contract (`BasePlugin`) and returns generic `Finding`-compatible dictionaries. It does **not** add plugin-local database tables or duplicate the existing `hibp` plugin.

## Supported passive sources

- `source_urls`: explicit public URLs approved by the operator.
- `source_url_templates`: explicit URL templates using `{target}` or `{target_query}`.
- `github_token`: optional authorized GitHub Code Search integration.

Example job config:

```json
{
  "email_exposure": {
    "intensity": "passive",
    "source_url_templates": ["https://example.test/search?q={target_query}"],
    "max_findings_per_source": 10
  }
}
```

## Privacy posture

- Raw matched emails are converted to SHA-256 hashes for `value` / `email_hash`.
- Evidence previews redact email addresses.
- HIBP and other breach databases remain separate plugins/integrations.