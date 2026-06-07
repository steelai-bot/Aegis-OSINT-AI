# Email Exposure Plugin — Phase 1 Passive MVP

`EmailExposurePlugin` follows the existing Aegis v2 plugin contract (`BasePlugin`) and returns generic `Finding`-compatible dictionaries. It does **not** add plugin-local database tables or duplicate the existing `hibp` plugin.

The Phase 1 implementation is intentionally passive: it only reads operator-approved public URLs/templates and optional authorized GitHub Code Search metadata. It does not crawl arbitrary websites or run offensive tooling.

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

## Linux smoke test

If you already cloned the repo earlier, update it instead of deleting/re-cloning:

```bash
./scripts/update_from_repo.sh
```

If your current clone does not have that helper yet, do this once first:

```bash
git fetch origin
git pull --ff-only origin main
```

If you have local edits that you want to keep temporarily:

```bash
./scripts/update_from_repo.sh --stash
```

Use `scripts/smoke_email_exposure.sh` to verify the plugin end-to-end against a running local API. The script:

1. starts a temporary local HTTP server with a synthetic leak fixture;
2. calls `POST /collections/run` with `plugin_name=email_exposure`;
3. validates the normalized finding shape, severity, indicator type, data types, and PII redaction.

### 1. Install runtime dependencies

From the repository root on Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.runtime.txt
pip install uvicorn
```

If you also want to run the unit tests:

```bash
pip install pytest pytest-asyncio
python3 -m pytest backend/tests/test_email_exposure_plugin.py -q
```

### 2. Start the API

In terminal 1:

```bash
source .venv/bin/activate
uvicorn backend.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

By default `AEGIS_AUTH_ENABLED=false`, so no bearer token is required locally. If you enable API auth, export `AEGIS_API_AUTH_TOKEN` before running the smoke test.

### 3. Run the smoke test

In terminal 2:

```bash
chmod +x scripts/smoke_email_exposure.sh
./scripts/smoke_email_exposure.sh
```

Expected result:

```text
[email_exposure smoke] PASS
```

The summary should show a single high-severity email finding with:

- `indicator_type: email`
- `redacted_email: al***@example.com`
- `email_domain: example.com`
- `data_types_found` containing `email` and `password`
- `email_hash` / `value` as a SHA-256 hash, not the raw email

### Configuration knobs

The smoke script supports these environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `AEGIS_API_URL` | `http://127.0.0.1:8000` | API base URL, including any custom prefix if configured. |
| `AEGIS_API_AUTH_TOKEN` | empty | Optional bearer token when API auth is enabled. Legacy `AEGIS_AUTH_TOKEN` is also accepted by the smoke script. |
| `AEGIS_EMAIL_SMOKE_TARGET` | `example.com` | Target sent to the collection API. |
| `AEGIS_EMAIL_SMOKE_TARGET_TYPE` | `domain` | Target type sent to the collection API. |
| `AEGIS_EMAIL_SMOKE_HOST` | `127.0.0.1` | Bind host for the temporary fixture server. |
| `AEGIS_EMAIL_SMOKE_PORT` | `8765` | Port for the temporary fixture server. |

Example with a custom API port:

```bash
AEGIS_API_URL=http://127.0.0.1:8080 ./scripts/smoke_email_exposure.sh
```

### Manual equivalent

If you prefer to inspect the response manually, create a public test fixture and call the collection endpoint:

```bash
mkdir -p /tmp/aegis-email-test
cat >/tmp/aegis-email-test/leak.txt <<'EOF'
public dump alice@example.com:Sup3rSecret123!
EOF
cd /tmp/aegis-email-test
python3 -m http.server 8765 --bind 127.0.0.1
```

Then, from the repository root:

```bash
curl -s -X POST http://127.0.0.1:8000/collections/run \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "example.com",
    "target_type": "domain",
    "plugin_name": "email_exposure",
    "config": {
      "source_urls": ["http://127.0.0.1:8765/leak.txt"],
      "max_findings_per_source": 10
    },
    "enrich": false,
    "async_mode": false
  }' | python3 -m json.tool
```
